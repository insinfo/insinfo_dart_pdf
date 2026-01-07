import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart' as pdf;
import 'package:test/test.dart';

void main() {
  final bool hasOpenSsl = _hasOpenSsl();

  test(
    'PdfSignatureValidator validates multiple incremental signatures',
    () async {
      if (!hasOpenSsl) return;

      final Directory testDir = await Directory.systemTemp.createTemp('sig_val_');
      try {
        final String keyPath = '${testDir.path}/user_key.pem';
        final String certPath = '${testDir.path}/user_cert.pem';

        await _runCmd('openssl', [
          'req',
          '-x509',
          '-newkey',
          'rsa:2048',
          '-keyout',
          keyPath,
          '-out',
          certPath,
          '-days',
          '365',
          '-nodes',
          '-subj',
          '/CN=John Doe',
          '-addext',
          'keyUsage=digitalSignature'
        ]);

        final pdf.PdfDocument doc = pdf.PdfDocument();
        doc.pages.add().graphics.drawString(
              'Hello, World! multi-signature test.',
              pdf.PdfStandardFont(pdf.PdfFontFamily.helvetica, 12),
            );
        final Uint8List unsignedPdf = Uint8List.fromList(await doc.save());
        doc.dispose();

        final Uint8List signedOnce = await _externallySignWithOpenSsl(
          pdfBytes: unsignedPdf,
          fieldName: 'Sig1',
          keyPath: keyPath,
          certPath: certPath,
          workDir: testDir,
        );

        final Uint8List signedTwice = await _externallySignWithOpenSsl(
          pdfBytes: signedOnce,
          fieldName: 'Sig2',
          keyPath: keyPath,
          certPath: certPath,
          workDir: testDir,
        );

        final pdf.PdfSignatureValidationReport report = await pdf.PdfSignatureValidator()
            .validateAllSignatures(
          signedTwice,
          trustedRootsPem: <String>[File(certPath).readAsStringSync()],
        );

        if (report.signatures.isNotEmpty) {
          for (final pdf.PdfSignatureValidationItem item in report.signatures) {
            // ignore: avoid_print
            print(
              '${item.fieldName}: cms=${item.validation.cmsSignatureValid} '
              'digest=${item.validation.byteRangeDigestOk} '
              'intact=${item.validation.documentIntact} '
              'certs=${item.validation.certsPem.length} '
              'chain=${item.chainTrusted}',
            );
          }
        }

        expect(report.signatures.length, 2);

        // Signatures must be ordered by signed revision length.
        expect(
          report.signatures[0].signedRevisionLength <
              report.signatures[1].signedRevisionLength,
          isTrue,
        );

        // First signature signs an earlier revision; second covers current file.
        expect(report.signatures[0].coversCurrentFile, isFalse);
        expect(report.signatures[1].coversCurrentFile, isTrue);

        for (final pdf.PdfSignatureValidationItem item in report.signatures) {
          expect(item.validation.cmsSignatureValid, isTrue,
              reason: 'CMS signature must be valid for ${item.fieldName}');
          expect(item.validation.byteRangeDigestOk, isTrue,
              reason: 'ByteRange digest must match for ${item.fieldName}');
          expect(item.validation.documentIntact, isTrue,
              reason: 'Document must be intact for ${item.fieldName}');
          expect(item.validation.certsPem, isNotEmpty,
              reason: 'CMS should contain certs for ${item.fieldName}');

          // When we provide the self-signed root (the same cert used to sign),
          // chain validation is expected to succeed.
          expect(item.chainTrusted, isTrue,
              reason: 'Chain trust should validate against provided trustedRootsPem');
        }
      } finally {
        await testDir.delete(recursive: true);
      }
    },
    timeout: const Timeout(Duration(minutes: 3)),
    skip: hasOpenSsl ? false : 'openssl not available',
  );
}

Future<Uint8List> _externallySignWithOpenSsl({
  required Uint8List pdfBytes,
  required String fieldName,
  required String keyPath,
  required String certPath,
  required Directory workDir,
}) async {
  final pdf.PdfSignature signature = pdf.PdfSignature();
  signature.contactInfo = 'Unit test';
  signature.reason = 'Multi-signature test';
  signature.digestAlgorithm = pdf.DigestAlgorithm.sha256;

  final pdf.PdfExternalSigningResult prepared = await pdf.PdfExternalSigning.preparePdf(
    inputBytes: Uint8List.fromList(pdfBytes),
    pageNumber: 1,
    bounds: pdf.Rect.fromLTWH(100, 100, 200, 50),
    fieldName: fieldName,
    signature: signature,
    publicCertificates: <List<int>>[],
  );

  final Uint8List preparedBytes = prepared.preparedPdfBytes;
  final List<int> ranges = pdf.PdfExternalSigning.extractByteRange(preparedBytes);

  final int start1 = ranges[0];
  final int len1 = ranges[1];
  final int start2 = ranges[2];
  final int len2 = ranges[3];

  final List<int> part1 = preparedBytes.sublist(start1, start1 + len1);
  final List<int> part2 = preparedBytes.sublist(start2, start2 + len2);

  final String dataToSignPath = '${workDir.path}/data_to_sign_$fieldName.bin';
  final IOSink dataSink = File(dataToSignPath).openWrite();
  dataSink.add(part1);
  dataSink.add(part2);
  await dataSink.close();

  final String p7sPath = '${workDir.path}/signature_$fieldName.p7s';

  await _runCmd('openssl', [
    'smime',
    '-sign',
    '-binary',
    '-in',
    dataToSignPath.replaceAll('/', Platform.pathSeparator),
    '-signer',
    certPath.replaceAll('/', Platform.pathSeparator),
    '-inkey',
    keyPath.replaceAll('/', Platform.pathSeparator),
    '-out',
    p7sPath.replaceAll('/', Platform.pathSeparator),
    '-outform',
    'DER'
  ]);

  // Sanity-check: OpenSSL must be able to verify what it produced.
  final String verifiedOutPath = '${workDir.path}/verified_$fieldName.out';
  await _runCmd('openssl', [
    'smime',
    '-verify',
    '-inform',
    'DER',
    '-in',
    p7sPath.replaceAll('/', Platform.pathSeparator),
    '-content',
    dataToSignPath.replaceAll('/', Platform.pathSeparator),
    '-noverify',
    '-out',
    verifiedOutPath.replaceAll('/', Platform.pathSeparator),
  ]);

  // Debug aid: show a small ASN.1 parse snippet.
  if (fieldName == 'Sig1') {
    final ProcessResult asn1 = await Process.run('openssl', [
      'asn1parse',
      '-inform',
      'DER',
      '-in',
      p7sPath.replaceAll('/', Platform.pathSeparator),
    ]);
    if (asn1.exitCode == 0) {
      final String out = (asn1.stdout ?? '').toString();
      // ignore: avoid_print
      print(out.split(RegExp(r'\r?\n')).take(140).join('\n'));
    }
  }

  final Uint8List sigBytes = Uint8List.fromList(File(p7sPath).readAsBytesSync());
  return pdf.PdfExternalSigning.embedSignature(
    preparedPdfBytes: preparedBytes,
    pkcs7Bytes: sigBytes,
  );
}

bool _hasOpenSsl() {
  try {
    final ProcessResult result = Process.runSync('openssl', const <String>['version']);
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}

Future<void> _runCmd(String cmd, List<String> args) async {
  final ProcessResult res = await Process.run(cmd, args);
  if (res.exitCode != 0) {
    throw Exception('Command failed: $cmd ${args.join(' ')}');
  }
}
