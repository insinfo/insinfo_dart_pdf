import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart' as pdf;
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/pdf_ltv_manager.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/x509/x509_certificates.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/x509/x509_utils.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/pdf_signature_validator.dart';
import 'package:test/test.dart';

void main() {
  final bool hasOpenSsl = _hasOpenSsl();

  test('PdfLtvManager creates DSS and VRI dictionaries', () async {
    if (!hasOpenSsl) return;

    final Directory testDir = await Directory.systemTemp.createTemp('ltv_test_');
    try {
      final String keyPath = '${testDir.path}/user_key.pem';
      final String certPath = '${testDir.path}/user_cert.pem';

      // Create Self-Signed Cert
      await _runCmd('openssl', [
        'req', '-x509', '-newkey', 'rsa:2048', '-keyout', keyPath, '-out', certPath,
        '-days', '365', '-nodes', '-subj', '/CN=LTV Test User', 
        '-addext', 'keyUsage=digitalSignature'
      ]);

      // Create PDF
      final pdf.PdfDocument docBuilder = pdf.PdfDocument();
      docBuilder.pages.add().graphics.drawString('LTV Test', pdf.PdfStandardFont(pdf.PdfFontFamily.helvetica, 12));
      final Uint8List unsignedPdf = Uint8List.fromList(await docBuilder.save());
      docBuilder.dispose();

      // Sign PDF
      final Uint8List signedPdf = await _externallySignWithOpenSsl(
        pdfBytes: unsignedPdf,
        fieldName: 'Sig1',
        keyPath: keyPath,
        certPath: certPath,
        workDir: testDir,
      );

      // Load Document for LTV
      final pdf.PdfDocument doc = pdf.PdfDocument(inputBytes: signedPdf);
      final PdfLtvManager ltvManager = PdfLtvManager(doc);

      // Load Cert as Trusted Root (so chain validates)
      final String certPem = File(certPath).readAsStringSync();
      final X509Certificate root = X509Utils.parsePemCertificate(certPem);

      // Enable LTV
      await ltvManager.enableLtv(
        signedPdf,
        trustedRoots: [root],
        addVri: true,
      );

      // Save Output
      final Uint8List ltvBytes = Uint8List.fromList(await doc.save());
      doc.dispose();

      // Verify LTV Structures
      final PdfSignatureValidator validator = PdfSignatureValidator();
      final PdfSignatureValidationReport report = await validator.validateAllSignatures(ltvBytes, trustedRootsPem: [certPem]);
      final PdfSignatureValidationItem sig = report.signatures.first;
      
      print('LTV Info: hasDss=${sig.ltv.hasDss} dssCerts=${sig.ltv.dssCertsCount}');

      expect(sig.ltv.hasDss, isTrue, reason: 'DSS Dictionary should be present');
      expect(sig.ltv.dssCertsCount, greaterThanOrEqualTo(1), reason: 'DSS should contain the signer certificate');
      
      // VRI presence check
      expect(sig.ltv.signatureHasVri, isTrue, reason: 'VRI should be created for the signature');

    } finally {
      if (testDir.existsSync()) testDir.deleteSync(recursive: true);
    }
  });
}

// Helpers
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
    throw Exception('Command failed: $cmd ${args.join(' ')}\n${res.stderr}');
  }
}
