import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart' as pdf;
import 'package:test/test.dart';

class SignaturePosition {
  final int pageNumber;
  final double x, y, width, height;
  const SignaturePosition(
      this.pageNumber, this.x, this.y, this.width, this.height);
}

class PdfAssinaturaGovBrService {
  Future<({String hashBase64, String tempFilePath})> prepararPdfParaAssinatura({
    required String inputPath,
    required SignaturePosition signaturePosition,
  }) async {
    final originalFile = File(inputPath);
    if (!originalFile.existsSync()) throw Exception('File not found');

    final tempFileName =
        'temp_align_${DateTime.now().millisecondsSinceEpoch}.pdf';
    final tempFilePath = '${originalFile.parent.path}/$tempFileName';
    final tempFile = File(tempFilePath);
    await originalFile.copy(tempFilePath);

    final fileBytes = await tempFile.readAsBytes();
    final signature = pdf.PdfSignature();
    signature.documentPermissions = [pdf.PdfCertificationFlags.allowFormFill];
    signature.contactInfo = 'Gov.br - Assinatura Digital';
    signature.reason = 'Assinatura eletronica via Gov.br';
    signature.digestAlgorithm = pdf.DigestAlgorithm.sha256;

    final prepared = await pdf.PdfExternalSigning.preparePdf(
      inputBytes: Uint8List.fromList(fileBytes),
      pageNumber: signaturePosition.pageNumber,
      bounds: pdf.Rect.fromLTWH(
        signaturePosition.x,
        signaturePosition.y,
        signaturePosition.width,
        signaturePosition.height,
      ),
      fieldName: 'GovBr_Signature',
      signature: signature,
      publicCertificates: <List<int>>[],
    );

    await tempFile.writeAsBytes(prepared.preparedPdfBytes, flush: true);

    return (hashBase64: prepared.hashBase64, tempFilePath: tempFilePath);
  }

  Future<Uint8List> finalizarAssinaturaNoPdf({
    required String tempFilePath,
    required String p7sHex,
  }) async {
    final tempFile = File(tempFilePath);
    if (!tempFile.existsSync()) throw Exception('Temp file missing');

    final fileBytes = await tempFile.readAsBytes();
    final sigBytes = _hexToBytes(p7sHex);
    return pdf.PdfExternalSigning.embedSignature(
      preparedPdfBytes: Uint8List.fromList(fileBytes),
      pkcs7Bytes: sigBytes,
    );
  }
}

void main() {
  final bool hasOpenSsl = _hasOpenSsl();

  test(
    'external signature flow with OpenSSL',
    () async {
      if (!hasOpenSsl) return;

      final testDir = await Directory.systemTemp.createTemp('sig_test_');
      try {
        final service = PdfAssinaturaGovBrService();

        await _runCmd('openssl', [
          'req',
          '-x509',
          '-newkey',
          'rsa:2048',
          '-keyout',
          '${testDir.path}/user_key.pem',
          '-out',
          '${testDir.path}/user_cert.pem',
          '-days',
          '365',
          '-nodes',
          '-subj',
          '/CN=John Doe',
          '-addext',
          'keyUsage=digitalSignature'
        ]);

        final doc = pdf.PdfDocument();
        doc.pages.add().graphics.drawString(
              'Hello, World! This is a test for Gov.br signature.',
              pdf.PdfStandardFont(pdf.PdfFontFamily.helvetica, 12),
            );
        final inputPdfPath = '${testDir.path}/input.pdf';
        File(inputPdfPath).writeAsBytesSync(await doc.save());

        final prepResult = await service.prepararPdfParaAssinatura(
          inputPath: inputPdfPath,
          signaturePosition: const SignaturePosition(1, 100, 100, 200, 50),
        );

        final tempPdfPath = prepResult.tempFilePath;
        final preparedBytes = File(tempPdfPath).readAsBytesSync();
        final ranges =
            pdf.PdfExternalSigning.extractByteRange(preparedBytes);

        final start1 = ranges[0];
        final len1 = ranges[1];
        final start2 = ranges[2];
        final len2 = ranges[3];

        final part1 = preparedBytes.sublist(start1, start1 + len1);
        final part2 = preparedBytes.sublist(start2, start2 + len2);
        final dataToSignPath = '${testDir.path}/data_to_sign.bin';
        final dataSink = File(dataToSignPath).openWrite();
        dataSink.add(part1);
        dataSink.add(part2);
        await dataSink.close();

        await _runCmd('openssl', [
          'smime',
          '-sign',
          '-binary',
          '-in',
          dataToSignPath.replaceAll('/', Platform.pathSeparator),
          '-signer',
          '${testDir.path}/user_cert.pem'
              .replaceAll('/', Platform.pathSeparator),
          '-inkey',
          '${testDir.path}/user_key.pem'
              .replaceAll('/', Platform.pathSeparator),
          '-out',
          '${testDir.path}/signature.p7s'
              .replaceAll('/', Platform.pathSeparator),
          '-outform',
          'DER'
        ]);

        final sigFile = File('${testDir.path}/signature.p7s');
        expect(sigFile.existsSync(), isTrue);
        final sigBytes = sigFile.readAsBytesSync();
        final sigHex = _hex(sigBytes);

        final finalizedBytes = await service.finalizarAssinaturaNoPdf(
          tempFilePath: tempPdfPath,
          p7sHex: sigHex,
        );

        final signedPdfPath = '${testDir.path}/final_signed.pdf';
        File(signedPdfPath).writeAsBytesSync(finalizedBytes);
        expect(finalizedBytes, isNotEmpty);
      } finally {
        await testDir.delete(recursive: true);
      }
    },
    timeout: const Timeout(Duration(minutes: 2)),
    skip: hasOpenSsl ? false : 'openssl not available',
  );
}

bool _hasOpenSsl() {
  try {
    final ProcessResult result =
        Process.runSync('openssl', const ['version']);
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}

Future<void> _runCmd(String cmd, List<String> args) async {
  final res = await Process.run(cmd, args);
  if (res.exitCode != 0) {
    throw Exception('Command failed: $cmd ${args.join(' ')}');
  }
}

String _hex(List<int> bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

List<int> _hexToBytes(String hex) {
  final String clean = hex.trim();
  if (clean.isEmpty) return <int>[];
  final String normalized = clean.length.isOdd ? '0$clean' : clean;
  final List<int> out = <int>[];
  for (int i = 0; i < normalized.length; i += 2) {
    out.add(int.parse(normalized.substring(i, i + 2), radix: 16));
  }
  return out;
}
