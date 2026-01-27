import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

void main() {
  test('PdfSignatureValidationItem.signerInfo exposes cert validity', () async {
    final File file = File('test/assets/2 ass leonardo e mauricio.pdf');
    expect(file.existsSync(), isTrue,
        reason: 'Arquivo não encontrado: ${file.path}');

    final Uint8List bytes = file.readAsBytesSync();

    final PdfSignatureValidationReport report =
        await PdfSignatureValidator().validateAllSignatures(
      bytes,
      fetchCrls: false,
      useEmbeddedIcpBrasil: true,
    );

    expect(report.signatures, isNotEmpty);

    for (final PdfSignatureValidationItem sig in report.signatures) {
      final PdfSignerInfo? info = sig.signerInfo;
      expect(info, isNotNull);
      expect(info!.certNotAfter, isNotNull);

      final PdfSignerInfo? infoDirect =
          PdfSignerInfo.fromCertificatesPem(sig.validation.certsPem);
      expect(infoDirect, isNotNull);
      expect(infoDirect!.certNotAfter, isNotNull);
      expect(infoDirect.certNotAfter, equals(info.certNotAfter));
    }
  });
}
