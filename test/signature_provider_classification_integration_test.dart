import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart' as pdf;
import 'package:dart_pdf/src/security/signer_classifier.dart';
import 'package:test/test.dart';

void main() {
  test('Classifies SERPRO signatures', () async {
    final pdf.PdfSignatureValidationReport r1 = await _validate('test/assets/serpro_Maurício_Soares_dos_Anjos.pdf');
    expect(r1.signatures, isNotEmpty);
    expect(classifySignerFromCertificatesPem(r1.signatures.first.validation.certsPem).providerLabel, 'serpro');

    final pdf.PdfSignatureValidationReport r2 = await _validate('test/assets/carlos_augusto.pdf');
    expect(r2.signatures, isNotEmpty);
    expect(classifySignerFromCertificatesPem(r2.signatures.first.validation.certsPem).providerLabel, 'serpro');
  });

  test('Classifies gov.br signatures', () async {
    final pdf.PdfSignatureValidationReport r = await _validate('test/assets/sample_govbr_signature_assinado.pdf');
    expect(r.signatures, isNotEmpty);
    expect(classifySignerFromCertificatesPem(r.signatures.first.validation.certsPem).providerLabel, 'gov.br');
  });

  test('Classifies Certisign signatures (OAB chain)', () async {
    final pdf.PdfSignatureValidationReport r = await _validate('test/assets/sample_token_icpbrasil_assinado.pdf');
    expect(r.signatures, isNotEmpty);
    expect(classifySignerFromCertificatesPem(r.signatures.first.validation.certsPem).providerLabel, 'certisign');
  });
}

Future<pdf.PdfSignatureValidationReport> _validate(String path) async {
  final File f = File(path);
  if (!f.existsSync()) {
    throw Exception('Missing test asset: $path');
  }
  final Uint8List bytes = f.readAsBytesSync();
  return pdf.PdfSignatureValidator().validateAllSignatures(bytes);
}
