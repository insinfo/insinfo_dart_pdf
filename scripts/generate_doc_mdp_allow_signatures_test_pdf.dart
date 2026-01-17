import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:pointycastle/export.dart';

import 'package:dart_pdf/src/pki/pki_builder.dart';

class RawRsaSigner implements IPdfExternalSigner {
  final RSAPrivateKey privateKey;
  final DigestAlgorithm _digest;

  RawRsaSigner(this.privateKey, [this._digest = DigestAlgorithm.sha256]);

  @override
  DigestAlgorithm get hashAlgorithm => _digest;

  @override
  Future<SignerResult?> sign(List<int> message) async {
    return _sign(message);
  }

  @override
  SignerResult? signSync(List<int> message) {
    return _sign(message);
  }

  SignerResult _sign(List<int> message) {
    final signatureBytes = PkiBuilder.signData(
      Uint8List.fromList(message),
      privateKey,
    );
    return SignerResult(signatureBytes);
  }
}

Future<void> main(List<String> args) async {
  final String outPath = args.isNotEmpty
      ? args.first
      : 'test/assets/generated_doc_mdp_allow_signatures.pdf';

  final rootKey = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
  final interKey = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
  final userKey = PkiUtils.generateRsaKeyPair(bitStrength: 2048);

  final Uint8List rootCert = PkiBuilder.createRootCertificate(
    keyPair: rootKey,
    dn: 'CN=Teste AC Raiz DocMDP,O=DartPDF,C=BR',
  );

  final Uint8List interCert = PkiBuilder.createIntermediateCertificate(
    keyPair: interKey,
    issuerKeyPair: rootKey,
    subjectDn: 'CN=Teste AC Intermediaria DocMDP,O=DartPDF,C=BR',
    issuerDn: 'CN=Teste AC Raiz DocMDP,O=DartPDF,C=BR',
    serialNumber: 1001,
  );

  final Uint8List userCert = PkiBuilder.createUserCertificate(
    keyPair: userKey,
    issuerKeyPair: interKey,
    subjectDn: 'CN=Teste Assinante DocMDP,O=DartPDF,C=BR',
    issuerDn: 'CN=Teste AC Intermediaria DocMDP,O=DartPDF,C=BR',
    serialNumber: 2001,
  );

  final PdfDocument document = PdfDocument();
  final PdfPage page = document.pages.add();
  page.graphics.drawString(
    'PDF de teste DocMDP (permite novas assinaturas).',
    PdfStandardFont(PdfFontFamily.helvetica, 12),
  );

  final PdfSignature signature = PdfSignature(
    signedName: 'Teste Assinante DocMDP',
    reason: 'Teste DocMDP permitir novas assinaturas',
    locationInfo: 'Gerado via script',
    contactInfo: 'test@example.com',
    digestAlgorithm: DigestAlgorithm.sha256,
  );

  signature.configureDocMdpForFirstSignature(document, permissionP: 2);

  final PdfSignatureField field = PdfSignatureField(
    page,
    'CertificationSignature',
    signature: signature,
    bounds: const Rect.fromLTWH(0, 0, 250, 50),
  );
  document.form.fields.add(field);

  final RawRsaSigner signer = RawRsaSigner(userKey.privateKey as RSAPrivateKey);
  final List<List<int>> chain = <List<int>>[userCert, interCert, rootCert];
  signature.addExternalSigner(signer, chain);

  final List<int> bytes = await document.save();
  document.dispose();

  final File outFile = File(outPath);
  outFile.parent.createSync(recursive: true);
  outFile.writeAsBytesSync(bytes, flush: true);

  stdout.writeln('Generated: ${outFile.path}');
}
