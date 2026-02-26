import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pki/pki_builder.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';

class _RawRsaSigner implements IPdfExternalSigner {
  _RawRsaSigner(this.privateKey);

  final pc.RSAPrivateKey privateKey;

  @override
  DigestAlgorithm get hashAlgorithm => DigestAlgorithm.sha256;

  @override
  Future<SignerResult?> sign(List<int> message) async => signSync(message);

  @override
  SignerResult? signSync(List<int> message) {
    final signatureBytes =
        PkiBuilder.signData(Uint8List.fromList(message), privateKey);
    return SignerResult(signatureBytes);
  }
}

void main() {
  group('Smart signature validation APIs', () {
    test('preflight + candidates + trustedRootsIndex validate direct root chain',
        () async {
      final rootKey = PkiUtils.generateRsaKeyPair(bitStrength: 1024);
      final userKey = PkiUtils.generateRsaKeyPair(bitStrength: 1024);

      final Uint8List rootCert = PkiBuilder.createRootCertificate(
        keyPair: rootKey,
        dn: 'CN=Root Candidate CA,O=Test',
      );

      final Uint8List userCert = PkiBuilder.createUserCertificate(
        keyPair: userKey,
        issuerKeyPair: rootKey,
        subjectDn: 'CN=Candidate User,O=Test,C=BR',
        issuerDn: 'CN=Root Candidate CA,O=Test',
        serialNumber: 987654321,
      );

      final PdfDocument document = PdfDocument();
      document.pages.add().graphics.drawString(
            'Candidate roots validation test',
            PdfStandardFont(PdfFontFamily.helvetica, 12),
          );

      final PdfSignature signature = PdfSignature(
        signedName: 'Candidate User',
        reason: 'Test',
        digestAlgorithm: DigestAlgorithm.sha256,
        cryptographicStandard: CryptographicStandard.cms,
      );

      final PdfPage page = document.pages[0];
      final PdfSignatureField field = PdfSignatureField(
        page,
        'Signature1',
        signature: signature,
        bounds: Rect.fromLTWH(10, 10, 220, 50),
      );
      document.form.fields.add(field);

      signature.addExternalSigner(
        _RawRsaSigner(userKey.privateKey as pc.RSAPrivateKey),
        <Uint8List>[userCert, rootCert],
      );

      final Uint8List pdfBytes = Uint8List.fromList(await document.save());
      document.dispose();

      final PdfSignatureValidator validator = PdfSignatureValidator();
      final PdfSignaturePreflightReport preflight =
          await validator.preflightSignatures(pdfBytes);

      expect(preflight.signatures, hasLength(1));
      final PdfSignaturePreflightItem pre = preflight.signatures.single;
      expect(pre.fieldName, equals('Signature1'));
      expect(pre.serialDecimal, isNotNull);
      expect(pre.issuerDn, isNotNull);

      final String rootPem = X509Utils.derToPem(rootCert);
      final PdfTrustedRootsIndex index = buildTrustedRootsIndex(<String>[rootPem]);

      final List<String> autoCandidates = index.findCandidateTrustedRoots(
        authorityKeyIdentifier: pre.authorityKeyIdentifier,
        issuerDn: pre.issuerDn,
        serial: pre.serialDecimal,
      );
      expect(autoCandidates, isNotEmpty);

      final PdfSignatureValidationReport reportWithCandidates =
          await validator.validateAllSignaturesWithCandidates(
        pdfBytes,
        candidateTrustedRootsPem: autoCandidates,
        fallbackToAllRoots: true,
        allTrustedRootsPem: <String>[rootPem],
        trustedRootsIndex: index,
      );

      expect(reportWithCandidates.signatures, hasLength(1));
      final PdfSignatureValidationItem item =
          reportWithCandidates.signatures.single;
      expect(item.validation.cmsSignatureValid, isTrue);
      expect(item.validation.byteRangeDigestOk, isTrue);
      expect(item.validation.documentIntact, isTrue);
      expect(item.chainTrusted, isTrue);
      expect(item.signerSerialHex, isNotNull);
      expect(item.signerSerialDecimal, isNotNull);

      final PdfSignerInfo? signerInfo = item.signerInfo;
      expect(signerInfo, isNotNull);
      expect(signerInfo!.serialNumberHex, isNotNull);
      expect(signerInfo.serialNumberDecimal, isNotNull);
      expect(signerInfo.issuerSerialNumberHex, isNotNull);
      expect(signerInfo.issuerSerialNumberDecimal, isNotNull);

      final PdfSignatureValidationReport reportWithIndexOnly =
          await validator.validateAllSignatures(
        pdfBytes,
        trustedRootsIndex: index,
      );

      expect(reportWithIndexOnly.signatures, hasLength(1));
      expect(reportWithIndexOnly.signatures.single.chainTrusted, isTrue);
    });
  });
}
