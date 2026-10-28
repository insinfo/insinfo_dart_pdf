@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:dart_pdf/pdf_server.dart' as pdf;
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/pdf_ltv_manager.dart';
import 'package:dart_pdf/src/pki/pki_builder.dart';
import 'package:dart_pdf/src/pki/pki_pem_utils.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

/// `timeStampTokenFor` and `PdfLtvManager.addValidationData` (1.0.8).
///
/// External signing could not carry a signature timestamp: the token is
/// computed over the signature value, which only exists after signing, and
/// the API took a ready-made token. And LTV could only be added by
/// downloading CRLs/OCSP from the certificate URLs, which for an in-house CA
/// means the server calling itself mid-signing.
void main() {
  late _Pki pki;

  setUpAll(() {
    pki = _Pki.create();
  });

  // OID 1.2.840.113549.1.9.16.2.14 (id-aa-signatureTimeStampToken), DER.
  const List<int> timestampAttributeOid = <int>[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, //
    0x01, 0x09, 0x10, 0x02, 0x0E,
  ];

  Uint8List digestOf(String text) =>
      Uint8List.fromList(sha256.convert(text.codeUnits).bytes);

  group('timeStampTokenFor', () {
    test('embeds the token computed from the signature value', () {
      Uint8List? receivedValue;
      // Any ContentInfo will do for the embedding: what matters here is that
      // it goes in as the signature-time-stamp unsigned attribute.
      final Uint8List token = pdf.PdfCmsSigner.signDetachedSha256RsaFromPem(
        contentDigest: digestOf('token'),
        privateKeyPem: pki.rootKeyPem,
        certificatePem: pki.rootPem,
      );

      final Uint8List cms = pdf.PdfCmsSigner.signDetachedSha256RsaFromPem(
        contentDigest: digestOf('content'),
        privateKeyPem: pki.leafKeyPem,
        certificatePem: pki.leafPem,
        chainPem: <String>[pki.rootPem],
        timeStampTokenFor: (Uint8List signatureValue) {
          receivedValue = signatureValue;
          return token;
        },
      );

      expect(receivedValue, hasLength(256),
          reason: 'RSA-2048 signature value, not a digest');
      expect(_contains(cms, receivedValue!), isTrue,
          reason: 'the value given to the callback is the one in the CMS');
      expect(_contains(cms, timestampAttributeOid), isTrue);
      expect(_contains(cms, token), isTrue);
      expect(
          pdf.PdfSignatureValidation()
              .validateCmsSignedData(cms)
              .cmsSignatureValid,
          isTrue,
          reason: 'the unsigned attribute does not touch the signed part');
    });

    test('null from the callback signs without timestamp', () {
      final Uint8List cms = pdf.PdfCmsSigner.signDetachedSha256RsaFromPem(
        contentDigest: digestOf('content'),
        privateKeyPem: pki.leafKeyPem,
        certificatePem: pki.leafPem,
        timeStampTokenFor: (_) => null,
      );

      expect(_contains(cms, timestampAttributeOid), isFalse);
      expect(
          pdf.PdfSignatureValidation()
              .validateCmsSignedData(cms)
              .cmsSignatureValid,
          isTrue);
    });
  });

  group('addValidationData', () {
    Future<Uint8List> signedPdf() async {
      final pdf.PdfDocument doc = pdf.PdfDocument();
      doc.pages.add().graphics.drawString(
          'DSS', pdf.PdfStandardFont(pdf.PdfFontFamily.helvetica, 12));
      final Uint8List unsigned = Uint8List.fromList(await doc.save());
      doc.dispose();

      final pdf.PdfExternalSigningResult prepared =
          await pdf.PdfExternalSigning.preparePdf(
        inputBytes: unsigned,
        pageNumber: 1,
        bounds: pdf.Rect.fromLTWH(100, 100, 200, 50),
        fieldName: 'Sig1',
      );
      final Uint8List cms = pdf.PdfCmsSigner.signDetachedSha256RsaFromPem(
        contentDigest: Uint8List.fromList(
            sha256.convert(_byteRangeContent(prepared)).bytes),
        privateKeyPem: pki.leafKeyPem,
        certificatePem: pki.leafPem,
        chainPem: <String>[pki.rootPem],
      );
      return pdf.PdfExternalSigning.embedSignature(
        preparedPdfBytes: prepared.preparedPdfBytes,
        pkcs7Bytes: cms,
      );
    }

    Future<Uint8List> withValidationData(Uint8List bytes) async {
      final pdf.PdfDocument doc = pdf.PdfDocument(inputBytes: bytes);
      PdfLtvManager(doc).addValidationData(
        certificates: <List<int>>[pki.leafDer, pki.rootDer],
        crls: <List<int>>[pki.crl],
      );
      final Uint8List out = Uint8List.fromList(await doc.save());
      doc.dispose();
      return out;
    }

    Future<pdf.PdfSignatureValidationItem> validate(Uint8List bytes) async {
      final pdf.PdfSignatureValidationReport report = await pdf
          .PdfSignatureValidator()
          .validateAllSignatures(bytes, trustedRootsPem: <String>[pki.rootPem]);
      return report.signatures.single;
    }

    test('writes the DSS without breaking the signature', () async {
      final Uint8List bytes = await withValidationData(await signedPdf());
      final pdf.PdfSignatureValidationItem sig = await validate(bytes);

      expect(sig.ltv.hasDss, isTrue);
      expect(sig.ltv.dssCertsCount, 2);
      expect(sig.ltv.dssCrlsCount, 1);
      expect(sig.validation.cmsSignatureValid, isTrue);
      expect(sig.validation.documentIntact, isTrue,
          reason: 'the DSS goes in an incremental update after the signature');
      expect(sig.chainTrusted, isTrue);
    });

    test('adding the same data again does not duplicate it', () async {
      final Uint8List once = await withValidationData(await signedPdf());
      final Uint8List twice = await withValidationData(once);
      final pdf.PdfSignatureValidationItem sig = await validate(twice);

      expect(sig.ltv.dssCertsCount, 2);
      expect(sig.ltv.dssCrlsCount, 1);
      expect(sig.validation.documentIntact, isTrue);
    });
  });
}

/// The two byte-range pieces of a prepared PDF, concatenated.
List<int> _byteRangeContent(pdf.PdfExternalSigningResult prepared) {
  final Uint8List bytes = prepared.preparedPdfBytes;
  final List<int> range = prepared.byteRange;
  return <int>[
    ...bytes.sublist(range[0], range[0] + range[1]),
    ...bytes.sublist(range[2], range[2] + range[3]),
  ];
}

bool _contains(List<int> haystack, List<int> needle) {
  if (needle.isEmpty || needle.length > haystack.length) return false;
  outer:
  for (int i = 0; i <= haystack.length - needle.length; i++) {
    for (int j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

class _Pki {
  _Pki({
    required this.rootPem,
    required this.rootDer,
    required this.rootKeyPem,
    required this.leafPem,
    required this.leafDer,
    required this.leafKeyPem,
    required this.crl,
  });

  factory _Pki.create() {
    final AsymmetricKeyPair<PublicKey, PrivateKey> rootKey =
        PkiUtils.generateRsaKeyPair(bitStrength: 2048);
    final AsymmetricKeyPair<PublicKey, PrivateKey> leafKey =
        PkiUtils.generateRsaKeyPair(bitStrength: 2048);
    const String rootDn = 'CN=DSS Test Root,O=DartPDF';
    final Uint8List rootDer =
        PkiBuilder.createRootCertificate(keyPair: rootKey, dn: rootDn);
    final Uint8List leafDer = PkiBuilder.createUserCertificate(
      keyPair: leafKey,
      issuerKeyPair: rootKey,
      subjectDn: 'CN=DSS Test User,O=DartPDF',
      issuerDn: rootDn,
      serialNumber: 77,
    );
    final DateTime now = DateTime.now().toUtc();
    final Uint8List crl = PkiBuilder.createCRL(
      issuerKeyPair: rootKey,
      issuerDn: rootDn,
      revokedCertificates: const <RevokedCertificate>[],
      thisUpdate: now.subtract(const Duration(hours: 1)),
      nextUpdate: now.add(const Duration(days: 1)),
      crlNumber: 1,
    );
    String keyPem(AsymmetricKeyPair<PublicKey, PrivateKey> pair) =>
        PkiPemUtils.rsaPrivateKeyToPem(
          pair.privateKey as RSAPrivateKey,
          publicExponent: (pair.publicKey as RSAPublicKey).exponent,
        );
    return _Pki(
      rootPem: PkiPemUtils.certificateDerToPem(rootDer),
      rootDer: rootDer,
      rootKeyPem: keyPem(rootKey),
      leafPem: PkiPemUtils.certificateDerToPem(leafDer),
      leafDer: leafDer,
      leafKeyPem: keyPem(leafKey),
      crl: crl,
    );
  }

  final String rootPem;
  final Uint8List rootDer;
  final String rootKeyPem;
  final String leafPem;
  final Uint8List leafDer;
  final String leafKeyPem;
  final Uint8List crl;
}
