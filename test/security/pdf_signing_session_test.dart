import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart' as asn1;
import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pki/pki_builder.dart';
import 'package:pointycastle/export.dart' as pk_export;
import 'package:pointycastle/pointycastle.dart';
import 'package:test/test.dart';

void main() {
  group('PdfSigningSession & IPdfSigner', () {
    late AsymmetricKeyPair<PublicKey, PrivateKey> keyPair;
    late Uint8List certDer;
    late String certPem;
    late String keyPem;

    setUpAll(() {
      keyPair = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
      certDer = PkiBuilder.createRootCertificate(
        keyPair: keyPair,
        dn: 'CN=Test Signer',
        validityYears: 1,
      );

      certPem = _certToPem(certDer);
      keyPem = _rsaPrivateKeyToPem(keyPair.privateKey as pk_export.RSAPrivateKey);
    });

    test('PdfLocalSigner should sign digest correctly', () async {
      final signer = PdfLocalSigner(
        privateKeyPem: keyPem,
        certificatePem: certPem,
      );

      final digest = Uint8List.fromList(List.filled(32, 0xAA));
      final signature = await signer.signDigest(digest);

      expect(signature, isNotEmpty);
      expect(signature[0], 0x30); // DER Sequence
    });

    test('PdfSigningSession should sign a PDF using a Mock Signer', () async {
      final doc = PdfDocument();
      doc.pages.add();
      final pdfBytes = Uint8List.fromList(await doc.save());

      final mockSigner = _MockSigner();

      final signedBytes = await PdfSigningSession.signPdf(
        pdfBytes: pdfBytes,
        signer: mockSigner,
        pageNumber: 1,
        bounds: const Rect.fromLTWH(0, 0, 100, 50),
        fieldName: 'TestSig',
        signature: PdfSignature()
          ..reason = 'Testing'
          ..locationInfo = 'Unit Test',
      );

      expect(signedBytes, isNotEmpty);
      expect(mockSigner.wasCalled, isTrue);

      final pdfStr = latin1.decode(signedBytes, allowInvalid: true);
      expect(pdfStr, contains('/Type /Sig'));
      expect(pdfStr, contains('/Reason (Testing)'));
      expect(pdfStr, contains('/Location (Unit Test)'));
      // The field name is stored as a string in the /T entry, e.g. /T (TestSig)
      expect(pdfStr, contains('(TestSig)'));
    });

    test('PdfSigningSession with PdfLocalSigner produces valid LTV-ready PDF', () async {
      final doc = PdfDocument();
      doc.pages.add();
      // Add some content
      doc.pages[0].graphics.drawString(
        'Signed Content',
        PdfStandardFont(PdfFontFamily.helvetica, 12),
        bounds: const Rect.fromLTWH(10, 10, 200, 20),
      );
      final pdfBytes = Uint8List.fromList(await doc.save());

      final signer = PdfLocalSigner(
        privateKeyPem: keyPem,
        certificatePem: certPem,
      );

      // We explicitly check parsing of signatures
      final signedBytes = await PdfSigningSession.signPdf(
        pdfBytes: pdfBytes,
        signer: signer,
        pageNumber: 1,
        bounds: const Rect.fromLTWH(50, 50, 150, 50),
        fieldName: 'LocalSig',
      );

      expect(signedBytes.length, greaterThan(pdfBytes.length));

      final parser = PdfDocument(inputBytes: signedBytes);
      expect(parser.hasSignatures, isTrue);
      
      bool found = false;
      for (int i = 0; i < parser.form.fields.count; i++) {
        final field = parser.form.fields[i];
        if (field is PdfSignatureField && field.name == 'LocalSig') {
          found = true;
          break;
        }
      }
      expect(found, isTrue);
    });
  });
}

class _MockSigner implements IPdfSigner {
  bool wasCalled = false;

  @override
  Future<Uint8List> signDigest(Uint8List digest) async {
    wasCalled = true;
    // Return a dummy DER sequence
    return Uint8List.fromList([0x30, 0x03, 0x01, 0x01, 0x00]);
  }
}

String _certToPem(Uint8List der) {
  final base64Str = base64Encode(der);
  final chunks = _chunk(base64Str, 64);
  return '-----BEGIN CERTIFICATE-----\n${chunks.join('\n')}\n-----END CERTIFICATE-----';
}

String _rsaPrivateKeyToPem(pk_export.RSAPrivateKey key) {
  final seq = asn1.ASN1Sequence();
  seq.add(asn1.ASN1Integer(BigInt.zero));
  seq.add(asn1.ASN1Integer(key.modulus!));
  seq.add(asn1.ASN1Integer(key.publicExponent!));
  seq.add(asn1.ASN1Integer(key.privateExponent!));
  seq.add(asn1.ASN1Integer(key.p!));
  seq.add(asn1.ASN1Integer(key.q!));

  final dP = key.privateExponent! % (key.p! - BigInt.one);
  seq.add(asn1.ASN1Integer(dP));

  final dQ = key.privateExponent! % (key.q! - BigInt.one);
  seq.add(asn1.ASN1Integer(dQ));

  final qInv = key.q!.modInverse(key.p!);
  seq.add(asn1.ASN1Integer(qInv));

  final base64Str = base64Encode(seq.encodedBytes);
  final chunks = _chunk(base64Str, 64);
  return '-----BEGIN RSA PRIVATE KEY-----\n${chunks.join('\n')}\n-----END RSA PRIVATE KEY-----';
}

List<String> _chunk(String text, int size) {
  final result = <String>[];
  for (var i = 0; i < text.length; i += size) {
    result.add(
        text.substring(i, i + size > text.length ? text.length : i + size));
  }
  return result;
}
