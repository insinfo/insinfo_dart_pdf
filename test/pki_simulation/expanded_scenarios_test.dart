import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pki/pki_builder.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

void main() {
  group('Expanded Real World Scenarios', () {
    test('Scenario 1: GovBr-Style 4-Level Chain Signature (Root -> Intermediate -> AC Final -> User)', () async {
      // 1. Setup PKI (Simulate GovBr 4-Level Hierarchy)
      // IMPORTANT: Issuer DN MUST match exactly the Subject DN of the issuer certificate!
      
      // ============================================
      // Level 1: Root CA (self-signed)
      // ============================================
      const rootDn = 'CN=Teste Autoridade Certificadora Raiz Brasileira v1, O=ICP-Brasil, C=BR';
      final rootKeyPair = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
      final rootCertDer = PkiBuilder.createRootCertificate(
        keyPair: rootKeyPair,
        dn: rootDn,
        validityYears: 20,
      );
      final rootCertPem = _certToPem(rootCertDer);
      // print('Level 1 - Root CA: $rootDn');
      
      // ============================================
      // Level 2: Intermediate CA (issued by Root)
      // ============================================
      const intermediateDn = 'CN=Teste AC Intermediaria do Governo Federal do Brasil v1, O=ICP-Brasil, C=BR';
      final intermediateKeyPair = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
      final intermediateCertDer = PkiBuilder.createIntermediateCertificate(
        keyPair: intermediateKeyPair,
        issuerKeyPair: rootKeyPair,
        issuerDn: rootDn, // MUST match rootDn exactly!
        subjectDn: intermediateDn,
        serialNumber: 2,
        validityYears: 10,
      );
      final intermediateCertPem = _certToPem(intermediateCertDer);
      // print('Level 2 - Intermediate CA: $intermediateDn');
      
      // ============================================
      // Level 3: AC Final (End Entity CA, issued by Intermediate)
      // ============================================
      const acFinalDn = 'CN=Teste AC Final do Governo Federal do Brasil v1, O=ICP-Brasil, C=BR';
      final acFinalKeyPair = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
      final acFinalCertDer = PkiBuilder.createIntermediateCertificate(
        keyPair: acFinalKeyPair,
        issuerKeyPair: intermediateKeyPair,
        issuerDn: intermediateDn, // MUST match intermediateDn exactly!
        subjectDn: acFinalDn,
        serialNumber: 3,
        validityYears: 5,
      );
      final acFinalCertPem = _certToPem(acFinalCertDer);
      // print('Level 3 - AC Final: $acFinalDn');
      
      // ============================================
      // Level 4: User Certificate (issued by AC Final) - THIS IS THE SIGNER!
      // ============================================
      const userDn = 'CN=Isaque Neves Sant Ana, OU=Pessoa Fisica, O=ICP-Brasil, C=BR';
      final userKeyPair = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
      final userCertDer = PkiBuilder.createUserCertificate(
        keyPair: userKeyPair,
        issuerKeyPair: acFinalKeyPair,
        issuerDn: acFinalDn, // MUST match acFinalDn exactly!
        subjectDn: userDn,
        serialNumber: 4,
        validityDays: 365 * 3, // 3 years
      );
      final userCertPem = _certToPem(userCertDer);
      final userKeyPem = _rsaPrivateKeyToPem(userKeyPair.privateKey as RSAPrivateKey);
      // print('Level 4 - User (Signer): $userDn');

      // Export the chain as P7B file (like Cadeia_GovBr-der.p7b)
      // Order: from leaf to root
      await _exportChainAsP7b(
        [userCertDer, acFinalCertDer, intermediateCertDer, rootCertDer],
        'test/tmp/Cadeia_Test-der.p7b',
      );
      
      // Export individual certs as PEM
      await File('test/tmp/AC_Raiz_Test.pem').writeAsString(rootCertPem);
      await File('test/tmp/AC_Intermediaria_Test.pem').writeAsString(intermediateCertPem);
      await File('test/tmp/AC_Final_Test.pem').writeAsString(acFinalCertPem);
      await File('test/tmp/Cert_Usuario_Isaque.pem').writeAsString(userCertPem);
      await File('test/tmp/Cert_Usuario_Isaque.key').writeAsString(userKeyPem);
      // print('Certificate chain exported to test/tmp/');

      // Validate chain linkage before signing
      _validateChainLinkageFromDerList([userCertDer, acFinalCertDer, intermediateCertDer, rootCertDer]);

      // 2. Create PDF
      final doc = PdfDocument();
      doc.pages.add().graphics.drawString('GovBr-Style 4-Level Chain Test', PdfStandardFont(PdfFontFamily.helvetica, 12), bounds: Rect.fromLTWH(0, 0, 300, 50));
      final pdfBytes = Uint8List.fromList(await doc.save());
      doc.dispose();

      // 3. Prepare Signing
      final prepared = await PdfExternalSigning.preparePdf(
        inputBytes: pdfBytes,
        fieldName: 'AssinaturaGovBr_1',
        pageNumber: 1,
        bounds: Rect.fromLTWH(50, 50, 200, 50),
        signature: PdfSignature(
          digestAlgorithm: DigestAlgorithm.sha256,
          contactInfo: 'SALI - Assinatura GovBr Style',
          reason: 'Assinatura com cadeia de 4 níveis estilo ICP-Brasil',
        ),
      );

      // 4. Compute Digest
      final digestBytes = _computeByteRangeDigest(prepared.preparedPdfBytes, prepared.byteRange);

      // 5. Sign (CMS) with FULL CHAIN (4 certs) - User signs with their key
      final pkcs7 = PdfCmsSigner.signDetachedSha256RsaFromPem(
        contentDigest: digestBytes,
        privateKeyPem: userKeyPem, // User's private key signs the document
        certificatePem: userCertPem, // User's certificate
        chainPem: [acFinalCertPem, intermediateCertPem, rootCertPem], // Full chain!
      );
      
      // Validate chain has 4 certs
      _validatePkcs7Chain(pkcs7, 4);

      // 6. Embed
      final signedBytes = PdfExternalSigning.embedSignature(
        preparedPdfBytes: prepared.preparedPdfBytes,
        pkcs7Bytes: pkcs7,
      );

      // 7. Save and Verify
      final file = File('test/tmp/out_scenario1_govbr_chain.pdf');
      if (!await file.parent.exists()) {
        await file.parent.create(recursive: true);
      }
      await file.writeAsBytes(signedBytes);
      // print('\nScenario 1: Signed PDF saved to ${file.path}');
      // print('Chain: Root -> Intermediate -> AC Final -> Isaque (4 levels)');

      final doc2 = PdfDocument(inputBytes: signedBytes);
      expect(doc2.form.fields.count, 1);
      final sigField = doc2.form.fields[0] as PdfSignatureField;
      expect(sigField.name, 'AssinaturaGovBr_1');
      doc2.dispose();
    });

    
    test('Scenario 2: Simple 2-Level Chain', () async {
        // Simple test with 2 levels (Root + User)
        final rootKeyPair = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
        final rootCertDer = PkiBuilder.createRootCertificate(
            keyPair: rootKeyPair,
            dn: 'CN=AC Interna Root, O=Test Org, C=BR',
            validityYears: 10,
        );
        final rootCertPem = _certToPem(rootCertDer);
        
        final userKeyPair = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
        final userCertDer = PkiBuilder.createUserCertificate(
            keyPair: userKeyPair,
            issuerKeyPair: rootKeyPair,
            issuerDn: 'CN=AC Interna Root, O=Test Org, C=BR',
            subjectDn: 'CN=User Internal, O=Test Org, C=BR',
            serialNumber: 2,
            validityDays: 365,
        );
        final userCertPem = _certToPem(userCertDer);
        final userKeyPem = _rsaPrivateKeyToPem(userKeyPair.privateKey as RSAPrivateKey);

        final doc = PdfDocument();
        doc.pages.add().graphics.drawString('Simple 2-Level Chain', PdfStandardFont(PdfFontFamily.helvetica, 12));
        final pdfBytes = Uint8List.fromList(await doc.save());
        doc.dispose();

        final prepared = await PdfExternalSigning.preparePdf(
            inputBytes: pdfBytes,
            fieldName: 'AssinaturaSimples_1',
            pageNumber: 1,
            bounds: Rect.fromLTWH(50, 50, 200, 50),
            signature: PdfSignature(digestAlgorithm: DigestAlgorithm.sha256),
        );

        final digestBytes = _computeByteRangeDigest(prepared.preparedPdfBytes, prepared.byteRange);

        final pkcs7 = PdfCmsSigner.signDetachedSha256RsaFromPem(
            contentDigest: digestBytes,
            privateKeyPem: userKeyPem,
            certificatePem: userCertPem,
            chainPem: [rootCertPem],
        );
        
        _validatePkcs7Chain(pkcs7, 2);

        final signedBytes = PdfExternalSigning.embedSignature(
            preparedPdfBytes: prepared.preparedPdfBytes,
            pkcs7Bytes: pkcs7,
        );

        final file = File('test/tmp/out_scenario2_simple.pdf');
        await file.writeAsBytes(signedBytes);
        // print('Scenario 2: Signed PDF saved to ${file.path}');
    });

    // --- DIAGNOSTIC TEST ---
    test('Diagnostic: Verify Chain Linkage (DN and KeyID)', () {
      // print('--- DIAGNOSTIC START ---');
      final rootKeyPair = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
      final rootCertDer = PkiBuilder.createRootCertificate(
        keyPair: rootKeyPair,
        dn: 'CN=Root CA, O=Test, C=US',
      );
      
      final userKeyPair = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
      final userCertDer = PkiBuilder.createUserCertificate(
        keyPair: userKeyPair,
        issuerKeyPair: rootKeyPair,
        issuerDn: 'CN=Root CA, O=Test, C=US',
        subjectDn: 'CN=User, O=Test, C=US',
        serialNumber: 123,
      );

      final rootCert = ASN1Parser(rootCertDer).nextObject() as ASN1Sequence;
      final userCert = ASN1Parser(userCertDer).nextObject() as ASN1Sequence;

      // Extract TBS
      final rootTbs = rootCert.elements[0] as ASN1Sequence;
      final userTbs = userCert.elements[0] as ASN1Sequence;

      // Identify fields based on tag/context.
      // TBS: [0] Version, Serial, SigAlg, Issuer, Validity, Subject, SPKI, [3] Exts
      
      // Issuer and Subject are standard sequences.
      // We need to count indices precisely.
      // Version is [0] Explicit (Tag A0)
      // Serial is Integer
      // SigAlg is Seq
      // Issuer is Seq
      // Validity is Seq
      // Subject is Seq
      
      // Let's find Issuer/Subject by index.
      // 0: Version (A0)
      // 1: Serial
      // 2: SigAlg
      // 3: Issuer
      // 4: Validity
      // 5: Subject
      // 6: SPKI
      // 7: Extensions (A3)
      
      final rootSubjectRaw = rootTbs.elements[5].encodedBytes;
      final userIssuerRaw = userTbs.elements[3].encodedBytes;
      
      // print('Root Subject: ${_bytesToHex(rootSubjectRaw)}');
      // print('User Issuer : ${_bytesToHex(userIssuerRaw)}');
      
      expect(
          _bytesToHex(userIssuerRaw), 
          equals(_bytesToHex(rootSubjectRaw)), 
          reason: 'User Issuer DN must match Root Subject DN byte-for-byte'
      );
      
      // Extract Extensions
      final rootExts = _getExtensions(rootTbs);
      final userExts = _getExtensions(userTbs);
      
      final rootSKI = _getExtensionValue(rootExts, '2.5.29.14'); // SubjectKeyIdentifier
      final userAKI = _getExtensionValue(userExts, '2.5.29.35'); // AuthorityKeyIdentifier
      
      // print('Root SKI: ${_bytesToHex(rootSKI)}');
      // print('User AKI: ${_bytesToHex(userAKI)}');

      expect(rootSKI, isNotNull, reason: 'Root must have SKI');
      expect(userAKI, isNotNull, reason: 'User must have AKI');
      
      // User AKI is SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING ... }
      // We need to extract the OCTET STRING from AKI.
      final akiParser = ASN1Parser(userAKI!);
      final akiSeq = akiParser.nextObject() as ASN1Sequence;
      var keyIdFromAki = <int>[];
      for(var el in akiSeq.elements) {
          if (el.tag == 0x80) { // [0] IMPLICIT OCTET STRING
             // In asn1lib, if tag is 0x80, it might be parsed as ASN1Object with that tag.
             // valueBytes() should be the content.
             keyIdFromAki = el.valueBytes();
             break;
          }
      }
      
      // Root SKI is OCTET STRING (KeyIdentifier) directly as the extension value?
      // "The value of the Subject Key Identifier extension is the KeyIdentifier (OCTET STRING)."
      // So rootSKI bytes IS the OCTET STRING content?
      // createExtension: seq.add(ASN1OctetString(value.encodedBytes));
      // value is ASN1OctetString. encodedBytes includes Tag and Length.
      // So rootSKI returned by _getExtensionValue (which is the content of the OCTET STRING wrapper) 
      // IS the encoded ASN1OctetString of the KeyID.
      // So it is 04 LL ID.
      // We want just ID.
      
      final skiParser = ASN1Parser(rootSKI!);
      final skiObj = skiParser.nextObject(); // Should be ASN1OctetString (04)
      final keyIdFromSki = skiObj.valueBytes();
      
      // print('KeyID from Root SKI: ${_bytesToHex(Uint8List.fromList(keyIdFromSki))}');
      // print('KeyID from User AKI: ${_bytesToHex(Uint8List.fromList(keyIdFromAki))}');
      
      expect(
          _bytesToHex(Uint8List.fromList(keyIdFromAki)), 
          equals(_bytesToHex(Uint8List.fromList(keyIdFromSki))),
          reason: 'User AKI KeyID must match Root SKI KeyID'
      );
      
    });

    test('Scenario 3: Multi-Signature (Internal + GovBr)', () async {
        final initialPdfFile = File('test/tmp/out_scenario1_internal.pdf');
        if (!await initialPdfFile.exists()) {
             // If scenario 1 failed or didn't run, create a mock one or skip
             // print('Skipping Scenario 3 because Scenario 1 output not found.');
             return;
        }
        final initialPdfBytes = await initialPdfFile.readAsBytes();
        
        final govRootKeyPair = PkiUtils.generateRsaKeyPair();
        final govRootCertDer = PkiBuilder.createRootCertificate(
            keyPair: govRootKeyPair,
            dn: 'CN=GovBr Root, O=GovBr, C=BR',
            validityYears: 20,
        );
        final govRootCertPem = _certToPem(govRootCertDer);

        final citizenKeyPair = PkiUtils.generateRsaKeyPair();
        final citizenCertDer = PkiBuilder.createUserCertificate(
            keyPair: citizenKeyPair,
            issuerKeyPair: govRootKeyPair,
            issuerDn: 'CN=GovBr Root, O=GovBr, C=BR',
            subjectDn: 'CN=Second Signer, O=GovBr, C=BR',
            serialNumber: 202,
            validityDays: 100,
        );
        final citizenCertPem = _certToPem(citizenCertDer);
        final citizenKeyPem = _rsaPrivateKeyToPem(citizenKeyPair.privateKey as RSAPrivateKey);

        final prepared = await PdfExternalSigning.preparePdf(
            inputBytes: initialPdfBytes,
            fieldName: 'AssinaturaGovBr_2',
            pageNumber: 1,
            bounds: Rect.fromLTWH(50, 250, 200, 50),
            signature: PdfSignature(
                digestAlgorithm: DigestAlgorithm.sha256,
            ),
        );
        
        final digestBytes = _computeByteRangeDigest(prepared.preparedPdfBytes, prepared.byteRange);
        
        final pkcs7 = PdfCmsSigner.signDetachedSha256RsaFromPem(
            contentDigest: digestBytes,
            privateKeyPem: citizenKeyPem,
            certificatePem: citizenCertPem,
            chainPem: [govRootCertPem],
        );
        
        final finalBytes = PdfExternalSigning.embedSignature(
            preparedPdfBytes: prepared.preparedPdfBytes,
            pkcs7Bytes: pkcs7,
        );
        
        final file = File('test/tmp/out_scenario3_multi.pdf');
        await file.writeAsBytes(finalBytes);
        // print('Scenario 3: Multi-Signed PDF saved to ${file.path}');
        
        final doc = PdfDocument(inputBytes: finalBytes);
        var sigCount = 0;
        for(var i=0; i<doc.form.fields.count; i++) {
            if (doc.form.fields[i] is PdfSignatureField) sigCount++;
        }
        expect(sigCount, 2);
        doc.dispose();
    });
  });
}

// --- Helpers ---

/// Exports a certificate chain as a PKCS#7/P7B file (DER format)
Future<void> _exportChainAsP7b(List<Uint8List> certsDer, String filePath) async {
    // Build PKCS#7 SignedData structure with only certificates (no signature)
    // ContentInfo ::= SEQUENCE { contentType, content [0] EXPLICIT ... }
    // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, certificates [0] IMPLICIT ... }
    
    final certsSet = ASN1Sequence(tag: 0xA0); // [0] IMPLICIT certificates
    for (final der in certsDer) {
        final certParser = ASN1Parser(der);
        certsSet.add(certParser.nextObject());
    }
    
    final signedData = ASN1Sequence();
    signedData.add(ASN1Integer(BigInt.from(1))); // version
    signedData.add(ASN1Set()); // digestAlgorithms (empty)
    
    // encapContentInfo
    final encapContent = ASN1Sequence();
    encapContent.add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.7.1')); // data
    signedData.add(encapContent);
    
    signedData.add(certsSet); // certificates [0]
    signedData.add(ASN1Set()); // signerInfos (empty)
    
    final contentInfo = ASN1Sequence();
    contentInfo.add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.7.2')); // signedData
    
    final content0 = ASN1Sequence(tag: 0xA0); // [0] EXPLICIT
    content0.add(signedData);
    contentInfo.add(content0);
    
    final file = File(filePath);
    if (!await file.parent.exists()) {
        await file.parent.create(recursive: true);
    }
    await file.writeAsBytes(contentInfo.encodedBytes);
    // print('P7B chain exported to $filePath');
}

String _bytesToHex(Uint8List? bytes) {
    if (bytes == null) return 'null';
    return hex.encode(bytes);
}

ASN1Sequence? _getExtensions(ASN1Sequence tbs) {
    for (var el in tbs.elements) {
        if (el.tag == 0xA3) { // [3] EXPLICIT
             // Unwrap
            final extSeqParser = ASN1Parser(el.valueBytes());
            return extSeqParser.nextObject() as ASN1Sequence;
        }
    }
    return null;
}

Uint8List? _getExtensionValue(ASN1Sequence? extensions, String oidStr) {
    if (extensions == null) return null;
    for (var el in extensions.elements) {
        if (el is ASN1Sequence) {
             final oid = el.elements[0] as ASN1ObjectIdentifier;
             if (oid.identifier == oidStr) { 
                 final octet = el.elements[1] is ASN1OctetString ? el.elements[1] as ASN1OctetString : 
                    // Should be [1] element if critical not present, or [2] if critical present.
                    // Actually, critical is optional element [1] BOOLEAN.
                    // If element [1] is BOOLEAN, then value is [2].
                    (el.elements[1] is ASN1Boolean ? el.elements[2] as ASN1OctetString : el.elements[1] as ASN1OctetString);
                 
                 return octet.valueBytes(); // The content of the OCTET STRING wrapper.
             }
        }
    }
    return null;
}

String _certToPem(Uint8List der) {
  final base64Str = base64.encode(der);
  final chunks = _chunk(base64Str, 64);
  return '-----BEGIN CERTIFICATE-----\n${chunks.join('\n')}\n-----END CERTIFICATE-----';
}

String _rsaPrivateKeyToPem(RSAPrivateKey key) {
  final seq = ASN1Sequence();
  seq.add(ASN1Integer(BigInt.zero)); // version
  seq.add(ASN1Integer(key.modulus!));
  seq.add(ASN1Integer(key.publicExponent!));
  seq.add(ASN1Integer(key.privateExponent!));
  seq.add(ASN1Integer(key.p!));
  seq.add(ASN1Integer(key.q!));
  // Calculate d mod (p-1)
  final dP = key.privateExponent! % (key.p! - BigInt.one);
  seq.add(ASN1Integer(dP));
  // Calculate d mod (q-1)
  final dQ = key.privateExponent! % (key.q! - BigInt.one);
  seq.add(ASN1Integer(dQ));
  // Calculate qInv
  final qInv = key.q!.modInverse(key.p!); 
  seq.add(ASN1Integer(qInv));
  
  final base64Str = base64.encode(seq.encodedBytes);
  final chunks = _chunk(base64Str, 64);
  return '-----BEGIN RSA PRIVATE KEY-----\n${chunks.join('\n')}\n-----END RSA PRIVATE KEY-----';
}

List<String> _chunk(String text, int size) {
  final result = <String>[];
  for (var i = 0; i < text.length; i += size) {
    result.add(text.substring(i, i + size > text.length ? text.length : i + size));
  }
  return result;
}

Uint8List _computeByteRangeDigest(Uint8List bytes, List<int> byteRange) {
  final hash = crypto.sha256;
  final sink = AccumulatorSink<crypto.Digest>();
  final input = hash.startChunkedConversion(sink);
  
  // byteRange is [offset1, length1, offset2, length2]
  final start1 = byteRange[0];
  final len1 = byteRange[1];
  final start2 = byteRange[2];
  final len2 = byteRange[3];
  
  input.add(bytes.sublist(start1, start1 + len1));
  input.add(bytes.sublist(start2, start2 + len2));
  input.close();
  
  return Uint8List.fromList(sink.events.single.bytes);
}

void _validatePkcs7Chain(Uint8List pkcs7, int expectedCertCount) {
  final parser = ASN1Parser(pkcs7);
  final topSeq = parser.nextObject() as ASN1Sequence;
  
  // PKCS7 ContentInfo: SEQUENCE { contentType, content [0] EXPLICIT ... }
  // The content is the tagged object.
  // In asn1lib, explicit tags usually wrap the content.
  // Let's inspect the second element.
  var contentTagged = topSeq.elements[1];
  
  // contentTagged.tag should be 0xA0 (Context Specific 0 Constructed)
  // The value inside is the SignedData SEQUENCE.
  
  // We need to unwrap the explicit tag. 
  // If use asn1lib's ASN1Parser on the value bytes, we get the inner object.
  final signedDataParser = ASN1Parser(contentTagged.valueBytes());
  final signedDataSeq = signedDataParser.nextObject() as ASN1Sequence;
  
  // SignedData ::= SEQUENCE {
  //   version CMSVersion,
  //   digestAlgorithms DigestAlgorithmIdentifiers,
  //   encapContentInfo EncapsulatedContentInfo,
  //   certificates [0] IMPLICIT CertificateSet OPTIONAL,
  //   ...
  // }
  
  // We look for the certificates element. It has tag [0] IMPLICIT.
  // Since it is IMPLICIT SET OF, the tag will be 0xA0 (Context 0 Constructed).
  // But wait, SignedData also has version (INTEGER), digestAlgs (SET), encapContentInfo (SEQUENCE).
  
  ASN1Object? certsTagged;
  for (var el in signedDataSeq.elements) {
    if (el.tag == 0xA0) {
      certsTagged = el;
      break;
    }
  }
  
  if (expectedCertCount == 0) {
      if (certsTagged != null) {
          // Verify it's empty? Or assume it shouldn't exist?
          // If it exists, count should be 0.
      }
      return;
  }
  
  expect(certsTagged, isNotNull, reason: 'Certificates set [0] not found in SignedData');
  
  // The content of the IMPLICIT TAG is the SET OF content.
  // We can parse the value bytes as a series of ASN1Objects (the certificates).
  final certsParser = ASN1Parser(certsTagged!.valueBytes());
  var count = 0;
  while (certsParser.hasNext()) {
    final cert = certsParser.nextObject() as ASN1Sequence;
    count++;

    // Validate if the certificate contains SKI and AKI extensions
    _validateCertificateExtensions(cert);
  }
  expect(count, equals(expectedCertCount), reason: 'Chain should contain $expectedCertCount certs, found $count');
  
  // *** RIGOROUS CHAIN VALIDATION ***
  // Extract all certs and verify that chain linkage is correct
  _validateChainLinkage(certsTagged);
}

/// Validates that the certificate chain can be built correctly.
/// For each non-self-signed cert, its AKI must match some cert's SKI.
void _validateChainLinkage(ASN1Object certsTagged) {
    final certsParser = ASN1Parser(certsTagged.valueBytes());
    final List<_CertInfo> certs = [];
    
    while (certsParser.hasNext()) {
        final cert = certsParser.nextObject() as ASN1Sequence;
        final tbs = cert.elements[0] as ASN1Sequence;
        
        final issuerBytes = tbs.elements[3].encodedBytes;
        final subjectBytes = tbs.elements[5].encodedBytes;
        
        String? ski;
        String? aki;
        String? subjectCN;
        
        // Extract Subject CN for debugging (simplified - just use subject hash)
        subjectCN = _bytesToHex(subjectBytes).substring(0, 16);
        
        // Find extensions
        for (var el in tbs.elements) {
            if (el.tag == 0xA3) {
                final extSeqParser = ASN1Parser(el.valueBytes());
                final extSeq = extSeqParser.nextObject() as ASN1Sequence;
                
                for (final ext in extSeq.elements) {
                    if (ext is ASN1Sequence) {
                        final oid = ext.elements[0] as ASN1ObjectIdentifier;
                        final oidStr = oid.identifier;
                        
                        // Get the OCTET STRING value (last element, after optional critical bool)
                        final valueOctet = ext.elements.last;
                        if (valueOctet is! ASN1OctetString) continue;
                        
                        if (oidStr == '2.5.29.14') { // SKI
                            // SKI value is OCTET STRING containing another OCTET STRING
                            final skiParser = ASN1Parser(valueOctet.valueBytes());
                            final skiOctet = skiParser.nextObject();
                            ski = _bytesToHex(Uint8List.fromList(skiOctet.valueBytes()));
                        }
                        if (oidStr == '2.5.29.35') { // AKI  
                            // AKI value is SEQUENCE { keyIdentifier [0] IMPLICIT ... }
                            final akiParser = ASN1Parser(valueOctet.valueBytes());
                            final akiSeq = akiParser.nextObject() as ASN1Sequence;
                            for (var akiEl in akiSeq.elements) {
                                if (akiEl.tag == 0x80) { // [0] IMPLICIT OCTET STRING
                                    aki = _bytesToHex(Uint8List.fromList(akiEl.valueBytes()));
                                    break;
                                }
                            }
                        }
                    }
                }
                break;
            }
        }
        
        certs.add(_CertInfo(
            subject: _bytesToHex(subjectBytes),
            issuer: _bytesToHex(issuerBytes),
            ski: ski,
            aki: aki,
            cn: subjectCN,
        ));
    }
    
    // print('=== CHAIN VALIDATION ===');
    // for (final cert in certs) {
    //    print('Cert: ${cert.cn}, SKI: ${cert.ski}, AKI: ${cert.aki}');
    // }
    
    // Validate linkage
    int nonSelfSignedCount = 0;
    int linkedCount = 0;
    
    for (final cert in certs) {
        final isSelfSigned = cert.subject == cert.issuer;
        
        if (!isSelfSigned) {
            nonSelfSignedCount++;
            if (cert.aki != null) {
                // Find issuer cert by matching SKI
                final issuerCert = certs.where((c) => c.ski == cert.aki).toList();
                expect(issuerCert, isNotEmpty, 
                    reason: 'Cert "${cert.cn}" with AKI=${cert.aki} has no matching issuer SKI in chain. '
                            'Available SKIs: ${certs.map((c) => '${c.cn}:${c.ski}').toList()}');
                linkedCount++;
                // print('✓ Cert "${cert.cn}" -> linked to "${issuerCert.first.cn}"');
            }
        } else {
            // print('✓ Cert "${cert.cn}" is self-signed (Root CA)');
        }
    }
    
    // At least one non-self-signed cert should be properly linked
    if (nonSelfSignedCount > 0) {
        expect(linkedCount, equals(nonSelfSignedCount),
            reason: 'Not all non-self-signed certs have valid AKI linkage');
    }
    // print('=== CHAIN VALID ===');
}

/// Validates chain linkage from a list of DER-encoded certificates.
/// This is used for pre-signing validation.
void _validateChainLinkageFromDerList(List<Uint8List> certsDer) {
    final List<_CertInfo> certs = [];
    
    for (final certDer in certsDer) {
        final certParser = ASN1Parser(certDer);
        final cert = certParser.nextObject() as ASN1Sequence;
        final tbs = cert.elements[0] as ASN1Sequence;
        
        final issuerBytes = tbs.elements[3].encodedBytes;
        final subjectBytes = tbs.elements[5].encodedBytes;
        
        String? ski;
        String? aki;
        String? subjectCN;
        
        // Extract Subject CN for debugging
        try {
            final subjectSeq = tbs.elements[5] as ASN1Sequence;
            for (final rdn in subjectSeq.elements) {
                if (rdn is ASN1Set && rdn.elements.isNotEmpty) {
                    final rdnList = rdn.elements.toList();
                    final atv = rdnList[0] as ASN1Sequence;
                    final oid = atv.elements[0] as ASN1ObjectIdentifier;
                    if (oid.identifier == '2.5.4.3') { // CN
                        subjectCN = (atv.elements[1] as dynamic).stringValue;
                        break;
                    }
                }
            }
        } catch (_) {
            subjectCN = _bytesToHex(subjectBytes).substring(0, 16);
        }
        
        // Find extensions
        for (var el in tbs.elements) {
            if (el.tag == 0xA3) {
                final extSeqParser = ASN1Parser(el.valueBytes());
                final extSeq = extSeqParser.nextObject() as ASN1Sequence;
                
                for (final ext in extSeq.elements) {
                    if (ext is ASN1Sequence) {
                        final oid = ext.elements[0] as ASN1ObjectIdentifier;
                        final oidStr = oid.identifier;
                        
                        // Get the OCTET STRING value (last element, after optional critical bool)
                        final valueOctet = ext.elements.last;
                        if (valueOctet is! ASN1OctetString) continue;
                        
                        if (oidStr == '2.5.29.14') { // SKI
                            final skiParser = ASN1Parser(valueOctet.valueBytes());
                            final skiOctet = skiParser.nextObject();
                            ski = _bytesToHex(Uint8List.fromList(skiOctet.valueBytes()));
                        }
                        if (oidStr == '2.5.29.35') { // AKI  
                            final akiParser = ASN1Parser(valueOctet.valueBytes());
                            final akiSeq = akiParser.nextObject() as ASN1Sequence;
                            for (var akiEl in akiSeq.elements) {
                                if (akiEl.tag == 0x80) {
                                    aki = _bytesToHex(Uint8List.fromList(akiEl.valueBytes()));
                                    break;
                                }
                            }
                        }
                    }
                }
                break;
            }
        }
        
        certs.add(_CertInfo(
            subject: _bytesToHex(subjectBytes),
            issuer: _bytesToHex(issuerBytes),
            ski: ski,
            aki: aki,
            cn: subjectCN ?? 'Unknown',
        ));
    }
    
    // print('=== PRE-SIGNING CHAIN VALIDATION ===');
    // for (final cert in certs) {
    //     print('Cert: ${cert.cn}');
    //     print('  SKI: ${cert.ski}');
    //     print('  AKI: ${cert.aki}');
    // }
    
    // Validate linkage
    int nonSelfSignedCount = 0;
    int linkedCount = 0;
    
    for (final cert in certs) {
        final isSelfSigned = cert.subject == cert.issuer;
        
        if (!isSelfSigned) {
            nonSelfSignedCount++;
            if (cert.aki != null) {
                final issuerCert = certs.where((c) => c.ski == cert.aki).toList();
                expect(issuerCert, isNotEmpty, 
                    reason: 'Cert "${cert.cn}" with AKI=${cert.aki} has no matching issuer SKI in chain. '
                            'Available SKIs: ${certs.map((c) => '${c.cn}:${c.ski}').toList()}');
                linkedCount++;
                // print('✓ Cert "${cert.cn}" -> linked to "${issuerCert.first.cn}"');
            }
        } else {
            // print('✓ Cert "${cert.cn}" is self-signed (Root CA)');
        }
    }
    
    if (nonSelfSignedCount > 0) {
        expect(linkedCount, equals(nonSelfSignedCount),
            reason: 'Not all non-self-signed certs have valid AKI linkage');
    }
    // print('=== CHAIN VALID ===\n');
}

class _CertInfo {
    final String subject;
    final String issuer;
    final String? ski;
    final String? aki;
    final String? cn;
    _CertInfo({required this.subject, required this.issuer, this.ski, this.aki, this.cn});
}

void _validateCertificateExtensions(ASN1Sequence cert) {
  // OBS: This is a heavy-handed check, assuming standard X.509 structure.
  // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
  final tbs = cert.elements[0] as ASN1Sequence;

  // TBScertificate structure varies, but Extensions is [3] EXPLICIT standardly at the end
  // Version, Serial, Sig, Issuer, Validity, Subject, SubjectPublicKeyInfo, (IssuerUniqueId?), (SubjectUniqueID?), Extensions
  
  ASN1Object? extensionsWrapped;
  for (var el in tbs.elements) {
    if (el.tag == 0xA3) { // [3] EXPLICIT
      extensionsWrapped = el;
      break;
    }
  }

  expect(extensionsWrapped, isNotNull, reason: 'Certificate must have Extensions [3]');
  
  // Unwrap the [3] tag to get the SEQUENCE of extensions
  final extSeqParser = ASN1Parser(extensionsWrapped!.valueBytes());
  final extSeq = extSeqParser.nextObject() as ASN1Sequence;

  // Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
  
  bool hasSKI = false;
  bool hasAKI = false;

  for (final ext in extSeq.elements) {
    if (ext is ASN1Sequence) {
       final oid = ext.elements[0] as ASN1ObjectIdentifier;
       final oidStr = oid.identifier;
       
       if (oidStr == '2.5.29.14') hasSKI = true; // Subject Key Identifier
       if (oidStr == '2.5.29.35') hasAKI = true; // Authority Key Identifier
    }
  }

  // Root CA might not have AKI (or it points to itself). User certs MUST have both.
  
  // Check if Self-Signed
  // TBS Elements: 3=Issuer, 5=Subject.
  // We need to compare them.
  // Note: elements are ASN1Objects.
  final issuerBytes = tbs.elements[3].encodedBytes;
  final subjectBytes = tbs.elements[5].encodedBytes; // Adjust index if explicit tags shift things?
  // 0:Ver, 1:Ser, 2:Sig, 3:Issuer, 4:Validity, 5:Subject, 6:SPKI, 7:Exts
  // This index assumes standard structure.
  
  final isSelfSigned = _bytesToHex(issuerBytes) == _bytesToHex(subjectBytes);

  expect(hasSKI, isTrue, reason: 'Certificate missing SubjectKeyIdentifier (2.5.29.14)');
  
  if (!isSelfSigned) {
      expect(hasAKI, isTrue, reason: 'Certificate missing AuthorityKeyIdentifier (2.5.29.35)');
  }
}

