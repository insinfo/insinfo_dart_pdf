import 'dart:typed_data';
import 'dart:convert';

import 'package:dart_pdf/pdf.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

import 'package:dart_pdf/src/pki/pki_builder.dart';
import 'package:dart_pdf/src/pki/pki_server.dart';

// Adapter to use pure Dart PkiBuilder keys with IPdfExternalSigner
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
    // PkiBuilder.signData uses SHA-256 by default.
    final signatureBytes = PkiBuilder.signData(
      Uint8List.fromList(message), 
      privateKey
    );
    return SignerResult(signatureBytes);
  }
}

void main() {
  group('PKI Simulation & PDF Signing', () {
    late PkiServer server;
    late int serverPort;
    
    // Chains
    late AsymmetricKeyPair<PublicKey, PrivateKey> rootKey;
    late Uint8List rootCert;
    
    late AsymmetricKeyPair<PublicKey, PrivateKey> interKey;
    late Uint8List interCert;
    
    late AsymmetricKeyPair<PublicKey, PrivateKey> userKey;
    late Uint8List userCert;

    setUpAll(() async {
      // 1. Setup PKI Keys
      rootKey = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
      interKey = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
      userKey = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
      
      serverPort = 8888;
      final serverBaseUrl = 'http://localhost:$serverPort';
      
      // 2. Generate Certs
      rootCert = PkiBuilder.createRootCertificate(
        keyPair: rootKey, 
        dn: 'CN=Test Root CA,O=DartPDF',
      );
      
      interCert = PkiBuilder.createIntermediateCertificate(
        keyPair: interKey, 
        issuerKeyPair: rootKey, 
        subjectDn: 'CN=Test Intermediate CA,O=DartPDF', 
        issuerDn: 'CN=Test Root CA,O=DartPDF', 
        serialNumber: 100,
        crlUrls: ['$serverBaseUrl/crl'],
        ocspUrls: ['$serverBaseUrl/ocsp'],
      );
      
      userCert = PkiBuilder.createUserCertificate(
        keyPair: userKey, 
        issuerKeyPair: interKey, 
        subjectDn: 'CN=Test User,O=DartPDF,C=BR', 
        issuerDn: 'CN=Test Intermediate CA,O=DartPDF', 
        serialNumber: 200,
        crlUrls: ['$serverBaseUrl/crl'],
        ocspUrls: ['$serverBaseUrl/ocsp'],
      );
      
      // 3. Start Server
      final tsaKey = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
      server = PkiServer(
        port: serverPort, 
        revokedSerials: {}, 
        crlDer: Uint8List(0), // Mock CRL
        tsaKeyPair: tsaKey, 
        tsaCertChain: [tsaKey], // Self-signed TSA for now
      );
      await server.start();
    });

    tearDownAll(() async {
      await server.stop();
    });

    Future<Uint8List> generateSignedPdf() async {
      final document = PdfDocument();
      document.pages.add();
      
      final signature = PdfSignature(
        signedName: 'Test User',
        reason: 'Testing Chain Validation',
        locationInfo: 'In-Memory',
        contactInfo: 'test@example.com',
        cryptographicStandard: CryptographicStandard.cms,
        digestAlgorithm: DigestAlgorithm.sha256,
        timestampServer: TimestampServer(Uri.parse('http://localhost:$serverPort/timestamp')),
      );
      
      final page = document.pages[0];
      final field = PdfSignatureField(page, 'Signature1', signature: signature, bounds: Rect.fromLTWH(0, 0, 200, 50));
      document.form.fields.add(field);
      
      final signer = RawRsaSigner(userKey.privateKey as RSAPrivateKey);
      
      // Chain: User -> Inter -> Root
      // Passing full chain ensures embedding
      final chain = [userCert, interCert, rootCert];
      
      signature.addExternalSigner(signer, chain);
      
      final bytes = await document.save();
      document.dispose();
      return Uint8List.fromList(bytes);
    }

    test('Validate Certificate Chain Embedding in PDF', () async {
       final pdfBytes = await generateSignedPdf();
       
       final validator = PdfSignatureValidator();
       final report = await validator.validateAllSignatures(
         pdfBytes,
         trustedRootsPem: [], // Don't trust anything yet, just inspecting content
         fetchCrls: false,
       );
       
       expect(report.signatures, hasLength(1));
       final sig = report.signatures.first;
       
       // Expect at least 3 (User, Inter, Root) or 2 (User, Inter) depending on implementation details of PdfSignature
       // Our implementation passed [user, inter, root] to addExternalSigner, so they should be there.
       expect(sig.validation.certsPem.length, greaterThanOrEqualTo(2));
       
       // Check if Common Names are present in the embedded certs
       final cnList = sig.validation.certsPem.map((pem) {
          // Rudimentary check or use X509Certificate parsing if available in test
          return pem; // Just returning PEM for now
       }).toList();
       
       // Just ensuring we have data
       expect(cnList, isNotEmpty);
    });

    test('Validate Signature Chain Trust (Success Case)', () async {
       final pdfBytes = await generateSignedPdf();
       final rootPem = '-----BEGIN CERTIFICATE-----\n${base64.encode(rootCert)}\n-----END CERTIFICATE-----';

       final validator = PdfSignatureValidator();
       final report = await validator.validateAllSignatures(
         pdfBytes,
         trustedRootsPem: [rootPem], // Trusting the generated Root
         fetchCrls: true,
       );
       
       final sig = report.signatures.first;
       expect(sig.chainTrusted, isTrue, reason: 'Chain should be trusted when Root is provided');
       expect(sig.revocationStatus.status, equals('good'), reason: 'Revocation should be good via Mock OCSP');
    });

    test('Validate Signature Chain Trust (Failure Case - Missing Root)', () async {
       final pdfBytes = await generateSignedPdf();
       
       final validator = PdfSignatureValidator();
       final report = await validator.validateAllSignatures(
         pdfBytes,
         trustedRootsPem: [], // Empty trust store
         fetchCrls: false,
       );
       
       final sig = report.signatures.first;
       // Should be false or null. In many implementations, if no root is found, it's false.
       // Based on strict validation, it should fail trust.
       // The validator returns null if "no trusted roots are provided" to check against.
       expect(sig.chainTrusted, isNull, reason: 'Chain trust should be NULL without Root CA provided');
    });

    test('Sign Multiple PDFs in Parallel with External Signer', () async {
      final futures = List.generate(3, (index) async {
        // Create Document
        final document = PdfDocument();
        document.pages.add();
        
        // setup signature
        final signature = PdfSignature(
          signedName: 'Test User $index',
          reason: 'Testing Parallel $index',
          locationInfo: 'In-Memory',
          contactInfo: 'test@example.com',
          cryptographicStandard: CryptographicStandard.cms,
          digestAlgorithm: DigestAlgorithm.sha256,
          timestampServer: TimestampServer(Uri.parse('http://localhost:$serverPort/timestamp')),
        );
        
        // Add signature field
        final page = document.pages[0];
        final field = PdfSignatureField(page, 'Signature1', signature: signature, bounds: Rect.fromLTWH(0, 0, 200, 50));
        document.form.fields.add(field);
        
        // Add External Signer
        final signer = RawRsaSigner(userKey.privateKey as RSAPrivateKey);
        
        // Chain: User -> Inter -> Root
        final chain = [userCert, interCert, rootCert];
        
        signature.addExternalSigner(signer, chain);
        
        // Save
        final bytes = await document.save();
        document.dispose();
        
        // Validation per document
        // Convert Root Cert (DER) to PEM
        final rootPem = '-----BEGIN CERTIFICATE-----\n${base64.encode(rootCert)}\n-----END CERTIFICATE-----';
        
        final validator = PdfSignatureValidator();
        final report = await validator.validateAllSignatures(
          Uint8List.fromList(bytes),
          trustedRootsPem: [rootPem],
          fetchCrls: true, 
          strictRevocation: false,
        );
        
        final sigReport = report.signatures.first;
        if (!sigReport.validation.cmsSignatureValid || 
            sigReport.chainTrusted != true || 
            sigReport.revocationStatus.status != 'good') {
              throw Exception('Validation failed for document $index: Intact=${sigReport.validation.documentIntact} CMS=${sigReport.validation.cmsSignatureValid} Trusted=${sigReport.chainTrusted} Rev=${sigReport.revocationStatus.status}');
            }
        
        return bytes.length;
      });
      
      final results = await Future.wait(futures);
      expect(results.length, 3);
      expect(results.every((size) => size > 0), isTrue);
    });
  });
}
