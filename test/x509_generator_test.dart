import 'package:dart_pdf/pdf.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';

void main() {
  group('X509GeneratorUtils', () {
    test('generateRsaKeyPair returns valid key pair', () {
      final pair = X509GeneratorUtils.generateRsaKeyPair(bitStrength: 1024);
      expect(pair.publicKey, isA<pc.RSAPublicKey>());
      expect(pair.privateKey, isA<pc.RSAPrivateKey>());
    });

    test('generateRsaCsrPem creates a PEM string', () {
      final pair = X509GeneratorUtils.generateRsaKeyPair(bitStrength: 1024);
      final attr = {'CN': 'Test User', 'O': 'Test Org', 'C': 'BR'};
      final csr = X509GeneratorUtils.generateRsaCsrPem(attr, pair.privateKey, pair.publicKey);
      
      expect(csr, startsWith('-----BEGIN CERTIFICATE REQUEST-----'));
      expect(csr, endsWith('-----END CERTIFICATE REQUEST-----\n'));
      expect(csr.contains('MII'), isTrue); // Base64 content check
    });

    test('generateSelfSignedCertificate creates a PEM string', () {
      final pair = X509GeneratorUtils.generateRsaKeyPair(bitStrength: 1024);
      final cert = X509GeneratorUtils.generateSelfSignedCertificate(
        pair,
        'CN=Test Self Signed',
        30,
      );
      
      expect(cert, startsWith('-----BEGIN CERTIFICATE-----'));
      expect(cert, endsWith('-----END CERTIFICATE-----\n'));
      
      // Parse it back to check properties we added
      final parsed = X509Utils.parsePemCertificate(cert);
      expect(parsed.subject.toString(), contains('CN=Test Self Signed'));
      expect(parsed.issuer.toString(), contains('CN=Test Self Signed')); // Self signed
      expect(parsed.startDate, isNotNull);
      expect(parsed.endDate, isNotNull);
    });
  });
}
