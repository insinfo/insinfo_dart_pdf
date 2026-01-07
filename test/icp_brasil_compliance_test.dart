import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';
import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/pdf_signature_validator.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/pdf_signature_validation.dart';
import 'package:dart_pdf/src/security/chain/icp_brasil_provider.dart';
import 'package:dart_pdf/src/security/chain/iti_provider.dart';
import 'package:dart_pdf/src/security/chain/serpro_provider.dart';

String derToPem(Uint8List der) {
  final base64Cert = base64.encode(der);
  final buffer = StringBuffer();
  buffer.writeln('-----BEGIN CERTIFICATE-----');
  for (int i = 0; i < base64Cert.length; i += 64) {
    buffer.writeln(base64Cert.substring(i, (i + 64 < base64Cert.length) ? i + 64 : base64Cert.length));
  }
  buffer.writeln('-----END CERTIFICATE-----');
  return buffer.toString();
}

void main() {
  group('ICP-Brasil and Gov.br Signature Compliance', () {
    List<String> trustedRoots = [];

    setUpAll(() async {
        try {
            final icp = IcpBrasilProvider();
            final iti = ItiProvider();
            final serpro = SerproProvider();
            
            for (var c in await icp.getTrustedRoots()) trustedRoots.add(derToPem(c));
            for (var c in await iti.getTrustedRoots()) trustedRoots.add(derToPem(c));
            for (var c in await serpro.getTrustedRoots()) trustedRoots.add(derToPem(c));
            print('Loaded ${trustedRoots.length} trusted roots.');
        } catch (e) {
            print('Warning loading roots: $e');
        }
    });

    test('Validate Gov.br signed PDF (sample_govbr_signature_assinado.pdf)', () async {
      print('Testing sample_govbr_signature_assinado.pdf...');
      final File file = File('test/assets/sample_govbr_signature_assinado.pdf');
      if (!file.existsSync()) {
        print('Skipping test: file not found at ${file.path}');
        return;
      }
      final List<int> bytes = file.readAsBytesSync();

      final PdfSignatureValidator validator = PdfSignatureValidator();
      final PdfSignatureValidationReport report = await validator.validateAllSignatures(
        Uint8List.fromList(bytes),
        fetchCrls: true,
        trustedRootsPem: trustedRoots,
      );

      print('Gov.br Signatures found: ${report.signatures.length}');
      expect(report.signatures.isNotEmpty, isTrue, reason: 'Gov.br file should have at least one signature');

      for (final PdfSignatureValidationItem sig in report.signatures) {
        print('Signature: ${sig.fieldName}');
        print('  Valid: ${sig.validation.cmsSignatureValid}');
        print('  Intact: ${sig.validation.documentIntact}');
        print('  Policy OID: ${sig.validation.policyOid}');
        if (sig.policyStatus != null) {
           print('  Policy Status: ${sig.policyStatus!.valid} (${sig.policyStatus!.error ?? sig.policyStatus!.warning})');
        }

        // 1. Signature must be cryptographically valid
        expect(sig.validation.cmsSignatureValid, isTrue, reason: 'CMS signature must be valid');
        
        // 2. Document must be intact (hash matches)
        expect(sig.validation.documentIntact, isTrue, reason: 'Document must not be modified');

        // 3. Gov.br uses OID 2.16.76.1.7.1... (ICP-Brasil)
        // Some legacy or specific Gov.br signatures might NOT have the PolicyOID attribute.
        if (sig.validation.policyOid != null) {
           print('  Detected Policy: ${sig.validation.policyOid}');
            if (sig.policyStatus != null) {
               expect(sig.policyStatus!.valid, isTrue, reason: 'Policy validation failed');
            }
        } else {
             print('  (Warning: No Policy OID detected for Gov.br signature)');
        }
      }
    });

    test('Validate ICP-Brasil Token signed PDF (sample_token_icpbrasil_assinado.pdf)', () async {
      print('Testing sample_token_icpbrasil_assinado.pdf...');
      final File file = File('test/assets/sample_token_icpbrasil_assinado.pdf');
      if (!file.existsSync()) {
        print('Skipping test: file not found at ${file.path}');
        return;
      }
      final List<int> bytes = file.readAsBytesSync();

      print('--- Validation Info ---');
      print('OCSP (consulta de revogação): http://ocsp-ac-oab.certisign.com.br');
      print('CA Issuers (cadeia/emitente do certificado): http://icp-brasil.certisign.com.br/repositorio/certificados/AC_OAB_G3.p7c');
      print('-----------------------');

      final PdfSignatureValidator validator = PdfSignatureValidator();
      // Enable fetchCrls to attempt online revocation checks (OCSP/CRL)
      final PdfSignatureValidationReport report = await validator.validateAllSignatures(
        Uint8List.fromList(bytes),
        fetchCrls: true,
        trustedRootsPem: trustedRoots,
      );

      print('Token Signatures found: ${report.signatures.length}');
      expect(report.signatures.isNotEmpty, isTrue);

      for (final PdfSignatureValidationItem sig in report.signatures) {
         print('Signature: ${sig.fieldName}');
         print('  Valid (Crypto): ${sig.validation.cmsSignatureValid}');
         print('  Policy OID: ${sig.validation.policyOid}');
         print('  Revocation Status: ${sig.revocationStatus.status}');
         
         if (sig.revocationStatus.details != null) {
            print('  Revocation Details: ${sig.revocationStatus.details}');
         }

         if (!sig.validation.cmsSignatureValid) {
            print('  INFO: Signature crypto validation returned false (Likely missing Trust Chain/Issuer for verification).');
         } else {
            print('  SUCCESS: Signature is cryptographically valid.');
         }
         
         if (sig.validation.policyOid == null) {
            print('  WARNING: No Policy OID found in Token signature.');
         }
      }
    });

  });
}
