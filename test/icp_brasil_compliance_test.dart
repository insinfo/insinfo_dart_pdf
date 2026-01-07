import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';
import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/pdf_signature_validator.dart';
import 'package:dart_pdf/src/security/chain/icp_brasil_provider.dart';
import 'package:dart_pdf/src/security/chain/iti_provider.dart';
import 'package:dart_pdf/src/security/chain/serpro_provider.dart';

const bool _verbose = bool.fromEnvironment('DART_PDF_TEST_VERBOSE');

String derToPem(Uint8List der) {
  final base64Cert = base64.encode(der);
  final buffer = StringBuffer();
  buffer.writeln('-----BEGIN CERTIFICATE-----');
  for (int i = 0; i < base64Cert.length; i += 64) {
    buffer.writeln(base64Cert.substring(
        i, (i + 64 < base64Cert.length) ? i + 64 : base64Cert.length));
  }
  buffer.writeln('-----END CERTIFICATE-----');
  return buffer.toString();
}

void main() {
  group('ICP-Brasil and Gov.br Signature Compliance', () {
    List<String> trustedRoots = [];

    setUpAll(() async {
      final icp = IcpBrasilProvider();
      final iti = ItiProvider();
      final serpro = SerproProvider();

      for (var c in await icp.getTrustedRoots()) trustedRoots.add(derToPem(c));
      for (var c in await iti.getTrustedRoots()) trustedRoots.add(derToPem(c));
      for (var c in await serpro.getTrustedRoots())
        trustedRoots.add(derToPem(c));

      if (_verbose) {
        // ignore: avoid_print
        print('Loaded ${trustedRoots.length} trusted roots.');
      }
    });

    test('Validate Gov.br signed PDF (sample_govbr_signature_assinado.pdf)',
        () async {
      final File file = File('test/assets/sample_govbr_signature_assinado.pdf');
      final List<int> bytes = file.readAsBytesSync();

      final PdfSignatureValidator validator = PdfSignatureValidator();
      final PdfSignatureValidationReport report =
          await validator.validateAllSignatures(
        Uint8List.fromList(bytes),
        fetchCrls: true,
        trustedRootsPem: trustedRoots,
      );

      expect(report.signatures.isNotEmpty, isTrue,
          reason: 'Gov.br file should have at least one signature');

      for (final PdfSignatureValidationItem sig in report.signatures) {
        if (_verbose) {
          // ignore: avoid_print
          print('Signature: ${sig.fieldName}');
          // ignore: avoid_print
          print('  Valid: ${sig.validation.cmsSignatureValid}');
          // ignore: avoid_print
          print('  Intact: ${sig.validation.documentIntact}');
          // ignore: avoid_print
          print('  Policy OID: ${sig.validation.policyOid}');
          if (sig.policyStatus != null) {
            // ignore: avoid_print
            print(
              '  Policy Status: ${sig.policyStatus!.valid} '
              '(${sig.policyStatus!.error ?? sig.policyStatus!.warning})',
            );
          }
        }

        // 1. Signature must be cryptographically valid
        expect(sig.validation.cmsSignatureValid, isTrue,
            reason: 'CMS signature must be valid');

        // 2. Document must be intact (hash matches)
        expect(sig.validation.documentIntact, isTrue,
            reason: 'Document must not be modified');

        // 2b. Timestamp status must be present in report (even if absent in PDF)
        expect(sig.timestampStatus, isNotNull);
        expect(sig.timestampStatus!.present, isA<bool>());

        // 2c. For ICP-Brasil/Gov.br policies, missing timestamp is a warning (not an error)
        if (sig.validation.policyOid != null &&
            sig.validation.policyOid!.startsWith('2.16.76.1.7.1.')) {
          if (sig.timestampStatus!.present == false) {
            expect(
              sig.issues.any((i) =>
                  i.code == 'timestamp_missing' && i.severity.name == 'warning'),
              isTrue,
              reason:
                  'Missing timestamp should be surfaced as warning for ICP-Brasil/Gov.br',
            );
          }
        }

        // 3. Gov.br uses OID 2.16.76.1.7.1... (ICP-Brasil)
        // Some legacy or specific Gov.br signatures might NOT have the PolicyOID attribute.
        if (sig.validation.policyOid != null) {
          if (_verbose) {
            // ignore: avoid_print
            print('  Detected Policy: ${sig.validation.policyOid}');
          }
          if (sig.policyStatus != null) {
            expect(sig.policyStatus!.valid, isTrue,
                reason: 'Policy validation failed');
          }
        }
      }
    },
        skip: File('test/assets/sample_govbr_signature_assinado.pdf')
                .existsSync()
            ? false
            : 'Missing test asset: test/assets/sample_govbr_signature_assinado.pdf');

    test(
        'Validate ICP-Brasil Token signed PDF (sample_token_icpbrasil_assinado.pdf)',
        () async {
      final File file = File('test/assets/sample_token_icpbrasil_assinado.pdf');
      final List<int> bytes = file.readAsBytesSync();

      final PdfSignatureValidator validator = PdfSignatureValidator();
      // Enable fetchCrls to attempt online revocation checks (OCSP/CRL)
      final PdfSignatureValidationReport report =
          await validator.validateAllSignatures(
        Uint8List.fromList(bytes),
        fetchCrls: true,
        trustedRootsPem: trustedRoots,
      );

      expect(report.signatures.isNotEmpty, isTrue);

      for (final PdfSignatureValidationItem sig in report.signatures) {
        if (_verbose) {
          // ignore: avoid_print
          print('Signature: ${sig.fieldName}');
          // ignore: avoid_print
          print('  Valid (Crypto): ${sig.validation.cmsSignatureValid}');
          // ignore: avoid_print
          print('  Policy OID: ${sig.validation.policyOid}');
          // ignore: avoid_print
          print('  Revocation Status: ${sig.revocationStatus.status}');

          if (sig.revocationStatus.details != null) {
            // ignore: avoid_print
            print('  Revocation Details: ${sig.revocationStatus.details}');
          }
        }

        expect(sig.validation.cmsSignatureValid, isTrue,
            reason: 'CMS signature must be valid');
      }
    },
        skip: File('test/assets/sample_token_icpbrasil_assinado.pdf')
                .existsSync()
            ? false
            : 'Missing test asset: test/assets/sample_token_icpbrasil_assinado.pdf');
  });
}
