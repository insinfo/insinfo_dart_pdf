import 'dart:convert' show base64;
import 'dart:io' show File;
import 'dart:typed_data';

import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/icp_brasil/etsi_policy.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/icp_brasil/etsi_policy_enforcer.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/pdf_signature_validation.dart'
    show CmsSignedDataValidationResult;
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/cryptography/cipher_block_chaining_mode.dart'
  show RsaKeyParam;
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/x509/x509_utils.dart';
import 'package:dart_pdf/src/security/chain/icp_brasil_provider.dart';
import 'package:test/test.dart';

String _derToPem(Uint8List der) {
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
  group('ETSI policy parsing/enforcement (ICP-Brasil policies)', () {
    test('Parse AlgorithmConstraintSet (PA_AD_RB_v2_3.xml)', () {
      final String xml = File(
              'assets/policy/engine/artifacts/PA_AD_RB_v2_3.xml')
          .readAsStringSync();

      final EtsiPolicyConstraints c = EtsiPolicyConstraints.parseXml(xml);

      expect(c.policyOid, isNotNull);
      expect(c.policyOid!.startsWith('2.16.76.1.7.1.'), isTrue);
      expect(
        c.signerAlgorithmConstraints.any((a) =>
            a.algorithmToken == 'rsa-sha256' && a.minKeyLength == 2048),
        isTrue,
      );
    });

    test('Detect mandated SignatureTimeStamp (PA_AD_RC_v2_3.xml)', () {
      final String xml = File(
              'assets/policy/engine/artifacts/PA_AD_RC_v2_3.xml')
          .readAsStringSync();

      final EtsiPolicyConstraints c = EtsiPolicyConstraints.parseXml(xml);

      expect(c.requiresSignatureTimeStamp, isTrue);
      expect(c.mandatedUnsignedQProperties.contains('SignatureTimeStamp'),
          isTrue);
    });

    test('Enforce key length minimum (policy_key_too_short)', () async {
      final IcpBrasilProvider provider = IcpBrasilProvider();
      final List<Uint8List> rootsDer = await provider.getTrustedRoots();

      String? rsaPem;
      int? rsaBits;

      for (final Uint8List der in rootsDer) {
        final String pem = _derToPem(der);
        try {
          final cert = X509Utils.parsePemCertificate(pem);
          final key = cert.getPublicKey();
          final int? bits = key is RsaKeyParam ? key.modulus?.bitLength : null;
          if (bits != null) {
            rsaPem = pem;
            rsaBits = bits;
            break;
          }
        } catch (_) {
          // ignore invalid certs
        }
      }

      if (rsaPem == null || rsaBits == null) {
        return;
      }

      final EtsiPolicyConstraints constraints = EtsiPolicyConstraints(
        policyOid: '2.16.76.1.7.1.999.1',
        mandatedSignedQProperties: const <String>{},
        mandatedUnsignedQProperties: const <String>{},
        signerAlgorithmConstraints: <EtsiAlgorithmConstraint>[
          EtsiAlgorithmConstraint(
            algorithmToken: 'rsa-sha256',
            minKeyLength: rsaBits + 1,
          ),
        ],
      );

      final CmsSignedDataValidationResult cmsInfo = CmsSignedDataValidationResult(
        cmsSignatureValid: true,
        certsPem: <String>[rsaPem],
        digestAlgorithmOid: '2.16.840.1.101.3.4.2.1',
        signatureAlgorithmOid: '1.2.840.113549.1.1.11',
      );

      final EtsiPolicyEnforcement enforcement =
          const EtsiPolicyEnforcer().evaluate(
        policyOid: constraints.policyOid!,
        constraints: constraints,
        cmsInfo: cmsInfo,
        signerChainPem: <String>[rsaPem],
      );

      expect(
        enforcement.issues.any((i) =>
            i.code == 'policy_key_too_short' && i.severity.name == 'error'),
        isTrue,
      );
    });
  });
}
