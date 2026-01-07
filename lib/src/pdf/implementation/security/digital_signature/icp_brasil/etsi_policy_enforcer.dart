import '../cryptography/cipher_block_chaining_mode.dart' show RsaKeyParam, EcPublicKeyParam;
import '../pdf_signature_validation.dart' show CmsSignedDataValidationResult;
import '../x509/x509_utils.dart';
import 'etsi_policy.dart';
import 'policy_engine.dart';

class EtsiPolicyEnforcement {
  const EtsiPolicyEnforcement({
    required this.timestampRequiredByPolicy,
    required this.issues,
  });

  final bool timestampRequiredByPolicy;
  final List<PolicyIssue> issues;
}

class EtsiPolicyEnforcer {
  const EtsiPolicyEnforcer();

  EtsiPolicyEnforcement evaluate({
    required String policyOid,
    required EtsiPolicyConstraints constraints,
    required CmsSignedDataValidationResult cmsInfo,
    required List<String> signerChainPem,
  }) {
    final List<PolicyIssue> issues = <PolicyIssue>[];

    final bool requiresTs = constraints.requiresSignatureTimeStamp;
    // Timestamp enforcement is applied by PdfSignatureValidator once it has
    // computed PdfTimestampStatus; here we only expose the requirement.

    // Algorithm constraints (when present in policy doc)
    if (constraints.signerAlgorithmConstraints.isNotEmpty) {
      final String? token = _normalizeCmsToToken(
        signatureAlgorithmOid: cmsInfo.signatureAlgorithmOid,
        digestAlgorithmOid: cmsInfo.digestAlgorithmOid,
      );

      if (token == null) {
        issues.add(
          PolicyIssue(
            severity: PolicyIssueSeverity.warning,
            code: 'policy_algorithm_unknown',
            message:
                'Could not normalize CMS algorithm (sig=${cmsInfo.signatureAlgorithmOid}, digest=${cmsInfo.digestAlgorithmOid}) for policy constraints.',
          ),
        );
      } else {
        final EtsiAlgorithmConstraint? allowed = constraints
            .signerAlgorithmConstraints
            .where((c) => c.algorithmToken == token)
            .cast<EtsiAlgorithmConstraint?>()
            .fold<EtsiAlgorithmConstraint?>(
              null,
              (prev, cur) => prev ?? cur,
            );

        if (allowed == null) {
          issues.add(
            PolicyIssue(
              severity: PolicyIssueSeverity.error,
              code: 'policy_algorithm_not_allowed',
              message:
                  'Algorithm $token is not allowed by policy ($policyOid).',
            ),
          );
        } else {
          final int? keyBits = _signerKeyBits(signerChainPem);
          if (keyBits == null) {
            issues.add(
              const PolicyIssue(
                severity: PolicyIssueSeverity.warning,
                code: 'policy_key_length_unknown',
                message:
                    'Could not determine signer public key length to validate policy key length constraints.',
              ),
            );
          } else if (keyBits < allowed.minKeyLength) {
            issues.add(
              PolicyIssue(
                severity: PolicyIssueSeverity.error,
                code: 'policy_key_too_short',
                message:
                    'Signer key length ($keyBits) is below policy minimum (${allowed.minKeyLength}) for $token.',
              ),
            );
          }
        }
      }
    }

    return EtsiPolicyEnforcement(
      timestampRequiredByPolicy: requiresTs,
      issues: issues,
    );
  }

  static int? _signerKeyBits(List<String> chainPem) {
    if (chainPem.isEmpty) return null;
    try {
      final cert = X509Utils.parsePemCertificate(chainPem.first);
      final key = cert.getPublicKey();
      if (key is RsaKeyParam) {
        return key.modulus?.bitLength;
      }
      if (key is EcPublicKeyParam) {
        // fieldSize is the best approximation for EC public key size.
        return key.publicKey.parameters?.curve.fieldSize;
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  static String? _normalizeCmsToToken({
    required String? signatureAlgorithmOid,
    required String? digestAlgorithmOid,
  }) {
    // SHA-256 OID = 2.16.840.1.101.3.4.2.1
    // SHA-384 OID = 2.16.840.1.101.3.4.2.2
    // SHA-512 OID = 2.16.840.1.101.3.4.2.3
    // RSA (sha256WithRSAEncryption) = 1.2.840.113549.1.1.11
    // RSA (sha512WithRSAEncryption) = 1.2.840.113549.1.1.13
    // RSA (rsaEncryption) = 1.2.840.113549.1.1.1 (digest indicated separately)

    if (signatureAlgorithmOid == '1.2.840.113549.1.1.11') return 'rsa-sha256';
    if (signatureAlgorithmOid == '1.2.840.113549.1.1.12') return 'rsa-sha384';
    if (signatureAlgorithmOid == '1.2.840.113549.1.1.13') return 'rsa-sha512';

    if (signatureAlgorithmOid == '1.2.840.113549.1.1.1') {
      // rsaEncryption with separate digest
      return switch (digestAlgorithmOid) {
        '2.16.840.1.101.3.4.2.1' => 'rsa-sha256',
        '2.16.840.1.101.3.4.2.2' => 'rsa-sha384',
        '2.16.840.1.101.3.4.2.3' => 'rsa-sha512',
        '1.3.14.3.2.26' => 'rsa-sha1',
        _ => null,
      };
    }

    // ECDSA (X9.62)
    if (signatureAlgorithmOid == '1.2.840.10045.4.3.2') return 'ecdsa-sha256';
    if (signatureAlgorithmOid == '1.2.840.10045.4.3.3') return 'ecdsa-sha384';
    if (signatureAlgorithmOid == '1.2.840.10045.4.3.4') return 'ecdsa-sha512';

    return null;
  }
}
