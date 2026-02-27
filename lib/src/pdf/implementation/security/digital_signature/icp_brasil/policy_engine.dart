import 'lpa.dart';

enum PolicyIssueSeverity {
  warning,
  error,
}

class PolicyIssue {
  const PolicyIssue({
    required this.severity,
    required this.code,
    required this.message,
  });

  final PolicyIssueSeverity severity;
  final String code;
  final String message;
}

class PolicyEvaluation {
  const PolicyEvaluation({
    required this.valid,
    this.issues = const <PolicyIssue>[],
  });

  final bool valid;
  final List<PolicyIssue> issues;

  String? get firstError =>
      issues.where((i) => i.severity == PolicyIssueSeverity.error).isEmpty
          ? null
          : issues
              .firstWhere((i) => i.severity == PolicyIssueSeverity.error)
              .message;

  String? get firstWarning =>
      issues.where((i) => i.severity == PolicyIssueSeverity.warning).isEmpty
          ? null
          : issues
              .firstWhere((i) => i.severity == PolicyIssueSeverity.warning)
              .message;
}

class IcpBrasilPolicyEngine {
  IcpBrasilPolicyEngine([this.lpa]);

  final Lpa? lpa;

  /// Validates if the given [policyOid] is valid at the [signingTime].
  ///
  /// If [lpa] is not provided, it falls back to a limited set of known hardcoded OIDs
  /// but warns about missing LPA.
  PolicyValidationResult validatePolicy(
      String policyOid, DateTime signingTime) {
    final PolicyEvaluation detailed = evaluatePolicy(policyOid, signingTime);
    return PolicyValidationResult(
      isValid: detailed.valid,
      error: detailed.firstError,
      warning: detailed.firstWarning,
    );
  }

  /// Returns a structured evaluation of policy validity.
  ///
  /// This method is additive and meant for richer reporting.
  PolicyEvaluation evaluatePolicy(String policyOid, DateTime signingTime) {
    if (lpa == null) {
      // Fallback: Check against known current policies if LPA is missing.
      // This is not fully compliant but allows operation without the LPA file.
      return _evaluateHardcoded(policyOid, signingTime);
    }

    final List<PolicyIssue> issues = <PolicyIssue>[];
    if (DateTime.now().isAfter(lpa!.nextUpdate)) {
      issues.add(
        PolicyIssue(
          severity: PolicyIssueSeverity.warning,
          code: 'lpa_outdated',
          message:
              'LPA is outdated (NextUpdate=${lpa!.nextUpdate.toUtc().toIso8601String()})',
        ),
      );
    }

    final String? aliasOid = _getIcpBrasilAliasOid(policyOid);

    for (final PolicyInfo info in lpa!.policyInfos) {
      if (info.policyOid == policyOid ||
          (aliasOid != null && info.policyOid == aliasOid)) {
        final PolicyEvaluation period = _evaluatePeriod(info, signingTime);
        issues.addAll(period.issues);
        return PolicyEvaluation(valid: period.valid, issues: issues);
      }
    }

    issues.add(
      const PolicyIssue(
        severity: PolicyIssueSeverity.error,
        code: 'policy_oid_not_found',
        message: 'Policy OID not found in LPA',
      ),
    );
    return PolicyEvaluation(valid: false, issues: issues);
  }

  /// Like [validatePolicy], but when the CMS signed attributes contain the
  /// SignaturePolicyId hash, validates it against LPA's [PolicyInfo.policyDigest].
  ///
  /// This makes policy validation deterministic when LPA is available.
  PolicyValidationResult validatePolicyWithDigest(
    String policyOid,
    DateTime signingTime, {
    String? policyHashAlgorithmOid,
    List<int>? policyHashValue,
    bool strictDigest = false,
  }) {
    final PolicyEvaluation detailed = evaluatePolicyWithDigest(
        policyOid, signingTime,
        policyHashAlgorithmOid: policyHashAlgorithmOid,
        policyHashValue: policyHashValue,
        strictDigest: strictDigest);
    return PolicyValidationResult(
      isValid: detailed.valid,
      error: detailed.firstError,
      warning: detailed.firstWarning,
    );
  }

  /// Structured variant of [validatePolicyWithDigest].
  PolicyEvaluation evaluatePolicyWithDigest(
    String policyOid,
    DateTime signingTime, {
    String? policyHashAlgorithmOid,
    List<int>? policyHashValue,
    bool strictDigest = false,
  }) {
    final PolicyEvaluation base = evaluatePolicy(policyOid, signingTime);
    if (!base.valid) return base;

    if (lpa == null) {
      // No LPA => cannot verify the policy document digest.
      return base;
    }

    final List<PolicyIssue> issues = <PolicyIssue>[...base.issues];
    if (policyHashAlgorithmOid == null || policyHashValue == null) {
      if (strictDigest) {
        issues.add(
          const PolicyIssue(
            severity: PolicyIssueSeverity.error,
            code: 'policy_digest_missing',
            message:
                'SignaturePolicyId hash missing (required for deterministic policy validation)',
          ),
        );
        return PolicyEvaluation(valid: false, issues: issues);
      }
      issues.add(
        const PolicyIssue(
          severity: PolicyIssueSeverity.warning,
          code: 'policy_digest_missing',
          message: 'SignaturePolicyId hash missing (digest check skipped)',
        ),
      );
      return PolicyEvaluation(valid: true, issues: issues);
    }

    final String? aliasOid = _getIcpBrasilAliasOid(policyOid);

    PolicyInfo? info;
    for (final PolicyInfo p in lpa!.policyInfos) {
      if (p.policyOid == policyOid ||
          (aliasOid != null && p.policyOid == aliasOid)) {
        info = p;
        break;
      }
    }
    if (info == null) {
      issues.add(
        const PolicyIssue(
          severity: PolicyIssueSeverity.error,
          code: 'policy_oid_not_found',
          message: 'Policy OID not found in LPA',
        ),
      );
      return PolicyEvaluation(valid: false, issues: issues);
    }

    final String expectedAlgOid =
        _normalizeDigestAlgorithmToOid(info.policyDigest.algorithm);
    if (expectedAlgOid != policyHashAlgorithmOid) {
      issues.add(
        PolicyIssue(
          severity: PolicyIssueSeverity.error,
          code: 'policy_digest_algorithm_mismatch',
          message:
              'Policy digest algorithm mismatch (expected $expectedAlgOid, got $policyHashAlgorithmOid)',
        ),
      );
      return PolicyEvaluation(valid: false, issues: issues);
    }

    final List<int> expected = info.policyDigest.value;
    if (expected.length != policyHashValue.length) {
      issues.add(
        const PolicyIssue(
          severity: PolicyIssueSeverity.error,
          code: 'policy_digest_length_mismatch',
          message: 'Policy digest length mismatch',
        ),
      );
      return PolicyEvaluation(valid: false, issues: issues);
    }
    for (int i = 0; i < expected.length; i++) {
      if (expected[i] != policyHashValue[i]) {
        issues.add(
          const PolicyIssue(
            severity: PolicyIssueSeverity.error,
            code: 'policy_digest_mismatch',
            message: 'Policy digest does not match LPA',
          ),
        );
        return PolicyEvaluation(valid: false, issues: issues);
      }
    }

    return PolicyEvaluation(valid: true, issues: issues);
  }

  static String _normalizeDigestAlgorithmToOid(String algorithm) {
    // LPA DER uses OIDs; LPA XML often uses xmlenc URIs.
    final RegExp oidRe = RegExp(r'^\d+(?:\.\d+)+$');
    if (oidRe.hasMatch(algorithm)) return algorithm;
    switch (algorithm) {
      case 'http://www.w3.org/2000/09/xmldsig#sha1':
        return '1.3.14.3.2.26';
      case 'http://www.w3.org/2001/04/xmlenc#sha224':
        return '2.16.840.1.101.3.4.2.4';
      case 'http://www.w3.org/2001/04/xmlenc#sha256':
        return '2.16.840.1.101.3.4.2.1';
      case 'http://www.w3.org/2001/04/xmlenc#sha384':
        return '2.16.840.1.101.3.4.2.2';
      case 'http://www.w3.org/2001/04/xmlenc#sha512':
        return '2.16.840.1.101.3.4.2.3';
    }
    return algorithm;
  }

  PolicyEvaluation _evaluatePeriod(PolicyInfo info, DateTime time) {
    final DateTime notBefore = info.signingPeriod.notBefore;
    final DateTime? notAfter = info.signingPeriod.notAfter;
    final DateTime? revoked = info.revocationDate;

    if (time.isBefore(notBefore)) {
      return const PolicyEvaluation(
        valid: false,
        issues: <PolicyIssue>[
          PolicyIssue(
            severity: PolicyIssueSeverity.error,
            code: 'policy_time_before_validity',
            message: 'Signature time before policy validity',
          )
        ],
      );
    }
    if (notAfter != null && time.isAfter(notAfter)) {
      return const PolicyEvaluation(
        valid: false,
        issues: <PolicyIssue>[
          PolicyIssue(
            severity: PolicyIssueSeverity.error,
            code: 'policy_time_after_validity',
            message: 'Signature time after policy validity',
          )
        ],
      );
    }
    if (revoked != null && time.isAfter(revoked)) {
      return const PolicyEvaluation(
        valid: false,
        issues: <PolicyIssue>[
          PolicyIssue(
            severity: PolicyIssueSeverity.error,
            code: 'policy_revoked_before_signature_time',
            message: 'Policy was revoked before signature time',
          )
        ],
      );
    }

    return const PolicyEvaluation(valid: true);
  }

  PolicyEvaluation _evaluateHardcoded(String oid, DateTime time) {
    if (oid.startsWith('2.16.76.1.7.1.')) {
      return const PolicyEvaluation(
        valid: true,
        issues: <PolicyIssue>[
          PolicyIssue(
            severity: PolicyIssueSeverity.warning,
            code: 'lpa_missing_hardcoded_prefix',
            message: 'Validated against hardcoded prefix (LPA invalid/missing)',
          )
        ],
      );
    }
    return const PolicyEvaluation(
      valid: false,
      issues: <PolicyIssue>[
        PolicyIssue(
          severity: PolicyIssueSeverity.error,
          code: 'lpa_missing_unknown_policy_oid',
          message: 'Unknown Policy OID (LPA missing)',
        )
      ],
    );
  }

  /// Validates if the digest algorithm is allowed by the policy.
  PolicyValidationResult validateAlgorithm(
      String policyOid, String digestAlgorithmOid,
      [DateTime? signingTime]) {
    // Since we might not have the full XML policy loaded, we use heuristics for known ICP-Brasil policies.
    // AD-RB v2.x (2.16.76.1.7.1.1.2.*) requires SHA-256 (2.16.840.1.101.3.4.2.1) or better.

    if (_isAdRbV2Family(policyOid)) {
      if (digestAlgorithmOid == '2.16.840.1.101.3.4.2.1') {
        return PolicyValidationResult(isValid: true);
      }
      // SHA-1 (1.3.14.3.2.26) is definitely banned for v2
      if (digestAlgorithmOid == '1.3.14.3.2.26') {
        return PolicyValidationResult(
            isValid: false, error: 'SHA-1 is not allowed for $policyOid');
      }

      return PolicyValidationResult(
          isValid: false,
          error:
              'Algorithm $digestAlgorithmOid not allowed for policy $policyOid (Expected SHA256)');
    }

    // Fallback for older or other policies
    return PolicyValidationResult(
        isValid: true,
        warning: 'Algorithm validation skipped (Policy XML missing)');
  }

  PolicyEvaluation evaluateAlgorithm(
      String policyOid, String digestAlgorithmOid,
      [DateTime? signingTime]) {
    if (_isAdRbV2Family(policyOid)) {
      if (digestAlgorithmOid == '2.16.840.1.101.3.4.2.1') {
        return const PolicyEvaluation(valid: true);
      }
      if (digestAlgorithmOid == '1.3.14.3.2.26') {
        return PolicyEvaluation(
          valid: false,
          issues: <PolicyIssue>[
            PolicyIssue(
              severity: PolicyIssueSeverity.error,
              code: 'digest_sha1_not_allowed',
              message: 'SHA-1 is not allowed for $policyOid',
            )
          ],
        );
      }

      return PolicyEvaluation(
        valid: false,
        issues: <PolicyIssue>[
          PolicyIssue(
            severity: PolicyIssueSeverity.error,
            code: 'digest_algorithm_not_allowed',
            message:
                'Algorithm $digestAlgorithmOid not allowed for policy $policyOid (Expected SHA256)',
          )
        ],
      );
    }

    return const PolicyEvaluation(
      valid: true,
      issues: <PolicyIssue>[
        PolicyIssue(
          severity: PolicyIssueSeverity.warning,
          code: 'digest_algorithm_validation_skipped',
          message: 'Algorithm validation skipped (Policy XML missing)',
        )
      ],
    );
  }

  static bool _isAdRbV2Family(String policyOid) {
    return policyOid.startsWith('2.16.76.1.7.1.1.2') ||
        policyOid.startsWith('2.16.76.1.7.1.6.2');
  }

  static String? _getIcpBrasilAliasOid(String policyOid) {
    const String basePrefix = '2.16.76.1.7.1.';
    if (!policyOid.startsWith(basePrefix)) return null;

    final String suffix = policyOid.substring(basePrefix.length);
    final List<String> parts = suffix.split('.');
    if (parts.length < 2) return null;

    final int? family = int.tryParse(parts.first);
    if (family == null) return null;

    final int? aliasFamily = (family >= 1 && family <= 5)
        ? family + 5
        : (family >= 6 && family <= 10)
            ? family - 5
            : null;
    if (aliasFamily == null) return null;

    final String tail = parts.skip(1).join('.');
    return '$basePrefix$aliasFamily.$tail';
  }
}

class PolicyValidationResult {
  PolicyValidationResult({required this.isValid, this.error, this.warning});
  final bool isValid;
  final String? error;
  final String? warning;
}
