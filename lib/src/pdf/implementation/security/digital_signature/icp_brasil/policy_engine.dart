import 'lpa.dart';

class IcpBrasilPolicyEngine {
  IcpBrasilPolicyEngine([this.lpa]);

  final Lpa? lpa;

  /// Validates if the given [policyOid] is valid at the [signingTime].
  ///
  /// If [lpa] is not provided, it falls back to a limited set of known hardcoded OIDs
  /// but warns about missing LPA.
  PolicyValidationResult validatePolicy(
      String policyOid, DateTime signingTime) {
    if (lpa == null) {
      // Fallback: Check against known current policies if LPA is missing.
      // This is not fully compliant but allows operation without the LPA file.
      return _validateHardcoded(policyOid, signingTime);
    }

    final String? lpaWarning = DateTime.now().isAfter(lpa!.nextUpdate)
        ? 'LPA is outdated (NextUpdate=${lpa!.nextUpdate.toUtc().toIso8601String()})'
        : null;

    // Iterate over LPA policies
    for (final PolicyInfo info in lpa!.policyInfos) {
      if (info.policyOid == policyOid) {
        final PolicyValidationResult base = _checkPeriod(info, signingTime);
        if (base.isValid && base.warning == null && lpaWarning != null) {
          return PolicyValidationResult(isValid: true, warning: lpaWarning);
        }
        if (base.isValid && base.warning != null && lpaWarning != null) {
          return PolicyValidationResult(
            isValid: true,
            warning: '${base.warning}; $lpaWarning',
          );
        }
        return base;
      }
    }

    return PolicyValidationResult(
        isValid: false, error: 'Policy OID not found in LPA');
  }

  PolicyValidationResult _checkPeriod(PolicyInfo info, DateTime time) {
    final DateTime notBefore = info.signingPeriod.notBefore;
    final DateTime? notAfter = info.signingPeriod.notAfter;
    final DateTime? revoked = info.revocationDate;

    if (time.isBefore(notBefore)) {
      return PolicyValidationResult(
          isValid: false, error: 'Signature time before policy validity');
    }
    if (notAfter != null && time.isAfter(notAfter)) {
      return PolicyValidationResult(
          isValid: false, error: 'Signature time after policy validity');
    }
    if (revoked != null && time.isAfter(revoked)) {
      return PolicyValidationResult(
          isValid: false, error: 'Policy was revoked before signature time');
    }

    return PolicyValidationResult(isValid: true);
  }

  PolicyValidationResult _validateHardcoded(String oid, DateTime time) {
    // Basic check for AD-RB syntax
    if (oid.startsWith('2.16.76.1.7.1.')) {
      // Assume valid for simplified engine if no LPA provided
      return PolicyValidationResult(
          isValid: true,
          warning: 'Validated against hardcoded prefix (LPA invalid/missing)');
    }
    return PolicyValidationResult(
        isValid: false, error: 'Unknown Policy OID (LPA missing)');
  }

  /// Validates if the digest algorithm is allowed by the policy.
  PolicyValidationResult validateAlgorithm(
      String policyOid, String digestAlgorithmOid,
      [DateTime? signingTime]) {
    // Since we might not have the full XML policy loaded, we use heuristics for known ICP-Brasil policies.
    // AD-RB v2.x (2.16.76.1.7.1.1.2.*) requires SHA-256 (2.16.840.1.101.3.4.2.1) or better.

    if (policyOid.startsWith('2.16.76.1.7.1.1.2')) {
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
}

class PolicyValidationResult {
  PolicyValidationResult({required this.isValid, this.error, this.warning});
  final bool isValid;
  final String? error;
  final String? warning;
}
