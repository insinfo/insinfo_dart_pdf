import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/icp_brasil/lpa.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/icp_brasil/policy_engine.dart';
import 'package:test/test.dart';

void main() {
  test('IcpBrasilPolicyEngine strictDigest=false allows missing SignaturePolicyId hash with warning', () {
    final Lpa lpa = _makeLpa(
      policyOid: '2.16.76.1.7.1.1.2.1',
      alg: '2.16.840.1.101.3.4.2.1',
      digest: List<int>.filled(32, 0xAB),
    );

    final IcpBrasilPolicyEngine engine = IcpBrasilPolicyEngine(lpa);
    final PolicyValidationResult res = engine.validatePolicyWithDigest(
      '2.16.76.1.7.1.1.2.1',
      DateTime.parse('2024-01-01T00:00:00Z'),
      // missing policyHashAlgorithmOid/policyHashValue
      strictDigest: false,
    );

    expect(res.isValid, isTrue);
    expect(res.warning, isNotNull);
    expect(res.error, isNull);
  });

  test('IcpBrasilPolicyEngine strictDigest=true fails when SignaturePolicyId hash is missing', () {
    final Lpa lpa = _makeLpa(
      policyOid: '2.16.76.1.7.1.1.2.1',
      alg: '2.16.840.1.101.3.4.2.1',
      digest: List<int>.filled(32, 0xAB),
    );

    final IcpBrasilPolicyEngine engine = IcpBrasilPolicyEngine(lpa);
    final PolicyValidationResult res = engine.validatePolicyWithDigest(
      '2.16.76.1.7.1.1.2.1',
      DateTime.parse('2024-01-01T00:00:00Z'),
      strictDigest: true,
    );

    expect(res.isValid, isFalse);
    expect(res.error, contains('SignaturePolicyId hash missing'));
  });

  test('IcpBrasilPolicyEngine validates digest match when provided', () {
    final List<int> digest = List<int>.generate(32, (i) => i);
    final Lpa lpa = _makeLpa(
      policyOid: '2.16.76.1.7.1.1.2.1',
      alg: 'http://www.w3.org/2001/04/xmlenc#sha256', // exercise URI->OID normalization
      digest: digest,
    );

    final IcpBrasilPolicyEngine engine = IcpBrasilPolicyEngine(lpa);
    final PolicyValidationResult res = engine.validatePolicyWithDigest(
      '2.16.76.1.7.1.1.2.1',
      DateTime.parse('2024-01-01T00:00:00Z'),
      policyHashAlgorithmOid: '2.16.840.1.101.3.4.2.1',
      policyHashValue: digest,
      strictDigest: true,
    );

    expect(res.isValid, isTrue);
    expect(res.error, isNull);
  });
}

Lpa _makeLpa({
  required String policyOid,
  required String alg,
  required List<int> digest,
}) {
  final PolicyInfo info = PolicyInfo(
    signingPeriod: SigningPeriod(
      notBefore: DateTime.parse('2020-01-01T00:00:00Z'),
      notAfter: DateTime.parse('2030-01-01T00:00:00Z'),
    ),
    policyOid: policyOid,
    policyUri: 'urn:example:$policyOid',
    policyDigest: PolicyDigest(algorithm: alg, value: digest),
  );

  return Lpa(
    policyInfos: <PolicyInfo>[info],
    nextUpdate: DateTime.parse('2030-01-01T00:00:00Z'),
  );
}
