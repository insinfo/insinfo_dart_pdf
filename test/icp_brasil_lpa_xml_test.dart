import 'dart:io';

import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/icp_brasil/lpa.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/icp_brasil/policy_oid_map_builder.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/icp_brasil/policy_engine.dart';
import 'package:test/test.dart';

void main() {
  test('Parses Demoiselle LPAv2.xml and validates policy periods', () {
    final String xmlString = File(
      'assets/policy/engine/artifacts/LPAv2.xml',
    ).readAsStringSync();

    final Lpa? lpa = Lpa.fromXmlString(xmlString);
    expect(lpa, isNotNull);
    expect(lpa!.version, 2);
    expect(lpa.policyInfos, isNotEmpty);

    final IcpBrasilPolicyEngine engine = IcpBrasilPolicyEngine(lpa);

    // From the artifact: Policy 2.16.76.1.7.1.6.2.2 has NotBefore 2012-09-21 and NotAfter 2023-06-21.
    final DateTime inside = DateTime.parse('2013-01-01T00:00:00.000Z');
    final DateTime before = DateTime.parse('2010-01-01T00:00:00.000Z');

    expect(
      engine.validatePolicy('2.16.76.1.7.1.6.2.2', inside).isValid,
      isTrue,
    );

    expect(
      engine.validatePolicy('2.16.76.1.7.1.6.2.2', before).isValid,
      isFalse,
    );

    expect(
      engine.validatePolicy('2.16.76.1.7.1.1.2.2', inside).isValid,
      isTrue,
    );
  });

  test('Builds OID map from XML and DER artifacts including CAdES aliases',
      () async {
    final Map<String, String> policyOidMap =
        await IcpBrasilPolicyOidMapBuilder.loadFromArtifactsDirectory(
      'assets/policy/engine/artifacts',
    );

    expect(policyOidMap, isNotEmpty);

    expect(policyOidMap['2.16.76.1.7.1.1.2.3'], isNotNull);
    expect(policyOidMap['2.16.76.1.7.1.6.2.3'], isNotNull);
    expect(
      policyOidMap['2.16.76.1.7.1.1.2.3'],
      equals(policyOidMap['2.16.76.1.7.1.6.2.3']),
    );

    final String resolvedPolicy =
        policyOidMap['2.16.76.1.7.1.1.2.3']!.toLowerCase();
    expect(resolvedPolicy, contains('pa_'));
  });

  test('Parses LPA_CAdES.der and finds AD-RB v2.3 OID', () {
    final List<int> derBytes =
        File('assets/policy/engine/artifacts/LPA_CAdES.der').readAsBytesSync();

    final Lpa? lpa = Lpa.fromBytes(derBytes);
    expect(lpa, isNotNull);
    expect(lpa!.policyInfos, isNotEmpty);
    expect(
      lpa.policyInfos.any((p) => p.policyOid == '2.16.76.1.7.1.1.2.3'),
      isTrue,
    );
  });
}
