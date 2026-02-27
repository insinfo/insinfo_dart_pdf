import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:dart_pdf/pdf.dart' as pdf;
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/icp_brasil/lpa.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/icp_brasil/policy_oid_map_builder.dart';
import 'package:test/test.dart';

void main() {
  const String expectedPolicyOid = '2.16.76.1.7.1.1.2.3';
  const String expectedSha256 =
      '2728e47333a1225f135605b4c5b42c89ad1130bc49b682fb8ff5679da5c2e056';

  group('Integração: documento assinado erro.pdf', () {
    test('modo estrito: exige parse de LPA_CAdES.der sem fallback', () async {
      final _Scenario scenario = await _loadScenario(
        expectedPolicyOid: expectedPolicyOid,
        expectedSha256: expectedSha256,
      );

      expect(scenario.lpa, isNotNull,
          reason:
              'LPA_CAdES.der deve ser parseado obrigatoriamente neste teste estrito');
      expect(scenario.lpa!.policyInfos, isNotEmpty);
      expect(
        scenario.lpa!.policyInfos.any((p) => p.policyOid == expectedPolicyOid),
        isTrue,
      );

      final pdf.PdfSignatureValidationReport report =
          await pdf.PdfSignatureValidator().validateAllSignatures(
        scenario.pdfBytes,
        useEmbeddedIcpBrasil: true,
        fetchCrls: false,
        strictRevocation: false,
        lpa: scenario.lpa,
      );

      expect(report.signatures.length, equals(1));
      final pdf.PdfSignatureValidationItem sig = report.signatures.single;

      expect(sig.validation.policyOid, equals(expectedPolicyOid));
      expect(sig.policyStatus, isNotNull);
      expect(sig.policyStatus!.valid, isFalse,
          reason:
              'No modo estrito com LPA CAdES explícita, a lib deve aplicar digest da LPA sem fallback');
      expect(sig.policyStatus!.error,
          contains('Policy digest does not match LPA'));
      expect(sig.policyStatus!.warning, contains('LPA is outdated'));
      expect(sig.chainTrusted, isTrue);
      expect(sig.validation.cmsSignatureValid, isTrue);
      expect(sig.validation.documentIntact, isTrue);

      final List<pdf.X509Certificate> certPool =
          pdf.OfflineCertificateChainBuilder.loadCertPoolFromDirectories(
        const <String>[
          'assets/truststore/icp_brasil',
          'assets/truststore/cadeia_icp_brasil',
          'assets/truststore/iti',
          'assets/truststore/serpro',
        ],
      );
      final List<pdf.X509Certificate> chain =
          pdf.OfflineCertificateChainBuilder.buildCompleteChain(
        signerCertsPem: sig.validation.certsPem,
        certPool: certPool,
      );
      expect(chain.length, greaterThanOrEqualTo(4),
          reason:
              'Cadeia completa esperada: assinante + intermediárias + raiz ICP-Brasil');

      final List<String> subjects = chain
          .map((c) => c.c?.subject?.toString() ?? '')
          .where((s) => s.isNotEmpty)
          .toList(growable: false);
      expect(
        subjects
            .any((s) => s.toUpperCase().contains('UBIRATAN NUNES DA SILVA')),
        isTrue,
      );
      expect(
        subjects.any((s) => s.toUpperCase().contains('SERPRORFBV5')),
        isTrue,
      );
      expect(
        subjects.any(
          (s) => s
              .toUpperCase()
              .contains('AC SECRETARIA DA RECEITA FEDERAL DO BRASIL V4'),
        ),
        isTrue,
      );
      expect(
        subjects.any((s) => s
            .toUpperCase()
            .contains('AUTORIDADE CERTIFICADORA RAIZ BRASILEIRA V5')),
        isTrue,
      );
    });

    test('modo completo: confere campos extras do relatório offline', () async {
      final _Scenario scenario = await _loadScenario(
        expectedPolicyOid: expectedPolicyOid,
        expectedSha256: expectedSha256,
      );

      final pdf.PdfSignatureValidationReport report =
          await pdf.PdfSignatureValidator().validateAllSignatures(
        scenario.pdfBytes,
        useEmbeddedIcpBrasil: true,
        fetchCrls: false,
        strictRevocation: false,
        lpa: scenario.lpa,
      );

      expect(report.allDocumentsIntact, isTrue);
      expect(report.signatures.length, equals(1));

      final pdf.PdfSignatureValidationItem sig = report.signatures.single;
      expect(sig.chainTrusted, isTrue);
      expect(sig.validation.certsPem.length, greaterThanOrEqualTo(1));
      expect(sig.validation.policyOid, equals(expectedPolicyOid));
      expect(sig.policyStatus, isNotNull);
      expect(sig.policyStatus!.valid, isFalse);
      expect(sig.policyStatus!.error,
          contains('Policy digest does not match LPA'));

      expect(sig.timestampStatus, isNotNull);
      expect(sig.timestampStatus!.present, isFalse);
      expect(sig.timestampStatus!.valid, isFalse);
      expect(
        sig.issues.any(
          (i) => i.code == 'timestamp_missing' && i.severity.name == 'warning',
        ),
        isTrue,
      );

      expect(sig.docMdp.permissionP, equals(2));
      expect(sig.docMdp.isCertificationSignature, isTrue);

      final List<pdf.X509Certificate> certPool =
          pdf.OfflineCertificateChainBuilder.loadCertPoolFromDirectories(
        const <String>[
          'assets/truststore/icp_brasil',
          'assets/truststore/cadeia_icp_brasil',
          'assets/truststore/iti',
          'assets/truststore/serpro',
        ],
      );
      final List<pdf.X509Certificate> chain =
          pdf.OfflineCertificateChainBuilder.buildCompleteChain(
        signerCertsPem: sig.validation.certsPem,
        certPool: certPool,
      );
      expect(chain.length, greaterThanOrEqualTo(4));

      final DateTime signingTime = sig.validation.signingTime!.toUtc();
      for (final pdf.X509Certificate cert in chain) {
        final DateTime? notBefore = cert.c?.startDate?.toDateTime()?.toUtc();
        final DateTime? notAfter = cert.c?.endDate?.toDateTime()?.toUtc();
        if (notBefore != null) {
          expect(signingTime.isBefore(notBefore), isFalse,
              reason:
                  'Certificado na cadeia ainda não era válido no signingTime');
        }
        if (notAfter != null) {
          expect(signingTime.isAfter(notAfter), isFalse,
              reason: 'Certificado na cadeia estava expirado no signingTime');
        }
      }

      expect(sig.revocationStatus.isRevoked, isFalse);
      expect(sig.revocationStatus.status, equals('good'));
      expect(sig.revocationStatus.source, equals('none'));

      final String subject = sig.signerInfo?.subject ?? '';
      expect(subject.toUpperCase(), contains('UBIRATAN NUNES DA SILVA'));
      expect(subject.toUpperCase(), contains('ICP-BRASIL'));
      expect(sig.validation.signingTime, isNotNull);
    });
  });
}

class _Scenario {
  const _Scenario({
    required this.pdfBytes,
    required this.lpa,
  });

  final Uint8List pdfBytes;
  final Lpa? lpa;
}

Future<_Scenario> _loadScenario({
  required String expectedPolicyOid,
  required String expectedSha256,
}) async {
  final File? pdfFile = _resolveExistingFile(const <String>[
    'test/assets/documento assinado erro.pdf',
    'assets/documento assinado erro.pdf',
  ]);
  expect(pdfFile, isNotNull,
      reason: 'Missing test asset: test/assets/documento assinado erro.pdf');

  final Uint8List pdfBytes = Uint8List.fromList(pdfFile!.readAsBytesSync());
  final String sha256 = crypto.sha256
      .convert(pdfBytes)
      .bytes
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();
  expect(sha256, equals(expectedSha256));

  final File? policyConfigFile = _resolveExistingFile(const <String>[
    'assets/policy-engine-config-default.properties',
  ]);
  expect(policyConfigFile, isNotNull,
      reason:
          'Missing policy config: assets/policy-engine-config-default.properties');

  final Map<String, String> policyConfig =
      _parseProperties(policyConfigFile!.readAsStringSync());
  final String? cadesUrl =
      policyConfig['url_iti_lpa_cades'] ?? policyConfig['url_local_lpa_cades'];
  expect(cadesUrl, isNotNull,
      reason:
          'Expected url_iti_lpa_cades or url_local_lpa_cades in policy config');

  final String? cadesLpaFilename = _extractLpaFilenameFromUrl(cadesUrl!);
  expect(cadesLpaFilename, isNotNull,
      reason: 'Could not extract LPA filename from $cadesUrl');

  final File? cadesLpaFile = _resolveExistingFile(<String>[
    'assets/policy/engine/artifacts/${cadesLpaFilename!}',
  ]);
  expect(cadesLpaFile, isNotNull,
      reason:
          'Missing LPA artifact: assets/policy/engine/artifacts/$cadesLpaFilename');

  final Map<String, String> policyOidMap =
      await IcpBrasilPolicyOidMapBuilder.loadFromArtifactsDirectory(
    'assets/policy/engine/artifacts',
  );
  expect(policyOidMap[expectedPolicyOid], equals('PA_AD_RB_v2_3'));

  final Lpa? lpa = Lpa.fromBytes(cadesLpaFile!.readAsBytesSync());
  return _Scenario(pdfBytes: pdfBytes, lpa: lpa);
}

File? _resolveExistingFile(List<String> candidates) {
  final List<Directory> bases = <Directory>[];
  Directory cursor = Directory.current;
  for (int i = 0; i < 5; i++) {
    bases.add(cursor);
    final Directory parent = cursor.parent;
    if (parent.path == cursor.path) break;
    cursor = parent;
  }

  for (final String path in candidates) {
    final File file = File(path);
    if (file.existsSync()) return file;

    for (final Directory base in bases) {
      final File rooted = File('${base.path}/$path');
      if (rooted.existsSync()) return rooted;
    }
  }
  return null;
}

Map<String, String> _parseProperties(String content) {
  final Map<String, String> out = <String, String>{};
  for (final String rawLine in content.split(RegExp(r'\r?\n'))) {
    final String line = rawLine.trim();
    if (line.isEmpty || line.startsWith('#')) continue;

    final int idx = line.indexOf('=');
    if (idx <= 0) continue;

    final String key = line.substring(0, idx).trim();
    final String value = line
        .substring(idx + 1)
        .trim()
        .replaceAll(r'\:', ':')
        .replaceAll(r'\=', '=');
    if (key.isEmpty || value.isEmpty) continue;
    out[key] = value;
  }
  return out;
}

String? _extractLpaFilenameFromUrl(String value) {
  final RegExp exp =
      RegExp(r'(LPA_[A-Za-z]+\.(?:der|xml))', caseSensitive: false);
  final RegExpMatch? match = exp.firstMatch(value);
  return match?.group(1);
}
