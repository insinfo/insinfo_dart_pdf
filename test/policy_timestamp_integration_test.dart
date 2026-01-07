import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/icp_brasil/etsi_policy.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/pdf_signature_validator.dart';
import 'package:test/test.dart';

class _Candidate {
  const _Candidate({
    required this.pdfPath,
    required this.policyOid,
    required this.policyXml,
    required this.fieldName,
  });

  final String pdfPath;
  final String policyOid;
  final String policyXml;
  final String fieldName;
}

Map<String, String> _loadPolicyXmlByOid() {
  final Directory artifactsDir = Directory('assets/policy/engine/artifacts');
  if (!artifactsDir.existsSync()) return <String, String>{};

  final Map<String, String> out = <String, String>{};
  final List<FileSystemEntity> entities = artifactsDir.listSync();
  for (final FileSystemEntity e in entities) {
    if (e is! File) continue;
    if (!e.path.toLowerCase().endsWith('.xml')) continue;

    final String xml = e.readAsStringSync();
    try {
      final EtsiPolicyConstraints c = EtsiPolicyConstraints.parseXml(xml);
      final String? oid = c.policyOid;
      if (oid != null && oid.isNotEmpty) {
        out[oid] = xml;
      }
    } catch (_) {
      // Ignore parse failures for unknown/legacy XMLs.
    }
  }

  return out;
}

List<File> _listCandidatePdfs() {
  final Directory root = Directory('test/assets');
  if (!root.existsSync()) return <File>[];

  // 1) Prefer a curated list (fast + stable).
  final List<String> preferred = <String>[
    'test/assets/generated_policy_mandated_timestamp_missing.pdf',
    'test/assets/sample_govbr_signature_assinado.pdf',
    'test/assets/sample_token_icpbrasil_assinado.pdf',
    'test/assets/gov_assinado.pdf',
    'test/assets/govbr_alcirleia.pdf',
    'test/assets/serpro_Maurício_Soares_dos_Anjos.pdf',
    'test/assets/Relatorios_assinado.pdf',
    'test/assets/decisao-4874-assinada.pdf',
  ];

  final List<File> out = <File>[];
  for (final String path in preferred) {
    final File f = File(path);
    if (f.existsSync() && f.path.toLowerCase().endsWith('.pdf')) {
      out.add(f);
    }
  }

  // 2) Add remaining PDFs from test/assets (size-ascending, capped).
  final List<File> rootPdfs = root
      .listSync()
      .whereType<File>()
      .where((f) => f.path.toLowerCase().endsWith('.pdf'))
      .toList(growable: false);

  rootPdfs.sort((a, b) => a.statSync().size.compareTo(b.statSync().size));
  for (final File f in rootPdfs) {
    if (out.any((x) => x.path == f.path)) continue;
    out.add(f);
    if (out.length >= 25) break;
  }

  return out;
}

bool _hasIssue(
  PdfSignatureValidationItem sig, {
  required String code,
  required PdfIssueSeverity severity,
}) {
  return sig.issues.any((i) => i.code == code && i.severity == severity);
}

Future<_Candidate?> _findCandidate({
  required Map<String, String> policyXmlByOid,
}) async {
  final PdfSignatureValidator validator = PdfSignatureValidator();
  final List<File> pdfs = _listCandidatePdfs();

  for (final File pdf in pdfs) {
    Uint8List bytes;
    try {
      bytes = Uint8List.fromList(pdf.readAsBytesSync());
    } catch (_) {
      continue;
    }

    PdfSignatureValidationReport report;
    try {
      report = await validator.validateAllSignatures(
        bytes,
        fetchCrls: false,
        strictRevocation: false,
      );
    } catch (_) {
      continue;
    }

    for (final PdfSignatureValidationItem sig in report.signatures) {
      final String? policyOid = sig.validation.policyOid;
      if (policyOid == null) continue;
      if (!policyOid.startsWith('2.16.76.1.7.1.')) continue; // ICP-Brasil/Gov.br

      final String? xml = policyXmlByOid[policyOid];
      if (xml == null) continue;

      EtsiPolicyConstraints constraints;
      try {
        constraints = EtsiPolicyConstraints.parseXml(xml);
      } catch (_) {
        continue;
      }

      if (!constraints.requiresSignatureTimeStamp) continue;
      if (sig.timestampStatus?.present != false) continue;

      // Candidate found: policy mandates SignatureTimeStamp but PDF has none.
      return _Candidate(
        pdfPath: pdf.path,
        policyOid: policyOid,
        policyXml: xml,
        fieldName: sig.fieldName,
      );
    }
  }

  return null;
}

void main() {
  group('Integration: policy-mandated timestamp enforcement', () {
    test('timestamp_missing flips warning -> error with policyXmlByOid',
        () async {
      final Map<String, String> policyXmlByOid = _loadPolicyXmlByOid();
      expect(policyXmlByOid.isNotEmpty, isTrue,
          reason:
              'Policy artifacts not found/loaded (assets/policy/engine/artifacts/*.xml)');

      final _Candidate? candidate =
          await _findCandidate(policyXmlByOid: policyXmlByOid);

      expect(
        candidate,
        isNotNull,
        reason:
            'No PDF found under test/assets with ICP policy that mandates SignatureTimeStamp but has no timestamp. '
            'Regenerate via scripts/generate_policy_mandated_timestamp_missing_pdf.dart if needed.',
      );

      final _Candidate candidateNonNull = candidate!;

      final Uint8List bytes =
          Uint8List.fromList(File(candidateNonNull.pdfPath).readAsBytesSync());

      final PdfSignatureValidator validator = PdfSignatureValidator();

      // 1) Default behavior (no policy XML): ICP policy missing timestamp is warning.
      final PdfSignatureValidationReport reportNoXml =
          await validator.validateAllSignatures(
        bytes,
        fetchCrls: false,
        strictRevocation: false,
      );

      final PdfSignatureValidationItem? sigNoXml = reportNoXml.signatures
          .where((s) => s.fieldName == candidateNonNull.fieldName)
          .cast<PdfSignatureValidationItem?>()
          .fold<PdfSignatureValidationItem?>(
            null,
            (prev, cur) => prev ?? cur,
          );

      expect(sigNoXml, isNotNull,
          reason:
              'Expected to find the same signature field (${candidateNonNull.fieldName})');

      if (sigNoXml!.timestampStatus?.present == false) {
        expect(
          _hasIssue(
            sigNoXml,
            code: 'timestamp_missing',
            severity: PdfIssueSeverity.warning,
          ),
          isTrue,
          reason:
              'Without policyXmlByOid, ICP missing timestamp should be warning',
        );
      }

      // 2) With policyXmlByOid requiring SignatureTimeStamp: missing timestamp is error.
      final PdfSignatureValidationReport reportWithXml =
          await validator.validateAllSignatures(
        bytes,
        fetchCrls: false,
        strictRevocation: false,
        policyXmlByOid: <String, String>{
          candidateNonNull.policyOid: candidateNonNull.policyXml,
        },
      );

      final PdfSignatureValidationItem? sigWithXml = reportWithXml.signatures
          .where((s) => s.fieldName == candidateNonNull.fieldName)
          .cast<PdfSignatureValidationItem?>()
          .fold<PdfSignatureValidationItem?>(
            null,
            (prev, cur) => prev ?? cur,
          );

      expect(sigWithXml, isNotNull,
          reason:
              'Expected to find the same signature field (${candidateNonNull.fieldName})');

      expect(sigWithXml!.timestampStatus?.present, isFalse,
          reason:
              'This integration test requires a PDF without RFC3161 timestamp');

      expect(
        _hasIssue(
          sigWithXml,
          code: 'timestamp_missing',
          severity: PdfIssueSeverity.error,
        ),
        isTrue,
        reason:
            'With policyXmlByOid mandating SignatureTimeStamp, timestamp_missing must be error',
      );
    });
  });
}
