import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/icp_brasil/etsi_policy.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/pdf_signature_validator.dart';

void main(List<String> args) async {
  final String path = args.isNotEmpty
      ? args.first
      : 'test/assets/generated_policy_mandated_timestamp_missing.pdf';

  final File f = File(path);
  if (!f.existsSync()) {
    stderr.writeln('File not found: $path');
    exitCode = 2;
    return;
  }

  final Map<String, String> policyXmlByOid = _loadPolicyXmlByOid();

  final Uint8List bytes = Uint8List.fromList(f.readAsBytesSync());
  final PdfSignatureValidator validator = PdfSignatureValidator();
  final PdfSignatureValidationReport report = await validator.validateAllSignatures(
    bytes,
    fetchCrls: false,
    strictRevocation: false,
  );

  stdout.writeln('PDF: $path');
  stdout.writeln('Signatures: ${report.signatures.length}');
  for (final PdfSignatureValidationItem sig in report.signatures) {
    final String? oid = sig.validation.policyOid;
    stdout.writeln('--- field=${sig.fieldName}');
    stdout.writeln('policyOid=$oid');
    stdout.writeln('timestamp.present=${sig.timestampStatus?.present} valid=${sig.timestampStatus?.valid}');
    if (oid != null && policyXmlByOid.containsKey(oid)) {
      try {
        final EtsiPolicyConstraints c = EtsiPolicyConstraints.parseXml(policyXmlByOid[oid]!);
        stdout.writeln('policy.requiresSignatureTimeStamp=${c.requiresSignatureTimeStamp}');
      } catch (e) {
        stdout.writeln('policy.parseError=$e');
      }
    } else {
      stdout.writeln('policy.xmlLoaded=${oid != null && policyXmlByOid.containsKey(oid)}');
    }

    final bool hasWarning = sig.issues.any((i) => i.code == 'timestamp_missing' && i.severity == PdfIssueSeverity.warning);
    final bool hasError = sig.issues.any((i) => i.code == 'timestamp_missing' && i.severity == PdfIssueSeverity.error);
    stdout.writeln('issue.timestamp_missing.warning=$hasWarning error=$hasError');
  }
}

Map<String, String> _loadPolicyXmlByOid() {
  final Directory artifactsDir = Directory('assets/policy/engine/artifacts');
  if (!artifactsDir.existsSync()) return <String, String>{};

  final Map<String, String> out = <String, String>{};
  for (final FileSystemEntity e in artifactsDir.listSync()) {
    if (e is! File) continue;
    if (!e.path.toLowerCase().endsWith('.xml')) continue;
    final String xml = e.readAsStringSync();
    try {
      final EtsiPolicyConstraints c = EtsiPolicyConstraints.parseXml(xml);
      final String? oid = c.policyOid;
      if (oid != null && oid.isNotEmpty) out[oid] = xml;
    } catch (_) {
      // ignore
    }
  }
  return out;
}
