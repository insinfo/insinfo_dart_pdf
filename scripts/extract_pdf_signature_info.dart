import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:dart_pdf/pdf.dart';

Future<void> main(List<String> args) async {
  final String path = args.isNotEmpty
      ? args.first
      : 'test/assets/2 ass leonardo e mauricio.pdf';

  final File file = File(path);
  if (!file.existsSync()) {
    stderr.writeln('File not found: $path');
    stderr.writeln(
        'Usage: dart run scripts/extract_pdf_signature_info.dart [pdf_path]');
    exitCode = 2;
    return;
  }

  final Uint8List bytes = file.readAsBytesSync();
  final String hashSha256 = _toHex(crypto.sha256.convert(bytes).bytes);

  final Map<String, String> policyXmlByOid = _loadPolicyXmlByOid();
  final Map<String, String> policyNameByOid = _loadPolicyNameByOid();

  final PdfSignatureValidator validator = PdfSignatureValidator();
  final PdfSignatureValidationReport report =
      await validator.validateAllSignatures(
    bytes,
    fetchCrls: false,
    strictRevocation: false,
    useEmbeddedIcpBrasil: true,
    policyXmlByOid: policyXmlByOid,
  );

  final List<Map<String, dynamic>> signatures =
      report.signatures.map((PdfSignatureValidationItem item) {
    final PdfSignerInfo? signer =
        PdfSignerInfo.fromCertificatesPem(item.validation.certsPem);
    final String? oid = item.validation.policyOid;
    final String? policyName =
        oid == null ? null : (policyNameByOid[oid] ?? oid);
    final PdfDocMdpInfo? docMdp = item.docMdp;

    return <String, dynamic>{
      'field_name': item.fieldName,
      'signed_by': signer?.commonName,
      'cpf': signer?.cpf,
      'subject': signer?.subject,
      'issuer': signer?.issuer,
      'issuer_common_name': signer?.issuerCommonName,
      'certificate_serial_hex': signer?.serialNumberHex,
      'certificate_serial_decimal': signer?.serialNumberDecimal,
      'certificate_not_before': signer?.certNotBefore?.toIso8601String(),
      'certificate_not_after': signer?.certNotAfter?.toIso8601String(),
      'signing_time': item.validation.signingTime?.toIso8601String(),
      'policy_oid': oid,
      'policy_name': policyName,
      'policy_present': item.validation.policyPresent,
      'policy_valid': item.policyStatus?.valid,
      'policy_error': item.policyStatus?.error,
      'policy_warning': item.policyStatus?.warning,
      'policy_digest_ok': item.validation.policyDigestOk,
      'document_intact': item.validation.documentIntact,
      'cms_signature_valid': item.validation.cmsSignatureValid,
      'byte_range_digest_ok': item.validation.byteRangeDigestOk,
      'chain_trusted': item.chainTrusted,
      'doc_mdp_is_certification': docMdp?.isCertificationSignature,
      'doc_mdp_permission_p': docMdp?.permissionP,
      'doc_mdp_permissions_text': _formatDocMdpPermissions(docMdp),
      'timestamp_present': item.timestampStatus?.present,
      'timestamp_valid': item.timestampStatus?.valid,
      'issues': item.issues.map((i) => i.toMap()).toList(growable: false),
    };
  }).toList(growable: false);

  final int validSignatures = report.signatures.where((item) {
    final bool integrityOk = item.validation.documentIntact &&
        item.validation.cmsSignatureValid &&
        item.validation.byteRangeDigestOk;
    final bool policyOk = item.policyStatus?.valid ?? true;
    return integrityOk && policyOk;
  }).length;

  final Map<String, dynamic> output = <String, dynamic>{
    'file_name': file.uri.pathSegments.last,
    'file_path': file.path,
    'hash_sha256': hashSha256,
    'validation_time': DateTime.now().toIso8601String(),
    'total_signatures': report.signatures.length,
    'valid_signatures': validSignatures,
    'document_intact': report.allDocumentsIntact,
    'signatures': signatures,
  };

  final JsonEncoder encoder = const JsonEncoder.withIndent('  ');
  stdout.writeln(encoder.convert(output));
}

String _toHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

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

Map<String, String> _loadPolicyNameByOid() {
  final Directory artifactsDir = Directory('assets/policy/engine/artifacts');
  if (!artifactsDir.existsSync()) return <String, String>{};

  final RegExp oidRe = RegExp(r'urn:oid:([0-9.]+)');
  final Map<String, String> out = <String, String>{};
  for (final FileSystemEntity e in artifactsDir.listSync()) {
    if (e is! File) continue;
    if (!e.path.toLowerCase().endsWith('.xml')) continue;
    try {
      final String xml = e.readAsStringSync();
      final Match? match = oidRe.firstMatch(xml);
      final String? oid = match?.group(1);
      if (oid == null || oid.isEmpty) continue;
      final String name = _basenameWithoutExtension(e.path);
      out[oid] = name;
    } catch (_) {
      // ignore
    }
  }
  return out;
}

String _basenameWithoutExtension(String path) {
  final String name = path.split(Platform.pathSeparator).last;
  final int dot = name.lastIndexOf('.');
  if (dot <= 0) return name;
  return name.substring(0, dot);
}

String _formatDocMdpPermissions(PdfDocMdpInfo? docMdp) {
  if (docMdp == null || docMdp.isCertificationSignature != true) {
    return 'Não informado';
  }
  switch (docMdp.permissionP) {
    case 1:
      return 'Nenhuma alteração permitida';
    case 2:
      return 'Formulários e assinaturas';
    case 3:
      return 'Anotações, formulários e assinaturas';
    default:
      return 'Desconhecido';
  }
}
