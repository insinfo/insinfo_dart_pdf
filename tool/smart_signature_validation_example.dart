import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';

void main(List<String> args) async {
  if (args.isEmpty) {
    stdout.writeln(
      'Usage: dart run tool/smart_signature_validation_example.dart <pdf-path> [extra-roots.pem|.crt|.cer|.der ...]',
    );
    exit(64);
  }

  final pdfPath = args.first;
  final extraRootPaths = args.sublist(1);

  final pdfFile = File(pdfPath);
  if (!pdfFile.existsSync()) {
    stderr.writeln('PDF not found: $pdfPath');
    exit(2);
  }

  final rootsPem = <String>[];

  final Directory truststoreDir = Directory('assets/truststore');
  if (!truststoreDir.existsSync()) {
    stderr.writeln('Truststore directory not found: ${truststoreDir.path}');
    exit(2);
  }

  final Iterable<FileSystemEntity> truststoreFiles =
      truststoreDir.listSync(recursive: true, followLinks: false);
  for (final entity in truststoreFiles) {
    if (entity is! File) continue;
    final String lowerPath = entity.path.toLowerCase();
    if (!(lowerPath.endsWith('.pem') ||
        lowerPath.endsWith('.crt') ||
        lowerPath.endsWith('.cer') ||
        lowerPath.endsWith('.der'))) {
      continue;
    }
    rootsPem.addAll(_extractCertificatesFromFile(entity));
  }

  for (final path in extraRootPaths) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Roots file not found: $path');
      exit(2);
    }
    rootsPem.addAll(_extractCertificatesFromFile(file));
  }

  final dedupedRootsPem = <String>{...rootsPem}.toList(growable: false);

  if (dedupedRootsPem.isEmpty) {
    stderr.writeln(
      'No certificates found in assets/truststore or provided extra roots files.',
    );
    exit(2);
  }

  final Uint8List pdfBytes = pdfFile.readAsBytesSync();
  final validator = PdfSignatureValidator();

  final index = buildTrustedRootsIndex(dedupedRootsPem);
  final preflight = await validator.preflightSignatures(pdfBytes);

  stdout.writeln('PDF: $pdfPath');
  stdout.writeln('Signatures found: ${preflight.signatures.length}');
  stdout.writeln('Truststore dir: ${truststoreDir.path}');
  stdout.writeln('Trusted roots indexed: ${index.allTrustedRootsPem.length}');
  stdout.writeln('');
  stdout.writeln('== Preflight ==');

  final autoCandidates = <String>{};
  for (int i = 0; i < preflight.signatures.length; i++) {
    final sig = preflight.signatures[i];
    final candidates = index.findCandidateTrustedRoots(
      authorityKeyIdentifier: sig.authorityKeyIdentifier,
      issuerDn: sig.issuerDn,
      serial: sig.serialDecimal,
    );
    autoCandidates.addAll(candidates);

    stdout.writeln('Signature #${i + 1}');
    stdout.writeln('  fieldName: ${sig.fieldName}');
    stdout.writeln('  serialDecimal: ${sig.serialDecimal ?? '-'}');
    stdout.writeln('  issuerDn: ${sig.issuerDn ?? '-'}');
    stdout.writeln(
        '  authorityKeyIdentifier: ${sig.authorityKeyIdentifier ?? '-'}');
    stdout
        .writeln('  subjectKeyIdentifier: ${sig.subjectKeyIdentifier ?? '-'}');
    stdout.writeln('  policyOid: ${sig.policyOid ?? '-'}');
    stdout.writeln(
        '  signingTime: ${sig.signingTime?.toUtc().toIso8601String() ?? '-'}');
    stdout.writeln('  candidateRootsMatched: ${candidates.length}');
  }

  final candidateRoots = autoCandidates.toList(growable: false);

  stdout.writeln('');
  stdout.writeln('== Validation ==');
  stdout.writeln('Candidate roots selected: ${candidateRoots.length}');

  final report = await validator.validateAllSignaturesWithCandidates(
    pdfBytes,
    candidateTrustedRootsPem: candidateRoots,
    fallbackToAllRoots: true,
    allTrustedRootsPem: index.allTrustedRootsPem,
    trustedRootsIndex: index,
  );

  for (int i = 0; i < report.signatures.length; i++) {
    final sig = report.signatures[i];
    final status = _status(sig);
    stdout.writeln('Signature #${i + 1} [$status]');
    stdout.writeln('  fieldName: ${sig.fieldName}');
    stdout.writeln('  cmsValid: ${sig.validation.cmsSignatureValid}');
    stdout.writeln('  digestValid: ${sig.validation.byteRangeDigestOk}');
    stdout.writeln('  intact: ${sig.validation.documentIntact}');
    stdout.writeln('  chainTrusted: ${sig.chainTrusted}');
    stdout.writeln('  signerSerialHex: ${sig.signerSerialHex ?? '-'}');
    stdout.writeln('  signerSerialDecimal: ${sig.signerSerialDecimal ?? '-'}');
    stdout.writeln('  issuerSerialHex: ${sig.issuerSerialHex ?? '-'}');
    stdout.writeln('  issuerSerialDecimal: ${sig.issuerSerialDecimal ?? '-'}');
    stdout.writeln('  policyOid: ${sig.validation.policyOid ?? '-'}');
    stdout.writeln(
        '  signingTime: ${sig.validation.signingTime?.toUtc().toIso8601String() ?? '-'}');
  }
}

String _status(PdfSignatureValidationItem item) {
  final bool ok = item.validation.cmsSignatureValid &&
      item.validation.byteRangeDigestOk &&
      item.validation.documentIntact &&
      (item.chainTrusted != false);
  if (ok) return 'APPROVED';
  if (!item.validation.documentIntact ||
      !item.validation.cmsSignatureValid ||
      !item.validation.byteRangeDigestOk) {
    return 'REJECTED';
  }
  return 'INDETERMINATE';
}

List<String> _extractPemCertificates(String content) {
  final regex = RegExp(
    r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----',
    multiLine: true,
  );
  return regex
      .allMatches(content)
      .map((m) => m.group(0)!)
      .toList(growable: false);
}

List<String> _extractCertificatesFromFile(File file) {
  final Uint8List bytes = file.readAsBytesSync();
  final String asText = String.fromCharCodes(bytes);
  final List<String> pemMatches = _extractPemCertificates(asText);
  if (pemMatches.isNotEmpty) {
    return pemMatches;
  }

  try {
    return <String>[X509Utils.derToPem(bytes)];
  } catch (_) {
    return const <String>[];
  }
}
