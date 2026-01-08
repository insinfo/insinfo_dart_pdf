import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/icp_brasil/etsi_policy.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/pdf_signature_validator.dart';

class CandidatePdf {
  CandidatePdf({
    required this.sourcePath,
    required this.fieldName,
    required this.policyOid,
    required this.size,
    required this.signatureCount,
    required this.timestampPresent,
  });

  final String sourcePath;
  final String fieldName;
  final String policyOid;
  final int size;
  final int signatureCount;
  final bool timestampPresent;
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
      if (oid != null && oid.isNotEmpty) {
        out[oid] = xml;
      }
    } catch (_) {
      // ignore
    }
  }
  return out;
}

Future<List<CandidatePdf>> _findCandidatesInFolder({
  required Directory folder,
  required Map<String, String> policyXmlByOid,
  required String mode,
  bool recursive = false,
  int minSignatures = 1,
  int limitScanned = 400,
  int? maxCandidates,
}) async {
  if (!folder.existsSync()) return <CandidatePdf>[];

  final List<File> pdfs = folder
      .listSync(recursive: recursive)
      .whereType<File>()
      .where((f) => f.path.toLowerCase().endsWith('.pdf'))
      .toList(growable: false);

  pdfs.sort((a, b) => a.statSync().size.compareTo(b.statSync().size));

  final PdfSignatureValidator validator = PdfSignatureValidator();
  final List<CandidatePdf> out = <CandidatePdf>[];

  int filesWithSignatures = 0;
  int sigsWithPolicyOid = 0;
  int sigsWithTimestamp = 0;
  int sigsMandatedTsMissing = 0;

  final Stopwatch sw = Stopwatch()..start();

  int scanned = 0;
  for (final File pdf in pdfs) {
    scanned++;
    if (scanned > limitScanned) break;
    if (maxCandidates != null && out.length >= maxCandidates) break;

    if (scanned % 500 == 0) {
      stdout.writeln(
        'Progress: scanned=$scanned/${limitScanned} candidates=${out.length} elapsed=${sw.elapsed.inSeconds}s',
      );
    }

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

    if (report.signatures.isNotEmpty) filesWithSignatures++;

    for (final PdfSignatureValidationItem sig in report.signatures) {
      if (maxCandidates != null && out.length >= maxCandidates) break;
      final String? policyOid = sig.validation.policyOid;
      final bool tsPresent = sig.timestampStatus?.present == true;
      if (tsPresent) sigsWithTimestamp++;

      if (policyOid != null) sigsWithPolicyOid++;

      final bool isIcp = policyOid != null && policyOid.startsWith('2.16.76.1.7.1.');

      if (mode == 'signed-any') {
        if (report.signatures.length < minSignatures) continue;
        out.add(
          CandidatePdf(
            sourcePath: pdf.path,
            fieldName: sig.fieldName,
            policyOid: policyOid ?? '',
            size: pdf.statSync().size,
            signatureCount: report.signatures.length,
            timestampPresent: tsPresent,
          ),
        );
        break;
      }

      if (mode == 'multi-sig') {
        if (report.signatures.length < minSignatures) continue;
        out.add(
          CandidatePdf(
            sourcePath: pdf.path,
            fieldName: sig.fieldName,
            policyOid: policyOid ?? '',
            size: pdf.statSync().size,
            signatureCount: report.signatures.length,
            timestampPresent: tsPresent,
          ),
        );
        break;
      }

      if (mode == 'policy-oid') {
        if (!isIcp) continue;
        out.add(
          CandidatePdf(
            sourcePath: pdf.path,
            fieldName: sig.fieldName,
            policyOid: policyOid,
            size: pdf.statSync().size,
            signatureCount: report.signatures.length,
            timestampPresent: tsPresent,
          ),
        );
        break;
      }

      // mode == policy-mandated-ts-missing
      if (!isIcp) continue;

      final String? xml = policyXmlByOid[policyOid];
      if (xml == null || xml.trim().isEmpty) continue;

      EtsiPolicyConstraints constraints;
      try {
        constraints = EtsiPolicyConstraints.parseXml(xml);
      } catch (_) {
        continue;
      }

      // We want a PDF where the policy mandates SignatureTimeStamp but the PDF
      // doesn't actually contain an RFC3161 timestamp.
      if (!constraints.requiresSignatureTimeStamp) continue;
      if (sig.timestampStatus?.present != false) continue;

      sigsMandatedTsMissing++;

      out.add(
        CandidatePdf(
          sourcePath: pdf.path,
          fieldName: sig.fieldName,
          policyOid: policyOid,
          size: pdf.statSync().size,
          signatureCount: report.signatures.length,
          timestampPresent: tsPresent,
        ),
      );

      // One candidate per PDF is enough.
      break;
    }
  }

  stdout.writeln(
    'Scan stats: scanned=$scanned, filesWithSignatures=$filesWithSignatures, '
    'sigsWithPolicyOid=$sigsWithPolicyOid, sigsWithTimestamp=$sigsWithTimestamp, '
    'sigsMandatedTsMissing=$sigsMandatedTsMissing',
  );

  return out;
}

Future<void> main(List<String> args) async {
  String sourceDirPath = 'test/assets';
  String targetDirPath = 'test/assets';
  bool dryRun = false;
  bool recursive = false;

  // Usage:
  //   dart run scripts/curate_policy_timestamp_test_pdfs.dart [flags] [mode] [maxCopy] [minSignatures]
  // Flags:
  //   --source PATH
  //   --target PATH
  //   --dryRun
  //   --recursive
  //   --limitScanned N
  //   --minSignatures N
  // Modes:
  //   - policy-mandated-ts-missing (default)
  //   - policy-oid
  //   - signed-any
  //   - multi-sig

  // First pass: extract flags that affect directories/flow; leave the rest to the existing parser.
  final List<String> argsWithoutDirFlags = <String>[];
  for (int i = 0; i < args.length; i++) {
    final String a = args[i];
    if (a == '--dryRun') {
      dryRun = true;
      continue;
    }
    if (a == '--recursive') {
      recursive = true;
      continue;
    }
    if (a.startsWith('--source=')) {
      sourceDirPath = a.substring('--source='.length);
      continue;
    }
    if (a == '--source' && i + 1 < args.length) {
      sourceDirPath = args[i + 1];
      i++;
      continue;
    }
    if (a.startsWith('--target=')) {
      targetDirPath = a.substring('--target='.length);
      continue;
    }
    if (a == '--target' && i + 1 < args.length) {
      targetDirPath = args[i + 1];
      i++;
      continue;
    }
    argsWithoutDirFlags.add(a);
  }

  final Directory sourceDir = Directory(sourceDirPath);
  final Directory targetDir = Directory(targetDirPath);

  if (!dryRun && !targetDir.existsSync()) {
    stderr.writeln('Target directory not found: ${targetDir.path}');
    exitCode = 2;
    return;
  }

  if (!sourceDir.existsSync()) {
    stderr.writeln('Source directory not found: ${sourceDir.path}');
    stderr.writeln('Nothing to do.');
    return;
  }

  int? limitScanned;
  int? minSignaturesFlag;
  final List<String> positional = <String>[];
  for (int i = 0; i < argsWithoutDirFlags.length; i++) {
    final String a = argsWithoutDirFlags[i];
    if (a.startsWith('--limitScanned=')) {
      limitScanned = int.tryParse(a.substring('--limitScanned='.length));
      continue;
    }
    if (a == '--limitScanned' && i + 1 < argsWithoutDirFlags.length) {
      limitScanned = int.tryParse(argsWithoutDirFlags[i + 1]);
      i++;
      continue;
    }
    if (a.startsWith('--minSignatures=')) {
      minSignaturesFlag = int.tryParse(a.substring('--minSignatures='.length));
      continue;
    }
    if (a == '--minSignatures' && i + 1 < argsWithoutDirFlags.length) {
      minSignaturesFlag = int.tryParse(argsWithoutDirFlags[i + 1]);
      i++;
      continue;
    }
    positional.add(a);
  }

  final String mode = positional.isNotEmpty ? positional.first : 'policy-mandated-ts-missing';
  final int maxCopy = positional.length >= 2 ? int.tryParse(positional[1]) ?? 3 : 3;
  final int minSignatures =
      minSignaturesFlag ?? (positional.length >= 3 ? int.tryParse(positional[2]) ?? 2 : 2);
  final int effectiveLimitScanned = limitScanned ?? 400;

  stdout.writeln('Loading policy XML artifacts...');
  final Map<String, String> policyXmlByOid = _loadPolicyXmlByOid();
  if (policyXmlByOid.isEmpty) {
    stderr.writeln('No policy XML loaded from assets/policy/engine/artifacts.');
    exitCode = 3;
    return;
  }

  stdout.writeln(
    'Scanning ${sourceDir.path} for candidate PDFs '
    '(mode=$mode, limitScanned=$effectiveLimitScanned, recursive=$recursive, dryRun=$dryRun)...',
  );
  final List<CandidatePdf> candidates = await _findCandidatesInFolder(
    folder: sourceDir,
    policyXmlByOid: policyXmlByOid,
    mode: mode,
    recursive: recursive,
    minSignatures: minSignatures,
    limitScanned: effectiveLimitScanned,
    maxCandidates: dryRun ? null : maxCopy,
  );

  if (candidates.isEmpty) {
    stdout.writeln('No suitable PDFs found in ${sourceDir.path}.');
    return;
  }

  if (dryRun) {
    stdout.writeln('Dry run: found ${candidates.length} candidate(s).');
    return;
  }

  candidates.sort((a, b) => a.size.compareTo(b.size));

  int copied = 0;
  for (final CandidatePdf c in candidates) {
    if (copied >= maxCopy) break;

    final String safeMode = mode.replaceAll(RegExp(r'[^a-zA-Z0-9_-]'), '_');
    final String safeOid =
      c.policyOid.isEmpty ? 'no_policy' : c.policyOid.replaceAll('.', '_');
    final String ts = c.timestampPresent ? 'ts' : 'no_ts';
    final String baseName =
      'curated_${safeMode}_${safeOid}_${ts}_${c.signatureCount}sig_${copied + 1}.pdf';
    final String destPath = '${targetDir.path}${Platform.pathSeparator}$baseName';

    if (File(destPath).existsSync()) {
      stdout.writeln('Already exists, skipping: $destPath');
      copied++;
      continue;
    }

    try {
      File(c.sourcePath).copySync(destPath);
      stdout.writeln('Copied: ${c.sourcePath} -> $destPath');
      stdout.writeln(
        '  policyOid=${c.policyOid.isEmpty ? '(none)' : c.policyOid} '
        'field=${c.fieldName} sigs=${c.signatureCount} tsPresent=${c.timestampPresent} size=${c.size}',
      );
      copied++;
    } catch (e) {
      stderr.writeln('Failed to copy ${c.sourcePath}: $e');
    }
  }

  stdout.writeln('Done. Copied $copied PDF(s) into ${targetDir.path}.');
}
