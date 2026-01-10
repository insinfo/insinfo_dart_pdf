import 'dart:io';

import 'dart:convert';

import 'package:dart_pdf/src/utils/pdf_percent_comments.dart';

void main(List<String> args) {
  if (args.isEmpty) {
    stderr.writeln('Usage: dart run scripts/inspect_pdf_percent_comments.dart <path-to-pdf>');
    exitCode = 64;
    return;
  }

  final pdfPath = args[0];
  final file = File(pdfPath);
  if (!file.existsSync()) {
    stderr.writeln('PDF not found: $pdfPath');
    exitCode = 66;
    return;
  }

  final bytes = file.readAsBytesSync();
  final results = extractPdfPercentCommentLines(bytes);

  stdout.writeln('PDF size: ${bytes.length} bytes');
  stdout.writeln("Found ${results.length} comment line(s) that start with '%'.");
  stdout.writeln('---');

  for (final r in results) {
    final ascii = r.toAsciiSafe();
    final hex = r.toHex(maxBytes: 80);
    stdout.writeln('@0x${r.offset.toRadixString(16)} len=${r.bytes.length} ascii="$ascii"');
    stdout.writeln('  hex=$hex');
  }

  stdout.writeln('---');
  final uniqueAscii = results.map((r) => r.toAsciiSafe()).toSet().toList()..sort();
  stdout.writeln('Unique (ASCII-sanitized) lines: ${uniqueAscii.length}');
  for (final line in uniqueAscii) {
    stdout.writeln(line);
  }

  // Try to decode likely-safe header lines for convenience.
  final headerCandidates = results
      .map((r) => latin1.decode(r.bytes, allowInvalid: true))
      .where((s) => s.startsWith('%PDF-') || s.startsWith('%%EOF'))
      .toList();
  if (headerCandidates.isNotEmpty) {
    stdout.writeln('---');
    stdout.writeln('Header/EOF decoded:');
    for (final s in headerCandidates) {
      stdout.writeln(s);
    }
  }
}
