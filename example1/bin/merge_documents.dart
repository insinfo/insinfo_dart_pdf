import 'dart:io';

import 'package:dart_pdf/pdf.dart';

/// Merges the PDF files given on the command line into `merged.pdf`.
///
/// ```
/// dart run bin/merge_documents.dart first.pdf second.pdf third.pdf
/// ```
void main(List<String> args) {
  if (args.length < 2) {
    stderr.writeln('usage: merge_documents.dart <input.pdf> <input.pdf> ...');
    exitCode = 64;
    return;
  }

  simpleMerge(args);
  mergeWithReport(args);
}

/// The one-liner: bytes in, bytes out.
void simpleMerge(List<String> paths) {
  final List<int> merged = PdfDocument.mergeSync(<List<int>>[
    for (final String path in paths) File(path).readAsBytesSync(),
  ]);
  File('merged.pdf').writeAsBytesSync(merged);
  stdout.writeln('merged.pdf written (${merged.length} bytes)');
}

/// The same merge driven page by page, so the warnings can be inspected and
/// the outline grouped per source document.
void mergeWithReport(List<String> paths) {
  final PdfDocument output = PdfDocument();
  final PdfDocumentMerger merger = PdfDocumentMerger(
    output,
    options: PdfMergeOptions(
      groupBookmarksPerDocument: true,
      // Merging rewrites the whole file, so any signature the sources carry is
      // invalidated. By default the signature fields are dropped and their
      // visible mark is kept as a stamp, so the page still looks signed. Three
      // knobs change that:
      //   rejectSignedSources: true       -> refuse to merge signed documents
      //   keepInvalidSignatures: true     -> keep the certificates, invalid
      //   removeSignatureAppearance: true -> drop the visible mark too
    ),
  );

  for (final String path in paths) {
    final PdfDocument source = PdfDocument(
      inputBytes: File(path).readAsBytesSync(),
    );
    final List<PdfPage> pages = merger.append(source);
    stdout.writeln('$path -> ${pages.length} page(s)');
    source.dispose();
  }

  File('merged_report.pdf').writeAsBytesSync(output.saveSync());
  output.dispose();

  if (merger.warnings.isEmpty) {
    stdout.writeln('no warnings');
  } else {
    stdout.writeln('warnings:');
    for (final String warning in merger.warnings) {
      stdout.writeln('  - $warning');
    }
  }
}
