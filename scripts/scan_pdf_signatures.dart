import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/pdf_signature_validator.dart';

Future<void> main(List<String> args) async {
  try {
    final String dirPath = args.isNotEmpty ? args.first : 'test/assets';
    final Directory dir = Directory(dirPath);
    if (!dir.existsSync()) {
      print('Directory not found: ${dir.path}');
      print('Usage: dart run scripts/scan_pdf_signatures.dart [directory]');
      return;
    }

    print('Scanning directory: ${dir.path} ...');

    final List<File> files = [];
    try {
      files.addAll(dir
          .listSync()
          .whereType<File>()
          .where((f) => f.path.toLowerCase().endsWith('.pdf'))
          .toList());
    } catch (e) {
      print('Error listing directory: $e');
      return;
    }

    print('Found ${files.length} PDF files.');

    final List<Map<String, dynamic>> results = [];
    int processedCount = 0;

    for (final File file in files) {
      processedCount++;
      if (processedCount % 10 == 0) {
        stdout.write('\rProcessing file $processedCount/${files.length}...');
      }

      try {
        final Uint8List bytes = file.readAsBytesSync();

        final PdfSignatureValidator validator = PdfSignatureValidator();

        // Validate signatures (fetchCrls: false for speed)
        final report = await validator.validateAllSignatures(
          bytes,
          fetchCrls: false,
        );

        final int count = report.signatures.length;
        if (count > 2) {
          results.add({
            'path': file.path,
            'filename': file.uri.pathSegments.last,
            'count': count,
          });
          // Optional: Print found candidate inline (commented out to reduce noise and confusion with sorting)
          // stdout.write('\nFound candidate: ${file.uri.pathSegments.last} ($count signatures)\n');
        }
      } catch (e) {
        // Suppress individual errors to avoid log spam, 
        // or print detailed log if needed.
        // print('\nError processing ${file.path}: $e');
      }
    }

    print('\nScanning complete. Found ${results.length} candidates.');

    // Sort by signature count descending
    results.sort((a, b) => (b['count'] as int).compareTo(a['count'] as int));

    // Take top 30
    final top30 = results.take(30).toList();

    print('\n--- Top 30 PDFs with > 2 Signatures ---');
    if (top30.isEmpty) {
      print('No PDF files found with more than 2 signatures.');
    } else {
      for (int i = 0; i < top30.length; i++) {
        final item = top30[i];
        print('${i + 1}. [${item['count']} signatures] ${item['filename']}');
      }
    }
  } catch (e, stack) {
    print('\nFatal error in script: $e');
    print(stack);
    exit(1);
  }
}
