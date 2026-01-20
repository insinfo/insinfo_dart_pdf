import 'dart:io';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

void main() {
  test(
    'Load slow PDF and measure page count time',
    () {
      final file = File('test/assets/slow_pdf.pdf');
      if (!file.existsSync()) {
        fail('slow_pdf.pdf not found in test/assets. Please add it to run this performance test.');
      }
      final bytes = file.readAsBytesSync();

      final stopwatch = Stopwatch()..start();
      final doc = PdfDocument(inputBytes: bytes);
      // Ensure pages are counted (loading them)
      // ignore: unused_local_variable
      final pageCount = doc.pages.count;
      stopwatch.stop();


      // The user reported ~1 minute. We expect a significant improvement.
      // Let's set a generous threshold for now.
      expect(stopwatch.elapsed.inSeconds, lessThan(10),
          reason: 'PDF loading should be reasonably fast.');

      doc.dispose();
    },
    timeout: Timeout(Duration(minutes: 2)),
  );
}
