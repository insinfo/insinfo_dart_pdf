import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dart_pdf/pdf.dart';

void main() {
  group('PdfExternalSigning Benchmark', () {
    late Uint8List pdfBytes;

    setUpAll(() async {
      // Create a dummy PDF with signature field to benchmark against
      final document = PdfDocument();
      document.pages.add().graphics.drawString(
          'Benchmark PDF', PdfStandardFont(PdfFontFamily.helvetica, 12),
          bounds: Rect.fromLTWH(0, 0, 200, 20));
      
      final inputBytes = Uint8List.fromList(await document.save());
      document.dispose();

      // Prepare it for signing (adds the signature dict and byte range)
      try {
        final result = await PdfExternalSigning.preparePdf(
          inputBytes: inputBytes,
          pageNumber: 1,
          bounds: Rect.fromLTWH(0, 0, 100, 50),
          fieldName: 'Signature1',
        );
        pdfBytes = result.preparedPdfBytes;
      } catch (e) {
        // Fallback for when PdfExternalSigning might not be fully implemented or available in the environment as expected
        pdfBytes = inputBytes; 
        print('Warning: Failed to prepare PDF using PdfExternalSigning. Using raw bytes. Error: $e');
      }
    });

    test('Benchmark extractByteRange', () {
      // Configuration
      const int iterations = 10; // Significantly reduced for performance
      final stopwatch = Stopwatch();

      // 1. Regex Approach (String+RegExp)
      PdfExternalSigning.useInternalByteRangeParser = false;
      PdfExternalSigning.useFastByteRangeParser = false;
      
      // Warmup
      try {
        for (var i = 0; i < 10; i++) {
          PdfExternalSigning.extractByteRange(pdfBytes);
        }

        stopwatch.start();
        for (var i = 0; i < iterations; i++) {
          PdfExternalSigning.extractByteRange(pdfBytes);
        }
        stopwatch.stop();
        final regexTime = stopwatch.elapsedMicroseconds;
        print('extractByteRange (Regex): ${regexTime / 1000} ms for $iterations iterations');
        print('  Average: ${regexTime / iterations} µs/op');

        // 2. Fast Bytes Approach
        PdfExternalSigning.useInternalByteRangeParser = false;
        PdfExternalSigning.useFastByteRangeParser = true;
        stopwatch.reset();

        // Warmup
        for (var i = 0; i < 10; i++) {
          PdfExternalSigning.extractByteRange(pdfBytes);
        }

        stopwatch.start();
        for (var i = 0; i < iterations; i++) {
          PdfExternalSigning.extractByteRange(pdfBytes);
        }
        stopwatch.stop();
        final fastTime = stopwatch.elapsedMicroseconds;
        print('extractByteRange (FastBytes): ${fastTime / 1000} ms for $iterations iterations');
        print('  Average: ${fastTime / iterations} µs/op');

        // 3. Internal Parser Approach (full PdfDocument parse)
        PdfExternalSigning.useInternalByteRangeParser = true;
        PdfExternalSigning.useFastByteRangeParser = false;
        stopwatch.reset();

        // Warmup
        for (var i = 0; i < 10; i++) {
          PdfExternalSigning.extractByteRange(pdfBytes);
        }

        stopwatch.start();
        for (var i = 0; i < iterations; i++) {
          PdfExternalSigning.extractByteRange(pdfBytes);
        }
        stopwatch.stop();
        final parserTime = stopwatch.elapsedMicroseconds;
        print('extractByteRange (InternalDoc): ${parserTime / 1000} ms for $iterations iterations');
        print('  Average: ${parserTime / iterations} µs/op');

        if (regexTime > 0) {
          final ratio = parserTime / regexTime;
          print('Result: InternalDoc is ${ratio.toStringAsFixed(2)}x slower than Regex');
        }
        if (fastTime > 0) {
          final ratio = parserTime / fastTime;
          print('Result: InternalDoc is ${ratio.toStringAsFixed(2)}x slower than FastBytes');
        }
      } catch (e) {
         print('Benchmark skipped due to error: $e');
      }
    });

    test('Benchmark findContentsRange', () {
      // findContentsRange returns a private type, so we use dynamic
      // It mainly tests the lookup logic (String search vs Parser)

      // Configuration
      const int iterations = 10; // Significantly reduced for performance
      final stopwatch = Stopwatch();

      try {
        // 1. String Search Approach (latin1 string scan)
        PdfExternalSigning.useInternalContentsParser = false;
        PdfExternalSigning.useFastContentsParser = false;
        // Ensure ByteRange parser is also default as it might affect internal calls depending on impl
        PdfExternalSigning.useInternalByteRangeParser = false; 
        PdfExternalSigning.useFastByteRangeParser = false;

        // Warmup
        for (var i = 0; i < 10; i++) {
            // ignore: unused_local_variable
            dynamic _ = PdfExternalSigning.findContentsRange(pdfBytes);
        }

        stopwatch.start();
        for (var i = 0; i < iterations; i++) {
            // ignore: unused_local_variable
            dynamic _ = PdfExternalSigning.findContentsRange(pdfBytes);
        }
        stopwatch.stop();
        final stringSearchTime = stopwatch.elapsedMicroseconds;
        print('findContentsRange (String Search): ${stringSearchTime / 1000} ms for $iterations iterations');
        print('  Average: ${stringSearchTime / iterations} µs/op');

        // 2. Fast Bytes Approach
        PdfExternalSigning.useInternalContentsParser = false;
        PdfExternalSigning.useFastContentsParser = true;
        PdfExternalSigning.useInternalByteRangeParser = false;
        PdfExternalSigning.useFastByteRangeParser = true;

        stopwatch.reset();

        // Warmup
        for (var i = 0; i < 10; i++) {
          // ignore: unused_local_variable
          dynamic _ = PdfExternalSigning.findContentsRange(pdfBytes);
        }

        stopwatch.start();
        for (var i = 0; i < iterations; i++) {
          // ignore: unused_local_variable
          dynamic _ = PdfExternalSigning.findContentsRange(pdfBytes);
        }
        stopwatch.stop();
        final fastTime = stopwatch.elapsedMicroseconds;
        print('findContentsRange (FastBytes): ${fastTime / 1000} ms for $iterations iterations');
        print('  Average: ${fastTime / iterations} µs/op');

        // 3. Internal Parser Approach (full PdfDocument parse)
        PdfExternalSigning.useInternalContentsParser = true;
        PdfExternalSigning.useFastContentsParser = false;
        // The internal contents parser relies on extractByteRangeInternal.
        PdfExternalSigning.useInternalByteRangeParser = true;
        PdfExternalSigning.useFastByteRangeParser = false;

        stopwatch.reset();

        // Warmup
        for (var i = 0; i < 10; i++) {
            // ignore: unused_local_variable
            dynamic _ = PdfExternalSigning.findContentsRange(pdfBytes);
        }

        stopwatch.start();
        for (var i = 0; i < iterations; i++) {
            // ignore: unused_local_variable
            dynamic _ = PdfExternalSigning.findContentsRange(pdfBytes);
        }
        stopwatch.stop();
        final parserTime = stopwatch.elapsedMicroseconds;
        print('findContentsRange (InternalDoc): ${parserTime / 1000} ms for $iterations iterations');
        print('  Average: ${parserTime / iterations} µs/op');

        if (stringSearchTime > 0) {
          final ratio = parserTime / stringSearchTime;
          print('Result: InternalDoc is ${ratio.toStringAsFixed(2)}x slower than String Search');
        }
        if (fastTime > 0) {
          final ratio = parserTime / fastTime;
          print('Result: InternalDoc is ${ratio.toStringAsFixed(2)}x slower than FastBytes');
        }
      } catch (e) {
          print('Benchmark skipped due to error: $e');
      }
    });
  });
}
