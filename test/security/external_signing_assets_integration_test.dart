import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

void main() {
  group('PdfExternalSigning - assets integration', () {
    test('Parsers behave correctly across all PDFs in test/assets', () {
      final assetsDir = Directory('test/assets');
      expect(assetsDir.existsSync(), isTrue);

      final pdfFiles = assetsDir
          .listSync(recursive: true)
          .whereType<File>()
          .where((f) => f.path.toLowerCase().endsWith('.pdf'))
          .toList();

      expect(pdfFiles, isNotEmpty);

      // Force hybrid strategy (FastBytes -> StringSearch -> InternalDoc).
      PdfExternalSigning.useInternalByteRangeParser = false;
      PdfExternalSigning.useInternalContentsParser = false;
      PdfExternalSigning.useFastByteRangeParser = true;
      PdfExternalSigning.useFastContentsParser = true;

      const byteRangeToken = <int>[
        0x2F, // /
        0x42, 0x79, 0x74, 0x65, // Byte
        0x52, 0x61, 0x6E, 0x67, 0x65, // Range
      ];

      for (final file in pdfFiles) {
        final Uint8List bytes = Uint8List.fromList(file.readAsBytesSync());
        final bool containsByteRange = _containsSequence(bytes, byteRangeToken);

        if (containsByteRange) {
          // Expected: should parse without throwing.
          final range = PdfExternalSigning.extractByteRange(bytes);
          expect(range.length, equals(4), reason: 'Invalid ByteRange length for ${file.path}');

          final contents = PdfExternalSigning.findContentsRange(bytes);
          expect(contents.start, lessThan(contents.end),
              reason: 'Invalid /Contents range for ${file.path}');
        } else {
          // Expected: should throw a clear error, not hang or mis-detect.
          expect(
            () => PdfExternalSigning.extractByteRange(bytes),
            throwsA(
              predicate(
                (e) => e is StateError && e.message == 'ByteRange not found',
              ),
            ),
            reason: 'Expected ByteRange not found for ${file.path}',
          );
        }
      }
    });
  });
}

bool _containsSequence(Uint8List bytes, List<int> pattern) {
  if (pattern.isEmpty) return true;
  final int max = bytes.length - pattern.length;
  for (int i = 0; i <= max; i++) {
    bool ok = true;
    for (int j = 0; j < pattern.length; j++) {
      if (bytes[i + j] != pattern[j]) {
        ok = false;
        break;
      }
    }
    if (ok) return true;
  }
  return false;
}
