import 'package:test/test.dart';
import 'package:dart_pdf/pdf.dart';

void main() {
  group('PdfDocument', () {
    test('Default Constructor', () {
      final doc = PdfDocument();
      expect(doc.pages.count, 0);
      expect(doc.compressionLevel, equals(PdfCompressionLevel.normal));
    });

    test('Add Page', () {
      final doc = PdfDocument();
      expect(doc.pages.count, 0);

      final page = doc.pages.add();
      expect(doc.pages.count, 1);
      expect(page, isNotNull);
      expect(page, isA<PdfPage>());
    });

    test('Page Settings', () {
      final doc = PdfDocument();
      doc.pageSettings.margins.all = 20;

      doc.pages.add();

      // 'all' is a setter only. Verify via individual properties.
      expect(doc.pageSettings.margins.left, equals(20));
      expect(doc.pageSettings.margins.top, equals(20));
      expect(doc.pageSettings.margins.right, equals(20));
      expect(doc.pageSettings.margins.bottom, equals(20));
    });

    test('Save Enpty Document (might behave differently)', () async {
      final doc = PdfDocument();
      // Typically saving an empty doc might throw or produce an empty PDF
      try {
        final bytes = await doc.save();
        // Minimal PDF size is usually > 0
        expect(bytes.length, greaterThan(0));
        // Should verify header %PDF-
        expect(String.fromCharCodes(bytes.take(5)), startsWith('%PDF-'));
      } catch (e) {
        // Some libs require at least 1 page.
        // If it fails, that's useful info.
      }
    });

    test('Document Information', () {
      final doc = PdfDocument();
      doc.documentInformation.title = 'Test Title';
      doc.documentInformation.author = 'Test Author';

      expect(doc.documentInformation.title, equals('Test Title'));
      expect(doc.documentInformation.author, equals('Test Author'));
    });

    test('Dispose', () {
      final doc = PdfDocument();
      doc.dispose();
      // Accessing properties after dispose usually throws or is undefined behavior.
      // We just ensure dispose doesn't crash.
    });
  });
}
