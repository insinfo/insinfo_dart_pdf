import 'package:test/test.dart';
import 'package:dart_pdf/pdf.dart';

void main() {
  group('PdfPage', () {
    test('Page Settings and Size', () {
      final doc = PdfDocument();
      // Default size usually Letter or A4 (595 x 842 for A4, 612 x 792 for Letter)
      // PdfPageSettings defaults to A4?
      final page = doc.pages.add();
      
      expect(page.size, isNotNull);
      expect(page.size.width, greaterThan(0));
      expect(page.size.height, greaterThan(0));
    });

    test('Rotation (New Page Default)', () {
      final doc = PdfDocument();
      final page = doc.pages.add();
      
      // Rotation property documented to work only on existing pages.
      // For new pages, it should remain default (0).
      page.rotation = PdfPageRotateAngle.rotateAngle90;
      expect(page.rotation, equals(PdfPageRotateAngle.rotateAngle0));
    });

    test('Graphics Context', () {
       final doc = PdfDocument();
       final page = doc.pages.add();
       
       expect(page.graphics, isNotNull);
       expect(page.layers.count, isNotNull);
    });

  });
}
