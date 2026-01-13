import 'package:test/test.dart';
import 'package:dart_pdf/pdf.dart';

void main() {
  group('PdfRectangleAnnotation', () {
    test('Constructor and Properties', () {
      final rect = Rect.fromLTWH(10, 20, 100, 50);
      final color = PdfColor(255, 0, 0); // Red
      final innerColor = PdfColor(0, 255, 0); // Green
      
      final annotation = PdfRectangleAnnotation(
        rect, 
        'Test Rect',
        color: color,
        innerColor: innerColor,
        author: 'Tester',
        opacity: 0.5
      );
      
      expect(annotation.text, equals('Test Rect'));
      expect(annotation.bounds, equals(rect));
      expect(annotation.color.r, equals(255));
      expect(annotation.innerColor.g, equals(255));
      expect(annotation.author, equals('Tester'));
      // Expect opacity is close to 0.5 if exposed
    });

    // Test adding to page?
    test('Add to Page', () {
        final doc = PdfDocument();
        final page = doc.pages.add();
        final annotation = PdfRectangleAnnotation(
            Rect.fromLTWH(0, 0, 50, 50),
            'Annotation'
        );
        
        page.annotations.add(annotation);
        
        expect(page.annotations.count, equals(1));
        
        final retrieved = page.annotations[0];
        expect(retrieved, isA<PdfRectangleAnnotation>());
        expect((retrieved as PdfRectangleAnnotation).text, equals('Annotation'));
    });
  });
}
