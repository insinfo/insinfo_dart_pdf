import 'package:test/test.dart';
import 'package:dart_pdf/pdf.dart';


void main() {
  group('PdfGraphics', () {
    test('Initialization via Page', () {
      final doc = PdfDocument();
      final page = doc.pages.add();
      final graphics = page.graphics;
      
      expect(graphics, isNotNull);
      expect(graphics.clientSize.width, greaterThan(0));
    });

    test('Save and Restore State', () {
       final doc = PdfDocument();
       final page = doc.pages.add();
       final graphics = page.graphics;
       
       graphics.save();
       // Perform operations
       graphics.restore();
       
       // Verification is tricky without mocking the stream or parsing the output.
       // But we ensure it triggers without error.
    });

    test('Draw Rectangle', () {
        final doc = PdfDocument();
        final page = doc.pages.add();
        final graphics = page.graphics;
        
        graphics.drawRectangle(
            pen: PdfPen(PdfColor(255, 0, 0)),
            bounds: Rect.fromLTWH(10, 10, 100, 50)
        );
        
        // At this level we trust it writes to stream.
        // Deep verification requires parsing the content stream.
    });
    
    test('Set Color Space', () {
         final doc = PdfDocument();
         final page = doc.pages.add();
         final graphics = page.graphics;
         
         graphics.colorSpace = PdfColorSpace.grayScale;
         expect(graphics.colorSpace, equals(PdfColorSpace.grayScale));
    });

  });
}
