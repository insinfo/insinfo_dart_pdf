import 'dart:convert';


import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

void main() {
  group('PdfGraphics Text Tests', () {
    test('Draw String with Standard Font', () async {
      final document = PdfDocument();
      final page = document.pages.add();
      final graphics = page.graphics;
      final font = PdfStandardFont(PdfFontFamily.helvetica, 12);
      
      // Basic draw
      graphics.drawString('Hello World', font,
          brush: PdfBrushes.black, bounds: Rect.fromLTWH(0, 0, 100, 20));

      final bytes = await document.save();
      expect(bytes, isNotEmpty);
      document.dispose();
    });

    test('Draw String with TrueType Font (Validate Embedding)', () async {
      // 1. Generate PDF with Standard Font (Not Embedded)
      int standardSize;
      {
        final document = PdfDocument();
        final page = document.pages.add();
        final graphics = page.graphics;
        final font = PdfStandardFont(PdfFontFamily.helvetica, 12);
        graphics.drawString('Hello TTF', font,
            brush: PdfBrushes.black, bounds: Rect.fromLTWH(0, 0, 100, 20));
        final bytes = await document.save();
        standardSize = bytes.length;
        document.dispose();
      }

      // 2. Generate PDF with TrueType Font (Embedded)
      int embeddedSize;
      List<int> embeddedBytes;
      
      // Minimal TrueType Font (Warsaw Bold ~1.8KB)
      const base64Font =
          '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';

      {
        final document = PdfDocument();
        final page = document.pages.add();
        final graphics = page.graphics;
        
        final fontData = base64Decode(base64Font);
        final font = PdfTrueTypeFont(fontData, 12);

        graphics.drawString('Hello TTF', font,
            brush: PdfBrushes.blue, bounds: Rect.fromLTWH(0, 0, 100, 20));

        embeddedBytes = await document.save();
        embeddedSize = embeddedBytes.length;
        document.dispose();
      }

      // Assert that the file with embedded font is significantly larger
      // The font is ~1.8KB, so we expect at least 1KB difference
      expect(embeddedSize, greaterThan(standardSize + 1000), 
          reason: 'PDF with embedded TrueType font should be larger than one with Standard Font');

      // 3. Validate correctness by loading it back
      {
        try {
          final loadedDoc = PdfDocument(inputBytes: embeddedBytes);
          expect(loadedDoc.pages.count, equals(1));
          loadedDoc.dispose();
        } catch (e) {
          fail('Failed to load generated PDF with embedded font: $e');
        }
      }
    });

    test('Draw String with Rotation', () async {
      final document = PdfDocument();
      final page = document.pages.add();
      final graphics = page.graphics;
      final font = PdfStandardFont(PdfFontFamily.timesRoman, 14);

      graphics.save();
      graphics.translateTransform(100, 100);
      graphics.rotateTransform(-45);
      graphics.drawString('Rotated Text', font,
          brush: PdfBrushes.red, bounds: Rect.fromLTWH(0, 0, 100, 20));
      graphics.restore();

      final bytes = await document.save();
      expect(bytes, isNotEmpty);
      document.dispose();
    });

    test('Draw String with Alignment', () async {
      final document = PdfDocument();
      final page = document.pages.add();
      final graphics = page.graphics;
      final font = PdfStandardFont(PdfFontFamily.courier, 12);
      
      final format = PdfStringFormat(alignment: PdfTextAlignment.center);

      graphics.drawString('Centered Text', font,
          brush: PdfBrushes.green, 
          bounds: Rect.fromLTWH(0, 0, page.getClientSize().width, 20),
          format: format);

      final bytes = await document.save();
      expect(bytes, isNotEmpty);
      document.dispose();
    });
  });
}
