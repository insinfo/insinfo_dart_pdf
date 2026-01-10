import 'package:test/test.dart';
import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/graphics/pdf_color.dart';

void main() {
  group('PdfColor', () {
    test('Constructor RGB', () {
      final color = PdfColor(100, 150, 200);
      expect(color.r, equals(100));
      expect(color.g, equals(150));
      expect(color.b, equals(200));
      // alpha is stored in helper internally, let's see if there is a public getter?
      // Based on source, no public getter for 'a' or 'alpha'.
      // It seems alpha is only used for internal operations? 
      // Wait, let's check equality if it includes alpha.
    });

    test('Constructor RGBA', () {
      final color = PdfColor(10, 20, 30, 40);
      expect(color.r, equals(10));
      expect(color.g, equals(20));
      expect(color.b, equals(30));
    });

    test('Empty Constructor (Black)', () {
      // PdfColor() usually implies black or empty?
      // Wait, there is no empty constructor in the source I read earlier.
      // It has named constructors mostly.
      // Let's check if there is a default one. In source: PdfColor(int red, int green, int blue, [int alpha = 255])
      // So no PdfColor().
      
      final empty = PdfColor.empty;
      expect(empty.isEmpty, isTrue);
    });

    test('From CMYK', () {
       // c,m,y,k getters check
       final color = PdfColor.fromCMYK(0, 1, 0, 0); 
       // The library might not expose c, m, y, k directly.
       // It seems it calculates RGB from it.
       // Let's verify RGB for Magenta (0, 1, 0, 0)
       // R = 255 * (1-C) * (1-K) = 255 * 1 * 1 = 255
       // G = 255 * (1-M) * (1-K) = 255 * 0 * 1 = 0
       // B = 255 * (1-Y) * (1-K) = 255 * 1 * 1 = 255
       expect(color.r, equals(255));
       expect(color.g, equals(0));
       expect(color.b, equals(255));
    });

    // Check equality
    test('Equality', () {
      final c1 = PdfColor(1, 2, 3);
      final c2 = PdfColor(1, 2, 3);
      final c3 = PdfColor(0, 0, 0);
      
      expect(c1, equals(c2)); // Assuming operator== is overridden
      expect(c1, isNot(equals(c3)));
    });
  });
}
