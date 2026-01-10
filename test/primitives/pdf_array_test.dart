import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_array.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_number.dart';
import 'package:dart_pdf/src/pdf/implementation/drawing/drawing.dart';

void main() {
  group('PdfArray', () {
    test('Constructor with number list', () {
      final array = PdfArray([1, 2, 3]);
      expect(array.count, 3);
      expect((array[0] as PdfNumber).value, 1);
      expect((array[1] as PdfNumber).value, 2);
      expect((array[2] as PdfNumber).value, 3);
    });

    test('add adds element', () {
      final array = PdfArray();
      final num = PdfNumber(10);
      array.add(num);
      expect(array.count, 1);
      expect(array[0], equals(num));
    });

    test('contains returns true if present', () {
      final array = PdfArray();
      final num = PdfNumber(10);
      array.add(num);
      expect(array.contains(num), isTrue);
      expect(array.contains(PdfNumber(10)), isFalse); // different instance
    });

    test('insert inserts element', () {
      final array = PdfArray([1, 3]);
      array.insert(1, PdfNumber(2));
      expect(array.count, 3);
      expect((array[0] as PdfNumber).value, 1);
      expect((array[1] as PdfNumber).value, 2);
      expect((array[2] as PdfNumber).value, 3);
    });

    test('clear removes all elements', () {
      final array = PdfArray([1, 2]);
      array.clear();
      expect(array.count, 0);
    });

    test('fromRectangle', () {
      final rect = PdfRectangle(10, 20, 100, 200);
      final array = PdfArray.fromRectangle(rect);
      expect(array.count, 4);
      expect((array[0] as PdfNumber).value, 10); // left
      expect((array[1] as PdfNumber).value, 20); // top
      expect((array[2] as PdfNumber).value, 110); // right
      expect((array[3] as PdfNumber).value, 220); // bottom
    });
  });
}
