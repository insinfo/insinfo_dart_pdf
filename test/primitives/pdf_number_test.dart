import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_number.dart';
import 'package:dart_pdf/src/pdf/interfaces/pdf_interface.dart';
import 'package:dart_pdf/src/pdf/implementation/pdf_document/pdf_document.dart';

class MockPdfWriter implements IPdfWriter {
  StringBuffer buffer = StringBuffer();

  @override
  PdfDocument? document;

  @override
  int? length;

  @override
  int? position;

  @override
  void write(dynamic pdfObject) {
    buffer.write(pdfObject);
  }
}

void main() {
  group('PdfNumber', () {
    test('Integer value', () {
      final num = PdfNumber(42);
      expect(num.value, 42);
    });

    test('Double value', () {
      final num = PdfNumber(3.14);
      expect(num.value, 3.14);
    });

    test('NaN throws ArgumentError', () {
      expect(() => PdfNumber(double.nan), throwsArgumentError);
    });

    group('save', () {
      test('Writes integer as string', () {
        final num = PdfNumber(42);
        final writer = MockPdfWriter();
        num.save(writer);
        expect(writer.buffer.toString(), '42');
      });

      test('Writes double with basic formatting', () {
        final num = PdfNumber(3.14);
        final writer = MockPdfWriter();
        num.save(writer);
        expect(writer.buffer.toString(), '3.14');
      });

      test('Writes double and removes trailing zeros', () {
        final num = PdfNumber(3.500);
        final writer = MockPdfWriter();
        num.save(writer);
        expect(writer.buffer.toString(), '3.5');
      });

      test('Writes integer-like double without decimal point', () {
        final num = PdfNumber(42.0);
        final writer = MockPdfWriter();
        num.save(writer);
        expect(writer.buffer.toString(), '42');
      });
      
      test('Writes max precision double', () {
         // toStringAsFixed(10)
        final num = PdfNumber(0.1234567891);
        final writer = MockPdfWriter();
        num.save(writer);
        expect(writer.buffer.toString(), '0.1234567891');
      });

       test('Truncates precision beyond 10 digits', () {
         // toStringAsFixed(10)
        final num = PdfNumber(0.12345678901);
        final writer = MockPdfWriter();
        num.save(writer);
        expect(writer.buffer.toString(), '0.123456789');
      });
    });
  });
}
