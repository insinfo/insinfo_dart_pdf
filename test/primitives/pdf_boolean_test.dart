import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_boolean.dart';
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
  group('PdfBoolean', () {
    test('Default constructor', () {
      final b = PdfBoolean();
      expect(b.value, isFalse);
    });

    test('Constructor with value', () {
      final t = PdfBoolean(true);
      expect(t.value, isTrue);

      final f = PdfBoolean(false);
      expect(f.value, isFalse);
    });

    test('save writes true', () {
      final b = PdfBoolean(true);
      final writer = MockPdfWriter();
      b.save(writer);
      expect(writer.buffer.toString(), 'true');
    });

    test('save writes false', () {
      final b = PdfBoolean(false);
      final writer = MockPdfWriter();
      b.save(writer);
      expect(writer.buffer.toString(), 'false');
    });
  });
}
