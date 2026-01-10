import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_null.dart';
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
  group('PdfNull', () {
    test('Constructor', () {
      final n = PdfNull();
      expect(n, isNotNull);
    });

    test('save writes null', () {
      final n = PdfNull();
      final writer = MockPdfWriter();
      n.save(writer);
      expect(writer.buffer.toString(), 'null');
    });
  });
}
