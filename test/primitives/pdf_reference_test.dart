import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_reference.dart';
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
  group('PdfReference', () {
    test('Constructor', () {
      final ref = PdfReference(10, 0);
      expect(ref.objNum, 10);
      expect(ref.genNum, 0);
    });

    test('toString', () {
      final ref = PdfReference(10, 0);
      expect(ref.toString(), '10 0 R');
    });

    test('save', () {
      final ref = PdfReference(5, 2);
      final writer = MockPdfWriter();
      ref.save(writer);
      expect(writer.buffer.toString(), '5 2 R');
    });
  });
}
