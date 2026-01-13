import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_cross_table.dart';
import 'package:dart_pdf/pdf.dart';

void main() {
  group('PdfCrossTable', () {
    test('Initialization with Document', () {
      final doc = PdfDocument();
      final table = PdfCrossTable(doc);
      
      expect(table.document, equals(doc));
    });

    test('Object Number Generation', () {
      final doc = PdfDocument();
      final table = PdfCrossTable(doc);
      
      // Initial count should be 0, next should be 1?
      // Source: if (count == 0) { count++; ...
      // But let's check via nextObjectNumber
      
      final num1 = table.nextObjectNumber;
      // It likely increments internal count.
      expect(num1, greaterThan(0));
      
      final num2 = table.nextObjectNumber;
      expect(num2, greaterThan(num1));
    });
  });
}
