import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_name.dart';

void main() {
  group('PdfName', () {
    test('Constructor and name property', () {
      final name = PdfName('TestName');
      expect(name.name, 'TestName');
    });

    test('toString adds forward slash', () {
      final name = PdfName('TestName');
      expect(name.toString(), '/TestName');
    });

    test('Equality', () {
      final name1 = PdfName('TestName');
      final name2 = PdfName('TestName');
      final name3 = PdfName('OtherName');

      expect(name1, equals(name2));
      expect(name1, isNot(equals(name3)));
    });

    test('Normalization with spaces', () {
      final name = PdfName('Test Name');
      expect(name.name, 'Test#20Name');
      expect(name.toString(), '/Test#20Name');
    });

    test('Normalization with special characters', () {
      final name = PdfName('Test\tName');
      expect(name.name, 'Test#09Name');
    });

    test('decodeName', () {
      expect(PdfName.decodeName('Test#20Name'), 'Test Name');
      expect(PdfName.decodeName('Test#09Name'), 'Test\tName');
    });

    test('hashCode', () {
      final name1 = PdfName('TestName');
      final name2 = PdfName('TestName');
      expect(name1.hashCode, equals(name2.hashCode));
    });
  });
}
