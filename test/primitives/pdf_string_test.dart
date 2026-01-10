import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_string.dart';

void main() {
  group('PdfString', () {
    test('Default Constructor with simple string', () {
      final str = PdfString('Hello');
      expect(str.value, 'Hello');
      expect(str.isHex, isFalse);
      expect(str.data, [72, 101, 108, 108, 111]); // ASCII values
    });

    test('Default Constructor with empty string', () {
      final str = PdfString('');
      expect(str.value, '');
      expect(str.isHex, isFalse);
      expect(str.data, isNull);
    });

    test('fromBytes Constructor', () {
      final bytes = [72, 101, 108, 108, 111];
      final str = PdfString.fromBytes(bytes);
      expect(str.value, 'Hello');
      expect(str.data, bytes);
      expect(str.isHex, isTrue);
    });

    
  });
}
