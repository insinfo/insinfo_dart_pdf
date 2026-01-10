import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_dictionary.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_name.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_number.dart';

void main() {
  group('PdfDictionary', () {
    test('Default constructor', () {
      final dict = PdfDictionary();
      expect(dict.count, 0);
    });

    test('Add and retrieve items using String key', () {
      final dict = PdfDictionary();
      final num = PdfNumber(1);
      dict['entry'] = num;
      expect(dict.count, 1);
      expect(dict.containsKey('entry'), isTrue);
      expect(dict['entry'], equals(num));
    });

    test('Add and retrieve items using PdfName key', () {
      final dict = PdfDictionary();
      final num = PdfNumber(2);
      final key = PdfName('entry2');
      dict[key] = num;
      expect(dict.count, 1);
      expect(dict.containsKey(key), isTrue);
      expect(dict[key], equals(num));
    });

    test('Interchangeable keys (String vs PdfName)', () {
      final dict = PdfDictionary();
      final num = PdfNumber(3);
      dict['entry'] = num;
      
      final key = PdfName('entry');
      expect(dict[key], equals(num));
      expect(dict.containsKey(key), isTrue);

      dict[key] = PdfNumber(4);
      expect((dict['entry'] as PdfNumber).value, 4);
    });
    
    test('Copy constructor', () {
      final dict1 = PdfDictionary();
      dict1['key'] = PdfNumber(10);
      
      final dict2 = PdfDictionary(dict1);
      expect(dict2.count, 1);
      expect(dict2.containsKey('key'), isTrue);
      expect((dict2['key'] as PdfNumber).value, 10);
    });

    test('remove', () {
      final dict = PdfDictionary();
      dict['key'] = PdfNumber(1);
      dict.remove('key');
      expect(dict.count, 0);
      expect(dict.containsKey('key'), isFalse);
    });

    test('clear', () {
      final dict = PdfDictionary();
      dict['key1'] = PdfNumber(1);
      dict['key2'] = PdfNumber(2);
      dict.clear();
      expect(dict.count, 0);
    });
  });
}
