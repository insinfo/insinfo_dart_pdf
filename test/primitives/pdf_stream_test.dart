import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_stream.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_dictionary.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_number.dart';

void main() {
  group('PdfStream', () {
    test('Default constructor', () {
      final stream = PdfStream();
      expect(stream.data, isEmpty);
      expect(stream.compress, isTrue);
    });

    test('Constructor with data and dictionary', () {
      final dict = PdfDictionary();
      final data = [1, 2, 3];
      final stream = PdfStream(dict, data);
      
      // stream.dataStream access might trigger decryption logic if hooked up, but here it's simple
      expect(stream.data, equals(data)); 
      expect(stream.compress, isFalse);
      
      // Check if length is set in dictionary
      expect(stream.containsKey('Length'), isTrue);
      // Wait, PdfStream constructor uses PdfDictionaryProperties.length which is likely 'Length'
    });

    test('clearStream', () {
      final stream = PdfStream();
      stream.data!.addAll([1, 2, 3]);
      stream.clearStream();
      expect(stream.data, isEmpty);
    });

    test('Dictionary behavior inherited', () {
      final stream = PdfStream();
      stream['key'] = PdfNumber(10);
      expect(stream.count, 1);
    });
  });
}
