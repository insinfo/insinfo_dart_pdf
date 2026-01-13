import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_stream.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_dictionary.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_number.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_name.dart';

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

    test('Decompress FlateDecode', () {
      final String originalText = 'Hello World';
      final List<int> originalBytes = utf8.encode(originalText);
      final List<int> compressedBytes = zlib.encode(originalBytes);
      
      final stream = PdfStream();
      // PdfStream initialization sets default values.
      // We manually set data and Filter to simulate reading a compressed stream.
      stream.data = compressedBytes;
      stream[PdfName('Filter')] = PdfName('FlateDecode');
      
      stream.decompress();
      
      expect(stream.data, equals(originalBytes));
      // decompress method usually removes the Filter entry
      expect(stream.containsKey('Filter'), isFalse);
    });
  });
}
