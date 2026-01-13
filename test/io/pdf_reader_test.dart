import 'dart:convert';
import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_reader.dart';


void main() {
  group('PdfReader Tests', () {
    PdfReader createReader(String input) {
      final bytes = utf8.encode(input);
      return PdfReader(bytes);
    }

    test('Read Bytes', () {
      final reader = createReader('12345');
      final bytes = reader.readBytes(3);
      expect(bytes, equals(utf8.encode('123')));
      expect(reader.position, equals(3));
    });

    test('Skip Whitespace', () {
      final reader = createReader('   123');
      reader.skipWhiteSpace();
      expect(reader.position, equals(3));
      final bytes = reader.readBytes(3);
      expect(bytes, equals(utf8.encode('123')));
    });

    test('Read Line', () {
      final reader = createReader('Line1\nLine2\rLine3\r\nLine4');
      expect(reader.readLine(), equals('Line1')); // \n
      expect(reader.readLine(), equals('Line2')); // \r
      expect(reader.readLine(), equals('Line3')); // \r\n
      expect(reader.readLine(), equals('Line4'));
      expect(reader.readLine(), equals(''));
    });

    test('Read Data', () {
      final reader = createReader('ABCDE');
      final buffer = List<int>.filled(5, 0);
      int read = reader.readData(buffer, 0, 3);
      expect(read, equals(3));
      expect(buffer.sublist(0, 3), equals(utf8.encode('ABC')));
      expect(reader.position, equals(3));
    });
    
    test('Search Back', () {
        // searchBack looks for a token searching backwards from current position?
        // Let's verify expectations based on implementation reading.
        // It seems to be used for finding 'startxref' from end of file usually.
        
        final input = 'startxref\n12345\n%%EOF';
        final reader = createReader(input);
        
        // Seek to end
        reader.position = input.length;
        
        // Search back for 'startxref'
        // But searchBack uses PdfOperators usually? 
        // Logic: position = _skipWhiteSpaceBack(); ...
        
        // Let's try finding 'EOF'
        int pos = reader.searchBack('EOF');
        expect(pos, equals(input.indexOf('EOF')));
    });
    
    test('Search Back startxref', () {
         final input = 'startxref\n12345\n%%EOF';
         final reader = createReader(input);
         reader.position = input.length;
         
         // Note: PdfOperators.startCrossReference is "startxref"
         // PdfOperators.crossReference is "xref"
         // The method has specific handling for these.
         
         int pos = reader.searchBack('startxref');
         // Implementation: 
         // while (token == PdfOperators.crossReference) ... this block seems relevant only if searching for 'xref'
         
         expect(pos, equals(input.indexOf('startxref')));
    });

  });
}
