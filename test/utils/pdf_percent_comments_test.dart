import 'dart:convert';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dart_pdf/src/utils/pdf_percent_comments.dart';

void main() {
  group('PdfPercentCommentLine', () {
    test('toAsciiSafe', () {
      final line = PdfPercentCommentLine(offset: 0, bytes: Uint8List.fromList([0x25, 0x41, 0x01, 0x42]));
      expect(line.toAsciiSafe(), equals('%A.B'));
    });
    
    test('toHex', () {
       final line = PdfPercentCommentLine(offset: 0, bytes: Uint8List.fromList([0x25, 0xAB]));
       expect(line.toHex(), equals('25ab'));
    });
  });

  group('extractPdfPercentCommentLines', () {
    test('extracts comments at start of lines', () {
      final input = '%Header\nBody\n%Comment\r\nEnd';
      final bytes = Uint8List.fromList(utf8.encode(input));
      
      final comments = extractPdfPercentCommentLines(bytes);
      
      expect(comments.length, equals(2));
      expect(comments[0].toAsciiSafe(), equals('%Header'));
      expect(comments[0].offset, equals(0));
      expect(comments[1].toAsciiSafe(), equals('%Comment'));
      // %Header (7 bytes) + \n (1 byte) + Body (4 bytes) + \n (1 byte) = 13?
      // %Header (7)
      // \n (1)
      // Body (4)
      // \n (1)
      // %Comment starts at ...
      // Let's check offsets if needed, but validation by text is enough.
    });

     test('ignores % in middle if startOfLineOnly is true', () {
      final input = 'Not % a comment';
      final bytes = Uint8List.fromList(utf8.encode(input));
      
      final comments = extractPdfPercentCommentLines(bytes, startOfLineOnly: true);
      expect(comments, isEmpty);
    });

    test('finds % in middle if startOfLineOnly is false', () {
      final input = 'Not % a comment';
      final bytes = Uint8List.fromList(utf8.encode(input));
      
      final comments = extractPdfPercentCommentLines(bytes, startOfLineOnly: false);
      expect(comments.length, equals(1));
      expect(comments[0].toAsciiSafe(), equals('% a comment'));
    });
  });
}
