import 'dart:convert';
import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_lexer.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_reader.dart';
import 'package:dart_pdf/src/pdf/implementation/io/enums.dart';

void main() {
  group('PdfLexer Tests', () {
    PdfLexer createLexer(String input) {
      final bytes = utf8.encode(input);
      final reader = PdfReader(bytes);
      return PdfLexer(reader);
    }

    test('Lex Name', () {
      final lexer = createLexer('/MyName');
      final token = lexer.getNextToken();
      expect(token, equals(PdfTokenType.name));
      expect(lexer.text, equals('/MyName')); 
    });

    test('Lex String', () {
      final lexer = createLexer('(Hello World)');
      final token = lexer.getNextToken();
      expect(token, equals(PdfTokenType.string));
      expect(lexer.stringText, equals('Hello World'));
    });

    test('Lex Number', () {
      final lexer = createLexer('123');
      final token = lexer.getNextToken();
      expect(token, equals(PdfTokenType.number));
      expect(lexer.text, equals('123'));
    });

    test('Lex Real', () {
      final lexer = createLexer('123.45');
      final token = lexer.getNextToken();
      expect(token, equals(PdfTokenType.real));
      expect(lexer.text, equals('123.45'));
    });

    test('Lex Dictionary', () {
      final lexer = createLexer('<< /Type /Page >>');
      
      expect(lexer.getNextToken(), equals(PdfTokenType.dictionaryStart));
      
      expect(lexer.getNextToken(), equals(PdfTokenType.name));
      expect(lexer.text, equals('/Type'));
      
      expect(lexer.getNextToken(), equals(PdfTokenType.name));
      expect(lexer.text, equals('/Page'));
      
      expect(lexer.getNextToken(), equals(PdfTokenType.dictionaryEnd));
    });

    test('Lex Array', () {
      final lexer = createLexer('[ 1 2 ]');
      expect(lexer.getNextToken(), equals(PdfTokenType.arrayStart));
      expect(lexer.getNextToken(), equals(PdfTokenType.number));
      expect(lexer.getNextToken(), equals(PdfTokenType.number));
      expect(lexer.getNextToken(), equals(PdfTokenType.arrayEnd));
    });

    test('Lex Boolean', () {
      final lexer = createLexer('true false');
      expect(lexer.getNextToken(), equals(PdfTokenType.boolean));
      expect(lexer.text, equals('true'));
      expect(lexer.getNextToken(), equals(PdfTokenType.boolean));
      expect(lexer.text, equals('false'));
    });
    
     test('Lex Null', () {
      final lexer = createLexer('null');
      expect(lexer.getNextToken(), equals(PdfTokenType.nullType));
    });

    test('Lex Indirect Object Start', () {
       final lexer = createLexer('1 0 obj');
       expect(lexer.getNextToken(), equals(PdfTokenType.number));
       expect(lexer.getNextToken(), equals(PdfTokenType.number));
       expect(lexer.getNextToken(), equals(PdfTokenType.objectStart));
    });
    
    test('Lex Reference', () {
       final lexer = createLexer('1 0 R');
       expect(lexer.getNextToken(), equals(PdfTokenType.number));
       expect(lexer.getNextToken(), equals(PdfTokenType.number));
       expect(lexer.getNextToken(), equals(PdfTokenType.reference));
    });
  });
}
