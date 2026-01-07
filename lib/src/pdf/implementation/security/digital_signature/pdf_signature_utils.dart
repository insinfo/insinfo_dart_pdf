import '../../io/cross_table.dart';
import '../../io/enums.dart';
import '../../io/pdf_cross_table.dart';
import '../../io/pdf_lexer.dart';
import '../../io/pdf_reader.dart';
import '../../pdf_document/pdf_document.dart';
import '../../primitives/pdf_reference.dart';

/// Holds the file offsets and values for ByteRange and Contents.
class PdfSignatureOffsets {
  PdfSignatureOffsets({
    required this.byteRange,
    required this.byteRangeOffsets,
    required this.contentsOffsets,
  });

  /// The parsed ByteRange values (e.g., [0, 100, 200, 300]).
  final List<int> byteRange;

  /// The start and end offsets of the ByteRange array in the file.
  /// offsets[0] is index of `[`. offsets[1] is index after `]`.
  final List<int> byteRangeOffsets;

  /// The start and end offsets of the Contents hex string in the file.
  /// offsets[0] is index of `<`. offsets[1] is index after `>`.
  final List<int> contentsOffsets;

  /// Helper to get the gap range (hole) defined by ByteRange.
  List<int> get gap {
    if (byteRange.length != 4) {
      return <int>[0, 0];
    }
    return <int>[byteRange[0] + byteRange[1], byteRange[2]];
  }
}

/// Utility to extract signature offsets safely using the PDF parser.
class PdfSignatureUtils {

  /// Finds the ByteRange and Contents offsets for a given signature reference.
  /// 
  /// [doc] The parsed document (used for CrossModel lookup).
  /// [pdfBytes] The raw file bytes (used for precise re-parsing).
  /// [signatureReference] The reference to the signature dictionary.
  static PdfSignatureOffsets? resolveOffsets({
    required PdfDocument doc,
    required List<int> pdfBytes,
    required PdfReference signatureReference,
  }) {
    final PdfCrossTable crossTable = PdfDocumentHelper.getHelper(doc).crossTable;
    final CrossTable? internalCrossTable = crossTable.crossTable;
    
    if (internalCrossTable == null) return null;

    final ObjectInformation? objInfo = internalCrossTable.objects[signatureReference.objNum];
    if (objInfo == null || objInfo.offset == null) return null;

    final int startOffset = objInfo.offset!;
    final PdfReader reader = PdfReader(pdfBytes);
    reader.position = startOffset;
    
    final PdfLexer lexer = PdfLexer(reader);
    
    // Skip 'objNum genNum obj'
    if (lexer.getNextToken() != PdfTokenType.number) return null;
    if (lexer.getNextToken() != PdfTokenType.number) return null;
    
    // Loop until we find the dictionary start '<<'
    PdfTokenType token = lexer.getNextToken();
    while (token != PdfTokenType.dictionaryStart && token != PdfTokenType.eof) {
      token = lexer.getNextToken();
    }
    
    if (token != PdfTokenType.dictionaryStart) return null;
    
    // Now inside dictionary
    List<int>? byteRangeValues;
    List<int>? byteRangeRange;
    List<int>? contentsRange;
    
    int loopCount = 0;
    while (loopCount++ < 1000) { // Safety break
      token = lexer.getNextToken();
      if (token == PdfTokenType.dictionaryEnd) break;
      if (token == PdfTokenType.eof) break;
      
      if (token == PdfTokenType.name) {
        final String key = lexer.text;
        if (key == 'ByteRange') {
          // Expect arrayStart following 'ByteRange'
          final int preArrayPos = lexer.position;
          
          token = lexer.getNextToken(); 
          if (token == PdfTokenType.arrayStart) {
             // Found '['. Scan for exact position of '['
             final int arrayStartPos = _scanForwardFor(pdfBytes, preArrayPos, 91); // '[' is 91
             if (arrayStartPos == -1) return null;
             
             final List<int> values = <int>[];
             while (true) {
               final PdfTokenType valToken = lexer.getNextToken();
               if (valToken == PdfTokenType.arrayEnd) break;
               if (valToken == PdfTokenType.eof) break;
               if (valToken == PdfTokenType.number) {
                 try {
                    values.add(int.parse(lexer.text));
                 } catch (_) {}
               }
             }
             
             // Found ']'.
             final int arrayEndPos = lexer.position;
             // Verify ']' at arrayEndPos-1 or near
             int p = arrayEndPos - 1;
             while (p > arrayStartPos && pdfBytes[p] != 93) p--; // 93 is ']'
             
             if (pdfBytes[p] == 93) {
                byteRangeRange = <int>[arrayStartPos, p + 1];
                byteRangeValues = values;
             }
          }
        } else if (key == 'Contents') {
           final int preValPos = lexer.position;
           token = lexer.getNextToken();
           if (token == PdfTokenType.hexStringStart) {
              final int startPos = _scanForwardFor(pdfBytes, preValPos, 60); // '<' is 60
              
              // lexer consumes content until '>'
              while (true) {
                token = lexer.getNextToken();
                if (token == PdfTokenType.hexStringEnd) break;
                if (token == PdfTokenType.eof) break;
              }
              
              final int endPos = lexer.position;
              // Verify '>' at endPos-1 or scan backward
              int p = endPos - 1;
              while (p > startPos && pdfBytes[p] != 62) p--; // 62 is '>'
              
              if (pdfBytes[p] == 62) {
                 contentsRange = <int>[startPos, p + 1];
              }
           }
        }
      }
    }
    
    if (byteRangeValues != null && byteRangeRange != null && contentsRange != null) {
      return PdfSignatureOffsets(
        byteRange: byteRangeValues,
        byteRangeOffsets: byteRangeRange,
        contentsOffsets: contentsRange,
      );
    }
    
    return null;
  }
  
  static int _scanForwardFor(List<int> bytes, int start, int char) {
    for (int i = start; i < bytes.length && i < start + 100; i++) { // Limit scan
       if (bytes[i] == char) return i;
       if (!_isWhitespace(bytes[i])) { 
         if (bytes[i] == 37) { // % comment
            // Skip to newline
            while (i < bytes.length && bytes[i] != 10 && bytes[i] != 13) i++;
         } else {
             return -1;
         }
       }
    }
    return -1;
  }
  
  static bool _isWhitespace(int c) {
    return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32;
  }
}
