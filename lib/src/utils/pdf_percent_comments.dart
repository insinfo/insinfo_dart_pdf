import 'dart:convert';
import 'dart:typed_data';

/// A single PDF comment line that starts with '%'.
///
/// In PDF syntax, a comment starts with '%' and continues until end-of-line.
class PdfPercentCommentLine {
  const PdfPercentCommentLine({required this.offset, required this.bytes});

  /// Byte offset in the original PDF where this comment line starts.
  final int offset;

  /// Raw bytes from '%' up to (but excluding) CR/LF.
  final Uint8List bytes;

  /// Returns a sanitized ASCII representation (printable 0x20..0x7E; others become '.').
  String toAsciiSafe() {
    final sb = StringBuffer();
    for (final b in bytes) {
      if (b >= 0x20 && b <= 0x7e) {
        sb.writeCharCode(b);
      } else {
        sb.write('.');
      }
    }
    return sb.toString();
  }

  /// Decodes bytes as Latin-1, preserving a 1:1 mapping for 0x00..0xFF.
  String toLatin1({bool allowInvalid = true}) {
    return latin1.decode(bytes, allowInvalid: allowInvalid);
  }

  /// Returns a lowercase hex string of the comment bytes.
  ///
  /// If [maxBytes] is provided, the hex is truncated to that many bytes and ends with '...'.
  String toHex({int? maxBytes}) {
    final effective = (maxBytes != null && bytes.length > maxBytes)
        ? bytes.sublist(0, maxBytes)
        : bytes;

    final sb = StringBuffer();
    for (final b in effective) {
      sb.write(b.toRadixString(16).padLeft(2, '0'));
    }
    if (maxBytes != null && bytes.length > maxBytes) {
      sb.write('...');
    }
    return sb.toString();
  }
}

/// Extracts PDF comment lines that start with '%' at a line start.
///
/// This is a byte-level scan; it does not parse PDF objects/streams.
List<PdfPercentCommentLine> extractPdfPercentCommentLines(
  Uint8List pdfBytes, {
  bool startOfLineOnly = true,
}) {
  final results = <PdfPercentCommentLine>[];

  int i = 0;
  while (i < pdfBytes.length) {
    final bool isStart = !startOfLineOnly ||
        i == 0 ||
        pdfBytes[i - 1] == 0x0A ||
        pdfBytes[i - 1] == 0x0D;

    if (isStart && pdfBytes[i] == 0x25) {
      int j = i;
      while (j < pdfBytes.length && pdfBytes[j] != 0x0A && pdfBytes[j] != 0x0D) {
        j++;
      }
      results.add(
        PdfPercentCommentLine(
          offset: i,
          bytes: Uint8List.fromList(pdfBytes.sublist(i, j)),
        ),
      );
      i = j;
    }

    i++;
  }

  return results;
}
