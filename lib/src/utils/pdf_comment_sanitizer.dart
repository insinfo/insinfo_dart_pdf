import 'dart:typed_data';

import 'pdf_percent_comments.dart';

/// Result of sanitizing a PDF.
class PdfCommentSanitizerResult {
  const PdfCommentSanitizerResult({
    required this.bytes,
    required this.scrubbedLineCount,
    required this.scrubbedOffsets,
  });

  /// Sanitized bytes.
  final Uint8List bytes;

  /// How many '%...' lines were scrubbed.
  final int scrubbedLineCount;

  /// Offsets (byte positions) where scrubbed lines started.
  final List<int> scrubbedOffsets;
}

/// Sanitizes *leading* PDF percent-comment lines (lines starting with '%') in the
/// header area before the first indirect object.
///
/// This is designed to remove "verbose" producer/debug headers that some
/// generators include as comments, while keeping the PDF structurally intact:
/// - It keeps file length unchanged.
/// - It preserves line breaks.
/// - It only touches the region before the first "N N obj" occurrence.
///
/// Notes:
/// - PDF comments are allowed by the specification; this is purely a cleanup.
/// - This does NOT attempt to scrub '%' bytes that occur inside compressed
///   streams (which would corrupt the file).
/// - Any *byte changes* to a signed PDF will invalidate signatures, even if the
///   structure remains readable.
PdfCommentSanitizerResult sanitizePdfLeadingPercentComments(
  Uint8List pdfBytes, {
  bool keepFirstTwoHeaderLines = true,
}) {
  final out = Uint8List.fromList(pdfBytes);

  final int firstObjOffset = _findFirstIndirectObjectOffset(out);
  if (firstObjOffset <= 0) {
    return PdfCommentSanitizerResult(
      bytes: out,
      scrubbedLineCount: 0,
      scrubbedOffsets: const <int>[],
    );
  }

  // Extract comment lines only in the header area.
  final headerSlice = Uint8List.sublistView(out, 0, firstObjOffset);
  final comments = extractPdfPercentCommentLines(headerSlice);

  int skip = 0;
  if (keepFirstTwoHeaderLines) {
    // Typical header:
    // 1) %PDF-x.y
    // 2) %<binary bytes>
    skip = comments.length >= 2 ? 2 : comments.length;
  }

  final scrubbedOffsets = <int>[];
  for (int idx = skip; idx < comments.length; idx++) {
    final c = comments[idx];
    final start = c.offset;
    final endExclusive = c.offset + c.bytes.length;

    // Replace the line bytes (including the leading '%') with spaces.
    for (int i = start; i < endExclusive; i++) {
      out[i] = 0x20; // ' '
    }
    scrubbedOffsets.add(start);
  }

  return PdfCommentSanitizerResult(
    bytes: out,
    scrubbedLineCount: scrubbedOffsets.length,
    scrubbedOffsets: scrubbedOffsets,
  );
}

int _findFirstIndirectObjectOffset(Uint8List bytes) {
  // Look for: <digits> <digits> obj
  // We do a simple ASCII scan; sufficient for "header area" detection.
  int i = 0;
  while (i < bytes.length) {
    // Skip until a digit at line start-ish.
    final b = bytes[i];
    if (b < 0x30 || b > 0x39) {
      i++;
      continue;
    }

    final start = i;

    // Parse first number.
    while (i < bytes.length && bytes[i] >= 0x30 && bytes[i] <= 0x39) {
      i++;
    }
    if (i >= bytes.length || bytes[i] != 0x20) {
      i = start + 1;
      continue;
    }
    i++; // space

    // Parse second number.
    final genStart = i;
    while (i < bytes.length && bytes[i] >= 0x30 && bytes[i] <= 0x39) {
      i++;
    }
    if (i == genStart || i >= bytes.length || bytes[i] != 0x20) {
      i = start + 1;
      continue;
    }
    i++; // space

    // Expect 'o''b''j'
    if (i + 2 < bytes.length &&
        bytes[i] == 0x6F &&
        bytes[i + 1] == 0x62 &&
        bytes[i + 2] == 0x6A) {
      // Ensure it's followed by whitespace.
      final next = i + 3;
      if (next >= bytes.length) return start;
      final nb = bytes[next];
      if (nb == 0x20 || nb == 0x0A || nb == 0x0D || nb == 0x09) {
        return start;
      }
    }

    i = start + 1;
  }

  return -1;
}
