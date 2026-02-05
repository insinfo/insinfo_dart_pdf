import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dart_pdf/src/vector/ui.dart';

import '../../annotations/enum.dart';
import '../../forms/pdf_signature_field.dart';
import '../../graphics/figures/pdf_template.dart';
import '../../graphics/pdf_graphics.dart';
import '../../pages/pdf_page.dart';
import '../../pdf_document/enums.dart';
import '../../pdf_document/pdf_document.dart';
import '../../primitives/pdf_array.dart';
import '../../primitives/pdf_number.dart';
import '../../io/pdf_cross_table.dart';
import '../enum.dart';
import 'pdf_external_signer.dart';
import 'pdf_signature.dart';

/// Result of preparing a PDF for external signing.
class PdfExternalSigningResult {
  PdfExternalSigningResult({
    required this.preparedPdfBytes,
    required this.hashBase64,
    required this.byteRange,
    required this.contentsStart,
    required this.contentsEnd,
  });

  /// PDF bytes containing the signature placeholder.
  final Uint8List preparedPdfBytes;

  /// Base64 SHA-256 hash computed from the ByteRange.
  final String hashBase64;

  /// ByteRange [start1, length1, start2, length2].
  final List<int> byteRange;

  /// Start index (inclusive) of the /Contents hex string.
  final int contentsStart;

  /// End index (exclusive) of the /Contents hex string.
  final int contentsEnd;
}

/// Helpers for external PDF signing flows (Gov.br, HSM, etc.).
class PdfExternalSigning {
  /// Controls whether ByteRange extraction uses the internal PDF parser.
  static bool useInternalByteRangeParser = false;

  /// Controls whether ByteRange extraction uses a fast byte-level scanner.
  ///
  /// This is xref-independent and typically much faster than building a full
  /// [PdfDocument]. If it fails for any reason, we fall back to the legacy
  /// latin1+regex scan.
  static bool useFastByteRangeParser = true;
  /// Controls whether /Contents lookup uses the internal parser-based flow.
  static bool useInternalContentsParser = false;

  /// Controls whether /Contents lookup uses a fast byte-level scanner.
  ///
  /// This is xref-independent. If it fails, we fall back to the legacy
  /// latin1 string scan.
  static bool useFastContentsParser = true;

  static const List<int> _byteRangeToken = <int>[
    0x2F, // /
    0x42, 0x79, 0x74, 0x65, // Byte
    0x52, 0x61, 0x6E, 0x67, 0x65, // Range
  ];

  static const List<int> _contentsToken = <int>[
    0x2F, // /
    0x43, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x73, // Contents
  ];

  // Minimum number of HEX digits expected inside a signature /Contents.
  // This is a validation heuristic to avoid false positives on malformed files.
  static const int _minContentsHexDigits = 64;

  /// Prepares a PDF for external signing by injecting a placeholder signature.
  static Future<PdfExternalSigningResult> preparePdf({
    required Uint8List inputBytes,
    required int pageNumber,
    required Rect bounds,
    required String fieldName,
    PdfSignature? signature,
    List<List<int>>? publicCertificates,
    void Function(PdfGraphics graphics, Rect bounds)? drawAppearance,
  }) async {
    final PdfDocument document = PdfDocument(inputBytes: inputBytes);
    PdfPage page;
    if (pageNumber > 0 && pageNumber <= document.pages.count) {
      page = document.pages[pageNumber - 1];
    } else {
      page = document.pages.add();
    }

    final PdfSignature sig = signature ?? PdfSignature();
    if (signature == null) {
      sig.documentPermissions = <PdfCertificationFlags>[
        PdfCertificationFlags.allowFormFill,
      ];
    }

    // For external signing, we only need a placeholder.
    sig.addExternalSigner(
      _PlaceholderExternalSigner(),
      publicCertificates ?? <List<int>>[],
    );
    document.fileStructure.incrementalUpdate = true;
    document.fileStructure.crossReferenceType =
        PdfCrossReferenceType.crossReferenceTable;

    final PdfSignatureField field = PdfSignatureField(
      page,
      fieldName,
      bounds: bounds,
      borderWidth: 0,
      borderStyle: PdfBorderStyle.solid,
      signature: sig,
    );
    document.form.fields.add(field);

    if (drawAppearance != null) {
      final PdfTemplate template = field.appearance.normal;
      final PdfGraphics? graphics = template.graphics;
      if (graphics != null) {
        drawAppearance(
          graphics,
          Rect.fromLTWH(0, 0, bounds.width, bounds.height),
        );
      }
    }

    final Uint8List preparedPdfBytes =
        Uint8List.fromList(await document.save());
    document.dispose();

    final List<int> byteRange = extractByteRange(preparedPdfBytes);
    final String hashBase64 =
        computeByteRangeHashBase64(preparedPdfBytes, byteRange);
    final _ContentsRange contents = findContentsRange(preparedPdfBytes);

    return PdfExternalSigningResult(
      preparedPdfBytes: preparedPdfBytes,
      hashBase64: hashBase64,
      byteRange: byteRange,
      contentsStart: contents.start,
      contentsEnd: contents.end,
    );
  }

  /// Computes the SHA-256 digest (raw bytes) of the provided ByteRange.
  static Uint8List computeByteRangeDigest(
    Uint8List pdfBytes,
    List<int> byteRange,
  ) {
    if (byteRange.length != 4) {
      throw ArgumentError.value(byteRange, 'byteRange', 'Invalid length');
    }
    final int start1 = byteRange[0];
    final int len1 = byteRange[1];
    final int start2 = byteRange[2];
    final int len2 = byteRange[3];

    final AccumulatorSink<crypto.Digest> output =
        AccumulatorSink<crypto.Digest>();
    final ByteConversionSink input =
        crypto.sha256.startChunkedConversion(output);
    input.add(pdfBytes.sublist(start1, start1 + len1));
    input.add(pdfBytes.sublist(start2, start2 + len2));
    input.close();

    return Uint8List.fromList(output.events.single.bytes);
  }

  /// Computes the Base64 SHA-256 hash of the provided ByteRange.
  static String computeByteRangeHashBase64(
    Uint8List pdfBytes,
    List<int> byteRange,
  ) {
    return base64Encode(computeByteRangeDigest(pdfBytes, byteRange));
  }

  /// Computes the Base64 SHA-256 hash of the entire file (detached mode).
  static String computeFileHashBase64(Uint8List pdfBytes) {
    final crypto.Digest digest = crypto.sha256.convert(pdfBytes);
    return base64Encode(digest.bytes);
  }

  /// Extracts the last ByteRange from a PDF.
  static List<int> extractByteRange(Uint8List pdfBytes) {
    if (useInternalByteRangeParser) {
      return extractByteRangeInternal(pdfBytes);
    }

    // Hybrid strategy (correction-first):
    // 1) FastBytes (xref-independent)
    // 2) StringSearch (latin1 + RegExp)
    // 3) InternalDoc (PdfDocument) as last resort
    if (useFastByteRangeParser) {
      try {
        final List<int> range = extractByteRangeFast(pdfBytes);
        if (_isValidByteRange(pdfBytes.length, range)) {
          return range;
        }
      } catch (e) {
        // If the token is truly absent, avoid decoding the whole file.
        if (e is StateError && e.message == 'ByteRange not found') {
          throw e;
        }
        // Otherwise fall through to attempt recovery.
      }
    }

    try {
      final List<int> range = _extractByteRangeStringSearch(pdfBytes);
      if (_isValidByteRange(pdfBytes.length, range)) {
        return range;
      }
    } catch (_) {
      // Fall through.
    }

    // Last resort: full parser.
    final List<int> range = extractByteRangeInternal(pdfBytes);
    if (!_isValidByteRange(pdfBytes.length, range)) {
      throw StateError('ByteRange found but inconsistent');
    }
    return range;
  }

  static List<int> _extractByteRangeStringSearch(Uint8List pdfBytes) {
    final String s = latin1.decode(pdfBytes, allowInvalid: true);
    final Iterable<RegExpMatch> matches = RegExp(
      r'/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]',
    ).allMatches(s);
    if (matches.isEmpty) {
      throw StateError('ByteRange not found');
    }
    final RegExpMatch match = matches.last;
    return <int>[
      int.parse(match.group(1)!),
      int.parse(match.group(2)!),
      int.parse(match.group(3)!),
      int.parse(match.group(4)!),
    ];
  }

  /// Embeds a PKCS#7 signature (DER) into the PDF placeholder.
  static Uint8List embedSignature({
    required Uint8List preparedPdfBytes,
    required List<int> pkcs7Bytes,
  }) {
    final _ContentsRange contents = findContentsRange(preparedPdfBytes);
    final int availableChars = contents.end - contents.start;
    String hexUp = _bytesToHex(pkcs7Bytes).toUpperCase();
    if (hexUp.length.isOdd) {
      hexUp = '0$hexUp';
    }
    if (hexUp.length > availableChars) {
      throw StateError(
        'Signature larger than placeholder: ${hexUp.length} > $availableChars',
      );
    }

    final Uint8List newBytes = Uint8List.fromList(preparedPdfBytes);
    final List<int> sigBytes = ascii.encode(hexUp);
    newBytes.setRange(
        contents.start, contents.start + sigBytes.length, sigBytes);
    for (int i = contents.start + sigBytes.length; i < contents.end; i++) {
      newBytes[i] = 0x30;
    }
    return newBytes;
  }

  /// Convenience helper to save PDF bytes to disk.
  static void writePdfFileSync(String path, Uint8List bytes) {
    File(path).writeAsBytesSync(bytes, flush: true);
  }

  static Future<void> writePdfFile(String path, Uint8List bytes) async {
    await File(path).writeAsBytes(bytes, flush: true);
  }

  static _ContentsRange findContentsRange(Uint8List pdfBytes) {
    if (useInternalContentsParser) {
      return _findContentsRangeInternal(pdfBytes);
    }

    // Hybrid strategy (correction-first):
    // 1) FastBytes (xref-independent; prefers using ByteRange gap)
    // 2) StringSearch (latin1 scan)
    // 3) InternalDoc (PdfDocument) as last resort
    if (useFastContentsParser) {
      try {
        final _ContentsRange r = findContentsRangeFast(pdfBytes);
        if (_isValidContentsRange(pdfBytes, r)) {
          return r;
        }
      } catch (e) {
        // If /ByteRange is not present, we can fail fast.
        if (e is StateError && e.message == 'ByteRange not found') {
          throw e;
        }
        // Otherwise fall through.
      }
    }

    try {
      final _ContentsRange r = _findContentsRangeStringSearch(pdfBytes);
      if (_isValidContentsRange(pdfBytes, r)) {
        return r;
      }
    } catch (_) {
      // Fall through.
    }

    final _ContentsRange r = _findContentsRangeInternal(pdfBytes);
    if (!_isValidContentsRange(pdfBytes, r)) {
      throw StateError('Contents range found but inconsistent');
    }
    return r;
  }

  static _ContentsRange _findContentsRangeStringSearch(Uint8List pdfBytes) {
    final String s = latin1.decode(pdfBytes, allowInvalid: true);
    final int sigPos = s.lastIndexOf('/Type /Sig');
    if (sigPos == -1) {
      throw StateError('No /Type /Sig');
    }
    final int dictStart = s.lastIndexOf('<<', sigPos);
    final int dictEnd = s.indexOf('>>', sigPos);
    if (dictStart == -1 || dictEnd == -1 || dictEnd <= dictStart) {
      throw StateError('Could not find signature dictionary bounds');
    }
    final int contentsLabelPos = s.indexOf('/Contents', dictStart);
    if (contentsLabelPos == -1 || contentsLabelPos > dictEnd) {
      throw StateError('No /Contents found in signature dictionary');
    }
    final int lt = s.indexOf('<', contentsLabelPos);
    final int gt = s.indexOf('>', lt + 1);
    if (lt == -1 || gt == -1 || gt > dictEnd || gt <= lt) {
      throw StateError('Contents hex string not found');
    }
    return _ContentsRange(lt + 1, gt);
  }

  static bool _isValidByteRange(int fileLength, List<int> byteRange) {
    if (byteRange.length != 4) return false;
    final int start1 = byteRange[0];
    final int len1 = byteRange[1];
    final int start2 = byteRange[2];
    final int len2 = byteRange[3];
    if (start1 < 0 || len1 < 0 || start2 < 0 || len2 < 0) return false;
    if (start1 > fileLength) return false;
    if (start1 + len1 > fileLength) return false;
    if (start2 > fileLength) return false;
    if (start2 + len2 > fileLength) return false;
    // Typically: [0, len1, start2, len2] and start2 >= start1+len1.
    if (start2 < start1 + len1) return false;
    return true;
  }
  static bool _isValidContentsRange(Uint8List pdfBytes, _ContentsRange r) {
    if (r.start < 0 || r.end < 0) return false;
    if (r.start >= r.end) return false;
    if (r.end > pdfBytes.length) return false;
    return _isValidContentsHex(pdfBytes, r.start, r.end);
  }

  static bool _isValidContentsHex(Uint8List pdfBytes, int start, int end) {
    // Validate that the contents range looks like a hex string.
    // We accept hex digits and whitespace only.
    int hexDigits = 0;
    for (int i = start; i < end; i++) {
      final int b = pdfBytes[i];
      final bool isWs = b == 0x00 || b == 0x09 || b == 0x0A || b == 0x0C || b == 0x0D || b == 0x20;
      if (isWs) {
        continue;
      }
      final bool isHex =
          (b >= 0x30 && b <= 0x39) ||
          (b >= 0x41 && b <= 0x46) ||
          (b >= 0x61 && b <= 0x66);
      if (!isHex) {
        return false;
      }
      hexDigits++;
    }

    if (hexDigits < _minContentsHexDigits) {
      return false;
    }
    // Hex strings should have an even number of hex digits.
    if (hexDigits.isOdd) {
      return false;
    }
    return true;
  }

  static String _bytesToHex(List<int> bytes) {
    final StringBuffer buffer = StringBuffer();
    for (final int b in bytes) {
      buffer.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }

  static List<int> extractByteRangeInternal(Uint8List pdfBytes) {
    final PdfDocument doc = PdfDocument(inputBytes: pdfBytes);
    try {
      List<int>? lastRange;
      for (int idx = 0; idx < doc.form.fields.count; idx++) {
        final field = doc.form.fields[idx];
        if (field is PdfSignatureField) {
          final PdfSignature? sig = field.signature;
          if (sig == null) continue;
          final PdfArray? range = PdfSignatureHelper.getHelper(sig).byteRange;
          if (range != null && range.count >= 4) {
            final List<int> values = <int>[];
            for (int i = 0; i < 4; i++) {
              final PdfNumber? number =
                  PdfCrossTable.dereference(range[i]) as PdfNumber?;
              if (number == null || number.value == null) {
                throw StateError('Invalid ByteRange entry at index $i');
              }
              values.add(number.value!.toInt());
            }
            lastRange = values;
          }
        }
      }
      if (lastRange == null) {
        throw StateError('ByteRange not found via internal parser');
      }
      return lastRange;
    } finally {
      doc.dispose();
    }
  }

  static _ContentsRange _findContentsRangeInternal(Uint8List pdfBytes) {
    final List<int> range = extractByteRangeInternal(pdfBytes);
    if (range.length != 4) {
      throw StateError('Invalid ByteRange length');
    }
    final int gapStart = range[0] + range[1];
    final int gapEnd = range[2];
    if (gapStart < 0 || gapEnd <= gapStart || gapEnd > pdfBytes.length) {
      throw StateError('Invalid ByteRange gap for /Contents');
    }
    int lt = -1;
    for (int i = gapStart; i < gapEnd; i++) {
      if (pdfBytes[i] == 0x3C) {
        lt = i;
        break;
      }
    }
    if (lt == -1) {
      throw StateError('Contents hex string not found');
    }
    int gt = -1;
    for (int i = lt + 1; i < gapEnd; i++) {
      if (pdfBytes[i] == 0x3E) {
        gt = i;
        break;
      }
    }
    if (gt == -1 || gt <= lt) {
      throw StateError('Contents hex string not found');
    }
    return _ContentsRange(lt + 1, gt);
  }

  /// Fast, xref-independent extraction of the last /ByteRange in the file.
  ///
  /// This avoids decoding the whole file to a [String] and avoids a full
  /// [PdfDocument] parse.
  static List<int> extractByteRangeFast(Uint8List pdfBytes) {
    final int tokenPos = _lastIndexOfSequence(pdfBytes, _byteRangeToken);
    if (tokenPos == -1) {
      throw StateError('ByteRange not found');
    }

    final int end = pdfBytes.length;
    int i = tokenPos + _byteRangeToken.length;
    i = _skipPdfWsAndComments(pdfBytes, i, end);

    // Find '[' after /ByteRange
    if (i >= end) {
      throw StateError('Invalid ByteRange syntax');
    }
    if (pdfBytes[i] != 0x5B /* [ */) {
      // Scan forward a little to find the bracket.
      final int limit = (i + 256 < end) ? i + 256 : end;
      bool found = false;
      for (int j = i; j < limit; j++) {
        if (pdfBytes[j] == 0x5B) {
          i = j;
          found = true;
          break;
        }
      }
      if (!found) {
        throw StateError('Invalid ByteRange syntax');
      }
    }
    i++; // skip '['

    final List<int> values = List<int>.filled(4, 0);
    for (int k = 0; k < 4; k++) {
      i = _skipPdfWsAndComments(pdfBytes, i, end);
      final ({int value, int nextIndex}) parsed = _readInt(pdfBytes, i, end);
      values[k] = parsed.value;
      i = parsed.nextIndex;
    }

    // Optional: validate closing bracket
    i = _skipPdfWsAndComments(pdfBytes, i, end);
    if (i < end && pdfBytes[i] != 0x5D /* ] */) {
      // Not fatal; some producers may have additional tokens before ']'.
    }
    return values;
  }

  /// Fast, xref-independent lookup of /Contents <...> range.
  ///
  /// It uses the /ByteRange gap and searches for a /Contents token inside the
  /// gap, then extracts the hex string bounds.
  static _ContentsRange findContentsRangeFast(Uint8List pdfBytes) {
    final List<int> range = extractByteRangeFast(pdfBytes);
    if (range.length != 4) {
      throw StateError('Invalid ByteRange length');
    }
    final int gapStart = range[0] + range[1];
    final int gapEnd = range[2];
    if (gapStart < 0 || gapEnd <= gapStart || gapEnd > pdfBytes.length) {
      throw StateError('Invalid ByteRange gap for /Contents');
    }

    // Search /Contents inside the gap for robustness.
    final int contentsPos = _indexOfSequenceInRange(
      pdfBytes,
      _contentsToken,
      gapStart,
      gapEnd,
    );
    if (contentsPos == -1) {
      // Fallback to scanning for '<' and '>' within the gap.
      return _findHexStringInGap(pdfBytes, gapStart, gapEnd);
    }

    int i = contentsPos + _contentsToken.length;
    i = _skipPdfWsAndComments(pdfBytes, i, gapEnd);

    // Find '<' after /Contents.
    int lt = -1;
    for (int j = i; j < gapEnd; j++) {
      if (pdfBytes[j] == 0x3C /* < */) {
        lt = j;
        break;
      }
    }
    if (lt == -1) {
      throw StateError('Contents hex string not found');
    }

    int gt = -1;
    for (int j = lt + 1; j < gapEnd; j++) {
      if (pdfBytes[j] == 0x3E /* > */) {
        gt = j;
        break;
      }
    }
    if (gt == -1 || gt <= lt) {
      throw StateError('Contents hex string not found');
    }
    return _ContentsRange(lt + 1, gt);
  }

  static _ContentsRange _findHexStringInGap(
    Uint8List pdfBytes,
    int gapStart,
    int gapEnd,
  ) {
    int lt = -1;
    for (int i = gapStart; i < gapEnd; i++) {
      if (pdfBytes[i] == 0x3C /* < */) {
        lt = i;
        break;
      }
    }
    if (lt == -1) {
      throw StateError('Contents hex string not found');
    }
    int gt = -1;
    for (int i = lt + 1; i < gapEnd; i++) {
      if (pdfBytes[i] == 0x3E /* > */) {
        gt = i;
        break;
      }
    }
    if (gt == -1 || gt <= lt) {
      throw StateError('Contents hex string not found');
    }
    return _ContentsRange(lt + 1, gt);
  }

  static int _lastIndexOfSequence(Uint8List bytes, List<int> pattern) {
    if (pattern.isEmpty) return -1;
    final int max = bytes.length - pattern.length;
    for (int i = max; i >= 0; i--) {
      bool ok = true;
      for (int j = 0; j < pattern.length; j++) {
        if (bytes[i + j] != pattern[j]) {
          ok = false;
          break;
        }
      }
      if (ok) return i;
    }
    return -1;
  }

  static int _indexOfSequenceInRange(
    Uint8List bytes,
    List<int> pattern,
    int start,
    int end,
  ) {
    if (pattern.isEmpty) return -1;
    final int max = end - pattern.length;
    for (int i = start; i <= max; i++) {
      bool ok = true;
      for (int j = 0; j < pattern.length; j++) {
        if (bytes[i + j] != pattern[j]) {
          ok = false;
          break;
        }
      }
      if (ok) return i;
    }
    return -1;
  }

  static int _skipPdfWsAndComments(Uint8List bytes, int i, int end) {
    while (i < end) {
      final int b = bytes[i];
      // Whitespace per PDF spec: 0x00, HT, LF, FF, CR, SP
      if (b == 0x00 || b == 0x09 || b == 0x0A || b == 0x0C || b == 0x0D || b == 0x20) {
        i++;
        continue;
      }
      // Comment: '%' to end of line.
      if (b == 0x25 /* % */) {
        i++;
        while (i < end) {
          final int c = bytes[i];
          if (c == 0x0A || c == 0x0D) break;
          i++;
        }
        continue;
      }
      break;
    }
    return i;
  }

  static ({int value, int nextIndex}) _readInt(
    Uint8List bytes,
    int i,
    int end,
  ) {
    if (i >= end) {
      throw StateError('Unexpected end while parsing int');
    }
    bool neg = false;
    if (bytes[i] == 0x2D /* - */) {
      neg = true;
      i++;
    }
    if (i >= end) {
      throw StateError('Unexpected end while parsing int');
    }
    int value = 0;
    int digits = 0;
    while (i < end) {
      final int b = bytes[i];
      if (b < 0x30 || b > 0x39) break;
      value = (value * 10) + (b - 0x30);
      i++;
      digits++;
    }
    if (digits == 0) {
      throw StateError('Invalid integer');
    }
    return (value: neg ? -value : value, nextIndex: i);
  }
}

class _ContentsRange {
  _ContentsRange(this.start, this.end);
  final int start;
  final int end;
}

class _PlaceholderExternalSigner extends IPdfExternalSigner {
  @override
  Future<SignerResult?> sign(List<int> message) async {
    return SignerResult(Uint8List(0));
  }

  @override
  SignerResult? signSync(List<int> message) {
    return SignerResult(Uint8List(0));
  }
}
