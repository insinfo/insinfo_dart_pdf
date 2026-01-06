import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dart_pdf/src/flutter/ui.dart';

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
  /// Controls whether /Contents lookup uses the internal parser-based flow.
  static bool useInternalContentsParser = false;

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

  /// Computes the Base64 SHA-256 hash of the provided ByteRange.
  static String computeByteRangeHashBase64(
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

    final List<int> digestBytes = output.events.single.bytes;
    return base64Encode(digestBytes);
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
    // TODO(isaque): replace this regex scan with a parser-based lookup for /ByteRange.
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
