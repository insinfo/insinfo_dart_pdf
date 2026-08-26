import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

import 'merge_fixtures.dart';

// A file a browser renders must merge. The cross-reference table is the part
// of a PDF most often damaged — a truncated download, a byte range copied
// wrong, a tool that appended without fixing the offsets — and viewers recover
// by ignoring it and scanning the file for object headers. So does this
// library: every case below used to fail to even load.

void main() {
  final List<int> good = MergeFixtures.text(pageCount: 3, prefix: 'Dmg');

  /// Damage a viewer shrugs off, paired with what should survive it.
  final Map<String, List<int>> damaged = <String, List<int>>{
    'garbage before the header': <int>[
      ...'GARBAGE\n\n'.codeUnits,
      ...good,
    ],
    'startxref pointing past the end': _breakStartxref(good),
    'corrupted xref offsets': _breakXrefOffsets(good),
    'tail truncated: no startxref, no trailer': _truncateTail(good, 40),
    'truncated at 95%': good.sublist(0, (good.length * 0.95).floor()),
    'endobj markers wiped': _removeAll(good, 'endobj'),
    'wrong stream /Length': _breakStreamLength(good),
    'no %%EOF': _removeAll(good, '%%EOF'),
    'header without a version': _replaceOnce(good, '%PDF-1.', '%PDF-X.'),
    'a byte flipped mid file': _flipByte(good, good.length ~/ 2),
  };

  group('damaged input still merges', () {
    test('the undamaged fixture is the baseline', () {
      final PdfDocument document = PdfDocument(inputBytes: good);
      addTearDown(document.dispose);
      expect(document.pages.count, 3);
    });

    for (final MapEntry<String, List<int>> entry in damaged.entries) {
      test('${entry.key}: loads', () {
        final PdfDocument document = PdfDocument(inputBytes: entry.value);
        addTearDown(document.dispose);
        expect(document.pages.count, 3);
      });

      test('${entry.key}: merges', () {
        final List<int> merged = PdfDocument.mergeSync(<List<int>>[
          entry.value,
        ]);
        final PdfDocument result = PdfDocument(inputBytes: merged);
        addTearDown(result.dispose);
        expect(result.pages.count, 3);
        expect(
          PdfTextExtractor(
            result,
          ).extractText(startPageIndex: 0, endPageIndex: 0),
          contains('Dmg 1'),
          reason: 'the recovered page still carries its content',
        );
      });

      test('${entry.key}: merges alongside a healthy document', () {
        final List<int> merged = PdfDocument.mergeSync(<List<int>>[
          MergeFixtures.text(pageCount: 1, prefix: 'Healthy'),
          entry.value,
        ]);
        final PdfDocument result = PdfDocument(inputBytes: merged);
        addTearDown(result.dispose);
        expect(result.pages.count, 4);
      });
    }
  });

  group('input that cannot be recovered fails cleanly', () {
    final Map<String, List<int>> hopeless = <String, List<int>>{
      'empty': <int>[],
      'not a PDF at all': 'this is a text file, not a PDF'.codeUnits,
      'header only': '%PDF-1.7\n'.codeUnits,
      'header and nothing that parses': <int>[
        ...'%PDF-1.7\n'.codeUnits,
        ...List<int>.filled(500, 0x41),
      ],
    };

    for (final MapEntry<String, List<int>> entry in hopeless.entries) {
      test('${entry.key}: throws PdfFormatException, does not hang', () {
        expect(
          () => PdfDocument(inputBytes: entry.value),
          throwsA(isA<PdfFormatException>()),
          reason:
              'a caller wrapping this in a service needs a typed, catchable '
              'failure for bad data',
        );
      });
    }

    test('the failure carries a message worth logging', () {
      try {
        PdfDocument(inputBytes: 'not a pdf'.codeUnits);
        fail('should have thrown');
      } on PdfFormatException catch (e) {
        expect(e.message, isNotEmpty);
        expect(e.toString(), contains('PdfFormatException'));
      }
    });

    test('it is a FormatException, the type Dart code already catches', () {
      // PdfFormatException extends FormatException on purpose: `on
      // FormatException` is what a Dart developer writes by reflex for bad
      // data, and an Error would be the wrong contract for a file someone
      // uploaded.
      expect(
        () => PdfDocument(inputBytes: 'not a pdf'.codeUnits),
        throwsA(isA<FormatException>()),
      );
      expect(
        () => PdfDocument(inputBytes: 'not a pdf'.codeUnits),
        throwsA(isA<Exception>()),
      );
      expect(
        () => PdfDocument(inputBytes: 'not a pdf'.codeUnits),
        isNot(throwsA(isA<Error>())),
        reason: 'bad data is not a programming error',
      );
    });

    test('a failure raised deep in the parser still surfaces as one', () {
      // The library throws ArgumentError in hundreds of places — the lexer,
      // the decompressor, the ASN.1 reader. Converting every one of them would
      // cover only the ones somebody remembered. Loading guards the whole
      // parse instead, so whatever fires underneath reaches the caller as a
      // format problem with the original kept in `cause`.
      final List<int> shredded =
          <String>[
            '%PDF-1.7',
            '1 0 obj',
            '<< /Type /Catalog /Pages 2 0 R >>',
            'endobj',
            '2 0 obj',
            '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
            'trailer',
            '<< /Root 1 0 R >>',
          ].join('\n').codeUnits;
      try {
        PdfDocument(inputBytes: shredded);
        // Recovering is a fine outcome too: the point is that it does not
        // escape as an Error.
      } on PdfFormatException catch (e) {
        expect(e.message, isNotEmpty);
      }
    });
  });
}

List<int> _breakStartxref(List<int> bytes) {
  final String s = String.fromCharCodes(bytes);
  final int i = s.lastIndexOf('startxref');
  if (i < 0) {
    return bytes;
  }
  final int nl = s.indexOf('\n', i + 10);
  return <int>[
    ...bytes.sublist(0, i),
    ...'startxref\n999999'.codeUnits,
    ...bytes.sublist(nl),
  ];
}

List<int> _breakXrefOffsets(List<int> bytes) {
  final String s = String.fromCharCodes(bytes);
  final int i = s.lastIndexOf('xref');
  if (i < 0) {
    return bytes;
  }
  final Uint8List out = Uint8List.fromList(bytes);
  // Shift every 10 digit offset in the table by a bogus amount.
  for (int p = i; p < out.length - 20; p++) {
    if (out[p] >= 0x30 && out[p] <= 0x39) {
      out[p] = 0x39;
    }
    if (p - i > 400) {
      break;
    }
  }
  return out;
}

List<int> _truncateTail(List<int> bytes, int drop) =>
    bytes.sublist(0, bytes.length - drop);

List<int> _removeAll(List<int> bytes, String token) {
  String s = String.fromCharCodes(bytes);
  s = s.replaceAll(token, ' ' * token.length);
  return s.codeUnits;
}

List<int> _replaceOnce(List<int> bytes, String from, String to) {
  final String s = String.fromCharCodes(bytes);
  return s.replaceFirst(from, to).codeUnits;
}

List<int> _breakStreamLength(List<int> bytes) {
  final String s = String.fromCharCodes(bytes);
  final int i = s.indexOf('/Length ');
  if (i < 0) {
    return bytes;
  }
  final int end = s.indexOf('\n', i);
  return <int>[
    ...bytes.sublist(0, i),
    ...'/Length 7'.codeUnits,
    ...bytes.sublist(end),
  ];
}

List<int> _flipByte(List<int> bytes, int at) {
  final Uint8List out = Uint8List.fromList(bytes);
  out[at] = out[at] ^ 0xFF;
  return out;
}
