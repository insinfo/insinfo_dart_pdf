import 'dart:convert';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

import '../merging/merge_fixtures.dart';

// Reconstructing a damaged cross-reference table is a guess: the file no
// longer says where its objects are, so the library scans and decides. That is
// what a viewer does and what merging wants, but it is not something a caller
// about to sign the result should get without asking. So it is opt-in, the
// document says whether it happened, and saving one that was repaired is
// governed rather than assumed.

void main() {
  final List<int> healthy = MergeFixtures.text(pageCount: 3, prefix: 'Rep');
  final List<int> damaged = _breakStartxref(healthy);

  PdfDocument load(
    List<int> bytes, {
    PdfStrictnessLevel strictness = PdfStrictnessLevel.lenient,
    PdfRepairedSaveMode repairedSaveMode = PdfRepairedSaveMode.reject,
  }) {
    final PdfDocument document = PdfDocument(
      inputBytes: bytes,
      strictness: strictness,
      repairedSaveMode: repairedSaveMode,
    );
    addTearDown(document.dispose);
    return document;
  }

  group('strictness', () {
    test('conservative is the default', () {
      expect(
        () => PdfDocument(inputBytes: damaged),
        throwsA(isA<PdfFormatException>()),
      );
    });

    test('lenient recovers the document', () {
      expect(load(damaged).pages.count, 3);
    });

    test('the refusal names the way out', () {
      try {
        PdfDocument(inputBytes: damaged);
        fail('expected a PdfFormatException');
      } on PdfFormatException catch (e) {
        expect(e.message, contains('PdfStrictnessLevel.lenient'));
      }
    });

    test('a healthy file is unaffected by either level', () {
      expect(
        load(healthy, strictness: PdfStrictnessLevel.conservative).pages.count,
        3,
      );
      expect(load(healthy).pages.count, 3);
    });

    test('fromBase64String takes the same level', () {
      final String base64String = base64.encode(damaged);
      expect(
        () => PdfDocument.fromBase64String(base64String),
        throwsA(isA<PdfFormatException>()),
      );
      final PdfDocument document = PdfDocument.fromBase64String(
        base64String,
        strictness: PdfStrictnessLevel.lenient,
      );
      addTearDown(document.dispose);
      expect(document.pages.count, 3);
    });
  });

  group('wasRepaired', () {
    test('is false for a healthy document', () {
      expect(load(healthy).wasRepaired, isFalse);
      expect(
        load(healthy, strictness: PdfStrictnessLevel.conservative).wasRepaired,
        isFalse,
      );
    });

    test('is false for a document created from scratch', () {
      final PdfDocument document = PdfDocument();
      addTearDown(document.dispose);
      document.pages.add();
      expect(document.wasRepaired, isFalse);
    });

    test('is true for a document recovered by scanning', () {
      expect(load(damaged).wasRepaired, isTrue);
    });

    test('is true for every pattern that needs the table rebuilt', () {
      expect(load(_truncateTail(healthy, 40)).wasRepaired, isTrue);
      expect(
        load(healthy.sublist(0, (healthy.length * 0.95).floor())).wasRepaired,
        isTrue,
      );
    });
  });

  group('saving a repaired document', () {
    test('is refused by default', () {
      final PdfDocument document = load(damaged);
      expect(
        document.saveSync,
        throwsA(
          isA<PdfFormatException>().having(
            (PdfFormatException e) => e.message,
            'message',
            contains('PdfRepairedSaveMode.fullRewrite'),
          ),
        ),
      );
    });

    test('a full rewrite produces a file that reads back', () {
      final PdfDocument document = load(
        damaged,
        repairedSaveMode: PdfRepairedSaveMode.fullRewrite,
      );
      final List<int> saved = document.saveSync();
      final PdfDocument reloaded = PdfDocument(inputBytes: saved);
      addTearDown(reloaded.dispose);
      expect(
        reloaded.pages.count,
        3,
        reason: 'the output must be sound under the conservative default',
      );
      expect(reloaded.wasRepaired, isFalse);
      expect(
        PdfTextExtractor(
          reloaded,
        ).extractText(startPageIndex: 0, endPageIndex: 0),
        contains('Rep 1'),
      );
    });

    test('the rewrite carries no /Prev back to the damaged offset', () {
      final PdfDocument document = load(
        damaged,
        repairedSaveMode: PdfRepairedSaveMode.fullRewrite,
      );
      expect(
        String.fromCharCodes(document.saveSync()),
        isNot(contains('/Prev')),
        reason:
            'the offset startxref carried is the damaged one; pointing an '
            'appended revision at it is what breaks the output',
      );
    });

    test('the escape hatch saves, and the result is on the caller', () {
      final PdfDocument document = load(
        damaged,
        repairedSaveMode: PdfRepairedSaveMode.incremental,
      );
      final List<int> saved = document.saveSync();
      expect(saved, isNotEmpty);
      expect(
        () => PdfDocument(inputBytes: saved),
        throwsA(isA<PdfFormatException>()),
        reason:
            'an appended revision cannot describe objects that only a scan '
            'found; this mode exists for a caller with its own repair step, '
            'and it still fails as data rather than as an Error',
      );
    });

    test('a healthy document still saves incrementally', () {
      final PdfDocument document = load(healthy);
      final List<int> saved = document.saveSync();
      expect(
        String.fromCharCodes(saved),
        contains('/Prev'),
        reason: 'the repair policy must not touch an undamaged document',
      );
      final PdfDocument reloaded = PdfDocument(inputBytes: saved);
      addTearDown(reloaded.dispose);
      expect(reloaded.pages.count, 3);
    });

    test('merging a repaired source is untouched by the policy', () {
      // A merge writes a fresh document, so the recovered reading never
      // reaches the output as a table anyone has to trust.
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[damaged]);
      final PdfDocument result = PdfDocument(inputBytes: merged);
      addTearDown(result.dispose);
      expect(result.pages.count, 3);
      expect(result.wasRepaired, isFalse);
    });
  });
}

List<int> _breakStartxref(List<int> bytes) {
  final String s = String.fromCharCodes(bytes);
  final int i = s.lastIndexOf('startxref');
  final int nl = s.indexOf('\n', i + 10);
  return <int>[
    ...bytes.sublist(0, i),
    ...'startxref\n999999'.codeUnits,
    ...bytes.sublist(nl),
  ];
}

List<int> _truncateTail(List<int> bytes, int drop) =>
    bytes.sublist(0, bytes.length - drop);
