import 'dart:io';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

// Text extraction: the page range API, the line/word/glyph model with its
// geometry, and search. Exercised both on documents this library writes — where
// the expected text is known exactly — and on the real corpus, which is what
// drags the TrueType and CID font readers through their paces.

PdfFont get helvetica => PdfStandardFont(PdfFontFamily.helvetica, 12);

void main() {
  group('extractText', () {
    test('reads back what was written, page by page', () {
      final PdfDocument document = _reopen(_pages(<String>[
        'primeira pagina',
        'segunda pagina',
        'terceira pagina',
      ]));
      addTearDown(document.dispose);
      final PdfTextExtractor extractor = PdfTextExtractor(document);
      expect(
        extractor.extractText(startPageIndex: 0, endPageIndex: 0),
        contains('primeira pagina'),
      );
      expect(
        extractor.extractText(startPageIndex: 2, endPageIndex: 2),
        contains('terceira pagina'),
      );
    });

    test('a range covers every page in it', () {
      final PdfDocument document = _reopen(_pages(<String>[
        'um',
        'dois',
        'tres',
        'quatro',
      ]));
      addTearDown(document.dispose);
      final String text = PdfTextExtractor(
        document,
      ).extractText(startPageIndex: 1, endPageIndex: 2);
      expect(text, contains('dois'));
      expect(text, contains('tres'));
      expect(text, isNot(contains('quatro')));
    });

    test('with no range it reads the whole document', () {
      final PdfDocument document = _reopen(_pages(<String>['alfa', 'beta']));
      addTearDown(document.dispose);
      final String text = PdfTextExtractor(document).extractText();
      expect(text, contains('alfa'));
      expect(text, contains('beta'));
    });

    test('a page index out of range is refused', () {
      final PdfDocument document = _reopen(_pages(<String>['so uma']));
      addTearDown(document.dispose);
      final PdfTextExtractor extractor = PdfTextExtractor(document);
      expect(
        () => extractor.extractText(startPageIndex: 5, endPageIndex: 5),
        throwsA(isA<ArgumentError>()),
        reason: 'asking for a page that is not there is a caller mistake',
      );
    });

    test('an empty page yields empty text, not a failure', () {
      final PdfDocument document = PdfDocument();
      document.pages.add();
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = _reopen(bytes);
      addTearDown(result.dispose);
      expect(
        PdfTextExtractor(
          result,
        ).extractText(startPageIndex: 0, endPageIndex: 0).trim(),
        isEmpty,
      );
    });
  });

  group('extractTextLines', () {
    test('lines carry their text, page index and geometry', () {
      final PdfDocument document = _reopen(
        _pages(<String>['linha de teste']),
      );
      addTearDown(document.dispose);
      final List<TextLine> lines = PdfTextExtractor(
        document,
      ).extractTextLines(startPageIndex: 0, endPageIndex: 0);
      expect(lines, isNotEmpty);
      final TextLine line = lines.first;
      expect(line.text, contains('linha de teste'));
      expect(line.pageIndex, 0);
      expect(line.bounds.width, greaterThan(0));
      expect(line.bounds.height, greaterThan(0));
      expect(line.fontSize, greaterThan(0));
      expect(line.fontName, isNotEmpty);
    });

    test('words and glyphs decompose the line', () {
      final PdfDocument document = _reopen(_pages(<String>['abc def']));
      addTearDown(document.dispose);
      final TextLine line = PdfTextExtractor(
        document,
      ).extractTextLines(startPageIndex: 0, endPageIndex: 0).first;

      expect(line.wordCollection.length, greaterThanOrEqualTo(2));
      final TextWord word = line.wordCollection.first;
      expect(word.text, isNotEmpty);
      expect(word.glyphs, isNotEmpty);
      final TextGlyph glyph = word.glyphs.first;
      expect(glyph.text.length, 1);
      expect(glyph.bounds.width, greaterThan(0));
    });

    test('glyphs run left to right across the line', () {
      final PdfDocument document = _reopen(_pages(<String>['ABCDE']));
      addTearDown(document.dispose);
      final List<TextGlyph> glyphs = PdfTextExtractor(document)
          .extractTextLines(startPageIndex: 0, endPageIndex: 0)
          .expand((TextLine line) => line.wordCollection)
          .expand((TextWord word) => word.glyphs)
          .toList();
      expect(glyphs.length, greaterThanOrEqualTo(5));
      for (int i = 1; i < glyphs.length; i++) {
        expect(
          glyphs[i].bounds.left,
          greaterThanOrEqualTo(glyphs[i - 1].bounds.left - 0.5),
          reason: 'glyph $i sits at or after the one before it',
        );
      }
    });

    test('lines of several pages carry the right page index', () {
      final PdfDocument document = _reopen(
        _pages(<String>['pagina um', 'pagina dois']),
      );
      addTearDown(document.dispose);
      final List<TextLine> lines = PdfTextExtractor(document)
          .extractTextLines(startPageIndex: 0, endPageIndex: 1);
      expect(lines.map((TextLine l) => l.pageIndex).toSet(), <int>{0, 1});
    });
  });

  group('findText', () {
    test('finds a word and reports where it is', () {
      final PdfDocument document = _reopen(
        _pages(<String>['procure por agulha aqui']),
      );
      addTearDown(document.dispose);
      final List<MatchedItem> found = PdfTextExtractor(
        document,
      ).findText(<String>['agulha']);
      expect(found, hasLength(1));
      expect(found.first.text, 'agulha');
      expect(found.first.pageIndex, 0);
      expect(found.first.bounds.width, greaterThan(0));
    });

    test('finds the same word on several pages', () {
      final PdfDocument document = _reopen(
        _pages(<String>['repete aqui', 'nada', 'repete de novo']),
      );
      addTearDown(document.dispose);
      final List<MatchedItem> found = PdfTextExtractor(
        document,
      ).findText(<String>['repete']);
      expect(found.length, 2);
      expect(found.map((MatchedItem m) => m.pageIndex).toSet(), <int>{0, 2});
    });

    test('search is case insensitive unless asked otherwise', () {
      final PdfDocument document = _reopen(_pages(<String>['Maiuscula']));
      addTearDown(document.dispose);
      final PdfTextExtractor extractor = PdfTextExtractor(document);
      expect(extractor.findText(<String>['maiuscula']), isNotEmpty);
      expect(
        extractor.findText(
          <String>['maiuscula'],
          searchOption: TextSearchOption.caseSensitive,
        ),
        isEmpty,
      );
    });

    test('whole word search ignores a substring hit', () {
      final PdfDocument document = _reopen(_pages(<String>['contracapa']));
      addTearDown(document.dispose);
      final PdfTextExtractor extractor = PdfTextExtractor(document);
      expect(extractor.findText(<String>['capa']), isNotEmpty);
      expect(
        extractor.findText(
          <String>['capa'],
          searchOption: TextSearchOption.wholeWords,
        ),
        isEmpty,
      );
    });

    test('several terms are searched at once', () {
      final PdfDocument document = _reopen(
        _pages(<String>['alfa e beta e gama']),
      );
      addTearDown(document.dispose);
      final List<MatchedItem> found = PdfTextExtractor(
        document,
      ).findText(<String>['alfa', 'gama']);
      expect(found.map((MatchedItem m) => m.text).toSet(),
          <String>{'alfa', 'gama'});
    });

    test('a term that is not there returns nothing', () {
      final PdfDocument document = _reopen(_pages(<String>['presente']));
      addTearDown(document.dispose);
      expect(
        PdfTextExtractor(document).findText(<String>['ausente']),
        isEmpty,
      );
    });
  });

  group('embedded fonts', () {
    test('text in an embedded TrueType font extracts', () {
      final File file = File(_findFont());
      final PdfDocument document = PdfDocument();
      document.pages.add().graphics.drawString(
        'fonte embutida',
        PdfTrueTypeFont(file.readAsBytesSync(), 14),
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(30, 30, 400, 24),
      );
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = _reopen(bytes);
      addTearDown(result.dispose);
      expect(
        PdfTextExtractor(
          result,
        ).extractText(startPageIndex: 0, endPageIndex: 0),
        contains('fonte embutida'),
      );
    });

    test('accented text in an embedded font round trips', () {
      final File file = File(_findFont());
      final PdfDocument document = PdfDocument();
      document.pages.add().graphics.drawString(
        'coração ação três',
        PdfTrueTypeFont(file.readAsBytesSync(), 14),
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(30, 30, 400, 24),
      );
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = _reopen(bytes);
      addTearDown(result.dispose);
      final String text = PdfTextExtractor(
        result,
      ).extractText(startPageIndex: 0, endPageIndex: 0);
      expect(text, contains('coração'));
      expect(text, contains('três'));
    });

    test('each of the standard fonts extracts', () {
      for (final PdfFontFamily family in PdfFontFamily.values) {
        final PdfDocument document = PdfDocument();
        document.pages.add().graphics.drawString(
          'familia ${family.name}',
          PdfStandardFont(family, 12),
          brush: PdfBrushes.black,
          bounds: const Rect.fromLTWH(20, 20, 400, 20),
        );
        final List<int> bytes = document.saveSync();
        document.dispose();

        final PdfDocument result = _reopen(bytes);
        final String text = PdfTextExtractor(
          result,
        ).extractText(startPageIndex: 0, endPageIndex: 0);
        result.dispose();
        if (family == PdfFontFamily.symbol ||
            family == PdfFontFamily.zapfDingbats) {
          // These map characters to symbols, so the text that comes back is
          // not the text that went in.
          continue;
        }
        expect(text, contains('familia'), reason: family.name);
      }
    });
  });

  group('the real corpus', () {
    const List<String> assets = <String>[
      'test/assets/Invoice.pdf',
      'test/assets/C008_2021_4HD.pdf',
      'test/assets/paginador (3).pdf',
      'test/assets/relatorio_de_conformidade.pdf',
      'test/assets/doc_assinado_icp_brasil_thais.pdf',
      'test/assets/stf-fachin-1.pdf',
    ];

    for (final String path in assets) {
      test('${path.split('/').last} extracts text and lines', () {
        final File file = File(path);
        if (!file.existsSync()) {
          markTestSkipped('$path is not available');
          return;
        }
        final PdfDocument document = PdfDocument(
          inputBytes: file.readAsBytesSync(),
        );
        addTearDown(document.dispose);
        final PdfTextExtractor extractor = PdfTextExtractor(document);
        final int pages = document.pages.count;
        final int last = pages > 3 ? 2 : pages - 1;

        final String text = extractor.extractText(
          startPageIndex: 0,
          endPageIndex: last,
        );
        expect(text, isNotEmpty, reason: 'these documents carry text');

        final List<TextLine> lines = extractor.extractTextLines(
          startPageIndex: 0,
          endPageIndex: last,
        );
        expect(lines, isNotEmpty);
        for (final TextLine line in lines.take(20)) {
          expect(line.pageIndex, inInclusiveRange(0, last));
          expect(line.text, isNotNull);
          expect(line.fontSize, greaterThanOrEqualTo(0));
        }
      }, timeout: const Timeout(Duration(minutes: 3)));
    }

    test('a word taken from a real page is found again by search', () {
      final File file = File('test/assets/Invoice.pdf');
      if (!file.existsSync()) {
        markTestSkipped('test/assets/Invoice.pdf is not available');
        return;
      }
      final PdfDocument document = PdfDocument(
        inputBytes: file.readAsBytesSync(),
      );
      addTearDown(document.dispose);
      final PdfTextExtractor extractor = PdfTextExtractor(document);
      final String word = extractor
          .extractText(startPageIndex: 0, endPageIndex: 0)
          .split(RegExp(r'\s+'))
          .firstWhere(
            (String w) => w.length >= 4 && RegExp(r'^[A-Za-z]+$').hasMatch(w),
            orElse: () => '',
          );
      if (word.isEmpty) {
        markTestSkipped('no plain word on the first page');
        return;
      }
      final List<MatchedItem> found = extractor.findText(
        <String>[word],
        startPageIndex: 0,
        endPageIndex: 0,
      );
      expect(found, isNotEmpty, reason: 'searching for "$word"');
    });

    test('text is identical before and after a merge', () {
      final File file = File('test/assets/C008_2021_4HD.pdf');
      if (!file.existsSync()) {
        markTestSkipped('asset is not available');
        return;
      }
      final List<int> bytes = file.readAsBytesSync();
      final PdfDocument original = PdfDocument(inputBytes: bytes);
      final String before = PdfTextExtractor(
        original,
      ).extractText(startPageIndex: 0, endPageIndex: 2);
      original.dispose();

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      final PdfDocument result = PdfDocument(inputBytes: merged);
      addTearDown(result.dispose);
      expect(
        PdfTextExtractor(
          result,
        ).extractText(startPageIndex: 0, endPageIndex: 2),
        before,
      );
    }, timeout: const Timeout(Duration(minutes: 3)));
  });
}

PdfDocument _reopen(List<int> bytes) => PdfDocument(inputBytes: bytes);

/// A document with one line of the given text per page.
List<int> _pages(List<String> texts) {
  final PdfDocument document = PdfDocument();
  for (final String text in texts) {
    document.pages.add().graphics.drawString(
      text,
      helvetica,
      brush: PdfBrushes.black,
      bounds: const Rect.fromLTWH(30, 30, 450, 20),
    );
  }
  final List<int> bytes = document.saveSync();
  document.dispose();
  return bytes;
}

String _findFont() {
  const List<String> candidates = <String>[
    r'C:\Windows\Fonts\arial.ttf',
    r'C:\Windows\Fonts\calibri.ttf',
    r'C:\Windows\Fonts\segoeui.ttf',
    '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
    '/System/Library/Fonts/Supplemental/Arial.ttf',
  ];
  for (final String candidate in candidates) {
    if (File(candidate).existsSync()) {
      return candidate;
    }
  }
  throw StateError('No TrueType font found for the test.');
}
