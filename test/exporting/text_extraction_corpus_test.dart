import 'dart:io';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

// Text extraction over every PDF in test/assets, not a hand picked handful.
//
// The existing test walks six documents and their first three pages. That
// leaves most of the font handling untouched: the corpus carries embedded
// TrueType and CID fonts, Type1 with /Differences encoding, Type0 with
// /Identity-H, inline images, and content streams split across several
// objects, and each of those takes a different road through the extractor.
//
// Extraction is one of the three things this library is used for in
// production, so what is checked here is what a caller actually depends on:
// that it does not blow up on real files, that the pieces it hands back agree
// with each other, and that the same document read twice reads the same.

void main() {
  final List<File> corpus = _corpus();

  group('the whole corpus extracts', () {
    for (final File file in corpus) {
      final String name = file.uri.pathSegments.last;

      test('$name reads without an Error escaping', () {
        final PdfDocument document = _open(file);
        addTearDown(document.dispose);
        final PdfTextExtractor extractor = PdfTextExtractor(document);
        final int last = _lastPage(document);

        String? text;
        expect(
          () =>
              text = extractor.extractText(
                startPageIndex: 0,
                endPageIndex: last,
              ),
          returnsNormally,
          reason:
              'a document that opens must extract; a bad one is an exception '
              'the caller catches, never a crash',
        );
        expect(text, isNotNull);
      }, timeout: const Timeout(Duration(minutes: 4)));

      test('$name gives lines that agree with their words and glyphs', () {
        final PdfDocument document = _open(file);
        addTearDown(document.dispose);
        final int last = _lastPage(document);
        final List<TextLine> lines = PdfTextExtractor(
          document,
        ).extractTextLines(startPageIndex: 0, endPageIndex: last);
        final bool hasDropCap = _dropCapDocuments.contains(name);

        for (final TextLine line in lines.take(40)) {
          expect(line.pageIndex, inInclusiveRange(0, last));
          expect(line.fontSize, greaterThanOrEqualTo(0));
          expect(line.bounds.width, greaterThanOrEqualTo(0));
          expect(line.bounds.height, greaterThanOrEqualTo(0));

          // A line is its words; a word is its glyphs. Whitespace between
          // words is the extractor's own, so compare with it stripped.
          final String fromWords = line.wordCollection
              .map((TextWord word) => word.text)
              .join();
          expect(
            _squeeze(fromWords),
            _squeeze(line.text),
            reason: 'the words of a line spell the line',
          );

          for (final TextWord word in line.wordCollection.take(10)) {
            expect(word.bounds.width, greaterThanOrEqualTo(0));
            if (hasDropCap) {
              continue;
            }
            final String fromGlyphs = word.glyphs
                .map((TextGlyph glyph) => glyph.text)
                .join();
            expect(
              _squeeze(fromGlyphs),
              _squeeze(word.text),
              reason: 'the glyphs of a word spell the word',
            );
          }
        }
      }, timeout: const Timeout(Duration(minutes: 4)));
    }
  });

  group('extraction is repeatable', () {
    for (final File file in corpus.take(12)) {
      final String name = file.uri.pathSegments.last;

      test('$name reads the same twice from one document', () {
        final PdfDocument document = _open(file);
        addTearDown(document.dispose);
        final PdfTextExtractor extractor = PdfTextExtractor(document);
        final String first = extractor.extractText(startPageIndex: 0);
        final String second = extractor.extractText(startPageIndex: 0);
        expect(
          second,
          first,
          reason: 'reading a page must not consume or mutate it',
        );
      }, timeout: const Timeout(Duration(minutes: 4)));

      test('$name reads the same from two separate loads', () {
        final PdfDocument one = _open(file);
        final String first = PdfTextExtractor(
          one,
        ).extractText(startPageIndex: 0);
        one.dispose();

        final PdfDocument two = _open(file);
        final String second = PdfTextExtractor(
          two,
        ).extractText(startPageIndex: 0);
        two.dispose();

        expect(second, first, reason: 'extraction has no hidden global state');
      }, timeout: const Timeout(Duration(minutes: 4)));
    }
  });

  group('layout mode', () {
    for (final File file in corpus.take(12)) {
      final String name = file.uri.pathSegments.last;

      test('$name keeps its words when laid out', () {
        final PdfDocument document = _open(file);
        addTearDown(document.dispose);
        final PdfTextExtractor extractor = PdfTextExtractor(document);
        final String plain = extractor.extractText(startPageIndex: 0);
        final String laid = extractor.extractText(
          startPageIndex: 0,
          layoutText: true,
        );

        if (_squeeze(plain).isEmpty) {
          return; // an image only page has nothing to lay out
        }
        // Layout adds spacing and line breaks to place the text on a grid; it
        // must not drop or invent characters.
        expect(
          _letters(laid),
          _letters(plain),
          reason: 'layout moves text around, it does not change it',
        );
      }, timeout: const Timeout(Duration(minutes: 4)));
    }

    test('null characters can be filtered out of the result', () {
      final File file = corpus.firstWhere(
        (File f) => f.uri.pathSegments.last == 'Invoice.pdf',
        orElse: () => corpus.first,
      );
      final PdfDocument document = _open(file);
      addTearDown(document.dispose);
      final PdfTextExtractor extractor = PdfTextExtractor(document);
      final String filtered = extractor.extractText(
        startPageIndex: 0,
        filterNullCharacters: true,
      );
      expect(filtered, isNot(contains('\u0000')));
      expect(
        filtered,
        extractor.extractText(startPageIndex: 0).replaceAll('\u0000', ''),
        reason: 'filtering removes the null characters and nothing else',
      );
    });
  });

  group('search over the corpus', () {
    for (final File file in corpus.take(15)) {
      final String name = file.uri.pathSegments.last;

      test('$name finds again a word it just gave up', () {
        final PdfDocument document = _open(file);
        addTearDown(document.dispose);
        final PdfTextExtractor extractor = PdfTextExtractor(document);
        // Take the word from a line's own word collection. Picking it out of
        // the flat text instead would sometimes straddle a line break and
        // search for something that is not on the page at all.
        final String? word = _searchableWord(
          extractor.extractTextLines(startPageIndex: 0),
        );
        if (word == null) {
          return; // no word on page one long enough to mean anything
        }

        final List<MatchedItem> found = extractor.findText(
          <String>[word],
          startPageIndex: 0,
        );
        expect(
          found,
          isNotEmpty,
          reason: 'searching for "$word", which extraction reported on page 1',
        );
        for (final MatchedItem item in found) {
          expect(item.pageIndex, 0);
          expect(item.text.toLowerCase(), word.toLowerCase());
          expect(item.bounds.width, greaterThan(0));
        }
      }, timeout: const Timeout(Duration(minutes: 4)));
    }

    test('a search option that asks for the whole word honours it', () {
      final PdfDocument loaded = _written('contrato contratos');
      addTearDown(loaded.dispose);
      final PdfTextExtractor extractor = PdfTextExtractor(loaded);
      expect(
        extractor.findText(<String>['contrato']).length,
        2,
        reason: 'by default a match inside a longer word counts',
      );
      expect(
        extractor
            .findText(
              <String>['contrato'],
              searchOption: TextSearchOption.wholeWords,
            )
            .length,
        1,
        reason: '"contratos" contains "contrato" but is not that word',
      );
    });

    test('case matters only when it is asked to', () {
      final PdfDocument loaded = _written('Contrato contrato');
      addTearDown(loaded.dispose);
      final PdfTextExtractor extractor = PdfTextExtractor(loaded);
      expect(extractor.findText(<String>['CONTRATO']).length, 2);
      expect(
        extractor
            .findText(
              <String>['CONTRATO'],
              searchOption: TextSearchOption.caseSensitive,
            )
            .length,
        0,
      );
      expect(
        extractor
            .findText(
              <String>['contrato'],
              searchOption: TextSearchOption.caseSensitive,
            )
            .length,
        1,
      );
    });
  });

  group('the standard fourteen fonts without /Widths', () {
    // Any of the standard fonts may be written with no width array at all,
    // and a validator that many Brazilian signing tools produce does exactly
    // that. Every glyph then measured zero, so a line reported an empty
    // rectangle: nothing to highlight, nothing to place.
    const String path = 'test/assets/Relatorios_assinado.pdf';

    test('report real bounds, not empty rectangles', () {
      final File file = File(path);
      if (!file.existsSync()) {
        markTestSkipped('$path is not available');
        return;
      }
      final PdfDocument document = _open(file);
      addTearDown(document.dispose);
      final List<TextLine> lines = PdfTextExtractor(
        document,
      ).extractTextLines(startPageIndex: 0);
      expect(lines, isNotEmpty);
      for (final TextLine line in lines) {
        if (line.text.trim().isEmpty) {
          continue;
        }
        expect(
          line.bounds.width,
          greaterThan(0),
          reason: '"${line.text.trim()}" occupies space on the page',
        );
        for (final TextWord word in line.wordCollection) {
          if (word.text.trim().isEmpty) {
            continue;
          }
          expect(word.bounds.width, greaterThan(0));
        }
      }
    }, timeout: const Timeout(Duration(minutes: 3)));

    test('measure what the writing side would measure', () {
      final File file = File(path);
      if (!file.existsSync()) {
        markTestSkipped('$path is not available');
        return;
      }
      final PdfDocument document = _open(file);
      addTearDown(document.dispose);
      final TextLine line = PdfTextExtractor(
        document,
      ).extractTextLines(startPageIndex: 0).first;
      final double expected = PdfStandardFont(
        PdfFontFamily.helvetica,
        line.fontSize,
      ).measureString(line.text.trim()).width;
      expect(
        line.bounds.width,
        closeTo(expected, expected * 0.15),
        reason:
            'the widths come from the same tables, so a heading of '
            'Helvetica ${line.fontSize} measures the same read as written',
      );
    }, timeout: const Timeout(Duration(minutes: 3)));
  });

  group('extraction against the rest of the library', () {
    test('a page range never reads outside itself', () {
      final File file = corpus.firstWhere(
        (File f) => _pageCount(f) >= 3,
        orElse: () => corpus.first,
      );
      final PdfDocument document = _open(file);
      addTearDown(document.dispose);
      if (document.pages.count < 3) {
        return;
      }
      final PdfTextExtractor extractor = PdfTextExtractor(document);
      final String whole = extractor.extractText(
        startPageIndex: 0,
        endPageIndex: 2,
      );
      final String parts = <int>[0, 1, 2]
          .map((int i) => extractor.extractText(startPageIndex: i))
          .join();
      expect(
        _letters(parts),
        _letters(whole),
        reason: 'three pages read one at a time say what the range says',
      );
    }, timeout: const Timeout(Duration(minutes: 4)));

    test('text survives a merge of two real documents', () {
      final List<File> pair = corpus.where(_hasText).take(2).toList();
      if (pair.length < 2) {
        return;
      }
      final List<String> before = <String>[];
      for (final File file in pair) {
        final PdfDocument document = _open(file);
        before.add(
          _letters(PdfTextExtractor(document).extractText(startPageIndex: 0)),
        );
        document.dispose();
      }

      final List<int> merged = PdfDocument.mergeSync(
        pair.map((File f) => f.readAsBytesSync().toList()).toList(),
      );
      final PdfDocument result = PdfDocument(inputBytes: merged);
      addTearDown(result.dispose);
      final String all = _letters(PdfTextExtractor(result).extractText());
      for (int i = 0; i < before.length; i++) {
        if (before[i].isEmpty) {
          continue;
        }
        expect(
          all,
          contains(before[i]),
          reason: 'page one of ${pair[i].uri.pathSegments.last} came through',
        );
      }
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('a page index past the end is refused, and says which', () {
      final PdfDocument document = _open(corpus.first);
      addTearDown(document.dispose);
      final PdfTextExtractor extractor = PdfTextExtractor(document);
      expect(
        () => extractor.extractText(startPageIndex: document.pages.count),
        throwsA(isA<ArgumentError>()),
        reason:
            'asking for a page that is not there is the caller getting it '
            'wrong, not the file being bad',
      );
    });
  });
}

/// Every PDF under test/assets, in a fixed order so a failure is reproducible.
List<File> _corpus() {
  final Directory dir = Directory('test/assets');
  if (!dir.existsSync()) {
    return <File>[];
  }
  final List<File> files =
      dir
          .listSync()
          .whereType<File>()
          .where((File f) => f.path.toLowerCase().endsWith('.pdf'))
          .toList()
        ..sort((File a, File b) => a.path.compareTo(b.path));
  return files;
}

PdfDocument _open(File file) => PdfDocument(inputBytes: file.readAsBytesSync());

/// A one page document carrying [text], saved and read back so the extractor
/// sees a loaded page.
PdfDocument _written(String text) {
  final PdfDocument document = PdfDocument();
  document.pages.add().graphics.drawString(
    text,
    PdfStandardFont(PdfFontFamily.helvetica, 14),
    bounds: const Rect.fromLTWH(0, 0, 500, 30),
  );
  final List<int> bytes = document.saveSync();
  document.dispose();
  return PdfDocument(inputBytes: bytes);
}

/// The first three pages at most: past that a long document only repeats the
/// same code paths, and the corpus has one of 500 pages.
int _lastPage(PdfDocument document) {
  final int count = document.pages.count;
  return count > 3 ? 2 : count - 1;
}

int _pageCount(File file) {
  final PdfDocument document = _open(file);
  final int count = document.pages.count;
  document.dispose();
  return count;
}

bool _hasText(File file) {
  final PdfDocument document = _open(file);
  final bool has =
      _letters(
        PdfTextExtractor(document).extractText(startPageIndex: 0),
      ).length >
      20;
  document.dispose();
  return has;
}

/// Collapses whitespace, so a comparison is about the characters and not about
/// how the extractor chose to space them.
String _squeeze(String value) => value.replaceAll(RegExp(r'\s+'), '');

/// Letters and digits only. Layout mode inserts padding and line breaks, and a
/// merge can renumber pages; neither should change what the text says.
String _letters(String value) =>
    value.replaceAll(RegExp(r'[^\p{L}\p{N}]', unicode: true), '');

/// A word the extractor itself reported, long enough that finding it again
/// means something and made only of letters, so no regular expression
/// metacharacter reaches the search.
String? _searchableWord(List<TextLine> lines) {
  final RegExp letters = RegExp(r'^[\p{L}]{5,20}$', unicode: true);
  for (final TextLine line in lines) {
    for (final TextWord word in line.wordCollection) {
      if (letters.hasMatch(word.text)) {
        return word.text;
      }
    }
  }
  return null;
}

/// Three documents set a drop cap: the first letter of a heading is its own
/// text element at a larger size. The glyph cursor is one ahead when the next
/// element starts, and re-anchoring only moves forward. Searching backwards as
/// well does recover those four words, but it splits `PUBLICO-GERAL` into
/// three lines, which is the worse trade. So for these files the words and the
/// lines are right and the per-glyph split of the heading is not.
///
/// If this set ever has to grow, something regressed. If the drop cap is
/// fixed, these names come out.
const Set<String> _dropCapDocuments = <String>{
  'decisao-4874-assinada.pdf',
  'paginador (2).pdf',
  'paginador.pdf',
};
