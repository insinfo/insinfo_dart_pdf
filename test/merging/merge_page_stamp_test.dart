import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_cross_table.dart';
import 'package:dart_pdf/src/pdf/implementation/pages/pdf_page.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_array.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_dictionary.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_stream.dart';
import 'package:dart_pdf/src/pdf/interfaces/pdf_interface.dart';
import 'package:test/test.dart';

import 'merge_fixtures.dart';

// PdfMergeOptions.onPageImported is the general hook for putting something of
// your own on an imported page — a footer, a page number, a watermark. What it
// must guarantee is that adding that content does not disturb what was
// imported: the original content stream stays byte for byte identical, and no
// graphics state the imported page left open can leak into the new drawing.

// A PdfFont belongs to the document it is drawn into: disposing that document
// disposes the font with it. Each test therefore builds its own.
PdfFont get font => PdfStandardFont(PdfFontFamily.helvetica, 9);

void main() {

  group('onPageImported - the callback contract', () {
    test('fires once per imported page, in order', () {
      final List<int> calls = <int>[];
      PdfDocument.mergeSync(
        <List<int>>[
          MergeFixtures.text(pageCount: 3, prefix: 'A'),
          MergeFixtures.text(pageCount: 2, prefix: 'B'),
        ],
        options: PdfMergeOptions(
          onPageImported: (PdfImportedPage info) {
            calls.add(info.importedPageNumber);
          },
        ),
      );
      expect(calls, <int>[1, 2, 3, 4, 5]);
    });

    test('carries where each page came from and where it landed', () {
      final List<String> seen = <String>[];
      PdfDocument.mergeSync(
        <List<int>>[
          MergeFixtures.text(pageCount: 2, prefix: 'A'),
          MergeFixtures.text(pageCount: 2, prefix: 'B'),
        ],
        options: PdfMergeOptions(
          onPageImported: (PdfImportedPage info) {
            seen.add(
              'src=${info.sourcePageIndex} '
              'dst=${info.destinationPageIndex} '
              'n=${info.importedPageNumber}',
            );
          },
        ),
      );
      expect(seen, <String>[
        'src=0 dst=0 n=1',
        'src=1 dst=1 n=2',
        'src=0 dst=2 n=3',
        'src=1 dst=3 n=4',
      ]);
    });

    test('the source page and document are reachable', () {
      final List<Size> sizes = <Size>[];
      PdfDocument.mergeSync(
        <List<int>>[
          MergeFixtures.text(pageCount: 1, size: PdfPageSize.a5),
        ],
        options: PdfMergeOptions(
          onPageImported: (PdfImportedPage info) {
            expect(info.source.pages.count, 1);
            expect(info.sourcePage.size.width, closeTo(info.page.size.width, 1));
            sizes.add(info.page.size);
          },
        ),
      );
      expect(sizes.single.width, closeTo(PdfPageSize.a5.width, 1));
    });

    test('the counter keeps running across separate calls to the merger', () {
      final List<int> numbers = <int>[];
      final PdfDocument output = PdfDocument();
      final PdfDocumentMerger merger = PdfDocumentMerger(
        output,
        options: PdfMergeOptions(
          onPageImported: (PdfImportedPage info) {
            numbers.add(info.importedPageNumber);
          },
        ),
      );
      final PdfDocument a = reopen(MergeFixtures.text(pageCount: 2));
      final PdfDocument b = reopen(MergeFixtures.text(pageCount: 3));
      merger.append(a);
      merger.append(b);
      a.dispose();
      b.dispose();
      output.dispose();
      expect(numbers, <int>[1, 2, 3, 4, 5]);
    });

    test('it fires in flatten mode too', () {
      final List<int> numbers = <int>[];
      PdfDocument.mergeSync(
        <List<int>>[MergeFixtures.text(pageCount: 2)],
        options: PdfMergeOptions(
          mode: PdfMergeMode.flatten,
          onPageImported: (PdfImportedPage info) {
            numbers.add(info.importedPageNumber);
          },
        ),
      );
      expect(numbers, <int>[1, 2]);
    });
  });

  group('appendGraphics - what it draws', () {
    test('the stamp text ends up on the page', () {
      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[MergeFixtures.text(pageCount: 3, prefix: 'Body')],
        options: PdfMergeOptions(
          onPageImported: (PdfImportedPage info) {
            info.appendGraphics().drawString(
              'Stamp ${info.importedPageNumber}',
              font,
              brush: PdfBrushes.black,
              bounds: Rect.fromLTWH(30, info.page.size.height - 30, 300, 14),
            );
          },
        ),
      );

      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      for (int i = 0; i < 3; i++) {
        final String text = PdfTextExtractor(
          result,
        ).extractText(startPageIndex: i, endPageIndex: i);
        expect(text, contains('Body ${i + 1}'), reason: 'page $i body');
        expect(text, contains('Stamp ${i + 1}'), reason: 'page $i stamp');
      }
    });

    test('a footer naming the source document', () {
      final List<int> first = MergeFixtures.text(pageCount: 2, prefix: 'One');
      final List<int> second = MergeFixtures.text(pageCount: 1, prefix: 'Two');
      final List<String> names = <String>['peca-A', 'peca-B'];
      int documentIndex = -1;
      PdfDocument? lastSource;

      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[first, second],
        options: PdfMergeOptions(
          onPageImported: (PdfImportedPage info) {
            if (!identical(info.source, lastSource)) {
              lastSource = info.source;
              documentIndex++;
            }
            info.appendGraphics().drawString(
              '${names[documentIndex]} - fl. ${info.importedPageNumber}',
              font,
              brush: PdfBrushes.gray,
              bounds: Rect.fromLTWH(30, info.page.size.height - 26, 300, 12),
            );
          },
        ),
      );

      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(
        PdfTextExtractor(result).extractText(
          startPageIndex: 0,
          endPageIndex: 0,
        ),
        contains('peca-A - fl. 1'),
      );
      expect(
        PdfTextExtractor(result).extractText(
          startPageIndex: 2,
          endPageIndex: 2,
        ),
        contains('peca-B - fl. 3'),
      );
    });

    test('it can be called more than once on the same page', () {
      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[MergeFixtures.text(pageCount: 1, prefix: 'Body')],
        options: PdfMergeOptions(
          onPageImported: (PdfImportedPage info) {
            info.appendGraphics().drawString(
              'first stamp',
              font,
              brush: PdfBrushes.black,
              bounds: const Rect.fromLTWH(30, 700, 200, 12),
            );
            info.appendGraphics().drawString(
              'second stamp',
              font,
              brush: PdfBrushes.black,
              bounds: const Rect.fromLTWH(30, 720, 200, 12),
            );
          },
        ),
      );

      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      final String text = PdfTextExtractor(
        result,
      ).extractText(startPageIndex: 0, endPageIndex: 0);
      expect(text, contains('first stamp'));
      expect(text, contains('second stamp'));
      expect(text, contains('Body 1'));
    });

    test('drawing an image works as well as text', () {
      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[MergeFixtures.text(pageCount: 1)],
        options: PdfMergeOptions(
          onPageImported: (PdfImportedPage info) {
            info.appendGraphics().drawRectangle(
              brush: PdfBrushes.yellow,
              bounds: const Rect.fromLTWH(20, 20, 60, 20),
            );
          },
        ),
      );
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(result.pages.count, 1);
    });
  });

  group('appendGraphics - what it must not disturb', () {
    test('the imported content stream is untouched', () {
      final List<int> bytes = MergeFixtures.text(pageCount: 1, prefix: 'Exact');
      final PdfDocument source = reopen(bytes);
      final List<String> original =
          _contentStreamsOf(source, 0).map(String.fromCharCodes).toList();
      source.dispose();

      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[bytes],
        options: PdfMergeOptions(
          onPageImported: (PdfImportedPage info) {
            info.appendGraphics().drawString(
              'stamped',
              font,
              brush: PdfBrushes.black,
              bounds: const Rect.fromLTWH(10, 10, 100, 12),
            );
          },
        ),
      );

      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      final List<String> streams =
          _contentStreamsOf(result, 0).map(String.fromCharCodes).toList();
      for (final String stream in original) {
        expect(
          streams,
          contains(stream),
          reason:
              'every stream of the imported page is still there byte for '
              'byte, in a stream of its own',
        );
      }
    });

    test('the contents array is q / original / Q / stamp', () {
      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[MergeFixtures.text(pageCount: 1)],
        options: PdfMergeOptions(
          onPageImported: (PdfImportedPage info) {
            info.appendGraphics().drawString(
              'stamped',
              font,
              brush: PdfBrushes.black,
              bounds: const Rect.fromLTWH(10, 10, 100, 12),
            );
          },
        ),
      );

      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      final List<String> shape = _contentStreamsOf(
        result,
        0,
      ).map((List<int> s) => String.fromCharCodes(s)).toList();
      expect(shape.first.trim(), 'q', reason: 'the guard opens the array');
      expect(
        shape.any((String s) => s.trim() == 'Q'),
        isTrue,
        reason: 'and closes before the appended content',
      );
      expect(
        shape.last,
        contains('stamped'),
        reason: 'the stamp is the last stream, drawn over everything',
      );
      final int restore = shape.indexWhere((String s) => s.trim() == 'Q');
      expect(
        restore,
        lessThan(shape.length - 1),
        reason: 'the stamp comes after the restore, in a clean state',
      );
    });

    test('state left open by the imported page cannot reach the stamp', () {
      // A page whose content ends mid transform: everything after it would be
      // scaled and shifted unless the merge guards against it.
      final List<int> bytes = _pageWithUnbalancedState();
      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[bytes],
        options: PdfMergeOptions(
          onPageImported: (PdfImportedPage info) {
            info.appendGraphics().drawString(
              'GUARDED',
              font,
              brush: PdfBrushes.black,
              bounds: const Rect.fromLTWH(20, 40, 200, 14),
            );
          },
        ),
      );

      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      final String text = PdfTextExtractor(
        result,
      ).extractText(startPageIndex: 0, endPageIndex: 0);
      expect(text, contains('GUARDED'));

      final List<TextGlyph> glyphs = PdfTextExtractor(
        result,
      ).extractTextLines(startPageIndex: 0, endPageIndex: 0)
          .expand((TextLine line) => line.wordCollection)
          .expand((TextWord word) => word.glyphs)
          .where((TextGlyph glyph) => glyph.text.trim().isNotEmpty)
          .toList();
      final Iterable<TextGlyph> stamped = glyphs.where(
        (TextGlyph glyph) => glyph.bounds.top > 30 && glyph.bounds.top < 60,
      );
      expect(
        stamped,
        isNotEmpty,
        reason:
            'the stamp sits where it was asked to, not where the leftover '
            'transform would have put it',
      );
    });

    test('annotations imported alongside the stamp survive', () {
      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[MergeFixtures.links()],
        options: PdfMergeOptions(
          onPageImported: (PdfImportedPage info) {
            info.appendGraphics().drawString(
              'fl. ${info.importedPageNumber}',
              font,
              brush: PdfBrushes.gray,
              bounds: const Rect.fromLTWH(10, 10, 100, 12),
            );
          },
        ),
      );
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(result.pages.count, 3);
      expect(annotationCountOf(result, 0), 1);
      expect(annotationCountOf(result, 1), 1);
    });

    test('a stamped merge can be merged again', () {
      final List<int> once = PdfDocument.mergeSync(
        <List<int>>[MergeFixtures.text(pageCount: 2, prefix: 'Body')],
        options: PdfMergeOptions(
          onPageImported: (PdfImportedPage info) {
            info.appendGraphics().drawString(
              'pass one ${info.importedPageNumber}',
              font,
              brush: PdfBrushes.black,
              bounds: const Rect.fromLTWH(10, 700, 200, 12),
            );
          },
        ),
      );
      final List<int> twice = PdfDocument.mergeSync(
        <List<int>>[once],
        options: PdfMergeOptions(
          onPageImported: (PdfImportedPage info) {
            info.appendGraphics().drawString(
              'pass two ${info.importedPageNumber}',
              font,
              brush: PdfBrushes.black,
              bounds: const Rect.fromLTWH(10, 720, 200, 12),
            );
          },
        ),
      );

      final PdfDocument result = reopen(twice);
      addTearDown(result.dispose);
      final String text = PdfTextExtractor(
        result,
      ).extractText(startPageIndex: 0, endPageIndex: 0);
      expect(text, contains('Body 1'));
      expect(text, contains('pass one 1'));
      expect(text, contains('pass two 1'));
    });
  });
}

/// The decompressed content streams of a page, in order.
List<List<int>> _contentStreamsOf(PdfDocument document, int pageIndex) {
  final PdfDictionary page =
      PdfPageHelper.getHelper(document.pages[pageIndex]).dictionary!;
  final IPdfPrimitive? contents = PdfCrossTable.dereference(page['Contents']);
  final List<List<int>> streams = <List<int>>[];
  if (contents is PdfStream) {
    streams.add(contents.getDecompressedData(false)!);
  } else if (contents is PdfArray) {
    for (int i = 0; i < contents.count; i++) {
      final IPdfPrimitive? entry = PdfCrossTable.dereference(contents[i]);
      if (entry is PdfStream) {
        streams.add(entry.getDecompressedData(false)!);
      }
    }
  }
  return streams;
}

/// A one page document whose content stream ends inside a transform, with the
/// `q` never restored — the shape that ruins anything appended after it.
List<int> _pageWithUnbalancedState() {
  final PdfDocument document = PdfDocument();
  final PdfPage page = document.pages.add();
  final PdfGraphics graphics = page.graphics;
  graphics.save();
  graphics.translateTransform(120, 240);
  graphics.rotateTransform(15);
  graphics.drawString(
    'skewed body',
    PdfStandardFont(PdfFontFamily.helvetica, 10),
    brush: PdfBrushes.black,
    bounds: const Rect.fromLTWH(0, 0, 200, 14),
  );
  // Deliberately no restore: the state stays open at the end of the stream.
  final List<int> bytes = document.saveSync();
  document.dispose();
  return bytes;
}
