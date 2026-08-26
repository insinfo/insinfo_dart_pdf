import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

import 'merge_fixtures.dart';

void main() {
  group('merge - page structure', () {
    test('appendDocument concatenates the pages of both documents', () {
      final List<int> first = MergeFixtures.text(pageCount: 2, prefix: 'A');
      final List<int> second = MergeFixtures.text(pageCount: 3, prefix: 'B');

      final PdfDocument output = PdfDocument();
      final PdfDocument a = reopen(first);
      final PdfDocument b = reopen(second);
      output.appendDocument(a);
      output.appendDocument(b);
      final List<int> merged = output.saveSync();
      a.dispose();
      b.dispose();
      output.dispose();

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 5);
      expect(pageTextOf(result, 0), contains('A 1'));
      expect(pageTextOf(result, 1), contains('A 2'));
      expect(pageTextOf(result, 2), contains('B 1'));
      expect(pageTextOf(result, 4), contains('B 3'));
      result.dispose();
    });

    test('mergeSync merges raw bytes in order', () {
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        MergeFixtures.text(pageCount: 1, prefix: 'First'),
        MergeFixtures.text(pageCount: 2, prefix: 'Second'),
      ]);

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 3);
      expect(pageTextOf(result, 0), contains('First 1'));
      expect(pageTextOf(result, 1), contains('Second 1'));
      expect(pageTextOf(result, 2), contains('Second 2'));
      result.dispose();
    });

    test('merge is the asynchronous counterpart of mergeSync', () async {
      final List<int> merged = await PdfDocument.merge(<List<int>>[
        MergeFixtures.text(pageCount: 1, prefix: 'Async'),
        MergeFixtures.text(pageCount: 1, prefix: 'Async2'),
      ]);

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 2);
      result.dispose();
    });

    test('page size is preserved per page', () {
      final List<int> a4 = MergeFixtures.text(
        pageCount: 1,
        size: PdfPageSize.a4,
      );
      final List<int> a5 = MergeFixtures.text(
        pageCount: 1,
        size: PdfPageSize.a5,
      );
      final List<int> letter = MergeFixtures.text(
        pageCount: 1,
        size: PdfPageSize.letter,
      );

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        a4,
        a5,
        letter,
      ]);
      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 3);
      expect(result.pages[0].size.width, closeTo(PdfPageSize.a4.width, 0.5));
      expect(result.pages[0].size.height, closeTo(PdfPageSize.a4.height, 0.5));
      expect(result.pages[1].size.width, closeTo(PdfPageSize.a5.width, 0.5));
      expect(result.pages[1].size.height, closeTo(PdfPageSize.a5.height, 0.5));
      expect(
        result.pages[2].size.width,
        closeTo(PdfPageSize.letter.width, 0.5),
      );
      expect(
        result.pages[2].size.height,
        closeTo(PdfPageSize.letter.height, 0.5),
      );
      result.dispose();
    });

    test('importPage brings a single page', () {
      final PdfDocument output = PdfDocument();
      final PdfDocument source = reopen(
        MergeFixtures.text(pageCount: 4, prefix: 'Src'),
      );
      output.importPage(source, 2);
      final List<int> merged = output.saveSync();
      source.dispose();
      output.dispose();

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 1);
      expect(pageTextOf(result, 0), contains('Src 3'));
      result.dispose();
    });

    test('importPageRange brings an inclusive range', () {
      final PdfDocument output = PdfDocument();
      final PdfDocument source = reopen(
        MergeFixtures.text(pageCount: 5, prefix: 'Src'),
      );
      output.importPageRange(source, 1, 3);
      final List<int> merged = output.saveSync();
      source.dispose();
      output.dispose();

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 3);
      expect(pageTextOf(result, 0), contains('Src 2'));
      expect(pageTextOf(result, 2), contains('Src 4'));
      result.dispose();
    });

    test('importing into a document that already has pages appends', () {
      final PdfDocument output = PdfDocument();
      output.pages.add().graphics.drawString(
        'Own page',
        PdfStandardFont(PdfFontFamily.helvetica, 20),
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(40, 40, 300, 30),
      );
      final PdfDocument source = reopen(
        MergeFixtures.text(pageCount: 2, prefix: 'Imported'),
      );
      output.appendDocument(source);
      final List<int> merged = output.saveSync();
      source.dispose();
      output.dispose();

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 3);
      expect(pageTextOf(result, 0), contains('Own page'));
      expect(pageTextOf(result, 1), contains('Imported 1'));
      result.dispose();
    });

    test('appending into a loaded destination document works', () {
      final PdfDocument destination = reopen(
        MergeFixtures.text(pageCount: 2, prefix: 'Host'),
      );
      final PdfDocument source = reopen(
        MergeFixtures.text(pageCount: 2, prefix: 'Guest', size: PdfPageSize.a5),
      );
      destination.appendDocument(source);
      final List<int> merged = destination.saveSync();
      source.dispose();
      destination.dispose();

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 4);
      expect(pageTextOf(result, 0), contains('Host 1'));
      expect(pageTextOf(result, 2), contains('Guest 1'));
      expect(pageTextOf(result, 3), contains('Guest 2'));
      expect(result.pages[0].size.width, closeTo(PdfPageSize.a4.width, 0.5));
      expect(result.pages[2].size.width, closeTo(PdfPageSize.a5.width, 0.5));
      result.dispose();
    });

    test('flatten into a loaded destination document works', () {
      final PdfDocument destination = reopen(
        MergeFixtures.text(pageCount: 1, prefix: 'Host'),
      );
      final PdfDocument source = reopen(
        MergeFixtures.text(pageCount: 2, prefix: 'Guest'),
      );
      PdfDocumentMerger(
        destination,
        options: PdfMergeOptions.flatten(),
      ).append(source);
      final List<int> merged = destination.saveSync();
      source.dispose();
      destination.dispose();

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 3);
      expect(pageTextOf(result, 0), contains('Host 1'));
      expect(pageTextOf(result, 1), contains('Guest 1'));
      expect(pageTextOf(result, 2), contains('Guest 2'));
      result.dispose();
    });

    test('out of range indices are rejected', () {
      final PdfDocument output = PdfDocument();
      final PdfDocument source = reopen(MergeFixtures.text(pageCount: 2));
      expect(
        () => output.importPage(source, 5),
        throwsA(isA<PdfMergeException>()),
      );
      expect(
        () => output.importPageRange(source, 1, 0),
        throwsA(isA<PdfMergeException>()),
      );
      source.dispose();
      output.dispose();
    });

    test('a document cannot be merged into itself', () {
      final PdfDocument document = reopen(MergeFixtures.text(pageCount: 1));
      expect(
        () => document.appendDocument(document),
        throwsA(isA<PdfMergeException>()),
      );
      document.dispose();
    });
  });

  group('merge - flatten mode', () {
    test('flatten keeps the graphical content and the page count', () {
      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[
          MergeFixtures.text(pageCount: 2, prefix: 'Flat'),
          MergeFixtures.text(pageCount: 1, prefix: 'Other'),
        ],
        options: PdfMergeOptions.flatten(),
      );

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 3);
      expect(pageTextOf(result, 0), contains('Flat 1'));
      expect(pageTextOf(result, 2), contains('Other 1'));
      result.dispose();
    });

    test('flatten drops annotations', () {
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        MergeFixtures.links(),
      ], options: PdfMergeOptions.flatten());

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 3);
      expect(annotationCountOf(result, 0), 0);
      expect(annotationCountOf(result, 1), 0);
      result.dispose();
    });
  });
}
