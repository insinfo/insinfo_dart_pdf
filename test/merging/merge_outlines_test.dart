import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

import 'merge_fixtures.dart';

void main() {
  group('merge - bookmarks', () {
    test('the outline tree is rebuilt in the destination', () {
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        MergeFixtures.bookmarks(),
      ]);

      final PdfDocument result = reopen(merged);
      expect(result.bookmarks.count, 2);
      expect(result.bookmarks[0].title, 'Chapter one');
      expect(result.bookmarks[0].count, 1);
      expect(result.bookmarks[0][0].title, 'Section 1.1');
      expect(result.bookmarks[1].title, 'Chapter two');
      result.dispose();
    });

    test('bookmarks target the imported copy of their page', () {
      final List<int> source = MergeFixtures.bookmarks();
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        source,
        source,
      ]);

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 4);
      expect(result.bookmarks.count, 4);
      expect(
        result.pages.indexOf(result.bookmarks[0].destination!.page),
        0,
        reason: 'the first copy points at its own first page',
      );
      expect(
        result.pages.indexOf(result.bookmarks[1].destination!.page),
        1,
        reason: 'the first copy points at its own second page',
      );
      expect(
        result.pages.indexOf(result.bookmarks[2].destination!.page),
        2,
        reason: 'the second copy points at its own first page',
      );
      expect(
        result.pages.indexOf(result.bookmarks[3].destination!.page),
        3,
        reason: 'the second copy points at its own second page',
      );
      result.dispose();
    });

    test('groupBookmarksPerDocument nests each source under one node', () {
      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[MergeFixtures.bookmarks(), MergeFixtures.bookmarks()],
        options: PdfMergeOptions(groupBookmarksPerDocument: true),
      );

      final PdfDocument result = reopen(merged);
      expect(result.bookmarks.count, 2);
      expect(result.bookmarks[0].count, 2);
      expect(result.bookmarks[0][0].title, 'Chapter one');
      expect(result.bookmarks[1].count, 2);
      result.dispose();
    });

    test('importBookmarks: false leaves the outline empty', () {
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        MergeFixtures.bookmarks(),
      ], options: PdfMergeOptions(importBookmarks: false));

      final PdfDocument result = reopen(merged);
      expect(result.bookmarks.count, 0);
      result.dispose();
    });

    test('a bookmark whose page was not imported keeps no destination', () {
      final PdfDocument output = PdfDocument();
      final PdfDocument source = reopen(MergeFixtures.bookmarks());
      final PdfDocumentMerger merger = PdfDocumentMerger(output);
      // Only the second page is imported; "Chapter one" targets the first.
      merger.importPage(source, 1);
      final List<int> merged = output.saveSync();
      expect(
        merger.warnings.any(
          (String w) => w.contains('outside the imported range'),
        ),
        isTrue,
      );
      source.dispose();
      output.dispose();

      final PdfDocument result = reopen(merged);
      expect(result.bookmarks.count, 2);
      expect(result.bookmarks[0].destination, isNull);
      expect(result.pages.indexOf(result.bookmarks[1].destination!.page), 0);
      result.dispose();
    });
  });
}
