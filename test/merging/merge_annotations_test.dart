import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_cross_table.dart';
import 'package:dart_pdf/src/pdf/implementation/pages/pdf_page.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_array.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_dictionary.dart';
import 'package:dart_pdf/src/pdf/interfaces/pdf_interface.dart';
import 'package:test/test.dart';

import 'merge_fixtures.dart';

void main() {
  group('merge - annotations and links', () {
    test('annotations survive the merge', () {
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        MergeFixtures.links(),
      ]);

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 3);
      expect(annotationCountOf(result, 0), 1);
      expect(annotationCountOf(result, 1), 1);
      expect(annotationCountOf(result, 2), 0);
      result.dispose();
    });

    test('an internal link retargets the imported copy of its page', () {
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        MergeFixtures.links(),
      ]);

      final PdfDocument result = reopen(merged);
      final IPdfPrimitive? target = _linkTargetOf(result, 0);
      expect(target, isNotNull, reason: 'the link kept a destination');
      expect(
        _isPageOfDocument(target!, result, 2),
        isTrue,
        reason: 'the destination is the third page of the merged document',
      );
      result.dispose();
    });

    test('two copies of the same document keep independent links', () {
      final List<int> source = MergeFixtures.links();
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        source,
        source,
      ]);

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 6);
      final IPdfPrimitive? firstCopy = _linkTargetOf(result, 0);
      final IPdfPrimitive? secondCopy = _linkTargetOf(result, 3);
      expect(firstCopy, isNotNull);
      expect(secondCopy, isNotNull);
      expect(
        _isPageOfDocument(firstCopy!, result, 2),
        isTrue,
        reason: 'the first copy links inside itself',
      );
      expect(
        _isPageOfDocument(secondCopy!, result, 5),
        isTrue,
        reason: 'the second copy links inside itself, not into the first',
      );
      result.dispose();
    });

    test('a URI link keeps its target', () {
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        MergeFixtures.links(),
      ]);

      final PdfDocument result = reopen(merged);
      final PdfAnnotation annotation = result.pages[1].annotations[0];
      expect(annotation, isA<PdfUriAnnotation>());
      expect((annotation as PdfUriAnnotation).uri, 'https://example.org/');
      result.dispose();
    });

    test('a link to a page outside the imported range is dropped', () {
      final PdfDocument output = PdfDocument();
      final PdfDocument source = reopen(MergeFixtures.links());
      // Only the first page comes across; its link targets the third one.
      final PdfDocumentMerger merger = PdfDocumentMerger(output);
      merger.importPage(source, 0);
      final List<int> merged = output.saveSync();
      expect(
        merger.warnings.any((String w) => w.contains('outside the imported')),
        isTrue,
      );
      source.dispose();
      output.dispose();

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 1);
      expect(_linkTargetOf(result, 0), isNull);
      result.dispose();
    });

    test('importAnnotations: false leaves the pages bare', () {
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        MergeFixtures.links(),
      ], options: PdfMergeOptions(importAnnotations: false));

      final PdfDocument result = reopen(merged);
      expect(annotationCountOf(result, 0), 0);
      expect(annotationCountOf(result, 1), 0);
      result.dispose();
    });
  });
}

/// The first element of the destination array of the first annotation on
/// page [pageIndex], or `null` when the annotation lost its destination.
IPdfPrimitive? _linkTargetOf(PdfDocument document, int pageIndex) {
  final PdfDictionary page =
      PdfPageHelper.getHelper(document.pages[pageIndex]).dictionary!;
  final IPdfPrimitive? annots = PdfCrossTable.dereference(page['Annots']);
  if (annots is! PdfArray || annots.count == 0) {
    return null;
  }
  final IPdfPrimitive? annotation = PdfCrossTable.dereference(annots[0]);
  if (annotation is! PdfDictionary) {
    return null;
  }
  IPdfPrimitive? destination = PdfCrossTable.dereference(annotation['Dest']);
  if (destination is! PdfArray) {
    final IPdfPrimitive? action = PdfCrossTable.dereference(annotation['A']);
    if (action is PdfDictionary) {
      destination = PdfCrossTable.dereference(action['D']);
    }
  }
  if (destination is! PdfArray || destination.count == 0) {
    return null;
  }
  return PdfCrossTable.dereference(destination[0]);
}

/// Whether [target] is the page at [pageIndex] of [document].
bool _isPageOfDocument(
  IPdfPrimitive target,
  PdfDocument document,
  int pageIndex,
) {
  return identical(
    target,
    PdfPageHelper.getHelper(document.pages[pageIndex]).dictionary,
  );
}
