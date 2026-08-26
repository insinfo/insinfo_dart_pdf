import 'dart:io';

import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_cross_table.dart';
import 'package:dart_pdf/src/pdf/implementation/pdf_document/pdf_document.dart'
    show PdfDocumentHelper;
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_array.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_dictionary.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_name.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_number.dart';
import 'package:dart_pdf/src/pdf/interfaces/pdf_interface.dart';
import 'package:test/test.dart';

import 'merge_fixtures.dart';

void main() {
  group('merge - round trip', () {
    test('a merged document can be merged again', () {
      final List<int> first = PdfDocument.mergeSync(<List<int>>[
        MergeFixtures.text(pageCount: 2, prefix: 'A'),
        MergeFixtures.links(),
      ]);
      final List<int> second = PdfDocument.mergeSync(<List<int>>[
        first,
        MergeFixtures.text(pageCount: 1, prefix: 'C'),
      ]);

      final PdfDocument result = reopen(second);
      expect(result.pages.count, 6);
      expect(pageTextOf(result, 0), contains('A 1'));
      expect(pageTextOf(result, 5), contains('C 1'));
      expect(annotationCountOf(result, 2), 1);
      result.dispose();
    });

    test('merging a merged form keeps the fields addressable', () {
      final List<int> once = PdfDocument.mergeSync(<List<int>>[
        MergeFixtures.form(fieldPrefix: 'a_'),
      ]);
      final List<int> twice = PdfDocument.mergeSync(<List<int>>[
        once,
        MergeFixtures.form(fieldPrefix: 'b_'),
      ]);

      final PdfDocument result = reopen(twice);
      expect(result.form.fields.count, 6);
      result.dispose();
    });

    test('real world text survives the merge unchanged', () {
      final File file = File('test/assets/Invoice.pdf');
      if (!file.existsSync()) {
        markTestSkipped('test/assets/Invoice.pdf is not available');
        return;
      }
      final List<int> bytes = file.readAsBytesSync();
      final PdfDocument original = reopen(bytes);
      final List<String> expected = <String>[
        for (int i = 0; i < original.pages.count; i++)
          pageTextOf(original, i),
      ];
      original.dispose();

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      final PdfDocument result = reopen(merged);
      expect(result.pages.count, expected.length);
      for (int i = 0; i < expected.length; i++) {
        expect(pageTextOf(result, i), expected[i], reason: 'page $i');
      }
      result.dispose();
    });
  });

  group('merge - page labels', () {
    test('label ranges are shifted by the destination offset', () {
      final List<int> labelled = _withPageLabels(
        MergeFixtures.text(pageCount: 3),
      );
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        MergeFixtures.text(pageCount: 2),
        labelled,
      ]);

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 5);
      final PdfArray numbers = _pageLabelNumbers(result)!;
      // The single source range started at page 0; it must now start at 2.
      expect((numbers[0]! as PdfNumber).value, 2);
      final IPdfPrimitive? style = PdfCrossTable.dereference(numbers[1]);
      expect(style, isA<PdfDictionary>());
      expect(
        ((style! as PdfDictionary)['S']! as PdfName).name,
        'r',
        reason: 'the numbering style travelled with the range',
      );
      result.dispose();
    });

    test('importPageLabels: false leaves /PageLabels out', () {
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        _withPageLabels(MergeFixtures.text(pageCount: 2)),
      ], options: PdfMergeOptions(importPageLabels: false));

      final PdfDocument result = reopen(merged);
      expect(_pageLabelNumbers(result), isNull);
      result.dispose();
    });
  });
}

/// Adds a `/PageLabels` number tree with a single lowercase roman range.
///
/// The library has no public API for page labels, so the entry is written
/// straight onto the catalog.
List<int> _withPageLabels(List<int> bytes) {
  final PdfDocument document = reopen(bytes);
  final PdfDictionary style = PdfDictionary();
  style['S'] = PdfName('r');
  final PdfArray numbers = PdfArray();
  numbers.add(PdfNumber(0));
  numbers.add(style);
  final PdfDictionary labels = PdfDictionary();
  labels['Nums'] = numbers;
  PdfDocumentHelper.getHelper(document).catalog['PageLabels'] = labels;
  PdfDocumentHelper.getHelper(document).catalog.modify();
  final List<int> result = document.saveSync();
  document.dispose();
  return result;
}

PdfArray? _pageLabelNumbers(PdfDocument document) {
  final IPdfPrimitive? labels = PdfCrossTable.dereference(
    PdfDocumentHelper.getHelper(document).catalog['PageLabels'],
  );
  if (labels is! PdfDictionary) {
    return null;
  }
  final IPdfPrimitive? numbers = PdfCrossTable.dereference(labels['Nums']);
  return numbers is PdfArray ? numbers : null;
}
