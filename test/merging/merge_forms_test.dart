import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

import 'merge_fixtures.dart';

void main() {
  group('merge - form fields', () {
    test('fields and their values survive the merge', () {
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        MergeFixtures.form(),
      ]);

      final PdfDocument result = reopen(merged);
      expect(result.form.fields.count, 3);
      final Map<String, PdfField> byName = _byName(result);
      expect(byName.keys, containsAll(<String>['name', 'agree', 'city']));
      expect((byName['name']! as PdfTextBoxField).text, 'Isaque');
      expect((byName['agree']! as PdfCheckBoxField).isChecked, isTrue);
      result.dispose();
    });

    test('colliding field names are renamed by default', () {
      final List<int> source = MergeFixtures.form();
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        source,
        source,
      ]);

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 2);
      expect(result.form.fields.count, 6);
      final Map<String, PdfField> byName = _byName(result);
      expect(
        byName.keys,
        containsAll(<String>[
          'name',
          'agree',
          'city',
          'name_2',
          'agree_2',
          'city_2',
        ]),
      );
      expect((byName['name_2']! as PdfTextBoxField).text, 'Isaque');
      result.dispose();
    });

    test('keepFirst drops the colliding import', () {
      final List<int> source = MergeFixtures.form();
      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[source, source],
        options: PdfMergeOptions(
          fieldNameConflict: PdfFieldNameConflictPolicy.keepFirst,
        ),
      );

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 2);
      expect(result.form.fields.count, 3);
      result.dispose();
    });

    test('throwError rejects the colliding import', () {
      final List<int> source = MergeFixtures.form();
      expect(
        () => PdfDocument.mergeSync(
          <List<int>>[source, source],
          options: PdfMergeOptions(
            fieldNameConflict: PdfFieldNameConflictPolicy.throwError,
          ),
        ),
        throwsA(isA<PdfMergeException>()),
      );
    });

    test('distinct names from two documents coexist', () {
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        MergeFixtures.form(fieldPrefix: 'a_'),
        MergeFixtures.form(fieldPrefix: 'b_'),
      ]);

      final PdfDocument result = reopen(merged);
      expect(result.form.fields.count, 6);
      final Map<String, PdfField> byName = _byName(result);
      expect(
        byName.keys,
        containsAll(<String>[
          'a_name',
          'a_agree',
          'a_city',
          'b_name',
          'b_agree',
          'b_city',
        ]),
      );
      result.dispose();
    });

    test('importFormFields: false leaves the form empty', () {
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        MergeFixtures.form(),
      ], options: PdfMergeOptions(importFormFields: false));

      final PdfDocument result = reopen(merged);
      expect(result.form.fields.count, 0);
      expect(annotationCountOf(result, 0), 0);
      result.dispose();
    });

    test('warnings report the renames', () {
      final PdfDocument output = PdfDocument();
      final PdfDocumentMerger merger = PdfDocumentMerger(output);
      final PdfDocument a = reopen(MergeFixtures.form());
      final PdfDocument b = reopen(MergeFixtures.form());
      merger.append(a);
      merger.append(b);
      expect(
        merger.warnings.where((String w) => w.contains('renamed')).length,
        3,
      );
      a.dispose();
      b.dispose();
      output.dispose();
    });
  });
}

Map<String, PdfField> _byName(PdfDocument document) {
  final Map<String, PdfField> fields = <String, PdfField>{};
  for (int i = 0; i < document.form.fields.count; i++) {
    final PdfField field = document.form.fields[i];
    fields[field.name!] = field;
  }
  return fields;
}
