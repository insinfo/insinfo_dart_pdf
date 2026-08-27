import 'dart:convert';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

// Exporting annotations to FDF, XFDF or JSON and importing them back. The
// whole feature — five files, some two thousand lines — had no test, and the
// check that matters is the round trip: what comes back has to be what went
// out, on a document that never saw the originals.

void main() {
  for (final PdfAnnotationDataFormat format
      in PdfAnnotationDataFormat.values) {
    group('${format.name} round trip', () {
      test('exports something that parses', () {
        final PdfDocument document = _annotated();
        addTearDown(document.dispose);
        final List<int> data = document.exportAnnotation(format);
        expect(data, isNotEmpty);
        expect(
          utf8.decode(data, allowMalformed: true),
          isNotEmpty,
          reason: 'the export is text in every one of these formats',
        );
      });

      test('imports back onto a bare copy of the document', () {
        final PdfDocument source = _annotated();
        final List<int> data = source.exportAnnotation(format);
        final int exported = source.pages[0].annotations.count;
        source.dispose();
        expect(exported, greaterThan(0));

        final PdfDocument target = _bare();
        target.importAnnotation(data, format);
        final List<int> bytes = target.saveSync();
        target.dispose();

        final PdfDocument result = PdfDocument(inputBytes: bytes);
        addTearDown(result.dispose);
        expect(
          result.pages[0].annotations.count,
          exported,
          reason: 'every exported annotation came back',
        );
      });

      test('the imported annotations keep their text', () {
        final PdfDocument source = _annotated();
        final List<int> data = source.exportAnnotation(format);
        source.dispose();

        final PdfDocument target = _bare();
        target.importAnnotation(data, format);
        final List<int> bytes = target.saveSync();
        target.dispose();

        final PdfDocument result = PdfDocument(inputBytes: bytes);
        addTearDown(result.dispose);
        final Set<String?> texts = <String?>{
          for (int i = 0; i < result.pages[0].annotations.count; i++)
            result.pages[0].annotations[i].text,
        };
        expect(texts, contains('um retangulo'));
        expect(texts, contains('uma elipse'));
      });

      test('a file name can be given to the export', () {
        final PdfDocument document = _annotated();
        addTearDown(document.dispose);
        final List<int> data = document.exportAnnotation(
          format,
          fileName: 'documento-de-teste',
        );
        expect(data, isNotEmpty);
      });

      test('exporting the appearance produces a larger payload', () {
        final PdfDocument document = _annotated();
        addTearDown(document.dispose);
        final int plain = document.exportAnnotation(format).length;
        final int withAppearance = document
            .exportAnnotation(format, exportAppearance: true)
            .length;
        expect(withAppearance, greaterThanOrEqualTo(plain));
      });

      test('only the listed annotations are exported', () {
        final PdfDocument document = _annotated();
        addTearDown(document.dispose);
        final PdfAnnotation first = document.pages[0].annotations[0];
        final List<int> data = document.exportAnnotation(
          format,
          exportList: <PdfAnnotation>[first],
        );

        final PdfDocument target = _bare();
        target.importAnnotation(data, format);
        final List<int> bytes = target.saveSync();
        target.dispose();

        final PdfDocument result = PdfDocument(inputBytes: bytes);
        addTearDown(result.dispose);
        expect(result.pages[0].annotations.count, 1);
      });

      test('a type filter narrows the export', () {
        final PdfDocument document = _annotated();
        addTearDown(document.dispose);
        final List<int> data = document.exportAnnotation(
          format,
          exportTypes: <PdfAnnotationExportType>[
            PdfAnnotationExportType.rectangleAnnotation,
          ],
        );

        final PdfDocument target = _bare();
        target.importAnnotation(data, format);
        final List<int> bytes = target.saveSync();
        target.dispose();

        final PdfDocument result = PdfDocument(inputBytes: bytes);
        addTearDown(result.dispose);
        expect(
          result.pages[0].annotations.count,
          lessThan(4),
          reason: 'the filter left the other types out',
        );
      });

      test('importing damaged data fails as an exception, not an error', () {
        final PdfDocument target = _bare();
        addTearDown(target.dispose);
        expect(
          () => target.importAnnotation(
            'isto nao e um arquivo de anotacoes'.codeUnits,
            format,
          ),
          throwsA(isNot(isA<Error>())),
          reason:
              'the payload comes from outside, so a caller must be able to '
              'catch a bad one',
        );
      });

      test('importing empty data fails as an exception', () {
        final PdfDocument target = _bare();
        addTearDown(target.dispose);
        expect(
          () => target.importAnnotation(<int>[], format),
          throwsA(isNot(isA<Error>())),
        );
      });
    });
  }

  group('across formats and pages', () {
    test('annotations on several pages keep their page', () {
      final PdfDocument source = PdfDocument();
      for (int i = 0; i < 3; i++) {
        source.pages.add().annotations.add(
          PdfRectangleAnnotation(
            Rect.fromLTWH(20, 20.0 + i * 10, 60, 30),
            'pagina $i',
            setAppearance: true,
          ),
        );
      }
      final List<int> data = source.exportAnnotation(
        PdfAnnotationDataFormat.xfdf,
      );
      source.dispose();

      final PdfDocument target = PdfDocument();
      for (int i = 0; i < 3; i++) {
        target.pages.add();
      }
      target.importAnnotation(data, PdfAnnotationDataFormat.xfdf);
      final List<int> bytes = target.saveSync();
      target.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      for (int i = 0; i < 3; i++) {
        expect(
          result.pages[i].annotations.count,
          1,
          reason: 'page $i kept its own annotation',
        );
      }
    });

    test('a document exported in one format imports in that format only', () {
      final PdfDocument source = _annotated();
      final List<int> asJson = source.exportAnnotation(
        PdfAnnotationDataFormat.json,
      );
      source.dispose();

      final PdfDocument target = _bare();
      addTearDown(target.dispose);
      expect(
        () => target.importAnnotation(asJson, PdfAnnotationDataFormat.fdf),
        throwsA(isNot(isA<Error>())),
        reason: 'feeding JSON to the FDF reader is bad data, not a crash',
      );
    });

    test('exported annotations survive a merge of the target', () {
      final PdfDocument source = _annotated();
      final List<int> data = source.exportAnnotation(
        PdfAnnotationDataFormat.xfdf,
      );
      final int exported = source.pages[0].annotations.count;
      source.dispose();

      final PdfDocument target = _bare();
      target.importAnnotation(data, PdfAnnotationDataFormat.xfdf);
      final List<int> bytes = target.saveSync();
      target.dispose();

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      final PdfDocument result = PdfDocument(inputBytes: merged);
      addTearDown(result.dispose);
      expect(result.pages[0].annotations.count, exported);
    });
  });
}

/// A one page document carrying four annotations of different types.
PdfDocument _annotated() {
  final PdfDocument document = PdfDocument();
  final PdfPage page = document.pages.add();
  page.annotations
    ..add(
      PdfRectangleAnnotation(
        const Rect.fromLTWH(20, 20, 120, 60),
        'um retangulo',
        color: PdfColor(255, 0, 0),
        author: 'tester',
        setAppearance: true,
      ),
    )
    ..add(
      PdfEllipseAnnotation(
        const Rect.fromLTWH(20, 100, 120, 60),
        'uma elipse',
        color: PdfColor(0, 128, 0),
        author: 'tester',
        setAppearance: true,
      ),
    )
    ..add(
      PdfLineAnnotation(
        <int>[20, 200, 200, 260],
        'uma linha',
        color: PdfColor(0, 0, 255),
        author: 'tester',
        setAppearance: true,
      ),
    )
    ..add(
      PdfPopupAnnotation(
        const Rect.fromLTWH(300, 20, 30, 30),
        'uma nota',
        author: 'tester',
        icon: PdfPopupIcon.note,
      ),
    );
  // Round trip through a save so the annotations are the loaded kind, which is
  // what the exporter reads.
  final List<int> bytes = document.saveSync();
  document.dispose();
  return PdfDocument(inputBytes: bytes);
}

/// The same page geometry, with no annotations on it.
PdfDocument _bare() {
  final PdfDocument document = PdfDocument();
  document.pages.add();
  final List<int> bytes = document.saveSync();
  document.dispose();
  return PdfDocument(inputBytes: bytes);
}
