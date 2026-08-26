import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_cross_table.dart';
import 'package:dart_pdf/src/pdf/implementation/pages/pdf_page.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_array.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_dictionary.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_name.dart';
import 'package:dart_pdf/src/pdf/interfaces/pdf_interface.dart';
import 'package:test/test.dart';

/// Round trips every annotation type the library can create: build it, save,
/// reload, and check the document really carries it. Several of these types
/// had no test at all.
void main() {
  group('annotation types round trip', () {
    test('rectangle', () {
      final List<int> bytes = _withAnnotation(
        (PdfPage page) => PdfRectangleAnnotation(
          const Rect.fromLTWH(20, 20, 120, 60),
          'a rectangle',
          color: PdfColor(255, 0, 0),
          innerColor: PdfColor(255, 255, 0),
          author: 'tester',
          subject: 'shapes',
          setAppearance: true,
        ),
      );
      expect(_subtypesOf(bytes), contains('Square'));
    });

    test('ellipse', () {
      final List<int> bytes = _withAnnotation(
        (PdfPage page) => PdfEllipseAnnotation(
          const Rect.fromLTWH(30, 120, 100, 80),
          'an ellipse',
          color: PdfColor(0, 128, 0),
          innerColor: PdfColor(200, 255, 200),
          setAppearance: true,
        ),
      );
      expect(_subtypesOf(bytes), contains('Circle'));
    });

    test('line', () {
      final List<int> bytes = _withAnnotation(
        (PdfPage page) => PdfLineAnnotation(
          <int>[40, 240, 240, 300],
          'a line',
          color: PdfColor(0, 0, 255),
          author: 'tester',
          setAppearance: true,
        ),
      );
      expect(_subtypesOf(bytes), contains('Line'));
    });

    test('polygon', () {
      final List<int> bytes = _withAnnotation(
        (PdfPage page) => PdfPolygonAnnotation(
          <int>[60, 340, 200, 340, 130, 430],
          'a polygon',
          color: PdfColor(128, 0, 128),
          setAppearance: true,
        ),
      );
      expect(_subtypesOf(bytes), contains('Polygon'));
    });

    test('text markup', () {
      final List<int> bytes = _withAnnotation(
        (PdfPage page) => PdfTextMarkupAnnotation(
          const Rect.fromLTWH(40, 460, 200, 20),
          'highlighted',
          PdfColor(255, 255, 0),
          author: 'tester',
          textMarkupAnnotationType: PdfTextMarkupAnnotationType.highlight,
        ),
      );
      expect(_subtypesOf(bytes), contains('Highlight'));
    });

    test('popup', () {
      final List<int> bytes = _withAnnotation(
        (PdfPage page) => PdfPopupAnnotation(
          const Rect.fromLTWH(300, 40, 30, 30),
          'a note',
          author: 'tester',
          icon: PdfPopupIcon.comment,
          open: true,
        ),
      );
      expect(_subtypesOf(bytes), contains('Text'));
    });

    test('uri link', () {
      final List<int> bytes = _withAnnotation(
        (PdfPage page) => PdfUriAnnotation(
          bounds: const Rect.fromLTWH(40, 520, 160, 20),
          uri: 'https://example.org/',
        ),
      );
      expect(_subtypesOf(bytes), contains('Link'));
    });

    test('document link', () {
      final PdfDocument document = PdfDocument();
      final PdfPage first = document.pages.add();
      final PdfPage second = document.pages.add();
      first.annotations.add(
        PdfDocumentLinkAnnotation(
          const Rect.fromLTWH(40, 560, 160, 20),
          PdfDestination(second, const Offset(0, 0)),
        ),
      );
      final List<int> bytes = document.saveSync();
      document.dispose();
      expect(_subtypesOf(bytes), contains('Link'));
    });
  });

  group('annotation properties survive the round trip', () {
    test('an author and a subject come back', () {
      final List<int> bytes = _withAnnotation(
        (PdfPage page) => PdfRectangleAnnotation(
          const Rect.fromLTWH(10, 10, 50, 50),
          'text of the annotation',
          author: 'Isaque',
          subject: 'assunto',
          setAppearance: true,
        ),
      );
      final PdfDocument document = PdfDocument(inputBytes: bytes);
      addTearDown(document.dispose);
      final PdfAnnotation annotation = document.pages[0].annotations[0];
      expect(annotation.text, 'text of the annotation');
      expect(annotation.author, 'Isaque');
      expect(annotation.subject, 'assunto');
    });

    test('bounds come back where they were put, margins aside', () {
      // Annotation bounds on a new page are given inside the page margins;
      // reloading reports them in page space. With the default 40pt margin the
      // two differ by exactly that, which is worth pinning down: it is the
      // difference between an annotation landing where the caller drew and
      // landing 40pt away.
      const Rect bounds = Rect.fromLTWH(72, 144, 200, 36);
      final List<int> bytes = _withAnnotation(
        (PdfPage page) => PdfRectangleAnnotation(
          bounds,
          'bounded',
          setAppearance: true,
        ),
      );
      final PdfDocument document = PdfDocument(inputBytes: bytes);
      addTearDown(document.dispose);
      final Rect actual = document.pages[0].annotations[0].bounds;
      expect(actual.left, closeTo(bounds.left + 40, 1));
      expect(actual.width, closeTo(bounds.width, 1));
      expect(actual.height, closeTo(bounds.height, 1));
    });

    test('with no margin the bounds come back unchanged', () {
      const Rect bounds = Rect.fromLTWH(72, 144, 200, 36);
      final PdfDocument document = PdfDocument();
      document.pageSettings.margins.all = 0;
      document.pages.add().annotations.add(
        PdfRectangleAnnotation(bounds, 'bounded', setAppearance: true),
      );
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      final Rect actual = result.pages[0].annotations[0].bounds;
      expect(actual.left, closeTo(bounds.left, 1));
      expect(actual.top, closeTo(bounds.top, 1));
      expect(actual.width, closeTo(bounds.width, 1));
      expect(actual.height, closeTo(bounds.height, 1));
    });

    test('several annotations on one page all survive', () {
      final PdfDocument document = PdfDocument();
      final PdfPage page = document.pages.add();
      page.annotations
        ..add(
          PdfRectangleAnnotation(
            const Rect.fromLTWH(10, 10, 40, 40),
            'r',
            setAppearance: true,
          ),
        )
        ..add(
          PdfEllipseAnnotation(
            const Rect.fromLTWH(60, 10, 40, 40),
            'e',
            setAppearance: true,
          ),
        )
        ..add(
          PdfUriAnnotation(
            bounds: const Rect.fromLTWH(110, 10, 40, 40),
            uri: 'https://example.org/',
          ),
        );
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      expect(result.pages[0].annotations.count, 3);
    });
  });

  group('annotations survive a merge', () {
    test('every type is still there afterwards', () {
      final PdfDocument document = PdfDocument();
      final PdfPage page = document.pages.add();
      page.annotations
        ..add(
          PdfRectangleAnnotation(
            const Rect.fromLTWH(10, 10, 40, 40),
            'r',
            setAppearance: true,
          ),
        )
        ..add(
          PdfEllipseAnnotation(
            const Rect.fromLTWH(60, 10, 40, 40),
            'e',
            setAppearance: true,
          ),
        )
        ..add(
          PdfLineAnnotation(
            <int>[10, 100, 200, 160],
            'l',
            setAppearance: true,
          ),
        )
        ..add(
          PdfPolygonAnnotation(
            <int>[10, 200, 100, 200, 55, 280],
            'p',
            setAppearance: true,
          ),
        );
      final List<int> bytes = document.saveSync();
      document.dispose();

      final Set<String> before = _subtypesOf(bytes);
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      expect(_subtypesOf(merged), before);
    });
  });
}

/// Builds a one page document carrying the annotation [build] returns.
List<int> _withAnnotation(PdfAnnotation Function(PdfPage) build) {
  final PdfDocument document = PdfDocument();
  final PdfPage page = document.pages.add();
  page.annotations.add(build(page));
  final List<int> bytes = document.saveSync();
  document.dispose();
  return bytes;
}

/// The `/Subtype` of every annotation in a document.
Set<String> _subtypesOf(List<int> bytes) {
  final PdfDocument document = PdfDocument(inputBytes: bytes);
  final Set<String> subtypes = <String>{};
  for (int i = 0; i < document.pages.count; i++) {
    final PdfDictionary page =
        PdfPageHelper.getHelper(document.pages[i]).dictionary!;
    final IPdfPrimitive? annots = PdfCrossTable.dereference(page['Annots']);
    if (annots is! PdfArray) {
      continue;
    }
    for (int j = 0; j < annots.count; j++) {
      final IPdfPrimitive? annotation = PdfCrossTable.dereference(annots[j]);
      if (annotation is! PdfDictionary) {
        continue;
      }
      final IPdfPrimitive? subtype = PdfCrossTable.dereference(
        annotation['Subtype'],
      );
      if (subtype is PdfName) {
        subtypes.add(subtype.name!);
      }
    }
  }
  document.dispose();
  return subtypes;
}
