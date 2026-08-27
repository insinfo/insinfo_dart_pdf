import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_cross_table.dart';
import 'package:dart_pdf/src/pdf/implementation/pdf_document/pdf_document.dart'
    show PdfDocumentHelper;
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_array.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_dictionary.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_string.dart';
import 'package:dart_pdf/src/pdf/interfaces/pdf_interface.dart';
import 'package:test/test.dart';

// Headers, footers and layers: the parts of the page model that put content on
// every page without the caller drawing it each time. Both were untested.

PdfFont get font => PdfStandardFont(PdfFontFamily.helvetica, 11);

void main() {
  group('document templates', () {
    test('a header appears on every page', () {
      final PdfDocument document = PdfDocument();
      document.template.top = PdfPageTemplateElement(
        const Rect.fromLTWH(0, 0, 515, 40),
      )..graphics.drawString(
        'CABECALHO',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(0, 10, 300, 20),
      );
      for (int i = 0; i < 3; i++) {
        document.pages.add().graphics.drawString(
          'corpo ${i + 1}',
          font,
          brush: PdfBrushes.black,
          bounds: const Rect.fromLTWH(0, 100, 300, 20),
        );
      }
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      expect(result.pages.count, 3);
      for (int i = 0; i < 3; i++) {
        expect(
          _textOf(result, i),
          contains('CABECALHO'),
          reason: 'page $i carries the header',
        );
      }
    });

    test('a footer appears on every page', () {
      final PdfDocument document = PdfDocument();
      document.template.bottom = PdfPageTemplateElement(
        const Rect.fromLTWH(0, 0, 515, 40),
      )..graphics.drawString(
        'RODAPE',
        font,
        brush: PdfBrushes.gray,
        bounds: const Rect.fromLTWH(0, 10, 300, 20),
      );
      document.pages.add();
      document.pages.add();
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      expect(_textOf(result, 0), contains('RODAPE'));
      expect(_textOf(result, 1), contains('RODAPE'));
    });

    test('left and right templates draw too', () {
      final PdfDocument document = PdfDocument();
      document.template.left = PdfPageTemplateElement(
        const Rect.fromLTWH(0, 0, 40, 700),
      )..graphics.drawString(
        'E',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(0, 100, 20, 20),
      );
      document.template.right = PdfPageTemplateElement(
        const Rect.fromLTWH(0, 0, 40, 700),
      )..graphics.drawString(
        'D',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(0, 100, 20, 20),
      );
      document.pages.add();
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      final String text = _textOf(result, 0);
      expect(text, contains('E'));
      expect(text, contains('D'));
    });

    test('a page number field on a template counts the pages', () {
      final PdfDocument document = PdfDocument();
      final PdfPageTemplateElement footer = PdfPageTemplateElement(
        const Rect.fromLTWH(0, 0, 515, 40),
      );
      final PdfCompositeField field = PdfCompositeField(
        font: font,
        brush: PdfBrushes.black,
        text: 'fl. {0} de {1}',
        fields: <PdfAutomaticField>[
          PdfPageNumberField(font: font),
          PdfPageCountField(font: font),
        ],
      );
      field.draw(footer.graphics, const Offset(0, 10));
      document.template.bottom = footer;
      for (int i = 0; i < 3; i++) {
        document.pages.add();
      }
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      expect(_textOf(result, 0), contains('fl. 1 de 3'));
      expect(_textOf(result, 2), contains('fl. 3 de 3'));
    });

    test('a section template overrides the document one', () {
      final PdfDocument document = PdfDocument();
      document.template.top = PdfPageTemplateElement(
        const Rect.fromLTWH(0, 0, 515, 40),
      )..graphics.drawString(
        'GERAL',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(0, 10, 300, 20),
      );
      document.pages.add();

      final PdfSection section = document.sections!.add();
      section.template.top = PdfPageTemplateElement(
        const Rect.fromLTWH(0, 0, 515, 40),
      )..graphics.drawString(
        'DA SECAO',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(0, 10, 300, 20),
      );
      // topTemplate = false means: do not also draw the document's top
      // template on this section's pages.
      section.template.topTemplate = false;
      section.pages.add();

      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      expect(_textOf(result, 0), contains('GERAL'));
      expect(_textOf(result, 1), contains('DA SECAO'));
    });

    test('template content survives a merge', () {
      final PdfDocument document = PdfDocument();
      document.template.top = PdfPageTemplateElement(
        const Rect.fromLTWH(0, 0, 515, 40),
      )..graphics.drawString(
        'MARCA',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(0, 10, 300, 20),
      );
      document.pages.add();
      document.pages.add();
      final List<int> bytes = document.saveSync();
      document.dispose();

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      final PdfDocument result = PdfDocument(inputBytes: merged);
      addTearDown(result.dispose);
      expect(_textOf(result, 0), contains('MARCA'));
      expect(_textOf(result, 1), contains('MARCA'));
    });
  });

  group('layers', () {
    test('a named layer is declared in /OCProperties', () {
      final PdfDocument document = PdfDocument();
      final PdfPage page = document.pages.add();
      document.layers.add(name: 'Camada A').createGraphics(page).drawString(
        'na camada',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(20, 20, 200, 20),
      );
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      expect(_layerNames(result), contains('Camada A'));
      expect(_textOf(result, 0), contains('na camada'));
    });

    test('a hidden layer is listed under /OFF', () {
      final PdfDocument document = PdfDocument();
      final PdfPage page = document.pages.add();
      document.layers.add(name: 'Visivel').createGraphics(page).drawString(
        'vis',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(20, 20, 200, 20),
      );
      document.layers
          .add(name: 'Oculta', visible: false)
          .createGraphics(page)
          .drawString(
            'ocu',
            font,
            brush: PdfBrushes.red,
            bounds: const Rect.fromLTWH(20, 60, 200, 20),
          );
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      // Only the hidden one is listed. A group absent from /OFF is on, which
      // is what the specification says, so the library does not write /ON —
      // worth pinning, because the merger does write it and the difference
      // would otherwise look like a bug on one side or the other.
      expect(_stateNames(result, 'OFF'), <String>['Oculta']);
      expect(_layerNames(result), containsAll(<String>['Visivel', 'Oculta']));
    });

    test('layers are readable back from a loaded document', () {
      final PdfDocument document = PdfDocument();
      final PdfPage page = document.pages.add();
      for (final String name in <String>['Um', 'Dois', 'Tres']) {
        document.layers.add(name: name).createGraphics(page).drawString(
          name,
          font,
          brush: PdfBrushes.black,
          bounds: const Rect.fromLTWH(20, 20, 200, 20),
        );
      }
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      expect(result.layers.count, 3);
      expect(result.layers[0].name, 'Um');
      expect(result.layers[2].name, 'Tres');
    });

    test('a page layer added directly appends a content stream', () {
      final PdfDocument document = PdfDocument();
      final PdfPage page = document.pages.add();
      page.graphics.drawString(
        'base',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(20, 20, 200, 20),
      );
      page.layers.add().graphics.drawString(
        'sobreposto',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(20, 60, 200, 20),
      );
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      final String text = _textOf(result, 0);
      expect(text, contains('base'));
      expect(text, contains('sobreposto'));
    });
  });

  group('sections', () {
    test('each section can have its own page size', () {
      final PdfDocument document = PdfDocument();
      final PdfSection a4 = document.sections!.add();
      a4.pageSettings = PdfPageSettings(PdfPageSize.a4);
      a4.pages.add();
      final PdfSection a5 = document.sections!.add();
      a5.pageSettings = PdfPageSettings(PdfPageSize.a5);
      a5.pages.add();
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      expect(result.pages.count, 2);
      expect(result.pages[0].size.width, closeTo(PdfPageSize.a4.width, 1));
      expect(result.pages[1].size.width, closeTo(PdfPageSize.a5.width, 1));
    });

    test('section margins are honoured', () {
      final PdfDocument document = PdfDocument();
      final PdfSection section = document.sections!.add();
      section.pageSettings = PdfPageSettings(PdfPageSize.a4)
        ..margins.all = 100;
      final PdfPage page = section.pages.add();
      expect(page.getClientSize().width,
          closeTo(PdfPageSize.a4.width - 200, 1));
      document.dispose();
    });
  });
}

String _textOf(PdfDocument document, int index) => PdfTextExtractor(
  document,
).extractText(startPageIndex: index, endPageIndex: index);

List<String> _layerNames(PdfDocument document) =>
    _namesOf(_optionalContent(document), 'OCGs');

List<String> _stateNames(PdfDocument document, String state) {
  final PdfDictionary? properties = _optionalContent(document);
  if (properties == null) {
    return <String>[];
  }
  final IPdfPrimitive? configuration = PdfCrossTable.dereference(
    properties['D'],
  );
  if (configuration is! PdfDictionary) {
    return <String>[];
  }
  return _namesOf(configuration, state);
}

List<String> _namesOf(PdfDictionary? owner, String key) {
  final List<String> names = <String>[];
  if (owner == null) {
    return names;
  }
  final IPdfPrimitive? groups = PdfCrossTable.dereference(owner[key]);
  if (groups is! PdfArray) {
    return names;
  }
  for (int i = 0; i < groups.count; i++) {
    final IPdfPrimitive? group = PdfCrossTable.dereference(groups[i]);
    if (group is! PdfDictionary) {
      continue;
    }
    final IPdfPrimitive? name = PdfCrossTable.dereference(group['Name']);
    if (name is PdfString && name.value != null) {
      names.add(name.value!);
    }
  }
  return names;
}

PdfDictionary? _optionalContent(PdfDocument document) {
  final IPdfPrimitive? properties = PdfCrossTable.dereference(
    PdfDocumentHelper.getHelper(document).catalog['OCProperties'],
  );
  return properties is PdfDictionary ? properties : null;
}
