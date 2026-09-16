import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

// `PdfPageCollection.insert` on a document built in memory. Until 1.0.2 the
// method only knew the page tree of a loaded document and died on a new one
// with "Null check operator used on a null value" — the cross table it walks
// does not exist before the first save. Every test here failed that way.

PdfFont get font => PdfStandardFont(PdfFontFamily.helvetica, 11);

void main() {
  group('insert on a new document', () {
    test('at the front: the page becomes pages[0] and the rest shift', () {
      final PdfDocument document = _withPages(<String>['A', 'B', 'C']);
      final PdfPage inserted = document.pages.insert(0);
      _write(inserted, 'INDICE');

      expect(document.pages.count, 4);
      expect(document.pages.indexOf(inserted), 0);
      expect(_textsOf(_reload(document)), <String>['INDICE', 'A', 'B', 'C']);
    });

    test('in the middle and at the end', () {
      final PdfDocument document = _withPages(<String>['A', 'B', 'C']);
      _write(document.pages.insert(2), 'X');
      _write(document.pages.insert(document.pages.count), 'FIM');

      expect(document.pages.count, 5);
      expect(_textsOf(_reload(document)), <String>['A', 'B', 'X', 'C', 'FIM']);
    });

    test('into an empty document', () {
      final PdfDocument document = PdfDocument();
      _write(document.pages.insert(0), 'SO');
      expect(document.pages.count, 1);
      expect(_textsOf(_reload(document)), <String>['SO']);
    });

    test('rejects an index out of range', () {
      final PdfDocument document = _withPages(<String>['A']);
      expect(() => document.pages.insert(-1), throwsArgumentError);
      expect(() => document.pages.insert(2), throwsArgumentError);
      document.dispose();
    });

    test('without settings the page takes the document settings, like add', () {
      final PdfDocument document = PdfDocument();
      document.pageSettings.size = PdfPageSize.letter;
      document.pageSettings.margins.all = 0;
      _write(document.pages.add(), 'A');
      _write(document.pages.insert(0), 'B');

      expect(document.sections!.count, 1,
          reason: 'same settings: no section of its own');
      final PdfDocument result = _reload(document);
      expect(
          result.pages[0].size.width, closeTo(PdfPageSize.letter.width, 0.5));
      expect(
          result.pages[1].size.width, closeTo(PdfPageSize.letter.width, 0.5));
    });

    test('a page with its own size in the middle splits the section', () {
      final PdfDocument document = _withPages(<String>['A', 'B', 'C']);
      final PdfPage landscape = document.pages.insert(
        1,
        PdfPageSize.a5,
        PdfMargins()..all = 0,
        PdfPageRotateAngle.rotateAngle0,
        PdfPageOrientation.landscape,
      );
      _write(landscape, 'L');

      expect(document.sections!.count, 3,
          reason: '[A] | [L] | [B, C]: each page keeps a single parent');
      expect(document.pages.indexOf(landscape), 1);

      final PdfDocument result = _reload(document);
      expect(_textsOf(result), <String>['A', 'L', 'B', 'C']);
      expect(result.pages[1].size.width, closeTo(PdfPageSize.a5.height, 0.5),
          reason: 'A5 landscape: the width is the A5 height');
      expect(result.pages[0].size.width, closeTo(PdfPageSize.a4.width, 0.5));
      expect(result.pages[2].size.width, closeTo(PdfPageSize.a4.width, 0.5));
    });

    test('own size at the front or at the end needs no split', () {
      final PdfDocument document = _withPages(<String>['A', 'B']);
      _write(document.pages.insert(0, PdfPageSize.a3), 'CAPA');
      _write(document.pages.insert(3, PdfPageSize.a3), 'CONTRACAPA');

      expect(document.sections!.count, 3);
      final PdfDocument result = _reload(document);
      expect(_textsOf(result), <String>['CAPA', 'A', 'B', 'CONTRACAPA']);
      expect(result.pages[0].size.width, closeTo(PdfPageSize.a3.width, 0.5));
      expect(result.pages[3].size.width, closeTo(PdfPageSize.a3.width, 0.5));
    });

    test('a second insert at the same boundary joins the section made before',
        () {
      final PdfDocument document = _withPages(<String>['A', 'B']);
      _write(document.pages.insert(1, PdfPageSize.a3), 'X1');
      _write(document.pages.insert(2, PdfPageSize.a3), 'X2');

      expect(document.sections!.count, 3,
          reason: 'X2 has the settings of the section X1 opened');
      expect(_textsOf(_reload(document)), <String>['A', 'X1', 'X2', 'B']);
    });

    test('through a section, the page takes the section settings', () {
      final PdfDocument document = PdfDocument();
      final PdfSection section = document.sections!.add();
      section.pageSettings = PdfPageSettings(PdfPageSize.a5);
      _write(section.pages.add(), 'A');
      _write(section.pages.add(), 'B');
      _write(section.pages.insert(1), 'MEIO');

      expect(section.pages.count, 3);
      expect(document.pages.count, 3);
      expect(() => section.pages.insert(0, PdfPageSize.a3), throwsArgumentError,
          reason: 'a section is one page setting');

      final PdfDocument result = _reload(document);
      expect(_textsOf(result), <String>['A', 'MEIO', 'B']);
      expect(result.pages[1].size.width, closeTo(PdfPageSize.a5.width, 0.5));
    });

    test('pageAdded fires once, for the inserted page', () {
      final PdfDocument document = _withPages(<String>['A', 'B']);
      final List<PdfPage> added = <PdfPage>[];
      document.pages.pageAdded = (Object sender, PageAddedArgs args) {
        added.add(args.page);
      };
      final PdfPage inserted = document.pages.insert(1);
      expect(added, <PdfPage>[inserted]);
      document.dispose();
    });

    test('odd/even templates follow the position after the insert', () {
      final PdfDocument document = PdfDocument();
      document.template.bottom = _footer('IMPAR');
      document.template.evenBottom = _footer('PAR');
      _write(document.pages.add(), 'A');
      _write(document.pages.add(), 'B');
      // A was odd (1st). With a page in front it is the 2nd — even.
      _write(document.pages.insert(0), 'CAPA');

      final List<String> texts = _textsOf(_reload(document));
      expect(texts[0], allOf(contains('CAPA'), contains('IMPAR')));
      expect(texts[1], allOf(contains('A'), contains('PAR')));
      expect(texts[2], allOf(contains('B'), contains('IMPAR')));
    });

    test('an index page inserted in front of merged pages', () {
      // The case that found the bug: a consolidated file is built by merging
      // pieces, and only then the caller knows where each piece starts and
      // can draw the index — which belongs in front.
      final List<int> piece = _bytesOf(_withPages(<String>['P1', 'P2']));
      final PdfDocument document = PdfDocument();
      final PdfDocument source = PdfDocument(inputBytes: piece);
      document.appendDocument(source);
      source.dispose();
      final int pagesBefore = document.pages.count;

      _write(document.pages.insert(0), 'INDICE');

      expect(document.pages.count, pagesBefore + 1);
      expect(_textsOf(_reload(document)), <String>['INDICE', 'P1', 'P2']);
    });
  });

  test('insert on a loaded document still works', () {
    final List<int> bytes = _bytesOf(_withPages(<String>['A', 'B']));
    final PdfDocument document = PdfDocument(inputBytes: bytes);
    _write(document.pages.insert(1), 'X');
    expect(_textsOf(_reload(document)), <String>['A', 'X', 'B']);
  });
}

PdfDocument _withPages(List<String> texts) {
  final PdfDocument document = PdfDocument();
  for (final String text in texts) {
    _write(document.pages.add(), text);
  }
  return document;
}

void _write(PdfPage page, String text) {
  page.graphics.drawString(
    text,
    font,
    brush: PdfBrushes.black,
    bounds: const Rect.fromLTWH(20, 20, 300, 20),
  );
}

PdfPageTemplateElement _footer(String text) =>
    PdfPageTemplateElement(const Rect.fromLTWH(0, 0, 300, 30))
      ..graphics.drawString(
        text,
        font,
        brush: PdfBrushes.gray,
        bounds: const Rect.fromLTWH(0, 5, 300, 20),
      );

List<int> _bytesOf(PdfDocument document) {
  final List<int> bytes = document.saveSync();
  document.dispose();
  return bytes;
}

/// Saves, disposes and reopens [document], so the assertions read the file as
/// a reader would, not the in-memory model.
PdfDocument _reload(PdfDocument document) {
  final PdfDocument result = PdfDocument(inputBytes: _bytesOf(document));
  addTearDown(result.dispose);
  return result;
}

List<String> _textsOf(PdfDocument document) {
  final PdfTextExtractor extractor = PdfTextExtractor(document);
  return <String>[
    for (int i = 0; i < document.pages.count; i++)
      extractor.extractText(startPageIndex: i, endPageIndex: i).trim(),
  ];
}
