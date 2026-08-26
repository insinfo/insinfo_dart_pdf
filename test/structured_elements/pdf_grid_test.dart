import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

/// `PdfGrid` is the table layout engine: columns, rows, headers, spanning,
/// pagination and the built-in styles. It had no tests at all.
void main() {
  group('PdfGrid - structure', () {
    test('columns and rows can be added and read back', () {
      final PdfGrid grid = PdfGrid();
      grid.columns.add(count: 3);
      expect(grid.columns.count, 3);

      final PdfGridRow first = grid.rows.add();
      first.cells[0].value = 'a';
      first.cells[1].value = 'b';
      first.cells[2].value = 'c';
      expect(grid.rows.count, 1);
      expect(grid.rows[0].cells.count, 3);
      expect(grid.rows[0].cells[1].value, 'b');
    });

    test('a column keeps the width it was given', () {
      final PdfGrid grid = PdfGrid();
      grid.columns.add(count: 2);
      grid.columns[0].width = 120;
      expect(grid.columns[0].width, 120);
      expect(grid.columns[1].width, lessThanOrEqualTo(0));
    });

    test('headers are separate from rows', () {
      final PdfGrid grid = PdfGrid();
      grid.columns.add(count: 2);
      grid.headers.add(1);
      grid.headers[0].cells[0].value = 'Name';
      grid.headers[0].cells[1].value = 'Value';
      grid.rows.add().cells[0].value = 'x';

      expect(grid.headers.count, 1);
      expect(grid.rows.count, 1);
      expect(grid.headers[0].cells[0].value, 'Name');
    });

    test('a row remembers the height it was given', () {
      final PdfGrid grid = PdfGrid();
      grid.columns.add(count: 1);
      final PdfGridRow row = grid.rows.add();
      row.height = 42;
      expect(row.height, 42);
    });

    test('cell spanning is recorded on the cell', () {
      final PdfGrid grid = PdfGrid();
      grid.columns.add(count: 3);
      grid.rows.add();
      grid.rows.add();
      grid.rows.setSpan(0, 0, 2, 3);
      expect(grid.rows[0].cells[0].rowSpan, 2);
      expect(grid.rows[0].cells[0].columnSpan, 3);
    });

    test('a grid with no columns still draws without throwing', () {
      final PdfDocument document = PdfDocument();
      addTearDown(document.dispose);
      final PdfGrid grid = PdfGrid();
      expect(
        () => grid.draw(page: document.pages.add(), bounds: Rect.zero),
        returnsNormally,
      );
    });
  });

  group('PdfGrid - drawing', () {
    test('a drawn grid puts its text on the page', () {
      final List<int> bytes = _gridDocument(rowCount: 3);
      final PdfDocument document = PdfDocument(inputBytes: bytes);
      addTearDown(document.dispose);
      final String text = PdfTextExtractor(
        document,
      ).extractText(startPageIndex: 0, endPageIndex: 0);
      expect(text, contains('Header 1'));
      expect(text, contains('r0c0'));
      expect(text, contains('r2c1'));
    });

    test('draw returns a layout result with the bounds it used', () {
      final PdfDocument document = PdfDocument();
      addTearDown(document.dispose);
      final PdfGrid grid = PdfGrid();
      grid.columns.add(count: 2);
      for (int i = 0; i < 4; i++) {
        final PdfGridRow row = grid.rows.add();
        row.cells[0].value = 'left $i';
        row.cells[1].value = 'right $i';
      }
      final PdfLayoutResult? result = grid.draw(
        page: document.pages.add(),
        bounds: const Rect.fromLTWH(20, 20, 400, 300),
      );
      expect(result, isNotNull);
      expect(result!.bounds.height, greaterThan(0));
      expect(result.page, isNotNull);
    });

    test('a long grid flows onto further pages', () {
      final PdfDocument document = PdfDocument();
      final PdfGrid grid = PdfGrid();
      grid.columns.add(count: 2);
      for (int i = 0; i < 120; i++) {
        final PdfGridRow row = grid.rows.add();
        row.cells[0].value = 'row $i';
        row.cells[1].value = 'value $i';
      }
      grid.draw(page: document.pages.add(), bounds: Rect.zero);
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      expect(
        result.pages.count,
        greaterThan(1),
        reason: '120 rows do not fit on one page',
      );
      expect(
        PdfTextExtractor(result).extractText(
          startPageIndex: result.pages.count - 1,
          endPageIndex: result.pages.count - 1,
        ),
        contains('row 119'),
      );
    });

    test('headers repeat on every page', () {
      final PdfDocument document = PdfDocument();
      final PdfGrid grid = PdfGrid();
      grid.columns.add(count: 2);
      grid.headers.add(1);
      grid.headers[0].cells[0].value = 'REPEATED';
      grid.headers[0].cells[1].value = 'HEADER';
      grid.repeatHeader = true;
      for (int i = 0; i < 120; i++) {
        final PdfGridRow row = grid.rows.add();
        row.cells[0].value = 'row $i';
        row.cells[1].value = '$i';
      }
      grid.draw(page: document.pages.add(), bounds: Rect.zero);
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      expect(result.pages.count, greaterThan(1));
      for (int i = 0; i < result.pages.count; i++) {
        expect(
          PdfTextExtractor(
            result,
          ).extractText(startPageIndex: i, endPageIndex: i),
          contains('REPEATED'),
          reason: 'page $i carries the repeated header',
        );
      }
    });
  });

  group('PdfGrid - styling', () {
    test('cell style overrides survive to the page', () {
      final PdfDocument document = PdfDocument();
      final PdfGrid grid = PdfGrid();
      grid.columns.add(count: 2);
      final PdfGridRow row = grid.rows.add();
      row.cells[0].value = 'styled';
      row.cells[0].style.backgroundBrush = PdfBrushes.lightBlue;
      row.cells[0].style.textBrush = PdfBrushes.white;
      row.cells[0].style.font = PdfStandardFont(
        PdfFontFamily.helvetica,
        14,
        style: PdfFontStyle.bold,
      );
      row.cells[1].value = 'plain';
      grid.draw(page: document.pages.add(), bounds: Rect.zero);
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      expect(
        PdfTextExtractor(
          result,
        ).extractText(startPageIndex: 0, endPageIndex: 0),
        contains('styled'),
      );
    });

    test('grid style controls padding and borders', () {
      final PdfGrid grid = PdfGrid();
      grid.columns.add(count: 1);
      grid.rows.add().cells[0].value = 'x';
      grid.style.cellPadding = PdfPaddings(left: 5, right: 5, top: 3, bottom: 3);
      grid.style.cellSpacing = 2;
      expect(grid.style.cellPadding.left, 5);
      expect(grid.style.cellSpacing, 2);
    });

    for (final PdfGridBuiltInStyle style in <PdfGridBuiltInStyle>[
      PdfGridBuiltInStyle.plainTable1,
      PdfGridBuiltInStyle.gridTable4,
      PdfGridBuiltInStyle.listTable3,
      PdfGridBuiltInStyle.gridTable6ColorfulAccent1,
    ]) {
      test('built-in style ${style.name} applies and draws', () {
        final PdfDocument document = PdfDocument();
        final PdfGrid grid = PdfGrid();
        grid.columns.add(count: 3);
        grid.headers.add(1);
        for (int c = 0; c < 3; c++) {
          grid.headers[0].cells[c].value = 'H$c';
        }
        for (int r = 0; r < 5; r++) {
          final PdfGridRow row = grid.rows.add();
          for (int c = 0; c < 3; c++) {
            row.cells[c].value = 'c$r$c';
          }
        }
        grid.applyBuiltInStyle(style);
        grid.draw(page: document.pages.add(), bounds: Rect.zero);
        final List<int> bytes = document.saveSync();
        document.dispose();

        final PdfDocument result = PdfDocument(inputBytes: bytes);
        addTearDown(result.dispose);
        expect(
          PdfTextExtractor(
            result,
          ).extractText(startPageIndex: 0, endPageIndex: 0),
          contains('c00'),
        );
      });
    }
  });

  group('PdfGrid - merging a document that contains one', () {
    test('the grid content survives a merge', () {
      final List<int> bytes = _gridDocument(rowCount: 40);
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);

      final PdfDocument original = PdfDocument(inputBytes: bytes);
      final int pages = original.pages.count;
      final String expected = PdfTextExtractor(
        original,
      ).extractText(startPageIndex: 0, endPageIndex: 0);
      original.dispose();

      final PdfDocument result = PdfDocument(inputBytes: merged);
      addTearDown(result.dispose);
      expect(result.pages.count, pages);
      expect(
        PdfTextExtractor(
          result,
        ).extractText(startPageIndex: 0, endPageIndex: 0),
        expected,
      );
    });
  });
}

/// A document whose single grid has a header and [rowCount] rows.
List<int> _gridDocument({required int rowCount}) {
  final PdfDocument document = PdfDocument();
  final PdfGrid grid = PdfGrid();
  grid.columns.add(count: 2);
  grid.headers.add(1);
  grid.headers[0].cells[0].value = 'Header 1';
  grid.headers[0].cells[1].value = 'Header 2';
  for (int r = 0; r < rowCount; r++) {
    final PdfGridRow row = grid.rows.add();
    row.cells[0].value = 'r${r}c0';
    row.cells[1].value = 'r${r}c1';
  }
  grid.draw(page: document.pages.add(), bounds: Rect.zero);
  final List<int> bytes = document.saveSync();
  document.dispose();
  return bytes;
}
