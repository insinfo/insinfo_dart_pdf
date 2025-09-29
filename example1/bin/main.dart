import 'dart:io';

import 'package:dart_pdf/pdf.dart' as dart_pdf;
import 'package:intl/intl.dart';

void main(List<String> args) async {
  await generateInvoice();
}

Future<void> generateInvoice() async {
  //Create a PDF document.

  final dart_pdf.PdfDocument document = dart_pdf.PdfDocument();
  //Add page to the PDF
  final dart_pdf.PdfPage page = document.pages.add();

  //Get page client size
  final  pageSize = page.getClientSize();
  //Draw rectangle
  page.graphics.drawRectangle(
      bounds: dart_pdf.Rect.fromLTWH(0, 0, pageSize.width, pageSize.height),
      pen: dart_pdf .PdfPen(dart_pdf.PdfColor(142, 170, 219, 255)));
  //Generate PDF grid.
  final dart_pdf .PdfGrid grid = getGrid();
  //Draw the header section by creating text element
  final dart_pdf .PdfLayoutResult result = drawHeader(page, pageSize, grid);

  //Draw grid
  drawGrid(page, grid, result);
  //Add invoice footer
  drawFooter(page, pageSize);
  //Save the PDF document
  final  bytes =await document.save();
  //Dispose the document.
  document.dispose();
  //Save and launch the file.
  await saveAndLaunchFile(bytes, 'example.pdf');
}

///To save the pdf file in the device
Future<void> saveAndLaunchFile(List<int> bytes, String fileName) async {
  print('saveAndLaunchFile');
  //Get the storage folder location using path_provider package.
  String? path;
  if (Platform.isAndroid ||
      Platform.isIOS ||
      Platform.isLinux ||
      Platform.isWindows) {
    final Directory directory = Directory.current;
    path = directory.path;
    print('path $path');
  }
  final File file =
      File(Platform.isWindows ? '$path\\$fileName' : '$path/$fileName');
  await file.writeAsBytes(bytes, flush: true);
  if (Platform.isAndroid || Platform.isIOS) {
    //Launch the file (used open_file package)

  } else if (Platform.isWindows) {
    await Process.run('start', <String>['$path\\$fileName'], runInShell: true);
  } else if (Platform.isMacOS) {
    await Process.run('open', <String>['$path/$fileName'], runInShell: true);
  } else if (Platform.isLinux) {
    await Process.run('xdg-open', <String>['$path/$fileName'],
        runInShell: true);
  }
}

//Draws the invoice header

dart_pdf .PdfLayoutResult drawHeader(dart_pdf .PdfPage page,
    dart_pdf .Size pageSize, dart_pdf .PdfGrid grid) {
  //Draw rectangle
  page.graphics.drawRectangle(
      brush: dart_pdf .PdfSolidBrush(dart_pdf .PdfColor(91, 126, 215, 255)),
      bounds: dart_pdf .Rect.fromLTWH(0, 0, pageSize.width - 115, 90));
  //Draw string
  page.graphics.drawString('INVOICE',
      dart_pdf .PdfStandardFont(dart_pdf .PdfFontFamily.helvetica, 30),
      brush: dart_pdf .PdfBrushes.white,
      bounds: dart_pdf .Rect.fromLTWH(25, 0, pageSize.width - 115, 90),
      format: dart_pdf .PdfStringFormat(
          lineAlignment: dart_pdf .PdfVerticalAlignment.middle));

  page.graphics.drawRectangle(
      bounds: dart_pdf .Rect.fromLTWH(400, 0, pageSize.width - 400, 90),
      brush: dart_pdf .PdfSolidBrush(dart_pdf .PdfColor(65, 104, 205)));

  page.graphics.drawString(r'$' + getTotalAmount(grid).toString(),
      dart_pdf .PdfStandardFont(dart_pdf .PdfFontFamily.helvetica, 18),
      bounds: dart_pdf .Rect.fromLTWH(400, 0, pageSize.width - 400, 100),
      brush: dart_pdf .PdfBrushes.white,
      format: dart_pdf .PdfStringFormat(
          alignment: dart_pdf .PdfTextAlignment.center,
          lineAlignment: dart_pdf .PdfVerticalAlignment.middle));

  final dart_pdf .PdfFont contentFont =
      dart_pdf .PdfStandardFont(dart_pdf .PdfFontFamily.helvetica, 9);
  //Draw string
  page.graphics.drawString('Amount', contentFont,
      brush: dart_pdf .PdfBrushes.white,
      bounds: dart_pdf .Rect.fromLTWH(400, 0, pageSize.width - 400, 33),
      format: dart_pdf .PdfStringFormat(
          alignment: dart_pdf .PdfTextAlignment.center,
          lineAlignment: dart_pdf .PdfVerticalAlignment.bottom));

  //Create data foramt and convert it to text.
  final DateFormat format = DateFormat.yMMMMd('en_US');
  final String invoiceNumber =
      'Invoice Number: 2058557939\r\n\r\nDate: ${format.format(DateTime.now())}';
  final dart_pdf .Size contentSize = contentFont.measureString(invoiceNumber);
  // ignore: leading_newlines_in_multiline_strings
  const String address = '''Bill To: \r\n\r\nAbraham Swearegin, 
        \r\n\r\nUnited States, California, San Mateo, 
        \r\n\r\n9920 BridgePointe Parkway, \r\n\r\n9365550136''';

  dart_pdf .PdfTextElement(text: invoiceNumber, font: contentFont).draw(
      page: page,
      bounds: dart_pdf .Rect.fromLTWH(
          pageSize.width - (contentSize.width + 30),
          120,
          contentSize.width + 30,
          pageSize.height - 120));

  return dart_pdf .PdfTextElement(text: address, font: contentFont).draw(
      page: page,
      bounds: dart_pdf .Rect.fromLTWH(30, 120,
          pageSize.width - (contentSize.width + 30), pageSize.height - 120))!;
}

//Draws the grid

void drawGrid(dart_pdf .PdfPage page, dart_pdf .PdfGrid grid,
    dart_pdf .PdfLayoutResult result) {
  dart_pdf .Rect? totalPriceCellBounds;
  dart_pdf .Rect? quantityCellBounds;
  //Invoke the beginCellLayout event.
  grid.beginCellLayout =
      (Object sender, dart_pdf .PdfGridBeginCellLayoutArgs args) {
    final dart_pdf .PdfGrid grid = sender as dart_pdf .PdfGrid;

    if (args.cellIndex == grid.columns.count - 1) {
      totalPriceCellBounds = args.bounds;
    } else if (args.cellIndex == grid.columns.count - 2) {
      quantityCellBounds = args.bounds;
    }
  };
  //Draw the PDF grid and get the result.
  result = grid.draw(
      page: page,
      bounds: dart_pdf .Rect.fromLTWH(0, result.bounds.bottom + 40, 0, 0))!;

  //Draw grand total.

  page.graphics.drawString(
      'Grand Total',
      dart_pdf .PdfStandardFont(dart_pdf .PdfFontFamily.helvetica, 9,
          style: dart_pdf .PdfFontStyle.bold),
      bounds: dart_pdf .Rect.fromLTWH(
          quantityCellBounds!.left,
          result.bounds.bottom + 10,
          quantityCellBounds!.width,
          quantityCellBounds!.height));

  page.graphics.drawString(
      getTotalAmount(grid).toString(),
      dart_pdf .PdfStandardFont(dart_pdf .PdfFontFamily.helvetica, 9,
          style: dart_pdf .PdfFontStyle.bold),
      bounds: dart_pdf .Rect.fromLTWH(
          totalPriceCellBounds!.left,
          result.bounds.bottom + 10,
          totalPriceCellBounds!.width,
          totalPriceCellBounds!.height));
}

//Draw the invoice footer data.

void drawFooter(dart_pdf .PdfPage page, dart_pdf .Size pageSize) {
  final dart_pdf .PdfPen linePen = dart_pdf .PdfPen(
      dart_pdf .PdfColor(142, 170, 219, 255),
      dashStyle: dart_pdf .PdfDashStyle.custom);

  linePen.dashPattern = <double>[3, 3];
  //Draw line
  page.graphics.drawLine(linePen, dart_pdf .Offset(0, pageSize.height - 100),
      dart_pdf .Offset(pageSize.width, pageSize.height - 100));

  const String footerContent =
      // ignore: leading_newlines_in_multiline_strings
      '''800 Interchange Blvd.\r\n\r\nSuite 2501, Austin,
         TX 78721\r\n\r\nAny Questions? support@adventure-works.com''';

  //Added 30 as a margin for the layout

  page.graphics.drawString(footerContent,
      dart_pdf .PdfStandardFont(dart_pdf .PdfFontFamily.helvetica, 9),
      format: dart_pdf .PdfStringFormat(
          alignment: dart_pdf .PdfTextAlignment.right),
      bounds: dart_pdf .Rect.fromLTWH(
          pageSize.width - 30, pageSize.height - 70, 0, 0));
}

//Create PDF grid and return

dart_pdf .PdfGrid getGrid() {
  //Create a PDF grid
  final dart_pdf .PdfGrid grid = dart_pdf .PdfGrid();
  //Secify the columns count to the grid.
  grid.columns.add(count: 5);
  //Create the header row of the grid.
  final dart_pdf .PdfGridRow headerRow = grid.headers.add(1)[0];
  //Set style
  headerRow.style.backgroundBrush =
      dart_pdf .PdfSolidBrush(dart_pdf .PdfColor(68, 114, 196));
  headerRow.style.textBrush = dart_pdf .PdfBrushes.white;
  headerRow.cells[0].value = 'Product Id';
  headerRow.cells[0].stringFormat.alignment =
      dart_pdf .PdfTextAlignment.center;

  headerRow.cells[1].value = 'Product Name';
  headerRow.cells[2].value = 'Price';
  headerRow.cells[3].value = 'Quantity';
  headerRow.cells[4].value = 'Total';
  //Add rows
  addProducts('CA-1098', 'AWC Logo Cap', 8.99, 2, 17.98, grid);
  addProducts('LJ-0192', 'Long-Sleeve Logo Jersey,M', 49.99, 3, 149.97, grid);
  addProducts('So-B909-M', 'Mountain Bike Socks,M', 9.5, 2, 19, grid);
  addProducts('LJ-0192', 'Long-Sleeve Logo Jersey,M', 49.99, 4, 199.96, grid);
  addProducts('FK-5136', 'ML Fork', 175.49, 6, 1052.94, grid);
  addProducts('HL-U509', 'Sports-100 Helmet,Black', 34.99, 1, 34.99, grid);
  //Apply the table built-in style

  grid.applyBuiltInStyle(dart_pdf .PdfGridBuiltInStyle.listTable4Accent5);

  //Set gird columns width
  grid.columns[1].width = 200;
  for (int i = 0; i < headerRow.cells.count; i++) {
    headerRow.cells[i].style.cellPadding =
        dart_pdf .PdfPaddings(bottom: 5, left: 5, right: 5, top: 5);
  }
  for (int i = 0; i < grid.rows.count; i++) {
    final dart_pdf .PdfGridRow row = grid.rows[i];
    for (int j = 0; j < row.cells.count; j++) {
      final dart_pdf .PdfGridCell cell = row.cells[j];
      if (j == 0) {
        cell.stringFormat.alignment = dart_pdf .PdfTextAlignment.center;
      }
      cell.style.cellPadding =
          dart_pdf .PdfPaddings(bottom: 5, left: 5, right: 5, top: 5);
    }
  }
  return grid;
}

//Create and row for the grid.
void addProducts(String productId, String productName, double price,
    int quantity, double total, dart_pdf .PdfGrid grid) {
  final dart_pdf .PdfGridRow row = grid.rows.add();

  row.cells[0].value = productId;
  row.cells[1].value = productName;
  row.cells[2].value = price.toString();
  row.cells[3].value = quantity.toString();
  row.cells[4].value = total.toString();
}

//Get the total amount.

double getTotalAmount(dart_pdf .PdfGrid grid) {
  double total = 0;
  for (int i = 0; i < grid.rows.count; i++) {
    final String value =
        grid.rows[i].cells[grid.columns.count - 1].value as String;
    total += double.parse(value);
  }
  return total;
}