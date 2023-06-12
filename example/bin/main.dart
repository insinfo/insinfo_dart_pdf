import 'dart:io';

import 'package:dart_pdf/pdf.dart' as flutter_pdf;
import 'package:intl/intl.dart';

void main(List<String> args) async {
  await generateInvoice();
}

Future<void> generateInvoice() async {
  //Create a PDF document.

  final flutter_pdf.PdfDocument document = flutter_pdf.PdfDocument();
  //Add page to the PDF
  final flutter_pdf.PdfPage page = document.pages.add();

  //Get page client size
  final  pageSize = page.getClientSize();
  //Draw rectangle
  page.graphics.drawRectangle(
      bounds: flutter_pdf.Rect.fromLTWH(0, 0, pageSize.width, pageSize.height),
      pen: flutter_pdf.PdfPen(flutter_pdf.PdfColor(142, 170, 219, 255)));
  //Generate PDF grid.
  final flutter_pdf.PdfGrid grid = getGrid();
  //Draw the header section by creating text element
  final flutter_pdf.PdfLayoutResult result = drawHeader(page, pageSize, grid);

  //Draw grid
  drawGrid(page, grid, result);
  //Add invoice footer
  drawFooter(page, pageSize);
  //Save the PDF document
  final  bytes =await document.save();
  //Dispose the document.
  document.dispose();
  //Save and launch the file.
  await saveAndLaunchFile(bytes, 'Invoice.pdf');
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

flutter_pdf.PdfLayoutResult drawHeader(flutter_pdf.PdfPage page,
    flutter_pdf.Size pageSize, flutter_pdf.PdfGrid grid) {
  //Draw rectangle
  page.graphics.drawRectangle(
      brush: flutter_pdf.PdfSolidBrush(flutter_pdf.PdfColor(91, 126, 215, 255)),
      bounds: flutter_pdf.Rect.fromLTWH(0, 0, pageSize.width - 115, 90));
  //Draw string
  page.graphics.drawString('INVOICE',
      flutter_pdf.PdfStandardFont(flutter_pdf.PdfFontFamily.helvetica, 30),
      brush: flutter_pdf.PdfBrushes.white,
      bounds: flutter_pdf.Rect.fromLTWH(25, 0, pageSize.width - 115, 90),
      format: flutter_pdf.PdfStringFormat(
          lineAlignment: flutter_pdf.PdfVerticalAlignment.middle));

  page.graphics.drawRectangle(
      bounds: flutter_pdf.Rect.fromLTWH(400, 0, pageSize.width - 400, 90),
      brush: flutter_pdf.PdfSolidBrush(flutter_pdf.PdfColor(65, 104, 205)));

  page.graphics.drawString(r'$' + getTotalAmount(grid).toString(),
      flutter_pdf.PdfStandardFont(flutter_pdf.PdfFontFamily.helvetica, 18),
      bounds: flutter_pdf.Rect.fromLTWH(400, 0, pageSize.width - 400, 100),
      brush: flutter_pdf.PdfBrushes.white,
      format: flutter_pdf.PdfStringFormat(
          alignment: flutter_pdf.PdfTextAlignment.center,
          lineAlignment: flutter_pdf.PdfVerticalAlignment.middle));

  final flutter_pdf.PdfFont contentFont =
      flutter_pdf.PdfStandardFont(flutter_pdf.PdfFontFamily.helvetica, 9);
  //Draw string
  page.graphics.drawString('Amount', contentFont,
      brush: flutter_pdf.PdfBrushes.white,
      bounds: flutter_pdf.Rect.fromLTWH(400, 0, pageSize.width - 400, 33),
      format: flutter_pdf.PdfStringFormat(
          alignment: flutter_pdf.PdfTextAlignment.center,
          lineAlignment: flutter_pdf.PdfVerticalAlignment.bottom));

  //Create data foramt and convert it to text.
  final DateFormat format = DateFormat.yMMMMd('en_US');
  final String invoiceNumber =
      'Invoice Number: 2058557939\r\n\r\nDate: ${format.format(DateTime.now())}';
  final flutter_pdf.Size contentSize = contentFont.measureString(invoiceNumber);
  // ignore: leading_newlines_in_multiline_strings
  const String address = '''Bill To: \r\n\r\nAbraham Swearegin, 
        \r\n\r\nUnited States, California, San Mateo, 
        \r\n\r\n9920 BridgePointe Parkway, \r\n\r\n9365550136''';

  flutter_pdf.PdfTextElement(text: invoiceNumber, font: contentFont).draw(
      page: page,
      bounds: flutter_pdf.Rect.fromLTWH(
          pageSize.width - (contentSize.width + 30),
          120,
          contentSize.width + 30,
          pageSize.height - 120));

  return flutter_pdf.PdfTextElement(text: address, font: contentFont).draw(
      page: page,
      bounds: flutter_pdf.Rect.fromLTWH(30, 120,
          pageSize.width - (contentSize.width + 30), pageSize.height - 120))!;
}

//Draws the grid

void drawGrid(flutter_pdf.PdfPage page, flutter_pdf.PdfGrid grid,
    flutter_pdf.PdfLayoutResult result) {
  flutter_pdf.Rect? totalPriceCellBounds;
  flutter_pdf.Rect? quantityCellBounds;
  //Invoke the beginCellLayout event.
  grid.beginCellLayout =
      (Object sender, flutter_pdf.PdfGridBeginCellLayoutArgs args) {
    final flutter_pdf.PdfGrid grid = sender as flutter_pdf.PdfGrid;

    if (args.cellIndex == grid.columns.count - 1) {
      totalPriceCellBounds = args.bounds;
    } else if (args.cellIndex == grid.columns.count - 2) {
      quantityCellBounds = args.bounds;
    }
  };
  //Draw the PDF grid and get the result.
  result = grid.draw(
      page: page,
      bounds: flutter_pdf.Rect.fromLTWH(0, result.bounds.bottom + 40, 0, 0))!;

  //Draw grand total.

  page.graphics.drawString(
      'Grand Total',
      flutter_pdf.PdfStandardFont(flutter_pdf.PdfFontFamily.helvetica, 9,
          style: flutter_pdf.PdfFontStyle.bold),
      bounds: flutter_pdf.Rect.fromLTWH(
          quantityCellBounds!.left,
          result.bounds.bottom + 10,
          quantityCellBounds!.width,
          quantityCellBounds!.height));

  page.graphics.drawString(
      getTotalAmount(grid).toString(),
      flutter_pdf.PdfStandardFont(flutter_pdf.PdfFontFamily.helvetica, 9,
          style: flutter_pdf.PdfFontStyle.bold),
      bounds: flutter_pdf.Rect.fromLTWH(
          totalPriceCellBounds!.left,
          result.bounds.bottom + 10,
          totalPriceCellBounds!.width,
          totalPriceCellBounds!.height));
}

//Draw the invoice footer data.

void drawFooter(flutter_pdf.PdfPage page, flutter_pdf.Size pageSize) {
  final flutter_pdf.PdfPen linePen = flutter_pdf.PdfPen(
      flutter_pdf.PdfColor(142, 170, 219, 255),
      dashStyle: flutter_pdf.PdfDashStyle.custom);

  linePen.dashPattern = <double>[3, 3];
  //Draw line
  page.graphics.drawLine(linePen, flutter_pdf.Offset(0, pageSize.height - 100),
      flutter_pdf.Offset(pageSize.width, pageSize.height - 100));

  const String footerContent =
      // ignore: leading_newlines_in_multiline_strings
      '''800 Interchange Blvd.\r\n\r\nSuite 2501, Austin,
         TX 78721\r\n\r\nAny Questions? support@adventure-works.com''';

  //Added 30 as a margin for the layout

  page.graphics.drawString(footerContent,
      flutter_pdf.PdfStandardFont(flutter_pdf.PdfFontFamily.helvetica, 9),
      format: flutter_pdf.PdfStringFormat(
          alignment: flutter_pdf.PdfTextAlignment.right),
      bounds: flutter_pdf.Rect.fromLTWH(
          pageSize.width - 30, pageSize.height - 70, 0, 0));
}

//Create PDF grid and return

flutter_pdf.PdfGrid getGrid() {
  //Create a PDF grid
  final flutter_pdf.PdfGrid grid = flutter_pdf.PdfGrid();
  //Secify the columns count to the grid.
  grid.columns.add(count: 5);
  //Create the header row of the grid.
  final flutter_pdf.PdfGridRow headerRow = grid.headers.add(1)[0];
  //Set style
  headerRow.style.backgroundBrush =
      flutter_pdf.PdfSolidBrush(flutter_pdf.PdfColor(68, 114, 196));
  headerRow.style.textBrush = flutter_pdf.PdfBrushes.white;
  headerRow.cells[0].value = 'Product Id';
  headerRow.cells[0].stringFormat.alignment =
      flutter_pdf.PdfTextAlignment.center;

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

  grid.applyBuiltInStyle(flutter_pdf.PdfGridBuiltInStyle.listTable4Accent5);

  //Set gird columns width
  grid.columns[1].width = 200;
  for (int i = 0; i < headerRow.cells.count; i++) {
    headerRow.cells[i].style.cellPadding =
        flutter_pdf.PdfPaddings(bottom: 5, left: 5, right: 5, top: 5);
  }
  for (int i = 0; i < grid.rows.count; i++) {
    final flutter_pdf.PdfGridRow row = grid.rows[i];
    for (int j = 0; j < row.cells.count; j++) {
      final flutter_pdf.PdfGridCell cell = row.cells[j];
      if (j == 0) {
        cell.stringFormat.alignment = flutter_pdf.PdfTextAlignment.center;
      }
      cell.style.cellPadding =
          flutter_pdf.PdfPaddings(bottom: 5, left: 5, right: 5, top: 5);
    }
  }
  return grid;
}

//Create and row for the grid.
void addProducts(String productId, String productName, double price,
    int quantity, double total, flutter_pdf.PdfGrid grid) {
  final flutter_pdf.PdfGridRow row = grid.rows.add();

  row.cells[0].value = productId;
  row.cells[1].value = productName;
  row.cells[2].value = price.toString();
  row.cells[3].value = quantity.toString();
  row.cells[4].value = total.toString();
}

//Get the total amount.

double getTotalAmount(flutter_pdf.PdfGrid grid) {
  double total = 0;
  for (int i = 0; i < grid.rows.count; i++) {
    final String value =
        grid.rows[i].cells[grid.columns.count - 1].value as String;
    total += double.parse(value);
  }
  return total;
}
