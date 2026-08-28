import '../graphics/pdf_graphics.dart';
import '../pages/pdf_page.dart';
import '../pdf_document/pdf_document.dart';

/// A page that was just imported into the destination document, handed to
/// [PdfMergeOptions.onPageImported] so the caller can add something of their
/// own to it — a footer naming the document the page came from, a page number
/// for the merged whole, a watermark, a bates number, a QR code.
///
/// The library does not decide what that content is. It only provides
/// [appendGraphics], which is the safe way to add any of it.
class PdfImportedPage {
  /// internal constructor
  PdfImportedPage(
    this.page,
    this.sourcePage,
    this.source, {
    required this.sourcePageIndex,
    required this.destinationPageIndex,
    required this.importedPageNumber,
  });

  /// The page as it now exists in the destination document.
  final PdfPage page;

  /// The page it was imported from, in the source document.
  final PdfPage sourcePage;

  /// The document the page came from.
  ///
  /// Its [PdfDocument.documentInformation] is often what a footer wants to
  /// name; the caller usually knows the file name too and can key off it.
  final PdfDocument source;

  /// Zero based index of the page within [source].
  final int sourcePageIndex;

  /// Zero based index of the page within the destination document.
  final int destinationPageIndex;

  /// One based count of pages this merge session has imported so far, across
  /// every source document.
  ///
  /// This is the number a consolidated document usually wants to print, as
  /// opposed to [sourcePageIndex], which restarts with each source.
  final int importedPageNumber;

  /// Opens a graphics context that draws on top of the imported content
  /// without rewriting a byte of it.
  ///
  /// This is [PdfPage.appendGraphics] on [page], named here so the callback
  /// has the safe drawing surface within reach; see it for the guarantees.
  ///
  /// ```dart
  /// PdfMergeOptions(
  ///   onPageImported: (PdfImportedPage info) {
  ///     final PdfGraphics graphics = info.appendGraphics();
  ///     graphics.drawString(
  ///       'Page ${info.importedPageNumber}',
  ///       PdfStandardFont(PdfFontFamily.helvetica, 8),
  ///       brush: PdfBrushes.gray,
  ///       bounds: Rect.fromLTWH(0, info.page.size.height - 24, 200, 12),
  ///     );
  ///   },
  /// )
  /// ```
  PdfGraphics appendGraphics() => page.appendGraphics();
}

/// Called once for every page a merge imports, after the page is complete.
///
/// See [PdfImportedPage.appendGraphics] for how to draw on the page without
/// disturbing what was imported.
typedef PdfPageImportedCallback = void Function(PdfImportedPage page);
