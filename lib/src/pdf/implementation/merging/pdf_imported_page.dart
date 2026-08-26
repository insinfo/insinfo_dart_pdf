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
  /// The page keeps its original content stream untouched. What this adds is a
  /// stream of its own, wrapped so that whatever graphics state the imported
  /// content left behind — an unbalanced `q`, a transform, a clipping path —
  /// cannot reach the new content:
  ///
  /// ```
  /// /Contents [ (q) (…the imported content, verbatim…) (Q) (your drawing) ]
  /// ```
  ///
  /// Coordinates are the same as anywhere else in this library: the origin is
  /// the top left of the page.
  ///
  /// It may be called more than once on the same page; each call gets its own
  /// clean state and draws over the previous one.
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
  PdfGraphics appendGraphics() {
    // Touching the layer collection is what puts the guard in place: it wraps
    // whatever content the page already has between a `q` stream and a `Q`
    // stream, and every layer added afterwards is appended past that `Q`. The
    // original stream is never rewritten, and the drawing starts from the
    // state the page began in.
    return page.layers.add().graphics;
  }
}

/// Called once for every page a merge imports, after the page is complete.
///
/// See [PdfImportedPage.appendGraphics] for how to draw on the page without
/// disturbing what was imported.
typedef PdfPageImportedCallback = void Function(PdfImportedPage page);
