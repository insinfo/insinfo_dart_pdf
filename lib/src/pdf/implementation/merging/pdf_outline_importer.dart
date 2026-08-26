import '../general/pdf_destination.dart';
import '../pages/pdf_page.dart';
import '../pdf_document/outlines/pdf_outline.dart';
import '../pdf_document/pdf_document.dart';
import 'pdf_import_context.dart';

/// Rebuilds the outline (bookmark) tree of a source document inside the
/// destination document of a merge session.
///
/// The tree is re-created through the public bookmark model rather than by
/// cloning `/Outlines`: the model owns `/First`, `/Last`, `/Prev`, `/Next` and
/// `/Count` and rewrites them when the document is saved, so a hand-grafted
/// tree would be overwritten.
///
/// This is an internal class.
class PdfOutlineImporter {
  /// internal constructor
  PdfOutlineImporter(this.context);

  /// The merge session state.
  final PdfImportContext context;

  /// Sources whose outline has already been copied, so importing two page
  /// ranges of the same document does not duplicate its bookmarks.
  final Set<PdfDocument> _imported = Set<PdfDocument>.identity();

  /// Copies the bookmarks of [source] into the destination document.
  void import(PdfDocument source) {
    if (!context.options.importBookmarks || !_imported.add(source)) {
      return;
    }
    final PdfBookmarkBase sourceRoot = source.bookmarks;
    if (sourceRoot.count == 0) {
      return;
    }
    PdfBookmarkBase target = context.destination.bookmarks;
    if (context.options.groupBookmarksPerDocument) {
      target = target.add(_labelOf(source));
    }
    _copyChildren(sourceRoot, target);
  }

  void _copyChildren(PdfBookmarkBase source, PdfBookmarkBase target) {
    for (int i = 0; i < source.count; i++) {
      final PdfBookmark item = source[i];
      final PdfBookmark created = target.add(
        item.title,
        isExpanded: item.isExpanded,
        destination: _mapDestination(item),
        color: item.color,
        textStyle: item.textStyle,
      );
      _copyChildren(item, created);
    }
  }

  /// Re-targets a bookmark destination at the imported copy of its page.
  PdfDestination? _mapDestination(PdfBookmark item) {
    PdfDestination? source;
    try {
      source = item.destination;
    } catch (error) {
      // Resolving a destination walks the name tree of the source document,
      // which can be malformed in ways the reader does not survive. A bookmark
      // that cannot say where it points is worth importing without a target;
      // it is not worth losing the merge over.
      context.addWarning(
        'Bookmark "${item.title}" has a destination that could not be read '
        '($error); it was imported without one.',
      );
      return null;
    }
    if (source == null) {
      return null;
    }
    final PdfPage? page = context.importedPages[source.page];
    if (page == null) {
      context.addWarning(
        'Bookmark "${item.title}" targets a page outside the imported range; '
        'it was imported without a destination.',
      );
      return null;
    }
    final PdfDestination destination = PdfDestination(page, source.location)
      ..mode = source.mode;
    if (source.zoom > 0) {
      destination.zoom = source.zoom;
    }
    return destination;
  }

  String _labelOf(PdfDocument source) {
    final String? title = source.documentInformation.title;
    if (title != null && title.isNotEmpty) {
      return title;
    }
    return 'Document ${_imported.length}';
  }
}
