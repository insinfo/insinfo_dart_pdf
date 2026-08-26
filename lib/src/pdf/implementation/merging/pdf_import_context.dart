import '../../interfaces/pdf_interface.dart';
import '../io/pdf_cross_table.dart';
import '../pages/pdf_page.dart';
import '../pdf_document/pdf_document.dart';
import '../primitives/pdf_dictionary.dart';
import '../primitives/pdf_reference_holder.dart';
import 'pdf_merge_options.dart';

/// Holds the state of a single merge session.
///
/// An instance is attached to the destination [PdfCrossTable] while pages are
/// being imported. Its presence is what enables page objects to be cloned at
/// all: [PdfReferenceHolder.cloneObject] refuses to clone `/Type /Page`
/// dictionaries unless a context is attached and [allowPageClone] is set.
///
/// This is an internal class.
class PdfImportContext {
  /// internal constructor
  PdfImportContext(this.destination, this.options);

  /// The document pages are being imported into.
  final PdfDocument destination;

  /// The merge settings in effect.
  final PdfMergeOptions options;

  /// Maps a page dictionary in the *source* document to the corresponding page
  /// dictionary in the *destination* document.
  ///
  /// Populated as pages are imported, and consulted afterwards to rewrite
  /// link destinations, bookmark targets and annotation back-references.
  final Map<PdfDictionary, PdfDictionary> pageMap =
      <PdfDictionary, PdfDictionary>{};

  /// Maps a page of the *source* document to the page created for it in the
  /// destination, for the importers that work at the object model level
  /// rather than on raw dictionaries.
  final Map<PdfPage, PdfPage> importedPages = <PdfPage, PdfPage>{};

  /// Maps a primitive in the source document to the clone already created for
  /// it in the destination document.
  ///
  /// [PdfDictionary], [PdfStream] and [PdfArray] memoize their own clone, but
  /// those memos are private and unreachable from
  /// [PdfReferenceHolder.cloneObject], which therefore falls back to its
  /// `prevReference` cycle guard and re-adopts the *source* object the second
  /// time a shared object is reached. This map lets the holder reuse the clone
  /// instead, so a font or an image referenced from several places is written
  /// once.
  final Map<IPdfPrimitive, IPdfPrimitive> clonedObjects =
      Map<IPdfPrimitive, IPdfPrimitive>.identity();

  /// Non fatal problems recorded during the merge.
  final List<String> warnings = <String>[];

  /// Enables cloning of `/Type /Page` dictionaries.
  ///
  /// Kept `false` outside the page import step so that every other consumer of
  /// the clone machinery (templates, form fields, FDF/JSON import) keeps its
  /// original behaviour.
  bool allowPageClone = false;

  /// Number of page references that could not be mapped to an imported page.
  int unresolvedPageReferences = 0;

  /// The cross table of the destination document.
  PdfCrossTable get crossTable =>
      PdfDocumentHelper.getHelper(destination).crossTable;

  /// Attaches this context to the destination cross table for the duration of
  /// [action], then detaches it.
  T runAttached<T>(T Function() action) {
    final PdfCrossTable table = crossTable;
    final PdfImportContext? previous = table.importContext;
    table.importContext = this;
    try {
      return action();
    } finally {
      table.importContext = previous;
    }
  }

  /// Runs [action] with page cloning enabled.
  T runWithPageClone<T>(T Function() action) {
    final bool previous = allowPageClone;
    allowPageClone = true;
    try {
      return action();
    } finally {
      allowPageClone = previous;
    }
  }

  /// Resolves a source page dictionary to a reference in the destination
  /// document, or `null` when that page was not imported.
  IPdfPrimitive? mapPageReference(PdfDictionary sourcePageDictionary) {
    final PdfDictionary? mapped = pageMap[sourcePageDictionary];
    if (mapped == null) {
      unresolvedPageReferences++;
      return null;
    }
    return PdfReferenceHolder(mapped);
  }

  /// Records a non fatal problem.
  void addWarning(String message) {
    warnings.add(message);
  }
}
