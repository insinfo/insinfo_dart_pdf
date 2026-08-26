import 'package:dart_pdf/src/vector/ui.dart';

import '../../interfaces/pdf_interface.dart';
import '../graphics/pdf_margins.dart';
import '../io/pdf_constants.dart';
import '../io/pdf_cross_table.dart';
import '../pages/enum.dart';
import '../pages/pdf_page.dart';
import '../pages/pdf_page_settings.dart';
import '../pages/pdf_section.dart';
import '../pdf_document/pdf_document.dart';
import '../primitives/pdf_array.dart';
import '../primitives/pdf_dictionary.dart';
import '../primitives/pdf_name.dart';
import '../primitives/pdf_number.dart';
import 'pdf_annotation_importer.dart';
import 'pdf_catalog_merger.dart';
import 'pdf_form_importer.dart';
import 'pdf_import_context.dart';
import 'pdf_merge_options.dart';
import 'pdf_outline_importer.dart';
import 'pdf_page_importer.dart';

/// Merges pages of other PDF documents into a destination document.
///
/// ```dart
/// //Create the document that receives the pages.
/// PdfDocument output = PdfDocument();
/// PdfDocumentMerger merger = PdfDocumentMerger(output);
/// //Append every page of two existing documents.
/// merger.append(PdfDocument(inputBytes: first));
/// merger.append(PdfDocument(inputBytes: second));
/// //Save the merged document.
/// List<int> bytes = await output.save();
/// output.dispose();
/// ```
class PdfDocumentMerger {
  /// Initializes a new instance of the [PdfDocumentMerger] class targeting
  /// [destination].
  ///
  /// The destination may be an empty document or an existing one; in the
  /// latter case the imported pages are appended after the pages it already
  /// has.
  PdfDocumentMerger(this.destination, {PdfMergeOptions? options})
    : options = options ?? PdfMergeOptions() {
    _context = PdfImportContext(destination, this.options);
    _pageImporter = PdfPageImporter(_context);
    _annotationImporter = PdfAnnotationImporter(_context, _pageImporter);
    _formImporter = PdfFormImporter(_context, _pageImporter);
    _outlineImporter = PdfOutlineImporter(_context);
    _catalogMerger = PdfCatalogMerger(_context, _pageImporter);
  }

  /// The document receiving the pages.
  final PdfDocument destination;

  /// The merge settings in effect.
  final PdfMergeOptions options;

  late final PdfImportContext _context;
  late final PdfPageImporter _pageImporter;
  late final PdfAnnotationImporter _annotationImporter;
  late final PdfFormImporter _formImporter;
  late final PdfOutlineImporter _outlineImporter;
  late final PdfCatalogMerger _catalogMerger;
  bool _documentInformationCopied = false;

  /// Non fatal problems recorded so far — a dropped link, a renamed form
  /// field, a stripped signature.
  List<String> get warnings => List<String>.unmodifiable(_context.warnings);

  /// Appends every page of [source] to the destination document.
  List<PdfPage> append(PdfDocument source) {
    if (source.pages.count == 0) {
      return <PdfPage>[];
    }
    return importPageRange(source, 0, source.pages.count - 1);
  }

  /// Imports a single page of [source], identified by its zero based
  /// [pageIndex].
  PdfPage importPage(PdfDocument source, int pageIndex) {
    return importPageRange(source, pageIndex, pageIndex).first;
  }

  /// Imports the pages of [source] from [start] to [end], both inclusive.
  List<PdfPage> importPageRange(PdfDocument source, int start, int end) {
    if (identical(source, destination)) {
      throw PdfMergeException(
        'A document cannot be merged into itself.',
      );
    }
    final int count = source.pages.count;
    if (start < 0 || start >= count) {
      throw PdfMergeException(
        'Start page index $start is out of range; the source document has '
        '$count page(s).',
      );
    }
    if (end < start || end >= count) {
      throw PdfMergeException(
        'End page index $end is out of range; the source document has '
        '$count page(s).',
      );
    }
    _checkSignatures(source);
    final List<PdfPage> created =
        options.mode == PdfMergeMode.flatten
            ? _flatten(source, start, end)
            : _importObjects(source, start, end);
    _copyDocumentInformation(source);
    return created;
  }

  /// Records — or, when asked to, refuses — a source that carries digital
  /// signatures.
  ///
  /// A merge rewrites the whole file, so every signature the source holds is
  /// invalidated by construction; every PDF tool that merges behaves this way.
  /// The signature fields are therefore dropped rather than carried over
  /// broken, and the caller is told through [warnings].
  void _checkSignatures(PdfDocument source) {
    if (!_hasSignatures(source)) {
      return;
    }
    if (options.rejectSignedSources) {
      throw PdfMergeException(
        'The source document contains digital signatures and '
        'PdfMergeOptions.rejectSignedSources is set. Merging always '
        'invalidates existing signatures.',
      );
    }
    if (options.keepInvalidSignatures) {
      _context.addWarning(
        'The source document was signed. Merging invalidates signatures; the '
        'signature fields were kept as requested and will be reported as '
        'invalid by any viewer.',
      );
      return;
    }
    _context.addWarning(
      options.removeSignatureAppearance
          ? 'The source document was signed. Merging invalidates signatures, '
              'so the signature fields and their visible mark were removed.'
          : 'The source document was signed. Merging invalidates signatures, '
              'so the signature fields were removed; their visible mark was '
              'kept as a stamp annotation and no longer certifies anything.',
    );
  }

  bool _hasSignatures(PdfDocument source) {
    final IPdfPrimitive? acroForm = PdfCrossTable.dereference(
      PdfDocumentHelper.getHelper(
        source,
      ).catalog[PdfDictionaryProperties.acroForm],
    );
    if (acroForm is! PdfDictionary) {
      return false;
    }
    final IPdfPrimitive? flags = PdfCrossTable.dereference(
      acroForm[PdfDictionaryProperties.sigFlags],
    );
    if (flags is PdfNumber && (flags.value!.toInt() & 1) != 0) {
      return true;
    }
    final IPdfPrimitive? fields = PdfCrossTable.dereference(
      acroForm[PdfDictionaryProperties.fields],
    );
    if (fields is! PdfArray) {
      return false;
    }
    for (int i = 0; i < fields.count; i++) {
      final IPdfPrimitive? field = PdfCrossTable.dereference(fields[i]);
      if (field is! PdfDictionary) {
        continue;
      }
      final IPdfPrimitive? type = PdfCrossTable.dereference(
        field[PdfDictionaryProperties.ft],
      );
      if (type is PdfName && type.name == PdfDictionaryProperties.sig) {
        return true;
      }
    }
    return false;
  }

  /// Imports the page object graph, in two passes.
  ///
  /// Pages come first so that every page of the range is registered before
  /// annotations, links and bookmarks are rewritten — a link on the first page
  /// may well target the last one.
  List<PdfPage> _importObjects(PdfDocument source, int start, int end) {
    final int destinationOffset = destination.pages.count;
    final List<PdfPage> created = <PdfPage>[];
    final List<PdfDictionary> sourceDictionaries = <PdfDictionary>[];
    for (int i = start; i <= end; i++) {
      final PdfPage sourcePage = source.pages[i];
      final PdfDictionary sourceDictionary =
          PdfPageHelper.getHelper(sourcePage).dictionary!;
      final PdfDictionary cloned = _pageImporter.clone(
        _pageImporter.buildSeed(sourceDictionary),
      );
      final PdfPage page = _createDestinationPage(sourcePage);
      _pageImporter.applyTo(page, cloned);
      _context.pageMap[sourceDictionary] =
          PdfPageHelper.getHelper(page).dictionary!;
      _context.importedPages[sourcePage] = page;
      created.add(page);
      sourceDictionaries.add(sourceDictionary);
    }

    final Map<PdfDictionary, PdfDictionary> widgets =
        <PdfDictionary, PdfDictionary>{};
    for (int i = 0; i < created.length; i++) {
      final PdfImportedAnnotations result = _annotationImporter.import(
        sourceDictionaries[i],
        created[i],
        source,
      );
      widgets.addAll(result.widgets);
    }
    _formImporter.importWidgets(widgets, source);
    _formImporter.importOrphanFields(source);
    _outlineImporter.import(source);
    _catalogMerger.importOptionalContent(source);
    _catalogMerger.importPageLabels(source, destinationOffset);
    return created;
  }

  /// Draws each source page into a fresh destination page as a form XObject.
  List<PdfPage> _flatten(PdfDocument source, int start, int end) {
    final List<PdfPage> created = <PdfPage>[];
    for (int i = start; i <= end; i++) {
      final PdfPage sourcePage = source.pages[i];
      final PdfPage page = _createDestinationPage(sourcePage);
      final Size size = _sizeOf(sourcePage);
      page.graphics.drawPdfTemplate(
        sourcePage.createTemplate(),
        Offset.zero,
        size,
      );
      created.add(page);
    }
    return created;
  }

  /// Creates the destination page matching the geometry of [sourcePage].
  PdfPage _createDestinationPage(PdfPage sourcePage) {
    final Size size = _sizeOf(sourcePage);
    final PdfPageRotateAngle rotation = sourcePage.rotation;
    if (PdfDocumentHelper.getHelper(destination).isLoadedDocument) {
      return destination.pages.insert(
        destination.pages.count,
        size,
        PdfMargins(),
        rotation,
      );
    }
    final PdfSection section = destination.sections!.add();
    section.pageSettings =
        PdfPageSettings(
            size,
            size.width > size.height
                ? PdfPageOrientation.landscape
                : PdfPageOrientation.portrait,
          )
          ..margins = PdfMargins()
          ..rotate = rotation;
    return section.pages.add();
  }

  /// The visible size of a page, preferring `/CropBox` over `/MediaBox` the
  /// way [PdfPage.size] does, with a fallback for pages that declare neither.
  Size _sizeOf(PdfPage page) {
    final Size size = page.size;
    if (size.width > 0 && size.height > 0) {
      return size;
    }
    return PdfPageSize.a4;
  }

  void _copyDocumentInformation(PdfDocument source) {
    if (!options.copyDocumentInfoFromFirst || _documentInformationCopied) {
      return;
    }
    _documentInformationCopied = true;
    destination.documentInformation.title = source.documentInformation.title;
    destination.documentInformation.author = source.documentInformation.author;
    destination.documentInformation.subject =
        source.documentInformation.subject;
    destination.documentInformation.keywords =
        source.documentInformation.keywords;
    destination.documentInformation.producer =
        source.documentInformation.producer;
  }
}
