import '../../interfaces/pdf_interface.dart';
import '../io/pdf_constants.dart';
import '../io/pdf_cross_table.dart';
import '../pages/pdf_page.dart';
import '../pdf_document/pdf_document.dart';
import '../primitives/pdf_array.dart';
import '../primitives/pdf_dictionary.dart';
import '../primitives/pdf_name.dart';
import '../primitives/pdf_null.dart';
import '../primitives/pdf_number.dart';
import '../primitives/pdf_reference_holder.dart';
import '../primitives/pdf_string.dart';
import 'pdf_import_context.dart';
import 'pdf_page_importer.dart';

/// Result of importing the annotations of one page.
///
/// This is an internal class.
class PdfImportedAnnotations {
  /// internal constructor
  PdfImportedAnnotations(this.imported, this.widgets);

  /// The cloned annotation dictionaries, in source order.
  final List<PdfDictionary> imported;

  /// Source dictionaries of `/Subtype /Widget` annotations, paired with their
  /// clone, for the form importer to wire into `/AcroForm`.
  final Map<PdfDictionary, PdfDictionary> widgets;
}

/// Copies page annotations — links, markup, popups and form widgets — from a
/// source document into the destination document of a merge session.
///
/// This is an internal class.
class PdfAnnotationImporter {
  /// internal constructor
  PdfAnnotationImporter(this.context, this.pageImporter);

  /// The merge session state.
  final PdfImportContext context;

  /// The object cloner shared with the page importer.
  final PdfPageImporter pageImporter;

  /// internal constant
  static const String popup = 'Popup';

  /// internal constant
  static const String inReplyTo = 'IRT';

  /// internal constant
  static const String destination = 'D';

  /// Imports the `/Annots` of [sourcePage] onto [destinationPage].
  PdfImportedAnnotations import(
    PdfDictionary sourcePage,
    PdfPage destinationPage,
    PdfDocument source,
  ) {
    final List<PdfDictionary> sourceAnnotations = _annotationsOf(sourcePage);
    final List<PdfDictionary> imported = <PdfDictionary>[];
    final Map<PdfDictionary, PdfDictionary> widgets =
        <PdfDictionary, PdfDictionary>{};
    if (sourceAnnotations.isEmpty) {
      return PdfImportedAnnotations(imported, widgets);
    }
    final PdfDictionary destinationDictionary =
        PdfPageHelper.getHelper(destinationPage).dictionary!;

    // Clone every annotation with its intra-page links cut, so that the
    // annotation <-> popup and reply-to cycles cannot drag the source page
    // into the destination document.
    final Map<PdfDictionary, PdfDictionary> clones =
        <PdfDictionary, PdfDictionary>{};
    for (final PdfDictionary annotation in sourceAnnotations) {
      bool isWidget = _isWidget(annotation);
      if (isWidget && !context.options.importFormFields) {
        continue;
      }
      if (!isWidget && !context.options.importAnnotations) {
        continue;
      }
      bool isStrippedSignature = false;
      if (isWidget &&
          !context.options.keepInvalidSignatures &&
          _isSignatureField(annotation)) {
        // The signature itself cannot survive a merge, only the mark it left
        // on the page.
        if (context.options.removeSignatureAppearance) {
          continue;
        }
        if (!_hasAppearance(annotation)) {
          // An invisible signature field leaves nothing worth keeping.
          continue;
        }
        isStrippedSignature = true;
        isWidget = false;
      }
      final PdfDictionary seed = _buildSeed(
        annotation,
        source,
        stripField: isStrippedSignature,
      );
      final PdfDictionary clone = pageImporter.clone(
        seed,
        allowPageClone: true,
      );
      _dropBrokenDestinations(clone);
      if (isStrippedSignature) {
        _demoteToStamp(clone);
      }
      clone[PdfDictionaryProperties.p] = PdfReferenceHolder(
        destinationDictionary,
      );
      clones[annotation] = clone;
      imported.add(clone);
      if (isWidget) {
        widgets[annotation] = clone;
      }
    }

    // Restore the links that were cut, now between the clones.
    for (final MapEntry<PdfDictionary, PdfDictionary> entry in clones.entries) {
      _relink(entry.key, entry.value, clones, destinationDictionary);
    }

    if (imported.isNotEmpty) {
      final PdfArray annots = PdfArray();
      for (final PdfDictionary clone in imported) {
        annots.add(PdfReferenceHolder(clone));
      }
      destinationDictionary[PdfDictionaryProperties.annots] = annots;
    }
    return PdfImportedAnnotations(imported, widgets);
  }

  /// Reads the annotation dictionaries of a page, skipping unresolvable
  /// entries.
  List<PdfDictionary> _annotationsOf(PdfDictionary page) {
    final List<PdfDictionary> result = <PdfDictionary>[];
    final IPdfPrimitive? annots = PdfCrossTable.dereference(
      page[PdfDictionaryProperties.annots],
    );
    if (annots is! PdfArray) {
      return result;
    }
    for (int i = 0; i < annots.count; i++) {
      final IPdfPrimitive? entry = PdfCrossTable.dereference(annots[i]);
      if (entry is PdfDictionary) {
        result.add(entry);
      }
    }
    return result;
  }

  /// Whether [annotation] belongs to a signature field, looking up the
  /// `/Parent` chain because `/FT` is inheritable.
  bool _isSignatureField(PdfDictionary annotation) {
    final Set<PdfDictionary> visited = <PdfDictionary>{};
    PdfDictionary? node = annotation;
    while (node != null && visited.add(node)) {
      final IPdfPrimitive? type = PdfCrossTable.dereference(
        node[PdfDictionaryProperties.ft],
      );
      if (type is PdfName) {
        return type.name == PdfDictionaryProperties.sig;
      }
      final IPdfPrimitive? parent = PdfCrossTable.dereference(
        node[PdfDictionaryProperties.parent],
      );
      node = parent is PdfDictionary ? parent : null;
    }
    return false;
  }

  /// Whether the annotation carries a normal appearance stream — the visible
  /// mark a signature left on the page.
  bool _hasAppearance(PdfDictionary annotation) {
    final IPdfPrimitive? appearance = PdfCrossTable.dereference(
      annotation[PdfDictionaryProperties.ap],
    );
    if (appearance is! PdfDictionary) {
      return false;
    }
    return PdfCrossTable.dereference(
          appearance[PdfDictionaryProperties.n],
        ) !=
        null;
  }

  /// Field entries that only make sense on a form widget.
  static const List<String> _fieldOnlyKeys = <String>[
    PdfDictionaryProperties.ft,
    PdfDictionaryProperties.v,
    PdfDictionaryProperties.dv,
    PdfDictionaryProperties.t,
    PdfDictionaryProperties.tu,
    PdfDictionaryProperties.fieldFlags,
    PdfDictionaryProperties.da,
    PdfDictionaryProperties.q,
    PdfDictionaryProperties.mk,
    PdfDictionaryProperties.aa,
    PdfDictionaryProperties.kids,
    'SV',
    'Lock',
    'H',
  ];

  /// Turns a cloned signature widget into a read-only stamp annotation.
  ///
  /// The field entries are already gone: [_buildSeed] pruned them from the
  /// seed so they were never cloned. What is left is the appearance and the
  /// geometry.
  ///
  /// The signature is gone — merging invalidated it — but the appearance
  /// stream that shows who signed and when is ordinary page decoration, and
  /// keeping it costs nothing. As a stamp it is no longer a form field, so no
  /// viewer offers to validate a signature that is not there, and read-only
  /// keeps it from being dragged around.
  void _demoteToStamp(PdfDictionary clone) {
    clone[PdfDictionaryProperties.subtype] = PdfName('Stamp');
    for (final String key in _fieldOnlyKeys) {
      clone.remove(key);
    }
    clone.remove(PdfDictionaryProperties.a);
    final IPdfPrimitive? flags = PdfCrossTable.dereference(
      clone[PdfDictionaryProperties.f],
    );
    final int current = flags is PdfNumber ? flags.value!.toInt() : _print;
    clone[PdfDictionaryProperties.f] = PdfNumber(current | _readOnly);
    clone.modify();
  }

  /// Annotation flag: print the annotation.
  static const int _print = 4;

  /// Annotation flag: the annotation cannot be edited by the user.
  static const int _readOnly = 64;

  bool _isWidget(PdfDictionary annotation) {
    final IPdfPrimitive? subtype = PdfCrossTable.dereference(
      annotation[PdfDictionaryProperties.subtype],
    );
    return subtype is PdfName &&
        subtype.name == PdfDictionaryProperties.widget;
  }

  /// Builds a detached shallow copy of [annotation] with every entry that
  /// points back into the source document removed or resolved.
  PdfDictionary _buildSeed(
    PdfDictionary annotation,
    PdfDocument source, {
    bool stripField = false,
  }) {
    final PdfDictionary seed = PdfDictionary(annotation);
    seed.remove(PdfDictionaryProperties.p);
    seed.remove(PdfDictionaryProperties.parent);
    seed.remove(popup);
    seed.remove(inReplyTo);
    if (context.options.dropStructureTree) {
      seed.remove('StructParent');
    }
    if (stripField) {
      // Prune before cloning, not after. Dropping `/V` from the clone would
      // leave the signature dictionary — the whole PKCS#7 blob — registered in
      // the destination as an unreachable object: invisible to a reader that
      // walks `/AcroForm /Fields`, but found by anything that scans for
      // signature dictionaries, and paying for tens of kilobytes of dead CMS.
      for (final String key in _fieldOnlyKeys) {
        seed.remove(key);
      }
    }
    _resolveNamedDestinations(seed, source);
    return seed;
  }

  /// Replaces `/Dest` and `/A /D` name references with the explicit
  /// destination array they stand for, so the target survives the clone even
  /// when the destination document has no name tree yet.
  void _resolveNamedDestinations(PdfDictionary seed, PdfDocument source) {
    final IPdfPrimitive? dest = seed[PdfDictionaryProperties.dest];
    final PdfArray? resolvedDest = _resolveDestination(dest, source);
    if (resolvedDest != null) {
      seed[PdfDictionaryProperties.dest] = resolvedDest;
    }
    final IPdfPrimitive? action = PdfCrossTable.dereference(
      seed[PdfDictionaryProperties.a],
    );
    if (action is! PdfDictionary) {
      return;
    }
    final PdfArray? resolvedAction = _resolveDestination(
      action[destination],
      source,
    );
    if (resolvedAction != null) {
      final PdfDictionary actionCopy = PdfDictionary(action);
      actionCopy[destination] = resolvedAction;
      seed[PdfDictionaryProperties.a] = actionCopy;
    }
  }

  /// Resolves a destination value to an explicit array in the *source*
  /// document. Returns `null` when [value] is already explicit or cannot be
  /// resolved.
  PdfArray? _resolveDestination(IPdfPrimitive? value, PdfDocument source) {
    final IPdfPrimitive? dereferenced = PdfCrossTable.dereference(value);
    if (dereferenced is! PdfName && dereferenced is! PdfString) {
      return null;
    }
    final PdfArray? resolved = PdfDocumentHelper.getHelper(
      source,
    ).getNamedDestination(dereferenced!);
    if (resolved == null) {
      context.addWarning(
        'Named destination could not be resolved and was dropped.',
      );
    }
    return resolved;
  }

  /// Removes destination entries whose target page was not imported.
  ///
  /// Such a page reference clones to [PdfNull]: inside an array it survives as
  /// a null element, which viewers read as a broken destination, so the whole
  /// entry is dropped instead.
  void _dropBrokenDestinations(PdfDictionary clone) {
    if (_isBrokenDestination(clone[PdfDictionaryProperties.dest])) {
      clone.remove(PdfDictionaryProperties.dest);
      context.addWarning(
        'Link destination pointed to a page outside the imported range '
        'and was dropped.',
      );
    }
    final IPdfPrimitive? action = PdfCrossTable.dereference(
      clone[PdfDictionaryProperties.a],
    );
    if (action is PdfDictionary && _isBrokenDestination(action[destination])) {
      // A GoTo action without a target is meaningless; drop the action so the
      // annotation stays inert instead of pointing at nothing.
      clone.remove(PdfDictionaryProperties.a);
      context.addWarning(
        'Link action pointed to a page outside the imported range '
        'and was dropped.',
      );
    }
  }

  bool _isBrokenDestination(IPdfPrimitive? value) {
    final IPdfPrimitive? dereferenced = PdfCrossTable.dereference(value);
    if (dereferenced is! PdfArray || dereferenced.count == 0) {
      return false;
    }
    final IPdfPrimitive? target = dereferenced[0];
    // A remote destination addresses the page by index, not by reference.
    if (target is PdfNumber) {
      return false;
    }
    return target is PdfNull || target == null;
  }

  /// Re-creates `/P`, `/Popup`, `/Parent` and `/IRT` between the clones.
  void _relink(
    PdfDictionary sourceAnnotation,
    PdfDictionary clone,
    Map<PdfDictionary, PdfDictionary> clones,
    PdfDictionary destinationPage,
  ) {
    final IPdfPrimitive? sourcePopup = PdfCrossTable.dereference(
      sourceAnnotation[popup],
    );
    if (sourcePopup is PdfDictionary) {
      final PdfDictionary? popupClone = clones[sourcePopup];
      if (popupClone != null) {
        clone[popup] = PdfReferenceHolder(popupClone);
        popupClone[PdfDictionaryProperties.parent] = PdfReferenceHolder(clone);
        popupClone[PdfDictionaryProperties.p] = PdfReferenceHolder(
          destinationPage,
        );
      }
    }
    final IPdfPrimitive? sourceReply = PdfCrossTable.dereference(
      sourceAnnotation[inReplyTo],
    );
    if (sourceReply is PdfDictionary) {
      final PdfDictionary? replyClone = clones[sourceReply];
      if (replyClone != null) {
        clone[inReplyTo] = PdfReferenceHolder(replyClone);
      }
    }
  }
}
