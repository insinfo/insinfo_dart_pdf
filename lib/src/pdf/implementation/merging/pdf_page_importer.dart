import '../../interfaces/pdf_interface.dart';
import '../io/pdf_constants.dart';
import '../io/pdf_cross_table.dart';
import '../pages/pdf_page.dart';
import '../primitives/pdf_dictionary.dart';
import '../primitives/pdf_name.dart';
import '../primitives/pdf_null.dart';
import '../primitives/pdf_reference.dart';
import 'pdf_import_context.dart';

/// Copies the object graph of a page from a source document into the
/// destination document of a merge session.
///
/// This is an internal class.
class PdfPageImporter {
  /// internal constructor
  PdfPageImporter(this.context);

  /// The merge session state.
  final PdfImportContext context;

  /// Page entries that describe the page itself and are safe to transfer.
  ///
  /// `/Parent`, `/Annots`, `/StructParents` and `/B` are deliberately absent:
  /// the first is rebuilt by the destination page tree, the second is handled
  /// by [PdfAnnotationImporter], and the last two belong to the structure tree,
  /// which is not merged.
  static const List<String> transferableKeys = <String>[
    PdfDictionaryProperties.contents,
    PdfDictionaryProperties.resources,
    PdfDictionaryProperties.mediaBox,
    PdfDictionaryProperties.cropBox,
    bleedBox,
    trimBox,
    artBox,
    PdfDictionaryProperties.rotate,
    PdfDictionaryProperties.group,
    userUnit,
    PdfDictionaryProperties.tabs,
  ];

  /// Entries a page may inherit from an ancestor node of the page tree.
  static const List<String> inheritableKeys = <String>[
    PdfDictionaryProperties.resources,
    PdfDictionaryProperties.mediaBox,
    PdfDictionaryProperties.cropBox,
    PdfDictionaryProperties.rotate,
  ];

  /// internal constant
  static const String bleedBox = 'BleedBox';

  /// internal constant
  static const String trimBox = 'TrimBox';

  /// internal constant
  static const String artBox = 'ArtBox';

  /// internal constant
  static const String userUnit = 'UserUnit';

  /// Builds a detached dictionary carrying everything the destination page
  /// needs, with inherited entries materialized.
  ///
  /// The values are taken in their original form — a reference holder stays a
  /// reference holder — so that objects shared by several source pages stay
  /// shared after the clone.
  PdfDictionary buildSeed(PdfDictionary sourcePage) {
    final PdfDictionary seed = PdfDictionary();
    for (final String key in transferableKeys) {
      final IPdfPrimitive? value =
          inheritableKeys.contains(key)
              ? resolveInherited(sourcePage, key)
              : sourcePage[key];
      if (value != null && value is! PdfNull) {
        seed[key] = value;
      }
    }
    return seed;
  }

  /// Returns the value of [key] on [pageDictionary], or the closest value
  /// found walking up the `/Parent` chain.
  ///
  /// Unlike [PdfDictionary.getValue] the result keeps its indirection, so a
  /// resource dictionary shared by the whole source document is cloned once
  /// rather than once per page.
  IPdfPrimitive? resolveInherited(PdfDictionary pageDictionary, String key) {
    if (pageDictionary.containsKey(key)) {
      return pageDictionary[key];
    }
    final Set<PdfDictionary> visited = <PdfDictionary>{};
    PdfDictionary? node = _parentOf(pageDictionary);
    while (node != null && visited.add(node)) {
      if (node.containsKey(key)) {
        return node[key];
      }
      node = _parentOf(node);
    }
    return null;
  }

  PdfDictionary? _parentOf(PdfDictionary dictionary) {
    final IPdfPrimitive? parent = PdfCrossTable.dereference(
      dictionary[PdfDictionaryProperties.parent],
    );
    return parent is PdfDictionary ? parent : null;
  }

  /// Clones [source] into the destination cross table.
  ///
  /// [allowPageClone] must be set when the graph can reach a page object —
  /// annotation destinations and bookmark targets do, page content does not.
  PdfDictionary clone(PdfDictionary source, {bool allowPageClone = false}) {
    return context.runAttached(() {
      IPdfPrimitive? cloned;
      final PdfCrossTable table = context.crossTable;
      final List<PdfReference?>? previous = table.prevReference;
      table.prevReference = <PdfReference?>[];
      try {
        if (allowPageClone) {
          cloned = context.runWithPageClone(() => source.cloneObject(table));
        } else {
          cloned = source.cloneObject(table);
        }
      } finally {
        table.prevReference = previous;
      }
      return cloned! as PdfDictionary;
    });
  }

  /// Writes the entries of [cloned] onto the dictionary of [destination].
  ///
  /// `/Type` and `/Parent` of the destination page are left untouched: they
  /// tie the page to the destination page tree.
  void applyTo(PdfPage destination, PdfDictionary cloned) {
    final PdfDictionary target = PdfPageHelper.getHelper(destination)
        .dictionary!;
    cloned.items!.forEach((PdfName? key, IPdfPrimitive? value) {
      if (key == null || value == null) {
        return;
      }
      if (key.name == PdfDictionaryProperties.type ||
          key.name == PdfDictionaryProperties.parent) {
        return;
      }
      target[key] = value;
    });
    target.modify();
  }
}
