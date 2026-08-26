import '../../interfaces/pdf_interface.dart';
import '../io/pdf_constants.dart';
import '../io/pdf_cross_table.dart';
import '../pdf_document/pdf_document.dart';
import '../primitives/pdf_array.dart';
import '../primitives/pdf_dictionary.dart';
import '../primitives/pdf_name.dart';
import '../primitives/pdf_number.dart';
import '../primitives/pdf_reference_holder.dart';
import 'pdf_import_context.dart';
import 'pdf_page_importer.dart';

/// Carries document level entries — optional content groups and page labels —
/// from a source document into the destination catalog.
///
/// This is an internal class.
class PdfCatalogMerger {
  /// internal constructor
  PdfCatalogMerger(this.context, this.pageImporter);

  /// The merge session state.
  final PdfImportContext context;

  /// The object cloner shared with the page importer.
  final PdfPageImporter pageImporter;

  /// internal constant
  static const String optionalContentGroups = 'OCGs';

  /// internal constant
  static const String defaultConfiguration = 'D';

  /// internal constant
  static const String order = 'Order';

  /// internal constant
  static const String on = 'ON';

  /// internal constant
  static const String off = 'OFF';

  /// internal constant
  static const String pageLabels = 'PageLabels';

  /// internal constant
  static const String numbers = 'Nums';

  /// Registers the optional content groups used by the imported pages in the
  /// destination `/OCProperties`.
  ///
  /// The group dictionaries themselves already travelled with the page
  /// resources; what is missing is the catalog level declaration that makes a
  /// viewer show them in its layer panel and honour their default visibility.
  void importOptionalContent(PdfDocument source) {
    if (!context.options.importLayers) {
      return;
    }
    final IPdfPrimitive? sourceProperties = PdfCrossTable.dereference(
      PdfDocumentHelper.getHelper(
        source,
      ).catalog[PdfDictionaryProperties.ocProperties],
    );
    if (sourceProperties is! PdfDictionary) {
      return;
    }
    final IPdfPrimitive? sourceGroups = PdfCrossTable.dereference(
      sourceProperties[optionalContentGroups],
    );
    if (sourceGroups is! PdfArray || sourceGroups.count == 0) {
      return;
    }
    final Set<IPdfPrimitive> hidden = _visibilitySet(sourceProperties, off);

    PdfDictionary? properties;
    PdfArray? groups;
    PdfArray? ordering;
    PdfArray? visible;
    PdfArray? invisible;
    for (int i = 0; i < sourceGroups.count; i++) {
      final IPdfPrimitive? group = PdfCrossTable.dereference(sourceGroups[i]);
      if (group is! PdfDictionary) {
        continue;
      }
      final IPdfPrimitive? clone = context.clonedObjects[group];
      if (clone == null) {
        // The group is not referenced by any imported page.
        continue;
      }
      properties ??= _destinationOptionalContent();
      groups ??= _arrayOf(properties, optionalContentGroups);
      final PdfDictionary configuration = _dictionaryOf(
        properties,
        defaultConfiguration,
      );
      ordering ??= _arrayOf(configuration, order);
      visible ??= _arrayOf(configuration, on);
      invisible ??= _arrayOf(configuration, off);

      final PdfReferenceHolder reference = PdfReferenceHolder(clone);
      groups.add(reference);
      ordering.add(PdfReferenceHolder(clone));
      if (hidden.contains(group)) {
        invisible.add(PdfReferenceHolder(clone));
      } else {
        visible.add(PdfReferenceHolder(clone));
      }
    }
  }

  /// Appends the page labels of [source], shifting every range by the index
  /// the imported pages start at.
  void importPageLabels(PdfDocument source, int destinationOffset) {
    if (!context.options.importPageLabels) {
      return;
    }
    final IPdfPrimitive? sourceLabels = PdfCrossTable.dereference(
      PdfDocumentHelper.getHelper(source).catalog[pageLabels],
    );
    if (sourceLabels is! PdfDictionary) {
      return;
    }
    final IPdfPrimitive? sourceNumbers = PdfCrossTable.dereference(
      sourceLabels[numbers],
    );
    if (sourceNumbers is! PdfArray || sourceNumbers.count < 2) {
      return;
    }
    final PdfDictionary labels = _dictionaryOf(
      PdfDocumentHelper.getHelper(context.destination).catalog,
      pageLabels,
    );
    final PdfArray target = _arrayOf(labels, numbers);
    for (int i = 0; i + 1 < sourceNumbers.count; i += 2) {
      final IPdfPrimitive? key = PdfCrossTable.dereference(sourceNumbers[i]);
      final IPdfPrimitive? value = PdfCrossTable.dereference(
        sourceNumbers[i + 1],
      );
      if (key is! PdfNumber || value is! PdfDictionary) {
        continue;
      }
      final IPdfPrimitive? clonedValue = pageImporter.clone(
        PdfDictionary()..[numbers] = sourceNumbers[i + 1],
      )[numbers];
      if (clonedValue == null) {
        continue;
      }
      target.add(PdfNumber(key.value!.toInt() + destinationOffset));
      target.add(clonedValue);
    }
    if (target.count > 0) {
      PdfDocumentHelper.getHelper(context.destination).catalog.modify();
    }
  }

  /// The source groups explicitly listed under `/D /[state]`.
  Set<IPdfPrimitive> _visibilitySet(PdfDictionary properties, String state) {
    final Set<IPdfPrimitive> result = Set<IPdfPrimitive>.identity();
    final IPdfPrimitive? configuration = PdfCrossTable.dereference(
      properties[defaultConfiguration],
    );
    if (configuration is! PdfDictionary) {
      return result;
    }
    final IPdfPrimitive? entries = PdfCrossTable.dereference(
      configuration[state],
    );
    if (entries is! PdfArray) {
      return result;
    }
    for (int i = 0; i < entries.count; i++) {
      final IPdfPrimitive? entry = PdfCrossTable.dereference(entries[i]);
      if (entry != null) {
        result.add(entry);
      }
    }
    return result;
  }

  /// The `/OCProperties` of the destination catalog, created if absent.
  PdfDictionary _destinationOptionalContent() {
    final PdfDictionary catalog =
        PdfDocumentHelper.getHelper(context.destination).catalog;
    final IPdfPrimitive? existing = PdfCrossTable.dereference(
      catalog[PdfDictionaryProperties.ocProperties],
    );
    if (existing is PdfDictionary) {
      return existing;
    }
    final PdfDictionary created = PdfDictionary();
    created[optionalContentGroups] = PdfArray();
    final PdfDictionary configuration = PdfDictionary();
    configuration[PdfDictionaryProperties.name] = PdfName('Default');
    created[defaultConfiguration] = configuration;
    catalog[PdfDictionaryProperties.ocProperties] = created;
    catalog.modify();
    return created;
  }

  PdfArray _arrayOf(PdfDictionary owner, String key) {
    final IPdfPrimitive? existing = PdfCrossTable.dereference(owner[key]);
    if (existing is PdfArray) {
      return existing;
    }
    final PdfArray created = PdfArray();
    owner[key] = created;
    owner.modify();
    return created;
  }

  PdfDictionary _dictionaryOf(PdfDictionary owner, String key) {
    final IPdfPrimitive? existing = PdfCrossTable.dereference(owner[key]);
    if (existing is PdfDictionary) {
      return existing;
    }
    final PdfDictionary created = PdfDictionary();
    owner[key] = created;
    owner.modify();
    return created;
  }
}
