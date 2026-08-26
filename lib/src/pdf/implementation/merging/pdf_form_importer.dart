import '../../interfaces/pdf_interface.dart';
import '../forms/pdf_form.dart';
import '../io/pdf_constants.dart';
import '../io/pdf_cross_table.dart';
import '../pdf_document/pdf_document.dart';
import '../primitives/pdf_array.dart';
import '../primitives/pdf_boolean.dart';
import '../primitives/pdf_dictionary.dart';
import '../primitives/pdf_name.dart';
import '../primitives/pdf_number.dart';
import '../primitives/pdf_reference_holder.dart';
import '../primitives/pdf_string.dart';
import 'pdf_import_context.dart';
import 'pdf_merge_options.dart';
import 'pdf_page_importer.dart';

/// Wires imported form widgets into the `/AcroForm` of the destination
/// document.
///
/// The field hierarchy of the source is flattened: every terminal field is
/// re-created at the top level of `/AcroForm /Fields` carrying its fully
/// qualified name in `/T`. Values, flags and appearance streams travel with
/// the clone, and multi-widget fields (radio button groups, fields spanning
/// several pages) keep their widgets grouped under a single field.
///
/// This is an internal class.
class PdfFormImporter {
  /// internal constructor
  PdfFormImporter(this.context, this.pageImporter);

  /// The merge session state.
  final PdfImportContext context;

  /// The object cloner shared with the page importer.
  final PdfPageImporter pageImporter;

  /// Source terminal field dictionary -> the field created for it in the
  /// destination. Keeps a field whose widgets live on different pages from
  /// being split into several fields.
  final Map<PdfDictionary, PdfDictionary> _importedFields =
      <PdfDictionary, PdfDictionary>{};

  /// Fully qualified names already present in the destination form.
  Set<String>? _takenNames;

  /// Whether a signature field made it into the destination form, so that
  /// `/SigFlags` has to be carried over for viewers to show the signature
  /// panel at all.
  bool _importedSignatureField = false;

  /// Sources whose widget-less fields have already been swept in, so importing
  /// two page ranges of the same document does not duplicate them.
  final Set<PdfDocument> _sweptSources = Set<PdfDocument>.identity();

  /// Adds [widgets] — source widget dictionary mapped to its clone — to the
  /// destination form.
  void importWidgets(
    Map<PdfDictionary, PdfDictionary> widgets,
    PdfDocument source,
  ) {
    if (widgets.isEmpty || !context.options.importFormFields) {
      return;
    }
    final PdfDictionary acroForm = _destinationAcroForm();
    final PdfArray fields = _fieldsArray(acroForm);
    _takenNames ??= _collectNames(fields);

    // Group the widgets by the terminal field they belong to, preserving the
    // page order so radio kids keep their export order.
    final Map<PdfDictionary, List<PdfDictionary>> groups =
        <PdfDictionary, List<PdfDictionary>>{};
    final Map<PdfDictionary, PdfDictionary> cloneOf =
        <PdfDictionary, PdfDictionary>{};
    for (final MapEntry<PdfDictionary, PdfDictionary> entry
        in widgets.entries) {
      final PdfDictionary terminal = _terminalField(entry.key);
      groups.putIfAbsent(terminal, () => <PdfDictionary>[]).add(entry.key);
      cloneOf[entry.key] = entry.value;
    }

    for (final MapEntry<PdfDictionary, List<PdfDictionary>> group
        in groups.entries) {
      final PdfDictionary terminal = group.key;
      final List<PdfDictionary> widgetSources = group.value;
      final PdfDictionary? existing = _importedFields[terminal];
      if (existing != null) {
        _attachKids(existing, widgetSources, cloneOf);
        continue;
      }
      final PdfDictionary? field = _createField(
        terminal,
        widgetSources,
        cloneOf,
      );
      if (field == null) {
        continue;
      }
      _importedFields[terminal] = field;
      _importedSignatureField |= _isSignatureField(field);
      fields.add(PdfReferenceHolder(field));
    }
    _mergeFormDefaults(acroForm, source);
  }

  /// Imports the fields of [source] that no page widget led to.
  ///
  /// A field is normally found through the widget annotation that shows it on
  /// a page, but `/AcroForm /Fields` may hold fields with no widget at all: a
  /// hidden data field, or — as documents produced by the SEI process system
  /// show — a signature whose widget was dropped from `/Annots` by an earlier
  /// merge. Those fields carry values and certificates, so they are swept in
  /// separately once every page of the source has been imported.
  void importOrphanFields(PdfDocument source) {
    if (!context.options.importFormFields || !_sweptSources.add(source)) {
      return;
    }
    final PdfDictionary? sourceForm = _sourceAcroForm(source);
    if (sourceForm == null) {
      return;
    }
    final IPdfPrimitive? sourceFields = PdfCrossTable.dereference(
      sourceForm[PdfDictionaryProperties.fields],
    );
    if (sourceFields is! PdfArray) {
      return;
    }
    final List<PdfDictionary> orphans =
        _terminalFieldsOf(sourceFields)
            .where((PdfDictionary f) => !_importedFields.containsKey(f))
            .toList();
    if (orphans.isEmpty) {
      return;
    }
    final PdfDictionary acroForm = _destinationAcroForm();
    final PdfArray fields = _fieldsArray(acroForm);
    _takenNames ??= _collectNames(fields);
    for (final PdfDictionary orphan in orphans) {
      if (_isSignatureField(orphan) &&
          !context.options.keepInvalidSignatures) {
        // Dropped for the same reason as the signatures that did have a
        // widget: merging invalidated them.
        continue;
      }
      final String? name = _resolveName(_qualifiedName(orphan));
      if (name == null) {
        continue;
      }
      final PdfDictionary seed = PdfDictionary(orphan);
      seed.remove(PdfDictionaryProperties.parent);
      seed.remove(PdfDictionaryProperties.kids);
      seed.remove(PdfDictionaryProperties.t);
      // The field has no page to belong to; a stale /P would drag the source
      // page into the destination.
      seed.remove(PdfDictionaryProperties.p);
      final PdfDictionary field = pageImporter.clone(
        seed,
        allowPageClone: true,
      );
      _materializeInherited(orphan, field);
      field[PdfDictionaryProperties.t] = PdfString(name);
      field.remove(PdfDictionaryProperties.parent);
      field.remove(PdfDictionaryProperties.p);
      field.modify();
      _importedFields[orphan] = field;
      _importedSignatureField |= _isSignatureField(field);
      fields.add(PdfReferenceHolder(field));
    }
    _mergeFormDefaults(acroForm, source);
  }

  /// The terminal fields of a `/Fields` array: the nodes that name a field and
  /// have no field children of their own. A `/Kids` entry without `/T` is a
  /// widget, not a nested field.
  List<PdfDictionary> _terminalFieldsOf(PdfArray nodes) {
    final List<PdfDictionary> terminals = <PdfDictionary>[];
    final Set<PdfDictionary> visited = <PdfDictionary>{};
    void walk(PdfArray current) {
      for (int i = 0; i < current.count; i++) {
        final IPdfPrimitive? node = PdfCrossTable.dereference(current[i]);
        if (node is! PdfDictionary || !visited.add(node)) {
          continue;
        }
        final IPdfPrimitive? kids = PdfCrossTable.dereference(
          node[PdfDictionaryProperties.kids],
        );
        if (kids is PdfArray && _hasFieldChildren(kids)) {
          walk(kids);
        } else {
          terminals.add(node);
        }
      }
    }

    walk(nodes);
    return terminals;
  }

  bool _hasFieldChildren(PdfArray kids) {
    for (int i = 0; i < kids.count; i++) {
      final IPdfPrimitive? kid = PdfCrossTable.dereference(kids[i]);
      if (kid is PdfDictionary && kid.containsKey(PdfDictionaryProperties.t)) {
        return true;
      }
    }
    return false;
  }

  PdfDictionary? _sourceAcroForm(PdfDocument source) {
    final IPdfPrimitive? form = PdfCrossTable.dereference(
      PdfDocumentHelper.getHelper(
        source,
      ).catalog[PdfDictionaryProperties.acroForm],
    );
    return form is PdfDictionary ? form : null;
  }

  /// Creates the destination field for one group, or `null` when the name
  /// policy says to drop it.
  PdfDictionary? _createField(
    PdfDictionary terminal,
    List<PdfDictionary> widgetSources,
    Map<PdfDictionary, PdfDictionary> cloneOf,
  ) {
    final String sourceName = _qualifiedName(terminal);
    final String? name = _resolveName(sourceName);
    if (name == null) {
      return null;
    }
    final bool merged =
        widgetSources.length == 1 && identical(widgetSources.first, terminal);
    if (merged) {
      final PdfDictionary field = cloneOf[terminal]!;
      _materializeInherited(terminal, field);
      field[PdfDictionaryProperties.t] = PdfString(name);
      field.remove(PdfDictionaryProperties.parent);
      field.modify();
      return field;
    }
    final PdfDictionary seed = PdfDictionary(terminal);
    seed.remove(PdfDictionaryProperties.parent);
    seed.remove(PdfDictionaryProperties.kids);
    seed.remove(PdfDictionaryProperties.t);
    final PdfDictionary field = pageImporter.clone(
      seed,
      allowPageClone: true,
    );
    _materializeInherited(terminal, field);
    field[PdfDictionaryProperties.t] = PdfString(name);
    field.remove(PdfDictionaryProperties.parent);
    _attachKids(field, widgetSources, cloneOf);
    return field;
  }

  /// Links widget clones to [field] through `/Kids` and `/Parent`.
  void _attachKids(
    PdfDictionary field,
    List<PdfDictionary> widgetSources,
    Map<PdfDictionary, PdfDictionary> cloneOf,
  ) {
    IPdfPrimitive? existingKids = PdfCrossTable.dereference(
      field[PdfDictionaryProperties.kids],
    );
    if (existingKids is! PdfArray) {
      existingKids = PdfArray();
      field[PdfDictionaryProperties.kids] = existingKids;
    }
    final PdfArray kids = existingKids;
    for (final PdfDictionary widgetSource in widgetSources) {
      final PdfDictionary widget = cloneOf[widgetSource]!;
      // The kid is a pure widget now: its name lives on the field.
      widget.remove(PdfDictionaryProperties.t);
      widget[PdfDictionaryProperties.parent] = PdfReferenceHolder(field);
      widget.modify();
      kids.add(PdfReferenceHolder(widget));
    }
    field.modify();
  }

  /// Entries a terminal field may inherit from its ancestors. Flattening the
  /// hierarchy detaches the field from those ancestors, so whatever it was
  /// inheriting has to be written onto it.
  static const List<String> inheritableFieldKeys = <String>[
    PdfDictionaryProperties.ft,
    PdfDictionaryProperties.fieldFlags,
    PdfDictionaryProperties.v,
    PdfDictionaryProperties.dv,
    PdfDictionaryProperties.da,
    PdfDictionaryProperties.q,
    PdfDictionaryProperties.opt,
    PdfDictionaryProperties.maxLen,
  ];

  void _materializeInherited(PdfDictionary terminal, PdfDictionary field) {
    for (final String key in inheritableFieldKeys) {
      if (field.containsKey(key)) {
        continue;
      }
      final IPdfPrimitive? inherited = _lookUp(terminal, key);
      if (inherited == null) {
        continue;
      }
      final IPdfPrimitive? cloned = pageImporter.clone(
        PdfDictionary()..[key] = inherited,
        allowPageClone: true,
      )[key];
      if (cloned != null) {
        field[key] = cloned;
      }
    }
  }

  bool _isSignatureField(PdfDictionary field) {
    final IPdfPrimitive? type = PdfCrossTable.dereference(
      field[PdfDictionaryProperties.ft],
    );
    return type is PdfName && type.name == PdfDictionaryProperties.sig;
  }

  IPdfPrimitive? _lookUp(PdfDictionary start, String key) {
    final Set<PdfDictionary> visited = <PdfDictionary>{};
    PdfDictionary? node = start;
    while (node != null && visited.add(node)) {
      if (node.containsKey(key)) {
        return node[key];
      }
      node = _fieldParent(node);
    }
    return null;
  }

  /// The nearest ancestor-or-self of [widget] that names a field.
  PdfDictionary _terminalField(PdfDictionary widget) {
    if (_hasName(widget)) {
      return widget;
    }
    final Set<PdfDictionary> visited = <PdfDictionary>{widget};
    PdfDictionary? node = _fieldParent(widget);
    while (node != null && visited.add(node)) {
      if (_hasName(node)) {
        return node;
      }
      node = _fieldParent(node);
    }
    return widget;
  }

  bool _hasName(PdfDictionary dictionary) {
    final IPdfPrimitive? name = PdfCrossTable.dereference(
      dictionary[PdfDictionaryProperties.t],
    );
    return name is PdfString && name.value != null && name.value!.isNotEmpty;
  }

  /// The `/Parent` of a field node, ignoring page tree links found in
  /// malformed documents.
  PdfDictionary? _fieldParent(PdfDictionary dictionary) {
    final IPdfPrimitive? parent = PdfCrossTable.dereference(
      dictionary[PdfDictionaryProperties.parent],
    );
    if (parent is! PdfDictionary) {
      return null;
    }
    final IPdfPrimitive? type = PdfCrossTable.dereference(
      parent[PdfDictionaryProperties.type],
    );
    if (type is PdfName &&
        (type.name == 'Page' || type.name == PdfDictionaryProperties.pages)) {
      return null;
    }
    return parent;
  }

  /// Builds the fully qualified name of [terminal] from the `/T` entries along
  /// its ancestor chain.
  String _qualifiedName(PdfDictionary terminal) {
    final List<String> parts = <String>[];
    final Set<PdfDictionary> visited = <PdfDictionary>{};
    PdfDictionary? node = terminal;
    while (node != null && visited.add(node)) {
      final IPdfPrimitive? name = PdfCrossTable.dereference(
        node[PdfDictionaryProperties.t],
      );
      if (name is PdfString && name.value != null && name.value!.isNotEmpty) {
        parts.insert(0, name.value!);
      }
      node = _fieldParent(node);
    }
    return parts.isEmpty ? 'field' : parts.join('.');
  }

  /// Applies [PdfMergeOptions.fieldNameConflict] and reserves the result.
  String? _resolveName(String name) {
    final Set<String> taken = _takenNames!;
    if (!taken.contains(name)) {
      taken.add(name);
      return name;
    }
    switch (context.options.fieldNameConflict) {
      case PdfFieldNameConflictPolicy.keepFirst:
        context.addWarning(
          'Form field "$name" already exists in the destination '
          'and was not imported.',
        );
        return null;
      case PdfFieldNameConflictPolicy.throwError:
        throw PdfMergeException(
          'Form field "$name" already exists in the destination document.',
        );
      case PdfFieldNameConflictPolicy.renameSuffix:
        int suffix = 2;
        while (taken.contains('${name}_$suffix')) {
          suffix++;
        }
        final String renamed = '${name}_$suffix';
        taken.add(renamed);
        context.addWarning(
          'Form field "$name" was renamed to "$renamed" to avoid a collision.',
        );
        return renamed;
    }
  }

  Set<String> _collectNames(PdfArray fields) {
    final Set<String> names = <String>{};
    for (int i = 0; i < fields.count; i++) {
      final IPdfPrimitive? field = PdfCrossTable.dereference(fields[i]);
      if (field is! PdfDictionary) {
        continue;
      }
      final IPdfPrimitive? name = PdfCrossTable.dereference(
        field[PdfDictionaryProperties.t],
      );
      if (name is PdfString && name.value != null) {
        names.add(name.value!);
      }
    }
    return names;
  }

  /// The `/AcroForm` dictionary of the destination, created if absent.
  ///
  /// Creation goes through [PdfDocument.form] so that the public form model
  /// and the catalog stay in sync — building the dictionary by hand would be
  /// silently replaced the first time the caller touches `document.form`.
  PdfDictionary _destinationAcroForm() {
    final IPdfPrimitive? existing = PdfCrossTable.dereference(
      PdfDocumentHelper.getHelper(
        context.destination,
      ).catalog[PdfDictionaryProperties.acroForm],
    );
    if (existing is PdfDictionary) {
      return existing;
    }
    final PdfForm form = context.destination.form;
    return PdfFormHelper.getHelper(form).dictionary!;
  }

  PdfArray _fieldsArray(PdfDictionary acroForm) {
    final IPdfPrimitive? fields = PdfCrossTable.dereference(
      acroForm[PdfDictionaryProperties.fields],
    );
    if (fields is PdfArray) {
      return fields;
    }
    final PdfArray created = PdfArray();
    acroForm[PdfDictionaryProperties.fields] = created;
    acroForm.modify();
    return created;
  }

  /// Carries `/DR`, `/DA`, `/Q` and `/NeedAppearances` over from the source
  /// form.
  void _mergeFormDefaults(PdfDictionary acroForm, PdfDocument source) {
    final PdfDictionary? sourceForm = _sourceAcroForm(source);
    if (sourceForm == null) {
      return;
    }
    _mergeDefaultResources(acroForm, sourceForm);
    for (final String key in <String>[
      PdfDictionaryProperties.da,
      PdfDictionaryProperties.q,
    ]) {
      if (!acroForm.containsKey(key) && sourceForm.containsKey(key)) {
        final IPdfPrimitive? cloned = pageImporter.clone(
          PdfDictionary()..[key] = sourceForm[key],
        )[key];
        if (cloned != null) {
          acroForm[key] = cloned;
        }
      }
    }
    if (_importedSignatureField) {
      _mergeSignatureFlags(acroForm, sourceForm);
    }
    final IPdfPrimitive? needAppearances = PdfCrossTable.dereference(
      sourceForm[PdfDictionaryProperties.needAppearances],
    );
    if (needAppearances is PdfBoolean && needAppearances.value == true) {
      acroForm[PdfDictionaryProperties.needAppearances] = PdfBoolean(true);
    }
    acroForm.modify();
  }

  /// Carries `/SigFlags` over, so viewers list the imported — and now
  /// invalid — signatures instead of ignoring them.
  void _mergeSignatureFlags(PdfDictionary acroForm, PdfDictionary sourceForm) {
    final IPdfPrimitive? sourceFlags = PdfCrossTable.dereference(
      sourceForm[PdfDictionaryProperties.sigFlags],
    );
    if (sourceFlags is! PdfNumber) {
      return;
    }
    final IPdfPrimitive? existing = PdfCrossTable.dereference(
      acroForm[PdfDictionaryProperties.sigFlags],
    );
    final int current = existing is PdfNumber ? existing.value!.toInt() : 0;
    acroForm[PdfDictionaryProperties.sigFlags] = PdfNumber(
      current | sourceFlags.value!.toInt(),
    );
  }

  /// Merges the source `/DR` into the destination one.
  ///
  /// Only names absent from the destination are added. Renaming a colliding
  /// resource would require rewriting every `/DA` string that mentions it, so
  /// the destination entry wins and the collision is reported instead.
  void _mergeDefaultResources(
    PdfDictionary acroForm,
    PdfDictionary sourceForm,
  ) {
    final IPdfPrimitive? sourceResources = PdfCrossTable.dereference(
      sourceForm[PdfDictionaryProperties.dr],
    );
    if (sourceResources is! PdfDictionary) {
      return;
    }
    IPdfPrimitive? resources = PdfCrossTable.dereference(
      acroForm[PdfDictionaryProperties.dr],
    );
    if (resources is! PdfDictionary) {
      resources = PdfDictionary();
      acroForm[PdfDictionaryProperties.dr] = resources;
    }
    final PdfDictionary target = resources;
    sourceResources.items!.forEach((PdfName? category, IPdfPrimitive? value) {
      if (category == null || value == null) {
        return;
      }
      final IPdfPrimitive? sourceCategory = PdfCrossTable.dereference(value);
      if (sourceCategory is! PdfDictionary) {
        return;
      }
      IPdfPrimitive? targetCategory = PdfCrossTable.dereference(
        target[category],
      );
      if (targetCategory is! PdfDictionary) {
        targetCategory = PdfDictionary();
        target[category] = targetCategory;
      }
      final PdfDictionary categoryTarget = targetCategory;
      sourceCategory.items!.forEach((PdfName? name, IPdfPrimitive? resource) {
        if (name == null || resource == null) {
          return;
        }
        if (categoryTarget.containsKey(name)) {
          context.addWarning(
            'Default resource /${category.name}/${name.name} already exists '
            'in the destination form; the source entry was ignored.',
          );
          return;
        }
        final IPdfPrimitive? cloned = pageImporter.clone(
          PdfDictionary()..[name] = resource,
        )[name];
        if (cloned != null) {
          categoryTarget[name] = cloned;
        }
      });
      categoryTarget.modify();
    });
    target.modify();
  }
}
