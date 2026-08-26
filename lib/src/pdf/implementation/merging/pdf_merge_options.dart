/// Specifies how pages are transferred from a source document into the
/// destination document during a merge.
enum PdfMergeMode {
  /// Imports the object graph of each source page.
  ///
  /// Preserves annotations, links, form fields, bookmarks and layers.
  objectImport,

  /// Flattens each source page into a single form XObject.
  ///
  /// Fast and predictable, but everything that is not graphical content
  /// (annotations, links, form fields, bookmarks) is discarded.
  flatten,
}

/// Specifies how field name collisions are resolved when two merged documents
/// declare form fields with the same fully qualified name.
enum PdfFieldNameConflictPolicy {
  /// Appends `_2`, `_3`, ... to the imported field name.
  renameSuffix,

  /// Keeps the field already present in the destination and drops the
  /// imported one.
  keepFirst,

  /// Throws a [PdfMergeException].
  throwError,
}

/// Specifies what happens when a source document carries digital signatures.
///
/// Merging always rewrites the whole file, so every existing signature is
/// invalidated by construction.
enum PdfSignedSourcePolicy {
  /// Throws a [PdfMergeException]. This is the default.
  reject,

  /// Removes the signature fields and continues, recording a warning.
  stripSignatures,
}

/// Controls the behaviour of [PdfDocumentMerger].
class PdfMergeOptions {
  /// Initializes a new instance of the [PdfMergeOptions] class.
  PdfMergeOptions({
    this.mode = PdfMergeMode.objectImport,
    this.importAnnotations = true,
    this.importFormFields = true,
    this.fieldNameConflict = PdfFieldNameConflictPolicy.renameSuffix,
    this.importBookmarks = true,
    this.importNamedDestinations = true,
    this.importLayers = true,
    this.importPageLabels = true,
    this.importAttachments = false,
    this.dropStructureTree = true,
    this.copyDocumentInfoFromFirst = false,
    this.signedSourcePolicy = PdfSignedSourcePolicy.reject,
    this.groupBookmarksPerDocument = false,
  });

  /// Creates options that flatten every source page.
  factory PdfMergeOptions.flatten() =>
      PdfMergeOptions(mode: PdfMergeMode.flatten);

  /// The merge strategy. Defaults to [PdfMergeMode.objectImport].
  PdfMergeMode mode;

  /// Whether page annotations (links, markup, popups) are imported.
  bool importAnnotations;

  /// Whether interactive form fields are imported.
  bool importFormFields;

  /// How form field name collisions are resolved.
  PdfFieldNameConflictPolicy fieldNameConflict;

  /// Whether the source outline (bookmark) tree is imported.
  bool importBookmarks;

  /// Whether named destinations are imported.
  bool importNamedDestinations;

  /// Whether optional content groups (layers) are imported.
  bool importLayers;

  /// Whether page labels are imported.
  bool importPageLabels;

  /// Whether embedded file attachments are imported. Defaults to `false`.
  bool importAttachments;

  /// Whether the logical structure tree is dropped.
  ///
  /// Merging structure trees is not supported yet, so the default is `true`.
  /// Setting it to `false` keeps `/StructParents` on the imported pages, which
  /// produces a broken structure tree.
  bool dropStructureTree;

  /// Whether the document information (title, author, ...) of the first merged
  /// document is copied into the destination.
  bool copyDocumentInfoFromFirst;

  /// What to do when a source document contains digital signatures.
  PdfSignedSourcePolicy signedSourcePolicy;

  /// Whether imported bookmarks are nested under one node per source document
  /// instead of being appended to the destination root.
  bool groupBookmarksPerDocument;
}

/// The exception that is thrown when a merge operation cannot be completed.
class PdfMergeException implements Exception {
  /// Initializes a new instance of the [PdfMergeException] class.
  PdfMergeException(this.message);

  /// A description of the failure.
  final String message;

  @override
  String toString() => 'PdfMergeException: $message';
}
