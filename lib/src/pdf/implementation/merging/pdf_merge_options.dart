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
    this.rejectSignedSources = false,
    this.keepInvalidSignatures = false,
    this.removeSignatureAppearance = false,
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

  /// Whether merging a source that carries digital signatures is refused.
  ///
  /// Merging always rewrites the whole file, so every signature the source
  /// holds is invalidated by construction — a signature covers the exact bytes
  /// of the document it was applied to, and no PDF tool can merge around that.
  /// The default is therefore `false`: the merge goes ahead, the signature
  /// fields are dropped instead of carried over broken, and the loss is
  /// reported through [PdfDocumentMerger.warnings].
  ///
  /// Set it to `true` when losing a signature must stop the operation rather
  /// than show up as a warning.
  bool rejectSignedSources;

  /// Whether the signature fields are carried over as they are, certificates
  /// included, even though merging has broken their integrity.
  ///
  /// The default is `false`: the fields are dropped, because a signature whose
  /// `/ByteRange` no longer describes the file makes viewers report the
  /// document as tampered with.
  ///
  /// Set it to `true` to keep the signature dictionaries — the CMS blob, the
  /// signing certificate and its chain — in the merged document. **The
  /// signatures will not validate**, and a viewer will say so; what you get is
  /// the signature data preserved for archival or forensic reading, not a
  /// document that still proves anything.
  ///
  /// Takes precedence over [removeSignatureAppearance].
  bool keepInvalidSignatures;

  /// Whether the visible signature mark is removed together with the
  /// signature.
  ///
  /// Ignored when [keepInvalidSignatures] is set, since the field then keeps
  /// its own appearance.
  ///
  /// The default is `false`: the appearance stream showing who signed and when
  /// is kept as a read-only stamp annotation, so the merged page still *looks*
  /// signed — what a reader of a signed report or judicial document expects —
  /// while no viewer reports a broken signature, because none is left to
  /// check.
  ///
  /// Set it to `true` to drop the mark as well, leaving no trace of the
  /// signature on the page.
  bool removeSignatureAppearance;

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
