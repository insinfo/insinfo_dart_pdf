# Changelog

## 1.0.0

- Add PDF merging. `PdfDocument.mergeSync` / `PdfDocument.merge` combine a list
  of PDF byte arrays into one document; `appendDocument`, `importPage` and
  `importPageRange` bring pages into an existing `PdfDocument`; and
  `PdfDocumentMerger` drives the same work page by page while collecting
  warnings. Two strategies are available through `PdfMergeOptions.mode`:
  - `PdfMergeMode.objectImport` (default) copies the object graph of each
    source page, preserving content, resources, annotations, links, form
    fields, bookmarks, optional content groups (layers) and page labels;
  - `PdfMergeMode.flatten` draws each source page as a single form XObject,
    which is faster and fully predictable but keeps only graphical content.
- Page tree attributes a source page inherited (`/Resources`, `/MediaBox`,
  `/CropBox`, `/Rotate`) are materialized on the imported page, so pages keep
  their geometry when detached from their original page tree.
- Link and bookmark destinations are re-targeted at the imported copy of their
  page; named destinations are resolved to explicit destinations at import
  time. A destination pointing outside the imported range is dropped and
  reported through `PdfDocumentMerger.warnings` instead of producing a broken
  link.
- Form field hierarchies are flattened onto fully qualified names, keeping
  values, flags and appearance streams. Name collisions are resolved by
  `PdfMergeOptions.fieldNameConflict` (rename with a numeric suffix by
  default). Multi-widget fields — radio groups, fields spanning several pages —
  stay grouped under a single field.
- Merging invalidates every digital signature the sources carry — a signature
  covers the exact bytes of the document it was applied to. Signed documents
  merge anyway, as every PDF tool does, and the loss is reported through
  `PdfDocumentMerger.warnings`. Three independent options control what happens:
  - `rejectSignedSources` (default `false`) refuses to merge a signed source;
  - `keepInvalidSignatures` (default `false`) carries the signature fields
    over, certificates included, at the cost of viewers reporting them as
    invalid;
  - `removeSignatureAppearance` (default `false`) drops the visible signature
    mark as well. By default the mark is kept as a read-only stamp annotation,
    so the merged page still looks signed while no viewer reports a broken
    signature.
- Objects shared inside a source document — a font program, an image, a
  resource dictionary — are cloned once and shared by the imported pages
  instead of being duplicated per page.
- Fix `PdfBookmarkBase.add`, which accepted `destination`, `namedDestination`,
  `action`, `color`, `textStyle` and `isExpanded` but silently discarded them.
  They are now applied to the created bookmark.
- Fix `PdfNamedDestinationCollection`, which threw a null check error while
  reading a name tree whose destination is written inline as a dictionary
  rather than as an indirect reference or an explicit array — a valid shape
  that `gov_assinado.pdf` in the test corpus uses. Reading
  `PdfDocument.namedDestinationCollection`, or any bookmark targeting a named
  destination, crashed on such documents. The reader now accepts every form
  the name tree may take, tolerates a non string key, and no longer reads past
  the end of an array with an odd number of entries.


- Fix validation of legacy PDF signatures using `/adbe.pkcs7.sha1`
  (ISO 32000-1 §12.8.3.3). These signatures are encapsulated, not detached: the
  PKCS#7 `eContent` is the SHA-1 digest of the signed ByteRange. The validator
  previously compared `digest(ByteRange)` directly against the (absent)
  `messageDigest`, so legitimate ICP-Brasil documents were reported with an
  invalid CMS signature and a broken ByteRange digest. The CMS parser now
  captures the encapsulated content and document integrity is verified through
  both required links: `hash(ByteRange) == eContent` and, when signed attributes
  are present, `messageDigest == hash(eContent)`. Signatures without signed
  attributes are verified directly over the encapsulated content. This fixes a
  false "tampered/invalid" result without allowing a document tampered together
  with its `eContent` to pass as intact.
- Add regression tests covering the real `/adbe.pkcs7.sha1` corpus samples and a
  tampering case that must break integrity.
