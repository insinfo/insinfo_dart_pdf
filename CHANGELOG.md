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
- Recover from a damaged cross-reference table instead of refusing the file.
  A `startxref` pointing past the end of the data, a missing `startxref`
  because the tail was truncated, or a table that fails to parse no longer
  aborts the load: the file is scanned for object headers and the table is
  rebuilt, the way a viewer does. The trailer is recovered too — from a
  `trailer` dictionary still present, or synthesized around whichever rebuilt
  object is the document catalog. A file a browser can render now loads and
  merges.
- **Breaking:** the library no longer reports bad data as an `Error`. Every
  `throw ArgumentError` was reclassified against one question — what can the
  caller do about it?

  | Failure | Type | What the caller does |
  |---|---|---|
  | the bytes are bad | `PdfFormatException` | show the user, move on |
  | the caller passed something wrong | `ArgumentError` | fix the code |
  | a library invariant broke | `StateError` | report the bug |
  | the file needs a feature this library lacks | `UnsupportedError` | take another route |

  Of 431 sites: 214 became `PdfFormatException`, 39 `UnsupportedError`, 5
  `StateError`, and 173 stayed `ArgumentError` because they really are caller
  contracts — a null argument, a page index out of range, a negative count.
  Signature structure failures in `PdfExternalSigning`, previously `StateError`,
  became `PdfFormatException` for the same reason.

  `PdfFormatException` extends `FormatException`, so `on FormatException` —
  what Dart code already writes for malformed data — catches it, and it carries
  the offending value in `source` plus, when it wraps another failure, `cause`.

  **Migration:** replace `on ArgumentError` with `on PdfFormatException` where
  you handle files supplied by users. Keep `on ArgumentError` only where you
  are guarding against your own mistakes. Catching `on Exception` covers the
  data cases and, deliberately, leaves `StateError` and `TypeError` to surface
  as the defects they are.

  This is enforced rather than promised: `test/api_contract_test.dart` runs the
  corpus through twelve mutations — truncation, wiped keywords, flipped bytes —
  against document loading, merging, signature reading and signature
  validation, and fails if an `Error` escapes any of them.
- Drop the signature dictionary from the output instead of leaving it
  unreachable. Removing `/V` from the cloned widget detached it from
  `/AcroForm /Fields` but left the PKCS#7 blob registered as an orphan object —
  invisible to a reader walking the form tree, found by anything scanning for
  signature dictionaries, and costing tens of kilobytes. The field entries are
  now pruned before the clone, so they never enter the destination.
- Import form fields that no page widget leads to. `/AcroForm /Fields` may hold
  a field with no widget annotation — a hidden data field, or a signature whose
  widget was dropped from `/Annots` by an earlier merge, the shape documents
  exported by the SEI process system have. Such fields carry values and
  certificates and were previously lost, since fields were discovered only
  through the widgets found on the imported pages.
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
