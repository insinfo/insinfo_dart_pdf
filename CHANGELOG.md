# Changelog

## 1.0.1

- Fix: drawing on an imported page — through `PdfPage.graphics`,
  `PdfPage.appendGraphics` or `PdfImportedPage.appendGraphics` — no longer
  replaces the page's `/Resources`. A page created in memory built an empty
  resource dictionary on first use and wrote it over the one the merge had
  copied, so the imported content pointed at fonts that were gone: a
  LibreOffice export with subset TrueType fonts rendered as `! " # $ %` once a
  footer was stamped on it. An existing `/Resources` is now wrapped, and the
  stamp's font is added next to the imported ones.
- Fix: a stamp drawn on a page appended to a *loaded* destination document was
  lost. `PdfPageCollection.insert` opens a drawing layer before the merger
  fills the page, and the stamp landed in that orphaned layer without ever
  reaching the saved file. The importer now discards the layers and resources
  built before the import, so the next access rebuilds them from the page as
  it now stands.

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
- Recover from a damaged cross-reference table, on request. A `startxref`
  pointing past the end of the data, a missing `startxref` because the tail was
  truncated, or a table that fails to parse can now be worked around: the file
  is scanned for object headers and the table is rebuilt, the way a viewer
  does. The trailer is recovered too — from a `trailer` dictionary still
  present, or synthesized around whichever rebuilt object is the document
  catalog. A file a browser can render loads and merges.

  Recovery is **opt-in**, through `PdfStrictnessLevel`, mirroring
  `PdfReader.setStrictnessLevel` in iText 7 and `COSParser.setLenient` in
  PDFBox. Unlike those two, the default here is `conservative`: the reader
  predates the recovery, and a document that used to fail to load should not
  start loading — as something subtly different — just because the dependency
  moved forward.

  ```dart
  PdfDocument(inputBytes: bytes)                                  // refuses
  PdfDocument(inputBytes: bytes, strictness: PdfStrictnessLevel.lenient)
  ```

  Merging is the exception: `PdfMergeOptions.strictness` defaults to `lenient`,
  because the merge API is new in this version — nothing regresses — and a
  merge writes a fresh document rather than appending to the damaged one, so
  the recovered reading never reaches the output as a table anyone has to
  trust. Set it to `conservative` to refuse damaged sources.

  Only the three patterns above need the opt-in. Damage the reader always
  absorbed — junk before the header, corrupted offsets, missing `endobj`, a
  wrong stream `/Length`, no `%%EOF`, a header without a version, a byte
  flipped mid file — still loads with no flag at all.
- `PdfDocument.wasRepaired` reports whether the object table came from a scan
  rather than from a cross-reference table the file supplied — the counterpart
  of iText's `PdfReader.hasRebuiltXref()`. Worth checking before signing: a
  reconstructed table is this library's reading of what the file meant, the
  next reader may read it differently, and a signature applied over it
  certifies less than it appears to.
- **Fix:** saving a repaired document no longer produces a file nothing can
  read. An incremental update appends a revision pointing back at the previous
  cross-reference table through `/Prev`; a repaired document has none, and the
  offset it carried is the damaged one. The result was a table that dangles —
  this library could not read its own output back, and the failure surfaced as
  a `TypeError` rather than as bad data. The path mattered because signing
  forces an incremental update, so a damaged PDF that loaded only thanks to
  recovery would be signed into an unreadable file.

  `PdfRepairedSaveMode` decides what happens instead:
  - `reject` (default) refuses the save with a `PdfFormatException`, leaving
    the choice to the caller rather than silently picking between a broken file
    and broken signatures;
  - `fullRewrite` writes the whole document again, producing a sound file at
    the cost of every signature the input carried;
  - `incremental` appends anyway — the behaviour of a library that does not
    check, for a caller with its own repair step downstream.

  There is no mode that both preserves signatures and produces a sound file,
  because the input did not have one.
- Report a `/Root` that does not resolve to a dictionary as a
  `PdfFormatException` instead of letting the cast fail as a `TypeError`. A
  dangling document catalog is bad data, not a defect in the caller.
- Rewrite the recovery scan to work on bytes. It read the file line by line as
  Dart strings, building each line by concatenation — which is quadratic on the
  lines a scanned document has, where a "line" is whatever sits between two
  accidental `0x0A` bytes inside a JPEG. On a real 2.1 GB scanned volume that
  cost **11 minutes and then failed anyway**; it now recovers the same document
  in **14 s**, and the reference implementations were the guide:
  - PDFBox (`BruteForceParser`) walks the file byte by byte against `char[]`
    constants hoisted out of the loop;
  - iText (`PdfReader.rebuildXref`) keeps reading lines, but into a 24 byte
    buffer that is reused and capped — full, it stops storing and drains the
    rest of the line, so a megabyte of image data never reaches memory;
  - MuPDF (`pdf_repair_xref_base`) tokenizes without materializing strings and
    seeks over stream bodies.

  Measured against them on the same files, opening plus counting pages:

  | | 2.1 GB, local disk | 3.0 GB, network share |
  |---|---|---|
  | iText 9.7.0 | 56.5 s | 89.4 s |
  | PDFBox 3.0.3 | 77.4 s | 129.2 s |
  | this library, `thorough` | **14.7 s** | **18.3 s** |
  | this library, `skipStreams` | **0.01 s** | **0.01 s** |

  All of them report the same page counts, 463 and 528, which is also what
  `mutool` reports.
- `PdfRepairScan` decides how much of a damaged file the scan reads.
  `thorough` (the default) reads every byte, like PDFBox and iText: nothing is
  assumed about the file beyond the object headers actually in it.
  `skipStreams` jumps over stream bodies using `/Length`, like MuPDF — which on
  a large file means those bytes are never read at all, and is the difference
  between 14 s and 0.01 s.

  `/Length` is treated as a hint: after the jump the scan checks that
  `endstream` is really there and falls back to searching for it when it is
  not, so a lying `/Length` costs time rather than correctness. An indirect
  `/Length 12 0 R` is recognized and not mistaken for a byte count. What is
  genuinely given up is finding an object header hidden *inside* a region the
  file calls a stream — hence the conservative default.
- **Fix:** the recovery kept the *first* definition of a repeated object number
  and discarded every object whose generation was not zero. Scanning runs front
  to back, so keeping the first hit rebuilds a document out of its oldest
  parts: in a file with an incremental update — every signed PDF is one — the
  valid definition of an object is the last. iText (`gen >= xr[num][1]`),
  PDFBox (a `HashMap.put` per hit) and MuPDF all resolve the collision the
  other way, and none of them drops a non zero generation. Now neither does
  this one.
- The scan now reports the document catalog and the position of every `trailer`
  keyword as it goes, the way iText does, instead of searching the file a
  second time and parsing objects back to front to find them.
- Stop paying eight bytes per byte of PDF. A growable `List<int>` in the Dart
  VM is a list of object references, and the library used one both to
  accumulate a document while saving and to copy a file that has junk after its
  last `%%EOF`. Measured on a 250 MB scanned document:

  | | before | after |
  |---|---|---|
  | loading, junk after `%%EOF` | 3270 ms, +2010 MB | 125 ms, +254 MB |
  | `saveSync`, 250 MB of output | +2 GB, peak 3840 MB | +251 MB, peak 989 MB |

  `PdfReader.readBytes` returns a `Uint8List` and copies by range instead of
  filling a growable list one byte at a time, and the document is accumulated
  in `PdfByteBuffer` — a `List<int>` backed by a byte array. It stays a flat
  mutable list rather than a rope of chunks because signing writes the document
  and then patches `/ByteRange` and `/Contents` back into it in place.

  `saveSync` and `save` now return a `Uint8List`. It is still a `List<int>`;
  the only difference is that it is fixed length, and appending to a saved PDF
  was never meaningful.
- Fix `saveAsBytesSync` and `saveAsBytes` for signed documents. They used a
  chunked builder, which has no bytes to patch, so applying a signature through
  them failed with a null check error. Both share the flat buffer now.
- `PdfDocument.saveToSink` writes the document straight out instead of building
  it in memory — 0 MB of extra RSS where `saveSync` costs the size of the
  output. `PdfOutputSink` is deliberately narrower than `dart:io`'s `IOSink` so
  the core keeps no dependency on `dart:io`. Creating a signature in the same
  save is refused with `UnsupportedError`: a signature fills its `/ByteRange`
  and `/Contents` after the rest of the file exists, which a stream cannot do.
- Read a document from a source instead of from bytes the caller holds.
  `PdfDataSource` is the abstraction every reference implementation has —
  PDFBox's `RandomAccessRead`, iText's `IRandomAccessSource`, MuPDF's
  `fz_stream` — and none of them loads a file by default.
  `PdfDocument.fromSource` takes one; `PdfFileDataSource.open`, from the
  separate `package:dart_pdf/pdf_io.dart` entry point, reads a file through an
  LRU of 32 blocks of 256 KB. Measured:

  | | `inputBytes` | `fromSource` |
  |---|---|---|
  | 250 MB, 262 pages | 2530 ms, +254 MB | **69 ms, +4 MB** |
  | 1.8 GB, 1885 pages | 17 s, +1.8 GB | **289 ms, +13 MB** |

  `dart:io` stays out of `pdf.dart`, so importing the library still costs
  nothing to a program with no file system; the file backed source lives in
  `pdf_io.dart`.

  An incremental save of a file backed document copies the original a block at
  a time instead of pulling it into memory to write it back out. Recovering a
  damaged cross-reference table is the exception: the scan walks the whole file
  and jumps around inside it, so a windowed source is read out first. MuPDF
  seeks over stream bodies on a file stream and does not pay that; matching it
  is still open.
- Recover a damaged file without reading it. The scan can now walk a window of
  the source instead of an array, which is what MuPDF does with `fz_seek` over
  a file stream — and why `mutool` repairs a multi gigabyte file in about a
  second. Combined with `PdfRepairScan.skipStreams`, the bytes of the stream
  bodies are never transferred at all. On the 3.0 GB damaged volume in the test
  corpus, opening it and counting its 528 pages:

  | | time | RSS |
  |---|---|---|
  | before this version | 11 min, and then failed | — |
  | reading the file out first | 28.6 s | +3 GB |
  | **windowed** | **3.7 s** | **+14 MB** |

  `PdfRepairWindow` decides. `auto`, the default, windows a file backed source
  scanned with `skipStreams` and nothing else: every other case either has the
  bytes already or is going to read them all anyway. `always` gives
  `thorough` a memory ceiling too, at the cost of the extra copies; `never`
  keeps the old behaviour.

  The window costs the in memory scan about 28% — 18.3 s to 23.5 s over 3 GB of
  `thorough` — because indexing goes through a bounds check the array access
  would otherwise do alone. That is the slowest combination there is, and the
  one this release makes unnecessary: a file that size wants `fromSource` and
  `skipStreams`, which is 3.7 s.
- `PdfPage.appendGraphics()` opens a graphics context over everything a page
  already holds, without rewriting any of it. It is what a loaded page wants
  instead of `graphics`: drawing through `graphics` joins the page's default
  layer and inherits whatever graphics state the existing content left open —
  an unbalanced `q`, a transform, a clipping path — so a stamp can land scaled
  or clipped out of sight. `PdfImportedPage.appendGraphics` now delegates to it.
- The package description says what the library does. It claimed "creating,
  reading, editing, and securing"; "editing" reads as replacing the text on a
  page, which this library does not do. It now says *structurally* editing, and
  the README carries a capability matrix, operation by operation.
- **Careful with `==` on the dates a document reports.** A PDF date carries a
  UTC offset, and a date read out of one now comes back in UTC rather than as
  the same wall clock reading in local time — reading it as local was silently
  moving the instant by three hours here. So a date written as
  `DateTime(2026, 8, 27, 14, 30)` reads back as `2026-08-27 17:30:00.000Z`:
  the same instant, said differently.

  That matters because **Dart's `DateTime.==` compares `isUtc` as well as the
  instant**, so it answers `false` for two values that name the same moment:

  ```dart
  final DateTime local = DateTime(2026, 8, 27, 14, 30);
  final DateTime utc = local.toUtc();
  local == utc;                    // false
  local.isAtSameMomentAs(utc);     // true
  local.compareTo(utc) == 0;       // true
  ```

  Code that compares `creationDate`, `modificationDate` or a signature's
  signing time against a local `DateTime` with `==` will fail even when the
  instant is right. Use `isAtSameMomentAs`, or `compareTo`, or `.toUtc()` on
  both sides. Formatting for a reader is unaffected: `toLocal()` gives back the
  wall clock reading that was written.
- `PdfReader.searchBack` compares bytes instead of building a `String` at every
  position it tries. On a file whose tail was truncated it walks to the front
  of the file, which made loading a damaged 16 MB document take seconds before
  the recovery scan had even started.
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
