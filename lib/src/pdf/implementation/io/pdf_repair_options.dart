/// How strictly an existing PDF is read.
///
/// The cross-reference table is the part of a PDF most often damaged — a
/// truncated download, a byte range copied wrong, a tool that appended without
/// fixing the offsets. A viewer recovers by ignoring the table and scanning the
/// file for object headers; this library can do the same, but only when asked.
///
/// The same knob exists in the Java libraries, under different names:
/// `PdfReader.setStrictnessLevel` in iText 7 and `COSParser.setLenient` in
/// PDFBox. Both default to recovering. This library defaults to
/// [conservative] instead, because recovery arrived after the reader did and a
/// document that used to fail to load should not start loading — as something
/// subtly different — just because the dependency moved forward.
enum PdfStrictnessLevel {
  /// Reads only what the file itself says.
  ///
  /// A cross-reference table that cannot be used is reported as a
  /// `PdfFormatException`. The reader still tolerates the damage it always
  /// tolerated: junk before the header, a missing `endobj`, a wrong stream
  /// `/Length`, a missing `%%EOF`, a header without a version.
  ///
  /// This is the default, and it is the right level for signing: a document
  /// whose object table this library reconstructed is a document the next
  /// reader may reconstruct differently, and a signature over it means less
  /// than it appears to.
  conservative,

  /// Recovers by scanning, the way a viewer does.
  ///
  /// When the cross-reference table is missing, points past the end of the
  /// file, or does not parse, the file is scanned for object headers and the
  /// trailer is recovered or synthesized. A file a browser can render loads.
  ///
  /// The result carries [PdfDocument.wasRepaired], and how it may be saved is
  /// governed by [PdfRepairedSaveMode].
  lenient,
}

/// What saving a document whose cross-reference table was rebuilt does.
///
/// An incremental update appends a revision that points back at the previous
/// cross-reference table through `/Prev`. A rebuilt table has no previous
/// table worth pointing at: the offset that was there is the damaged one. So
/// an incremental save of a repaired document produces a file whose object
/// table dangles — this library cannot read it back, and neither can anything
/// else without repairing it again.
///
/// A full rewrite always produces a valid file, but it is a new document: it
/// invalidates every signature the original carried. There is no mode that
/// both preserves signatures and produces a sound file, because the input did
/// not have one.
enum PdfRepairedSaveMode {
  /// Refuses the save with a `PdfFormatException`.
  ///
  /// The default. Makes the caller decide, rather than silently choosing
  /// between a broken file and broken signatures on its behalf.
  reject,

  /// Writes the whole document again, dropping the incremental update.
  ///
  /// Produces a sound file. Any signature the input carried stops verifying,
  /// because the bytes it covered no longer exist.
  fullRewrite,

  /// Appends the revision anyway.
  ///
  /// The behaviour of a library that does not check. The output is very likely
  /// unreadable; this exists for a caller that has its own repair step
  /// downstream and knows what it is doing.
  incremental,
}

/// How much of a damaged file the recovery scan reads.
///
/// Recovering a cross-reference table means finding every `N G obj` header in
/// the file. Where implementations differ is what they do with the megabytes of
/// stream data between those headers.
///
/// The default reads everything, because that is the answer that cannot be
/// wrong. [skipStreams] is faster by roughly the same factor again, and is
/// worth turning on for large files — where it is also the difference between
/// reading gigabytes and reading kilobytes.
enum PdfRepairScan {
  /// Reads every byte of the file.
  ///
  /// The default, and what PDFBox (`BruteForceParser`) and iText
  /// (`PdfReader.rebuildXref`) both do. Nothing is assumed about the file
  /// beyond the object headers actually present in it, so a wrong `/Length`,
  /// a stream whose `endstream` is missing, or an object hidden inside what
  /// claims to be stream data are all found anyway.
  thorough,

  /// Jumps over stream bodies using `/Length`, checking each landing.
  ///
  /// What MuPDF does, and why `mutool` repairs a multi gigabyte file in about
  /// a second: seeking over a stream body means those bytes are never read at
  /// all. On a file held on a network share that is the difference between
  /// transferring the whole document and transferring its headers.
  ///
  /// `/Length` is treated as a hint. After the jump, the scan checks that
  /// `endstream` is really there and falls back to searching for it when it is
  /// not — so a lying `/Length` costs time, not correctness. What is genuinely
  /// given up is the ability to find an object header that sits *inside* a
  /// region the file describes as a stream, which a damaged document can
  /// produce. Hence the default is [thorough].
  skipStreams,
}
