/// Thrown when PDF data cannot be read.
///
/// This is about the *data*, not about how the library was called: the bytes
/// are empty, are not a PDF, or are damaged past the point where scanning the
/// file can recover a document catalog. Code that accepts files from users —
/// an upload endpoint, a batch job, a document service — needs to tell that
/// apart from its own mistakes, log it, and answer the caller. Hence an
/// [Exception] rather than an [Error].
///
/// Most damage never reaches here. A broken cross-reference table, a
/// `startxref` pointing past the end of the file, missing `endobj` markers, a
/// wrong stream `/Length`, a truncated tail — all of that is recovered by
/// scanning the file for object headers, the way a viewer does. A file a
/// browser can render should load.
///
/// ```dart
/// try {
///   document = PdfDocument(inputBytes: bytes);
/// } on PdfFormatException catch (e) {
///   log.warning('rejected upload: ${e.message}');
///   return badRequest(e.message);
/// }
/// ```
class PdfFormatException implements Exception {
  /// Initializes a new instance of the [PdfFormatException] class.
  PdfFormatException(this.message);

  /// What is wrong with the data, in terms worth putting in a log or showing
  /// to whoever supplied the file.
  final String message;

  @override
  String toString() => 'PdfFormatException: $message';
}
