/// Thrown when PDF data cannot be read.
///
/// Extends [FormatException], the type Dart already uses for "this data is not
/// in the expected format", so `on FormatException` catches it too. That
/// matters: an [Error] means the program has a bug and should not be caught,
/// while a file supplied by a user being malformed is an ordinary, recoverable
/// condition.
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
class PdfFormatException extends FormatException {
  /// Initializes a new instance of the [PdfFormatException] class.
  ///
  /// [source] is whatever value made the data unreadable — an offset, a
  /// malformed token, an unexpected object — kept because it is usually the
  /// first thing anyone diagnosing the file wants to see.
  PdfFormatException(String message, {this.cause, Object? source, int? offset})
    : super(message, source, offset);

  /// The underlying failure, when this exception wraps one.
  ///
  /// Reading a PDF touches a lexer, a decompressor and, for an encrypted file,
  /// a cipher — each of which reports damage in its own way. Loading catches
  /// whatever they throw and reports it as a format problem, but keeps the
  /// original here so nothing is lost when diagnosing a file that should have
  /// worked.
  final Object? cause;

  @override
  String toString() {
    final StringBuffer buffer = StringBuffer('PdfFormatException: $message');
    if (source != null) {
      buffer.write(' (at $source)');
    }
    if (cause != null) {
      buffer.write(' (caused by $cause)');
    }
    return buffer.toString();
  }
}
