import 'dart:io';
import 'dart:typed_data';

import 'pdf_data_source.dart';

/// Reads blocks of a document straight from a file.
///
/// Wrap it in a [PdfCachedDataSource] — [open] does — so that a bounded window
/// of the file is kept instead of the file itself. Without a cache every token
/// the parser reads would cost a system call.
class PdfFileBlockReader implements PdfBlockReader {
  /// internal constructor
  PdfFileBlockReader(this._file, this.length);

  /// Opens [file] for reading.
  factory PdfFileBlockReader.open(File file) =>
      PdfFileBlockReader(file.openSync(), file.lengthSync());

  final RandomAccessFile _file;

  @override
  final int length;

  @override
  Uint8List readBlock(int offset, int count) {
    if (offset < 0 || offset >= length || count <= 0) {
      return Uint8List(0);
    }
    int size = count;
    if (offset + size > length) {
      size = length - offset;
    }
    _file.setPositionSync(offset);
    return _file.readSync(size);
  }

  @override
  void close() => _file.closeSync();
}

/// A [PdfDataSource] over a file, keeping a bounded window of it in memory.
///
/// ```dart
/// final PdfDocument document = PdfDocument.fromSource(
///   PdfFileDataSource.open(File('volume.pdf')),
/// );
/// ```
///
/// The document is read as it is needed, so a file of any size is opened
/// against a fixed memory ceiling — 8 MB with the defaults. It is what
/// `Loader.loadPDF(File)` does in PDFBox and what `CreateBestSource` does in
/// iText, where reading the file into memory is the opt-in.
abstract final class PdfFileDataSource {
  /// Opens [file], reading through a cache of [maxBlocks] blocks of
  /// [blockSize] bytes.
  static PdfDataSource open(
    File file, {
    int blockSize = 256 * 1024,
    int maxBlocks = 32,
  }) {
    return PdfCachedDataSource(
      PdfFileBlockReader.open(file),
      blockSize: blockSize,
      maxBlocks: maxBlocks,
    );
  }
}
