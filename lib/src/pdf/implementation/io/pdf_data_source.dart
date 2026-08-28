import 'dart:collection';
import 'dart:typed_data';

/// Where the bytes of a document being read come from.
///
/// The library used to hold the whole file in a `List<int>`, which costs one
/// times the file — the single largest allocation left after the buffers were
/// fixed. Every reference implementation reads through an abstraction like
/// this one instead, and none of them loads the file by default:
///
/// * PDFBox's `RandomAccessRead`, whose `RandomAccessReadBufferedFile` pages
///   the file in 4 KB and keeps an LRU of a thousand pages — a 4 MB ceiling,
///   whatever the file weighs. `Loader.loadPDF(File)` uses it.
/// * iText's `IRandomAccessSource`, where `RandomAccessSourceFactory` has
///   `forceRead` off by default, so opening a PDF by path does not bring it
///   into memory.
/// * MuPDF's `fz_stream`, a 4 KB buffer per open file. It is why `mutool`
///   answers in about a second on a 3 GB file held on a network share: the
///   bytes it does not need are never transferred.
///
/// [bytes] is the concession to the fact that this library grew up around a
/// byte array. A source that already has the whole document answers it and the
/// existing paths stay exactly as they were; a file backed source answers
/// `null` and callers take the general route.
abstract class PdfDataSource {
  /// Total number of bytes.
  int get length;

  /// The byte at [offset], or `-1` past the end.
  int byteAt(int offset);

  /// Copies at most [count] bytes from [offset] into [target].
  ///
  /// Returns how many were copied, which is short only at the end of the data.
  int copyInto(int offset, int count, Uint8List target, int targetOffset);

  /// [count] bytes from [offset], as their own array.
  Uint8List readRange(int offset, int count);

  /// The whole document, when it is already in memory; `null` otherwise.
  List<int>? get bytes;

  /// Releases whatever the source holds.
  void close();
}

/// A source over bytes the caller already has.
class PdfMemoryDataSource implements PdfDataSource {
  /// internal constructor
  PdfMemoryDataSource(this._bytes);

  final List<int> _bytes;

  @override
  int get length => _bytes.length;

  @override
  List<int> get bytes => _bytes;

  @override
  int byteAt(int offset) =>
      offset < 0 || offset >= _bytes.length ? -1 : _bytes[offset];

  @override
  int copyInto(int offset, int count, Uint8List target, int targetOffset) {
    if (offset < 0 || count <= 0 || offset >= _bytes.length) {
      return 0;
    }
    int copied = count;
    if (offset + copied > _bytes.length) {
      copied = _bytes.length - offset;
    }
    target.setRange(targetOffset, targetOffset + copied, _bytes, offset);
    return copied;
  }

  @override
  Uint8List readRange(int offset, int count) {
    final Uint8List out = Uint8List(count < 0 ? 0 : count);
    copyInto(offset, count, out, 0);
    return out;
  }

  @override
  void close() {}
}

/// Reads bytes through [reader], keeping a bounded window of the file.
///
/// The block size and the number of blocks are the two numbers that decide
/// whether this is faster or slower than holding the file: too small and every
/// token costs a system call, too large and the ceiling stops being a ceiling.
/// The defaults — 256 KB blocks, 32 of them, so **8 MB** — are the ones
/// `pdf_plus` settled on for the same job in Dart. PDFBox uses 4 KB pages and
/// a thousand of them, which is the same order.
class PdfCachedDataSource implements PdfDataSource {
  /// internal constructor
  PdfCachedDataSource(
    this._reader, {
    this.blockSize = 256 * 1024,
    this.maxBlocks = 32,
  });

  final PdfBlockReader _reader;

  /// How many bytes are fetched at a time.
  final int blockSize;

  /// How many blocks are kept.
  final int maxBlocks;

  final LinkedHashMap<int, Uint8List> _blocks = LinkedHashMap<int, Uint8List>();

  @override
  int get length => _reader.length;

  @override
  List<int>? get bytes => null;

  @override
  int byteAt(int offset) {
    if (offset < 0 || offset >= length) {
      return -1;
    }
    final int index = offset ~/ blockSize;
    final Uint8List block = _block(index);
    final int inside = offset - index * blockSize;
    return inside < block.length ? block[inside] : -1;
  }

  @override
  int copyInto(int offset, int count, Uint8List target, int targetOffset) {
    if (offset < 0 || count <= 0 || offset >= length) {
      return 0;
    }
    int end = offset + count;
    if (end > length) {
      end = length;
    }
    int position = offset;
    int written = targetOffset;
    while (position < end) {
      final int index = position ~/ blockSize;
      final Uint8List block = _block(index);
      final int inside = position - index * blockSize;
      if (inside >= block.length) {
        break;
      }
      int take = end - position;
      if (take > block.length - inside) {
        take = block.length - inside;
      }
      target.setRange(written, written + take, block, inside);
      written += take;
      position += take;
    }
    return written - targetOffset;
  }

  @override
  Uint8List readRange(int offset, int count) {
    final Uint8List out = Uint8List(count < 0 ? 0 : count);
    copyInto(offset, count, out, 0);
    return out;
  }

  @override
  void close() {
    _blocks.clear();
    _reader.close();
  }

  Uint8List _block(int index) {
    final Uint8List? cached = _blocks.remove(index);
    if (cached != null) {
      _blocks[index] = cached; // move to the end: least recently used first
      return cached;
    }
    final Uint8List block = _reader.readBlock(index * blockSize, blockSize);
    _blocks[index] = block;
    if (_blocks.length > maxBlocks) {
      _blocks.remove(_blocks.keys.first);
    }
    return block;
  }
}

/// The part of reading a file that depends on the platform.
///
/// Kept as an interface so that [PdfCachedDataSource] — and everything above
/// it — has no dependency on `dart:io` and stays usable where there are no
/// files.
abstract class PdfBlockReader {
  /// Total number of bytes.
  int get length;

  /// Reads up to [count] bytes starting at [offset].
  Uint8List readBlock(int offset, int count);

  /// Releases the underlying handle.
  void close();
}
