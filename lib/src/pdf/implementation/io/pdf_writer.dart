import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import '../../interfaces/pdf_interface.dart';
import '../pdf_document/pdf_document.dart';

/// Helper class to write PDF primitive elements easily.
/// Where a document goes when it is written straight out instead of being
/// accumulated in memory.
///
/// Deliberately narrower than `dart:io`'s `IOSink`, so the core of the library
/// does not depend on `dart:io` and a caller can send the document anywhere —
/// a file, a socket, a hash. Adapting a file is three lines:
///
/// ```dart
/// class _FileSink implements PdfOutputSink {
///   _FileSink(this.sink);
///   final IOSink sink;
///   @override
///   void add(List<int> data) => sink.add(data);
/// }
/// ```
abstract class PdfOutputSink {
  /// Appends [data] to the output.
  void add(List<int> data);
}

class PdfWriter implements IPdfWriter {
  //Constructor
  /// internal constructor
  PdfWriter(this.buffer, [PdfBytesBuilder? bytesBuilder]) {
    if (bytesBuilder != null) {
      this.bytesBuilder = bytesBuilder;
      length = this.bytesBuilder!.length;
      position = this.bytesBuilder!.length;
      isBytesBuilder = true;
    } else {
      length = buffer!.length;
      position = buffer!.length;
    }
  }

  /// internal constructor
  ///
  /// Writes straight to [sink] instead of holding the document in memory.
  /// Nothing can be read back, so [buffer] stays null: the one thing that
  /// needs to read what it already wrote is signing, which patches
  /// `/ByteRange` and `/Contents` into the finished bytes.
  PdfWriter.toSink(this.sink) {
    length = 0;
    position = 0;
  }

  //Fields
  /// internal field
  List<int>? buffer;
  PdfBytesBuilder? bytesBuilder;
  bool isBytesBuilder = false;

  /// internal field
  PdfOutputSink? sink;
  //IPdfWriter members
  @override
  PdfDocument? document;
  @override
  //ignore:unused_field
  int? length;
  @override
  int? position;
  @override
  void write(dynamic data, [int? end]) {
    if (data == null) {
      throw ArgumentError.value(data, 'data', 'value cannot be null');
    }
    if (data is int) {
      write(data.toString());
    } else if (data is double) {
      String value = data.toStringAsFixed(2);
      if (value.endsWith('.00')) {
        if (value.length == 3) {
          value = '0';
        } else {
          value = value.substring(0, value.length - 3);
        }
      }
      write(value);
    } else if (data is String) {
      write(utf8.encode(data));
    } else if (data is IPdfPrimitive) {
      data.save(this);
    } else if (data is List<int>) {
      int tempLength;
      if (end == null) {
        tempLength = data.length;
      } else {
        tempLength = end;
      }
      length = length! + tempLength;
      position = position! + tempLength;
      final List<int> payload =
          end == null ? data : data.sublist(0, end > data.length ? data.length : end);
      if (sink != null) {
        sink!.add(payload);
      } else if (isBytesBuilder) {
        bytesBuilder!.add(payload);
      } else {
        _addDataInChunks(payload);
      }
    }
  }

  /// Appends [data] to the flat buffer.
  ///
  /// This used to copy in 8190 byte slices, because `addAll` on a growable
  /// `List<int>` was the expensive part. [PdfByteBuffer] grows by doubling and
  /// copies by range, so the slicing — which allocated a sublist per chunk —
  /// only got in the way.
  void _addDataInChunks(List<int> data) {
    buffer!.addAll(data);
  }

  /// Internal method
  Future<void> writeAsync(dynamic data, [int? end]) async {
    if (data == null) {
      throw ArgumentError.value(data, 'data', 'value cannot be null');
    }
    if (data is int) {
      writeAsync(data.toString());
    } else if (data is double) {
      String value = data.toStringAsFixed(2);
      if (value.endsWith('.00')) {
        if (value.length == 3) {
          value = '0';
        } else {
          value = value.substring(0, value.length - 3);
        }
      }
      writeAsync(value);
    } else if (data is String) {
      writeAsync(utf8.encode(data));
    } else if (data is IPdfPrimitive) {
      data.save(this);
    } else if (data is List<int>) {
      int tempLength;
      if (end == null) {
        tempLength = data.length;
      } else {
        tempLength = end;
      }
      length = length! + tempLength;
      position = position! + tempLength;
      final List<int> payload =
          end == null ? data : data.sublist(0, end > data.length ? data.length : end);
      if (sink != null) {
        sink!.add(payload);
      } else if (isBytesBuilder) {
        bytesBuilder!.add(payload);
      } else {
        _addDataInChunks(payload);
      }
    }
  }
}

///Helper class to write the PDF document data.
class PdfBytesBuilder {
  /// internal fields
  final List<Uint8List> _chunks = [];
  int _length = 0;

  /// get the length of the data
  int get length => _length;

  /// add the data
  void add(List<int> data) {
    if (data.isEmpty) {
      return;
    }
    final Uint8List chunk = Uint8List.fromList(data);
    _chunks.add(chunk);
    _length += chunk.length;
  }

  /// get the bytes
  Uint8List takeBytes() {
    final Uint8List result = Uint8List(_length);
    int offset = 0;
    for (final Uint8List chunk in _chunks) {
      result.setRange(offset, offset + chunk.length, chunk);
      offset += chunk.length;
    }
    return result;
  }

  /// clear the data
  void clear() {
    _chunks.clear();
    _length = 0;
  }
}

/// A `List<int>` backed by a byte array, for accumulating a document while it
/// is written.
///
/// The document used to be accumulated in a plain growable `List<int>`. In the
/// Dart VM that is a list of object references — **eight bytes per element** —
/// so a 250 MB document occupied 2 GB, with a peak near 4 GB while the list
/// doubled. This holds one byte per byte.
///
/// It has to remain a flat, mutable list rather than a rope of chunks: signing
/// writes the document first and then patches `/ByteRange` and `/Contents`
/// back into it in place, and digests the result over byte ranges. A chunked
/// builder cannot answer that without flattening, which is the copy this class
/// exists to avoid.
class PdfByteBuffer extends ListBase<int> {
  /// internal constructor
  PdfByteBuffer([int initialCapacity = 64 * 1024])
    : _bytes = Uint8List(initialCapacity < 16 ? 16 : initialCapacity);

  Uint8List _bytes;
  int _length = 0;

  @override
  int get length => _length;

  @override
  set length(int value) {
    if (value > _length) {
      _reserve(value);
    }
    _length = value;
  }

  @override
  int operator [](int index) {
    if (index < 0 || index >= _length) {
      throw RangeError.index(index, this, 'index', null, _length);
    }
    return _bytes[index];
  }

  @override
  void operator []=(int index, int value) {
    if (index < 0 || index >= _length) {
      throw RangeError.index(index, this, 'index', null, _length);
    }
    _bytes[index] = value;
  }

  @override
  void add(int element) {
    _reserve(_length + 1);
    _bytes[_length++] = element;
  }

  @override
  void addAll(Iterable<int> iterable) {
    if (iterable is List<int>) {
      final int count = iterable.length;
      if (count == 0) {
        return;
      }
      _reserve(_length + count);
      _bytes.setRange(_length, _length + count, iterable);
      _length += count;
      return;
    }
    for (final int value in iterable) {
      add(value);
    }
  }

  /// The written bytes, as a view over the backing array.
  ///
  /// No copy is made, so the result stops being valid if anything is written
  /// afterwards. Saving is finished by the time a caller sees it.
  Uint8List takeBytes() => Uint8List.sublistView(_bytes, 0, _length);

  void _reserve(int capacity) {
    if (capacity <= _bytes.length) {
      return;
    }
    int grown = _bytes.length;
    while (grown < capacity) {
      grown *= 2;
    }
    final Uint8List bigger = Uint8List(grown);
    bigger.setRange(0, _length, _bytes);
    _bytes = bigger;
  }
}
