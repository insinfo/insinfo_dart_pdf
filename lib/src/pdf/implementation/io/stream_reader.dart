import 'pdf_data_source.dart';
import 'pdf_format_exception.dart';

/// internal class
class PdfStreamReader {
  //Constructor
  /// internal constructor
  PdfStreamReader([List<int>? data])
    : source = PdfMemoryDataSource(data ?? <int>[]) {
    _position = 0;
  }

  /// internal constructor
  ///
  /// Reads through [source] rather than from a byte array the caller already
  /// holds. See [PdfDataSource].
  PdfStreamReader.fromSource(this.source) {
    _position = 0;
  }

  //Fields
  /// internal field
  PdfDataSource source;
  int? _position;

  //Properties
  /// internal property
  ///
  /// The whole document as a list, when the source has it; `null` when the
  /// document is being read from a file. Code that reaches for this has to
  /// cope with `null` or go through [source].
  List<int>? get data => source.bytes;

  /// internal property
  int? get length => source.length;

  /// internal property
  int get position => _position!;
  set position(int value) {
    if (value < 0) {
      throw PdfFormatException('Invalid position', source: value);
    }
    _position = value;
  }

  //Implementation
  /// internal method
  int? readByte() {
    if (_position != source.length) {
      final int result = source.byteAt(_position!);
      _position = _position! + 1;
      return result;
    } else {
      return -1;
    }
  }

  /// internal method
  int? read(List<int> buffer, int offset, int length) {
    _position = offset;
    int pos = offset;
    final int end = _position! + length;
    while (_position! < end) {
      final int byte = readByte()!;
      if (byte == -1) {
        break;
      }
      buffer[pos++] = byte;
    }
    return pos - offset;
  }
}
