import 'dart:convert';
import 'dart:typed_data';

import 'pdf_constants.dart';
import 'pdf_data_source.dart';
import 'stream_reader.dart';
import 'pdf_format_exception.dart';

/// internal class
class PdfReader {
  //Constructor
  /// internal constructor
  PdfReader(List<int>? data) {
    streamReader = PdfStreamReader(data);
    _peekedByte = 0;
    _bytePeeked = false;
    _delimiters = '()<>[]{}/%';
  }

  /// internal constructor
  ///
  /// Reads through [source] instead of from a byte array. See [PdfDataSource].
  PdfReader.fromSource(PdfDataSource source) {
    streamReader = PdfStreamReader.fromSource(source);
    _peekedByte = 0;
    _bytePeeked = false;
    _delimiters = '()<>[]{}/%';
  }

  //Fields
  /// internal field
  late PdfStreamReader streamReader;
  late String _delimiters;
  final List<String> _spaceCharacters = <String>[
    '\u0020',
    '\u00a0',
    '\u1680',
    '\u2000',
    '\u2001',
    '\u2002',
    '\u2003',
    '\u2004',
    '\u2005',
    '\u2006',
    '\u2007',
    '\u2008',
    '\u2009',
    '\u200a',
    '\u202f',
    '\u205f',
    '\u3000',
    '\u2028',
    '\u2029',
    '\u0009',
    '\u000a',
    '\u000b',
    '\u000c',
    '\u000d',
    '\u0085',
  ];
  late int _peekedByte;
  late bool _bytePeeked;

  //Properties
  /// internal property
  int get position => streamReader.position;
  set position(int value) {
    streamReader.position = value;
  }

  /// internal property
  int? get length => streamReader.length;

  //Implementation
  /// internal method
  void skipWhiteSpace() {
    if (position != streamReader.length) {
      int value;
      do {
        value = _read();
      } while (value != -1 &&
          _spaceCharacters.contains(String.fromCharCode(value)));
      position = value == -1 ? streamReader.length! : (position - 1);
    }
  }

  int _skipWhiteSpaceBack() {
    if (position == 0) {
      throw PdfFormatException('Invalid PDF Document Format', source: position);
    }
    position -= 1;
    while (_spaceCharacters.contains(String.fromCharCode(_read()))) {
      position -= 2;
    }
    return position;
  }

  int _read() {
    int? value = 0;
    if (_bytePeeked) {
      value = _getPeeked(value);
    } else {
      value = streamReader.readByte();
    }
    return value!;
  }

  /// internal method
  ///
  /// Copies [length] bytes from the current position into a [Uint8List].
  ///
  /// It used to fill a growable `List<int>` one byte at a time. A growable
  /// list of `int` in the Dart VM costs eight bytes per element, so copying a
  /// 250 MB document — which `CrossTable` does whenever there is junk after
  /// the last `%%EOF` — cost 2 GB and three seconds. A typed list costs one
  /// byte per byte, and a range copy costs a `memmove`.
  ///
  /// Bytes past the end of the data stay zero. Both callers clamp the length
  /// against what is available, so that case does not arise in practice; the
  /// previous version wrote `-1` there, which a byte array cannot hold anyway.
  Uint8List readBytes(int length) {
    if (length <= 0) {
      return Uint8List(0);
    }
    final Uint8List bytes = Uint8List(length);
    int index = 0;
    if (_bytePeeked) {
      bytes[0] = _read();
      index = 1;
    }
    final int start = streamReader.position;
    final int copied = streamReader.source.copyInto(
      start,
      length - index,
      bytes,
      index,
    );
    if (copied > 0) {
      streamReader.position = start + copied;
    }
    return bytes;
  }

  /// internal method
  int readBlock(List<String> buffer, int index, int count) {
    if (count < 0) {
      throw ArgumentError.value(count, 'The value cannot be less then zero');
    }
    int i = index;
    if (_bytePeeked && count > 0) {
      buffer[i] = String.fromCharCode(_peekedByte);
      _bytePeeked = false;
      --count;
      ++i;
    }
    if (count > 0) {
      final List<int> buf = List<int>.filled(count, 0);
      int tempCount = 0;
      for (int j = 0; j < count && position < length!; j++) {
        buf[j] = _read();
        tempCount++;
      }
      count = tempCount;
      for (int k = 0; k < count; ++k) {
        final String ch = String.fromCharCode(buf[k]);
        buffer[i + k] = ch;
      }
      i += count;
    }
    return i - index;
  }

  /// internal method
  String readLine() {
    String line = '';
    int character;
    character = _read();
    while (character != -1 && !_isEol(String.fromCharCode(character))) {
      line += String.fromCharCode(character);
      character = _read();
    }
    if (character == 13) {
      if (String.fromCharCode(_read()) != '\n') {
        position -= 1;
      }
    }
    return line;
  }

  bool _isEol(String character) {
    return character == '\n' || character == '\r';
  }

  /// internal method
  int readData(List<int>? buffer, int index, int count) {
    if (count < 0) {
      throw ArgumentError.value(count, "The value can't be less then zero");
    }
    int i = index;
    if (_bytePeeked && count > 0) {
      buffer![i] = _peekedByte;
      _bytePeeked = false;
      --count;
      ++i;
    }
    if (count > 0) {
      if (position == length) {
        count = 0;
      } else {
        final int lp = length! - position;
        count = count > lp ? lp : count;
        final List<int> bytes = readBytes(count);
        for (int j = 0; j < count; j++) {
          buffer![i + j] = bytes[j];
        }
      }
      i += count;
    }
    return i - index;
  }

  /// internal method
  Map<String, dynamic> copyBytes(List<int>? buffer, int index, int count) {
    if (index < 0 || index > buffer!.length) {
      throw ArgumentError.value(index, 'Invalid index to read');
    }
    final int pos = position;
    for (
      int i = pos;
      i < length! && i < (pos + count) && index < buffer.length;
      i++
    ) {
      buffer[index] = _read();
      index++;
    }
    return <String, dynamic>{'next': index, 'buffer': buffer};
  }

  /// internal method
  int? seekEnd() {
    return streamReader.length;
  }

  /// internal method
  int searchBack(String token) {
    // Compares bytes rather than building a `String` per position. On a file
    // whose tail was truncated this walks all the way to the front, and the
    // allocation used to make that a multi second affair on a file of a few
    // megabytes.
    final List<int> needle = token.codeUnits;
    int pos = position;
    position = _skipWhiteSpaceBack();
    if (position < token.length) {
      return -1;
    }
    bool found = _matchesBack(needle);
    pos = position - token.length;
    while (!found) {
      if (pos < 0) {
        throw PdfFormatException('Invalid PDF Document Format', source: pos);
      }
      position -= 1;
      if (position < token.length) {
        return -1;
      }
      found = _matchesBack(needle);
      pos = position - token.length;
    }
    while (token == PdfOperators.crossReference) {
      final int xrefPos = pos;
      final int startPos = searchBack(PdfOperators.startCrossReference);
      if (startPos == xrefPos - 5) {
        found = false;
        while (!found) {
          if (pos < 0) {
            throw PdfFormatException('Invalid PDF Document Format', source: pos);
          }
          position -= 1;
          if (position < token.length) {
            return -1;
          }
          found = _matchesBack(needle);
          pos = position - token.length;
        }
      } else {
        pos = xrefPos;
        break;
      }
    }
    position = pos;
    return pos;
  }

  /// Whether the [needle] bytes end exactly at [position].
  ///
  /// Leaves [position] where it found it, like the `_readBack` it replaced.
  bool _matchesBack(List<int> needle) {
    final int start = position - needle.length;
    if (start < 0) {
      return false;
    }
    final PdfDataSource data = streamReader.source;
    if (start + needle.length > data.length) {
      return false;
    }
    for (int i = 0; i < needle.length; i++) {
      if (data.byteAt(start + i) != needle[i]) {
        return false;
      }
    }
    return true;
  }

  /// internal method
  int searchForward(String token) {
    List<int>? buf = List<int>.filled(token.length, 0);
    bool isStartXref = false;
    while (true) {
      int pos = position;
      final int character = _read();
      buf![0] = character.toUnsigned(8);
      if (buf[0] == token.codeUnitAt(0)) {
        if (!isStartXref) {
          pos = position - 1;
          final Map<String, dynamic> result = copyBytes(
            buf,
            1,
            token.length - 1,
          );
          final int length = result['next'] as int;
          buf = result['buffer'] as List<int>?;
          position = pos;
          if (length < token.length - 1) {
            return -1;
          } else if (token == String.fromCharCodes(buf!)) {
            return pos;
          } else {
            position += 1;
          }
        }
      } else if (buf[0] == PdfOperators.startCrossReference.codeUnitAt(0)) {
        isStartXref = false;
        pos = position - 1;
        position = pos;
        int newPosition = pos;
        List<int>? buff = List<int>.filled(
          PdfOperators.startCrossReference.length,
          0,
        );
        final Map<String, dynamic> result = copyBytes(
          buff,
          1,
          PdfOperators.startCrossReference.length,
        );
        buff = result['buffer'] as List<int>?;
        if (PdfOperators.startCrossReference == String.fromCharCodes(buff!)) {
          isStartXref = true;
          position = ++newPosition;
        }
      } else if (character == -1) {
        return -1;
      }
    }
  }

  int _getPeeked(int? byteValue) {
    if (_bytePeeked) {
      _bytePeeked = false;
      byteValue = _peekedByte;
    } else {
      byteValue = 0;
    }
    return byteValue;
  }

  String _getEqualChar(int? charCode) {
    return charCode == -1 ? '\uffff' : String.fromCharCode(charCode!);
  }

  /// internal method
  String? getNextToken() {
    String? token = '';
    int? character = 0;
    skipWhiteSpace();
    character = _peek();
    if (_isDelimiter(_getEqualChar(character))) {
      final Map<String, dynamic> result = _appendCharacter(token);
      character = result['character'] as int?;
      token = result['token'] as String?;
      return token;
    }
    while (character != -1 &&
        !_isSeparator(_getEqualChar(character)) &&
        token != '\u0000') {
      final Map<String, dynamic> result = _appendCharacter(token);
      character = result['character'] as int?;
      token = result['token'] as String?;
      character = _peek();
    }
    return token;
  }

  Map<String, dynamic> _appendCharacter(String? token) {
    final int character = _read();
    if (character != -1) {
      token = token! + String.fromCharCode(character);
    }
    final Map<String, dynamic> result = <String, dynamic>{};
    result['token'] = token;
    result['character'] = character;
    return result;
  }

  int _peek() {
    int? value = 0;
    if (_bytePeeked) {
      value = _getPeeked(value);
    } else {
      _peekedByte = _read();
      value = _peekedByte;
    }
    if (_peekedByte != -1) {
      _bytePeeked = true;
    }
    return value;
  }

  bool _isDelimiter(String character) {
    for (int index = 0; index < _delimiters.length; index++) {
      if (_delimiters[index] == character) {
        return true;
      }
    }
    return false;
  }

  bool _isSeparator(String character) {
    return _spaceCharacters.contains(character) || _isDelimiter(character);
  }

  bool _isJsonDelimiter(String character) {
    // ignore: unnecessary_string_escapes
    return character.contains(RegExp('[":,{}]|[\[]|]'));
  }

  /// internal method
  String getNextJsonToken() {
    String token = '';
    int character;
    final List<int> word = <int>[];
    skipWhiteSpace();
    character = _peek();
    //Return the character if it is a delimiter character.
    if (_isJsonDelimiter(_getEqualChar(character))) {
      final Map<String, dynamic> result = _appendCharacter(token);
      character = result['character'] as int;
      return token = result['token'] as String;
    }
    //Read all character sequentially until separator read.
    while (character != -1 &&
        !_isJsonDelimiter(String.fromCharCode(character)) &&
        token != '\u0000') {
      word.add(character.toUnsigned(8));
      _read();
      character = _peek();
    }
    token = '';
    if (word.isNotEmpty) {
      token = utf8.decode(word);
    }
    word.clear();
    return token;
  }
}
