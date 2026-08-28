import 'dart:typed_data';

import 'pdf_data_source.dart';
import 'pdf_repair_options.dart';

/// An object header found by scanning a file whose cross-reference table could
/// not be used.
class PdfRepairedObject {
  /// internal constructor
  const PdfRepairedObject(this.offset, this.generation);

  /// Offset of the first digit of the `N G obj` header.
  final int offset;

  /// The generation number the header declared.
  final int generation;
}

/// What scanning a damaged file turned up.
class PdfRepairScanResult {
  /// internal constructor
  const PdfRepairScanResult(
    this.objects,
    this.catalogNumber,
    this.trailerOffsets,
  );

  /// Object number to where its header sits.
  final Map<int, PdfRepairedObject> objects;

  /// The object number of the document catalog, when the scan saw a
  /// `/Type /Catalog` while passing over it.
  ///
  /// Found on the way, so the caller does not have to parse objects back to
  /// front looking for it.
  final int? catalogNumber;

  /// Offsets of every `trailer` keyword, in file order.
  ///
  /// The last one is normally the one that matters, but a damaged incremental
  /// update can leave a broken trailer at the very end, so the caller walks
  /// them backwards.
  final List<int> trailerOffsets;
}

/// Rebuilds the object table of a damaged PDF by scanning it for object
/// headers, the way a viewer does.
///
/// Works on bytes and allocates nothing per byte. That is not a micro
/// optimization — it is the difference between this and every reference
/// implementation. A scan that builds a Dart `String` per line is quadratic on
/// the lines a scanned document has, where the "line" is whatever sits between
/// two accidental `0x0A` bytes inside a JPEG: hundreds of kilobytes.
///
/// * PDFBox (`BruteForceParser.bfSearchForObjects`) walks the file byte by byte
///   comparing against `char[]` constants hoisted out of the loop.
/// * iText (`PdfReader.rebuildXref`) keeps reading lines, but into a 24 byte
///   buffer that is reused and **capped**: full, it stops storing and drains
///   the rest of the line. An object header fits in 24 bytes; the megabyte of
///   image data behind it never reaches memory.
/// * MuPDF (`pdf_repair_xref_base`) tokenizes without materializing strings at
///   all, and additionally seeks over stream bodies.
class PdfRepairScanner {
  PdfRepairScanner._(this._bytes, this._mode);

  /// Scans [source] and returns what it found.
  ///
  /// A source that is not already a byte array is materialized first. The scan
  /// walks the whole file and jumps around inside it, so reading it through a
  /// window would cost more than it saves — and a caller only reaches here for
  /// a document damaged badly enough that no cross-reference table survived.
  /// MuPDF is the counter-example, seeking over stream bodies on a file
  /// stream; matching that is worth doing, and is not done here.
  static PdfRepairScanResult scanSource(
    PdfDataSource source, {
    PdfRepairScan mode = PdfRepairScan.thorough,
  }) {
    final List<int>? bytes = source.bytes;
    return scan(bytes ?? source.readRange(0, source.length), mode: mode);
  }

  /// Scans [data] and returns what it found.
  static PdfRepairScanResult scan(
    List<int> data, {
    PdfRepairScan mode = PdfRepairScan.thorough,
  }) {
    // Indexing a `Uint8List` through a `Uint8List`-typed variable is what makes
    // the loop cheap. Input that is not already one is copied, which is only
    // the uncommon path — `File.readAsBytesSync` and `PdfDocument` both hand
    // over a `Uint8List`.
    final Uint8List bytes =
        data is Uint8List ? data : Uint8List.fromList(data);
    return PdfRepairScanner._(bytes, mode)._run();
  }

  final Uint8List _bytes;
  final PdfRepairScan _mode;

  /// Out parameter of [_readInteger], to keep it from allocating a record.
  int _integer = 0;

  /// Out parameters of [_readDictionaryHead].
  bool _dictionaryIsCatalog = false;
  bool _dictionaryHasPages = false;

  static const int _lineFeed = 0x0A;
  static const int _carriageReturn = 0x0D;
  static const int _space = 0x20;
  static const int _percent = 0x25;
  static const int _openParen = 0x28;
  static const int _closeParen = 0x29;
  static const int _plus = 0x2B;
  static const int _minus = 0x2D;
  static const int _solidus = 0x2F;
  static const int _zero = 0x30;
  static const int _nine = 0x39;
  static const int _less = 0x3C;
  static const int _greater = 0x3E;
  static const int _backslash = 0x5C;

  static const List<int> _obj = <int>[0x6F, 0x62, 0x6A]; // obj
  static const List<int> _trailer = <int>[
    0x74, 0x72, 0x61, 0x69, 0x6C, 0x65, 0x72, //
  ]; // trailer
  static const List<int> _stream = <int>[
    0x73, 0x74, 0x72, 0x65, 0x61, 0x6D, //
  ]; // stream
  static const List<int> _endStream = <int>[
    0x65, 0x6E, 0x64, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6D, //
  ]; // endstream
  static const List<int> _keyLength = <int>[
    0x2F, 0x4C, 0x65, 0x6E, 0x67, 0x74, 0x68, //
  ]; // /Length
  static const List<int> _keyType = <int>[0x2F, 0x54, 0x79, 0x70, 0x65]; // /Type
  static const List<int> _keyPages = <int>[
    0x2F, 0x50, 0x61, 0x67, 0x65, 0x73, //
  ]; // /Pages
  static const List<int> _nameCatalog = <int>[
    0x2F, 0x43, 0x61, 0x74, 0x61, 0x6C, 0x6F, 0x67, //
  ]; // /Catalog
  static const int _referenceR = 0x52; // R

  /// How far into an object dictionary the scan looks for `/Length` and
  /// `/Type`. Both sit near the front; a bounded window keeps a damaged or
  /// enormous dictionary from turning the scan back into a full parse.
  static const int _dictionaryWindow = 4096;

  PdfRepairScanResult _run() {
    final Map<int, PdfRepairedObject> objects = <int, PdfRepairedObject>{};
    final List<int> trailerOffsets = <int>[];
    final int end = _bytes.length;
    // Two candidates, because a damaged file can carry an emptied catalog from
    // an earlier revision. One that leads to pages wins; failing that, any.
    int? catalogWithPages;
    int? anyCatalog;

    // The two integers most recently read, with where each started. `N G obj`
    // is recognized only once `obj` shows up, so both have to be remembered.
    int previousInteger = 0;
    int previousOffset = -1;
    int lastInteger = 0;
    int lastOffset = -1;

    int i = 0;
    while (i < end) {
      final int byte = _bytes[i];

      if (byte >= _zero && byte <= _nine || byte == _plus || byte == _minus) {
        final int start = i;
        final int next = _readInteger(i, end);
        if (next == start) {
          i++;
          continue;
        }
        previousInteger = lastInteger;
        previousOffset = lastOffset;
        lastInteger = _integer;
        lastOffset = start;
        i = next;

        final int afterSpace = _skipWhitespace(i, end);
        if (!_matches(afterSpace, _obj)) {
          continue;
        }
        i = afterSpace + _obj.length;
        if (previousOffset < 0 || previousInteger < 0) {
          continue;
        }

        // The header is `previousInteger previousGeneration obj`, starting at
        // previousOffset.
        final int number = previousInteger;
        final PdfRepairedObject? known = objects[number];
        if (known == null || previousOffset > known.offset) {
          // The later definition wins. Scanning runs front to back, so a
          // higher offset is a later revision — which is the one an
          // incremental update meant to be current. iText, PDFBox and MuPDF
          // all resolve the collision this way.
          objects[number] = PdfRepairedObject(previousOffset, lastInteger);
        }
        previousOffset = -1;
        lastOffset = -1;

        i = _readObjectBody(i, end, number, (int found, bool hasPages) {
          // The later one wins, for the same reason the later object header
          // does: it is the current revision.
          anyCatalog = found;
          if (hasPages) {
            catalogWithPages = found;
          }
        });
        continue;
      }

      if (byte == _trailer[0] && _matches(i, _trailer)) {
        trailerOffsets.add(i);
        i += _trailer.length;
        continue;
      }

      i++;
    }

    return PdfRepairScanResult(
      objects,
      catalogWithPages ?? anyCatalog,
      trailerOffsets,
    );
  }

  /// Reads the dictionary of the object that starts at [i], reporting a
  /// catalog through [onCatalog], and steps over the stream body when the
  /// scan is allowed to.
  ///
  /// Returns where scanning should resume.
  int _readObjectBody(
    int i,
    int end,
    int number,
    void Function(int, bool) onCatalog,
  ) {
    int position = _skipWhitespace(i, end);
    int? streamLength;
    if (position + 1 < end &&
        _bytes[position] == _less &&
        _bytes[position + 1] == _less) {
      final int limit =
          position + _dictionaryWindow < end
              ? position + _dictionaryWindow
              : end;
      position = _readDictionaryHead(position, limit);
      streamLength = _integer >= 0 ? _integer : null;
      if (_dictionaryIsCatalog) {
        onCatalog(number, _dictionaryHasPages);
      }
    }
    if (_mode != PdfRepairScan.skipStreams) {
      return position;
    }

    position = _skipWhitespace(position, end);
    if (!_matches(position, _stream)) {
      return position;
    }
    position += _stream.length;
    if (position < end && _bytes[position] == _carriageReturn) {
      position++;
    }
    if (position < end && _bytes[position] == _lineFeed) {
      position++;
    }
    final int body = position;

    if (streamLength != null && streamLength > 0) {
      final int landing = body + streamLength;
      if (landing > body && landing < end) {
        // `/Length` is a hint, not a promise. MuPDF jumps by it and then
        // checks that `endstream` is really there; only a failed check costs a
        // scan. Trusting it blind would trade slowness for silent corruption.
        final int afterSpace = _skipWhitespace(landing, end);
        if (_matches(afterSpace, _endStream)) {
          return afterSpace + _endStream.length;
        }
      }
    }

    final int found = _indexOf(_endStream, body, end);
    if (found < 0) {
      return body;
    }
    return found + _endStream.length;
  }

  /// Walks an object dictionary far enough to pick up `/Length` and to notice
  /// `/Type /Catalog`, leaving the length in [_integer] (`-1` when unknown).
  int _readDictionaryHead(int start, int limit) {
    int i = start + 2;
    int depth = 1;
    int length = -1;
    _dictionaryIsCatalog = false;
    _dictionaryHasPages = false;
    while (i < limit) {
      final int byte = _bytes[i];
      if (byte == _less) {
        if (i + 1 < limit && _bytes[i + 1] == _less) {
          depth++;
          i += 2;
          continue;
        }
        // A hex string, which may well contain `>` bytes.
        i = _skipHexString(i, limit);
        continue;
      }
      if (byte == _greater) {
        if (i + 1 < limit && _bytes[i + 1] == _greater) {
          depth--;
          i += 2;
          if (depth <= 0) {
            _integer = length;
            return i;
          }
          continue;
        }
        i++;
        continue;
      }
      if (byte == _openParen) {
        i = _skipLiteralString(i, limit);
        continue;
      }
      if (byte == _percent) {
        i = _skipComment(i, limit);
        continue;
      }
      if (byte == _solidus && depth == 1) {
        if (_matches(i, _keyLength)) {
          final int value = _readLengthValue(i + _keyLength.length, limit);
          if (value >= 0) {
            length = value;
          }
          i += _keyLength.length;
          continue;
        }
        if (_matches(i, _keyType)) {
          final int afterKey = _skipWhitespace(i + _keyType.length, limit);
          if (_matches(afterKey, _nameCatalog)) {
            _dictionaryIsCatalog = true;
          }
          i += _keyType.length;
          continue;
        }
        if (_matches(i, _keyPages)) {
          _dictionaryHasPages = true;
          i += _keyPages.length;
          continue;
        }
      }
      i++;
    }
    // Ran past the window without closing the dictionary: report no length
    // rather than a half read one, and resume from where the object body
    // starts so the caller can still look for `stream`.
    _integer = length;
    return limit;
  }

  /// Reads the value of `/Length`, refusing an indirect reference.
  ///
  /// `/Length 12 0 R` is legal and common in files written by iText. Taking
  /// the `12` as the byte count would jump into the middle of the stream.
  int _readLengthValue(int start, int limit) {
    int i = _skipWhitespace(start, limit);
    if (i >= limit || _bytes[i] < _zero || _bytes[i] > _nine) {
      return -1;
    }
    final int afterFirst = _readInteger(i, limit);
    final int value = _integer;
    int probe = _skipWhitespace(afterFirst, limit);
    if (probe < limit && _bytes[probe] >= _zero && _bytes[probe] <= _nine) {
      probe = _readInteger(probe, limit);
      probe = _skipWhitespace(probe, limit);
      if (probe < limit && _bytes[probe] == _referenceR) {
        _integer = value;
        return -1;
      }
    }
    _integer = value;
    return value;
  }

  /// Reads an integer starting at [i], leaving the value in [_integer].
  ///
  /// Returns [i] unchanged when there is no integer there.
  int _readInteger(int i, int end) {
    int position = i;
    bool negative = false;
    if (position < end &&
        (_bytes[position] == _plus || _bytes[position] == _minus)) {
      negative = _bytes[position] == _minus;
      position++;
    }
    int value = 0;
    int digits = 0;
    while (position < end &&
        _bytes[position] >= _zero &&
        _bytes[position] <= _nine) {
      // A run of digits longer than an object number can ever be is binary
      // data, not a number; stop rather than overflow on it.
      if (digits < 18) {
        value = value * 10 + (_bytes[position] - _zero);
      }
      digits++;
      position++;
    }
    if (digits == 0) {
      return i;
    }
    _integer = negative ? -value : value;
    return position;
  }

  int _skipWhitespace(int i, int end) {
    int position = i;
    while (position < end) {
      final int byte = _bytes[position];
      if (byte == _space ||
          byte == _lineFeed ||
          byte == _carriageReturn ||
          byte == 0x09 ||
          byte == 0x0C ||
          byte == 0x00) {
        position++;
        continue;
      }
      if (byte == _percent) {
        position = _skipComment(position, end);
        continue;
      }
      break;
    }
    return position;
  }

  int _skipComment(int i, int end) {
    int position = i;
    while (position < end &&
        _bytes[position] != _lineFeed &&
        _bytes[position] != _carriageReturn) {
      position++;
    }
    return position;
  }

  int _skipLiteralString(int i, int end) {
    int position = i + 1;
    int depth = 1;
    while (position < end) {
      final int byte = _bytes[position];
      if (byte == _backslash) {
        position += 2;
        continue;
      }
      if (byte == _openParen) {
        depth++;
      } else if (byte == _closeParen) {
        depth--;
        if (depth == 0) {
          return position + 1;
        }
      }
      position++;
    }
    return end;
  }

  int _skipHexString(int i, int end) {
    int position = i + 1;
    while (position < end && _bytes[position] != _greater) {
      position++;
    }
    return position < end ? position + 1 : end;
  }

  bool _matches(int i, List<int> token) {
    if (i < 0 || i + token.length > _bytes.length) {
      return false;
    }
    for (int k = 0; k < token.length; k++) {
      if (_bytes[i + k] != token[k]) {
        return false;
      }
    }
    return true;
  }

  int _indexOf(List<int> token, int from, int end) {
    final int last = end - token.length;
    final int first = token[0];
    for (int i = from; i <= last; i++) {
      if (_bytes[i] != first) {
        continue;
      }
      bool hit = true;
      for (int k = 1; k < token.length; k++) {
        if (_bytes[i + k] != token[k]) {
          hit = false;
          break;
        }
      }
      if (hit) {
        return i;
      }
    }
    return -1;
  }

  /// Searches backwards for [token], without materializing a `String` per
  /// position the way `PdfReader.searchBack` does.
  static int lastIndexOf(List<int> data, List<int> token, int from) {
    final Uint8List bytes =
        data is Uint8List ? data : Uint8List.fromList(data);
    int start = from;
    if (start > bytes.length - token.length) {
      start = bytes.length - token.length;
    }
    final int first = token[0];
    for (int i = start; i >= 0; i--) {
      if (bytes[i] != first) {
        continue;
      }
      bool hit = true;
      for (int k = 1; k < token.length; k++) {
        if (bytes[i + k] != token[k]) {
          hit = false;
          break;
        }
      }
      if (hit) {
        return i;
      }
    }
    return -1;
  }
}
