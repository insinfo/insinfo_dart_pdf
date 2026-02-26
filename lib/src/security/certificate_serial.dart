import 'dart:typed_data';

/// Immutable serial-number value object with canonical representations.
///
/// Canonical rules:
/// - hex: lowercase, no `0x`, no leading zeros (except zero => `0`)
/// - decimal: arbitrary precision (BigInt -> String)
class CertificateSerial {
  CertificateSerial._({
    required this.hex,
    required this.decimal,
    required this.rawBytes,
  });

  /// Canonical lowercase hex without prefix.
  final String hex;

  /// Canonical decimal string (arbitrary precision).
  final String decimal;

  /// Unsigned raw bytes, without sign-padding byte.
  final Uint8List rawBytes;

  /// Canonical `0x...` representation.
  String get hexPrefixed => '0x$hex';

  factory CertificateSerial.fromHex(String input) {
    final cleaned = _cleanHex(input);
    if (cleaned.isEmpty) {
      throw ArgumentError.value(input, 'input', 'Invalid hex serial.');
    }
    final bytes = _hexToBytes(cleaned);
    return CertificateSerial._(
      hex: _bytesToCanonicalHex(bytes),
      decimal: _bytesToBigInt(bytes).toString(),
      rawBytes: bytes,
    );
  }

  factory CertificateSerial.fromDecimal(String input) {
    final cleaned = input.trim();
    if (cleaned.isEmpty) {
      throw ArgumentError.value(input, 'input', 'Invalid decimal serial.');
    }
    final value = BigInt.parse(cleaned);
    if (value < BigInt.zero) {
      throw ArgumentError.value(input, 'input', 'Serial must be non-negative.');
    }
    final bytes = _bigIntToBytes(value);
    return CertificateSerial._(
      hex: _bytesToCanonicalHex(bytes),
      decimal: value.toString(),
      rawBytes: bytes,
    );
  }

  /// Creates a serial from DER INTEGER bytes.
  ///
  /// Accepts either:
  /// - full DER INTEGER TLV (`0x02 <len> <value...>`)
  /// - raw integer content bytes.
  factory CertificateSerial.fromDerInteger(Uint8List derInteger) {
    if (derInteger.isEmpty) {
      throw ArgumentError.value(derInteger, 'derInteger', 'Empty DER integer.');
    }

    Uint8List content;
    if (derInteger[0] == 0x02) {
      if (derInteger.length < 3) {
        throw ArgumentError.value(
            derInteger, 'derInteger', 'Invalid DER INTEGER.');
      }
      final lenInfo = _readDerLength(derInteger, 1);
      final int start = 1 + lenInfo.$1;
      final int length = lenInfo.$2;
      final int end = start + length;
      if (start < 0 || end > derInteger.length || length <= 0) {
        throw ArgumentError.value(
            derInteger, 'derInteger', 'Invalid DER INTEGER length.');
      }
      content = Uint8List.sublistView(derInteger, start, end);
    } else {
      content = Uint8List.fromList(derInteger);
    }

    // Remove sign-padding 0x00 for positive INTEGER.
    while (content.length > 1 && content[0] == 0x00) {
      content = Uint8List.sublistView(content, 1);
    }

    return CertificateSerial._(
      hex: _bytesToCanonicalHex(content),
      decimal: _bytesToBigInt(content).toString(),
      rawBytes: Uint8List.fromList(content),
    );
  }

  @override
  String toString() => hexPrefixed;
}

/// Compares serials supplied as decimal or hex.
bool equalsSerial(String a, String b) {
  final sa = _parseSerialFlex(a);
  final sb = _parseSerialFlex(b);
  return _bytesEqual(sa.rawBytes, sb.rawBytes);
}

/// Normalizes decimal/hex serial into canonical hex (no prefix).
String normalizeSerialToHex(String input) => _parseSerialFlex(input).hex;

/// Normalizes decimal/hex serial into canonical decimal.
String normalizeSerialToDecimal(String input) =>
    _parseSerialFlex(input).decimal;

CertificateSerial _parseSerialFlex(String input) {
  final trimmed = input.trim();
  if (trimmed.isEmpty) {
    throw ArgumentError.value(input, 'input', 'Empty serial.');
  }
  if (_looksLikeHex(trimmed)) {
    return CertificateSerial.fromHex(trimmed);
  }
  return CertificateSerial.fromDecimal(trimmed);
}

bool _looksLikeHex(String input) {
  final normalized = input.startsWith('0x') || input.startsWith('0X')
      ? input.substring(2)
      : input;
  if (normalized.isEmpty) return false;
  return RegExp(r'^[0-9a-fA-F]+$').hasMatch(normalized) &&
      RegExp(r'[a-fA-F]').hasMatch(normalized);
}

String _cleanHex(String input) {
  var s = input.trim();
  if (s.startsWith('0x') || s.startsWith('0X')) {
    s = s.substring(2);
  }
  if (!RegExp(r'^[0-9a-fA-F]+$').hasMatch(s)) {
    throw ArgumentError.value(input, 'input', 'Invalid hex serial.');
  }
  s = s.toLowerCase();
  s = s.replaceFirst(RegExp(r'^0+'), '');
  if (s.isEmpty) return '0';
  return s;
}

Uint8List _hexToBytes(String hex) {
  var h = hex;
  if (h.length.isOdd) {
    h = '0$h';
  }
  final out = Uint8List(h.length ~/ 2);
  for (int i = 0; i < h.length; i += 2) {
    out[i ~/ 2] = int.parse(h.substring(i, i + 2), radix: 16);
  }
  // remove left zero padding from parser canonicalization
  int firstNonZero = 0;
  while (firstNonZero < out.length - 1 && out[firstNonZero] == 0x00) {
    firstNonZero++;
  }
  return Uint8List.fromList(out.sublist(firstNonZero));
}

String _bytesToCanonicalHex(Uint8List bytes) {
  final sb = StringBuffer();
  for (final b in bytes) {
    sb.write(b.toRadixString(16).padLeft(2, '0'));
  }
  var h = sb.toString().toLowerCase();
  h = h.replaceFirst(RegExp(r'^0+'), '');
  return h.isEmpty ? '0' : h;
}

BigInt _bytesToBigInt(Uint8List bytes) {
  var value = BigInt.zero;
  for (final b in bytes) {
    value = (value << 8) | BigInt.from(b);
  }
  return value;
}

Uint8List _bigIntToBytes(BigInt value) {
  if (value == BigInt.zero) return Uint8List.fromList(<int>[0]);
  final out = <int>[];
  var current = value;
  while (current > BigInt.zero) {
    out.add((current & BigInt.from(0xff)).toInt());
    current = current >> 8;
  }
  return Uint8List.fromList(out.reversed.toList(growable: false));
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Returns `(lengthBytesCount, valueLength)`.
(int, int) _readDerLength(Uint8List bytes, int offset) {
  if (offset >= bytes.length) {
    throw ArgumentError('Invalid DER length offset.');
  }
  final first = bytes[offset];
  if ((first & 0x80) == 0) {
    return (1, first);
  }
  final count = first & 0x7f;
  if (count == 0 || count > 4 || offset + count >= bytes.length) {
    throw ArgumentError('Unsupported DER length.');
  }
  var value = 0;
  for (int i = 0; i < count; i++) {
    value = (value << 8) | bytes[offset + 1 + i];
  }
  return (1 + count, value);
}
