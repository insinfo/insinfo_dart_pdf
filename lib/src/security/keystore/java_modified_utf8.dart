import 'dart:typed_data';

/// Java DataInput/DataOutput "modified UTF-8" codec.
///
/// - U+0000 is encoded as 0xC0 0x80 (not 0x00)
/// - Surrogates are encoded as 3-byte sequences each (no pair-combining)
class JavaModifiedUtf8 {
  const JavaModifiedUtf8._();

  static Uint8List encode(String s) {
    final List<int> out = <int>[];
    final List<int> units = s.codeUnits; // UTF-16 code units
    for (final int c in units) {
      if (c == 0x0000) {
        out.add(0xC0);
        out.add(0x80);
      } else if (c <= 0x007F) {
        out.add(c);
      } else if (c <= 0x07FF) {
        out.add(0xC0 | ((c >> 6) & 0x1F));
        out.add(0x80 | (c & 0x3F));
      } else {
        out.add(0xE0 | ((c >> 12) & 0x0F));
        out.add(0x80 | ((c >> 6) & 0x3F));
        out.add(0x80 | (c & 0x3F));
      }
    }
    return Uint8List.fromList(out);
  }

  static String decode(Uint8List bytes) {
    final StringBuffer sb = StringBuffer();
    int i = 0;
    while (i < bytes.length) {
      final int b = bytes[i] & 0xFF;
      if (b < 0x80) {
        sb.writeCharCode(b);
        i += 1;
        continue;
      }
      if ((b & 0xE0) == 0xC0) {
        if (i + 1 >= bytes.length) {
          throw StateError('Invalid modified UTF-8 (truncated 2-byte sequence)');
        }
        final int b2 = bytes[i + 1] & 0xFF;
        final int ch = ((b & 0x1F) << 6) | (b2 & 0x3F);
        sb.writeCharCode(ch);
        i += 2;
        continue;
      }
      if ((b & 0xF0) == 0xE0) {
        if (i + 2 >= bytes.length) {
          throw StateError('Invalid modified UTF-8 (truncated 3-byte sequence)');
        }
        final int b2 = bytes[i + 1] & 0xFF;
        final int b3 = bytes[i + 2] & 0xFF;
        final int ch =
            ((b & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F);
        sb.writeCharCode(ch);
        i += 3;
        continue;
      }
      throw StateError('Invalid modified UTF-8 leading byte: 0x${b.toRadixString(16)}');
    }
    return sb.toString();
  }
}
