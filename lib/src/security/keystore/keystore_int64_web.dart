import 'dart:typed_data';

const int _twoTo32 = 0x100000000;

/// Signed big-endian int64 at [offset], from two uint32 reads.
int keystoreReadInt64(ByteData data, int offset) {
  final int hi = data.getUint32(offset, Endian.big);
  final int lo = data.getUint32(offset + 4, Endian.big);
  if (hi & 0x80000000 == 0) return hi * _twoTo32 + lo;
  return -(((~hi) & 0xFFFFFFFF) * _twoTo32 + ((~lo) & 0xFFFFFFFF) + 1);
}

/// Writes [value] as a signed big-endian int64 at [offset]. Division instead
/// of `>> 32`, which truncates to 32 bits in JavaScript; exact below 2^53.
void keystoreWriteInt64(ByteData data, int offset, int value) {
  final int hi = (value / _twoTo32).floor();
  data.setUint32(offset, hi & 0xFFFFFFFF, Endian.big);
  data.setUint32(offset + 4, value - hi * _twoTo32, Endian.big);
}
