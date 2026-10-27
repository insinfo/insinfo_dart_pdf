import 'dart:typed_data';

/// Signed big-endian int64 at [offset].
int keystoreReadInt64(ByteData data, int offset) =>
    data.getInt64(offset, Endian.big);

/// Writes [value] as a signed big-endian int64 at [offset].
void keystoreWriteInt64(ByteData data, int offset, int value) =>
    data.setInt64(offset, value, Endian.big);
