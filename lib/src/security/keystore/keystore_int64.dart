// 64-bit big-endian integers for keystore dates (BKS and JKS).
//
// The VM reads and writes them natively with ByteData; JavaScript has no
// 64-bit integers (`getInt64` throws, `>> 32` truncates), so builds without
// dart:io split them into two 32-bit halves.
export 'keystore_int64_web.dart'
    if (dart.library.io) 'keystore_int64_vm.dart';
