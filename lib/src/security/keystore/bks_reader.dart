import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// BouncyCastle KeyStore (BKS) v2 codec.
///
/// This supports reading, editing and creating BKS v2 stores.
///
/// Notes:
/// - Integrity check is HMAC-SHA1 with a key derived from the password using
///   PKCS#12 PBE (salt + iteration count).
/// - This implementation focuses on correctness and round-tripping for common
///   trust stores (certificate entries). It also supports KEY/SECRET/SEALED
///   entries as opaque/encrypted payloads.
/// - BKS v1 is not supported.
class BksStore {
  BksStore({
    required this.version,
    required this.salt,
    required this.iterationCount,
    required this.entries,
  });

  factory BksStore.empty({
    int iterationCount = 1024,
    Uint8List? salt,
  }) {
    return BksStore(
      version: BksCodec.storeVersion,
      salt: salt ?? BksCodec.generateSalt(),
      iterationCount: iterationCount,
      entries: <BksEntry>[],
    );
  }

  final int version;
  final Uint8List salt;
  final int iterationCount;
  final List<BksEntry> entries;

  Iterable<BksEntry> get certificateEntries =>
      entries.where((e) => e.type == BksEntryType.certificate);

  /// Returns raw DER bytes for all certificate entries (including chain certs).
  List<Uint8List> allCertificatesDer() {
    final List<Uint8List> out = <Uint8List>[];
    for (final e in entries) {
      for (final c in e.chain) {
        out.add(Uint8List.fromList(c.encoded));
      }
      if (e.type == BksEntryType.certificate && e.certificate != null) {
        out.add(Uint8List.fromList(e.certificate!.encoded));
      }
    }
    return out;
  }

  /// Adds or replaces a trusted certificate entry.
  void upsertTrustedCertificate({
    required String alias,
    required Uint8List certificateDer,
    String certificateType = 'X.509',
    DateTime? date,
  }) {
    final int idx = entries.indexWhere((e) => e.alias == alias);
    final BksEntry entry = BksEntry.certificate(
      alias: alias,
      date: date ?? DateTime.now().toUtc(),
      certificate: BksEncodedCertificate(
        type: certificateType,
        encoded: Uint8List.fromList(certificateDer),
      ),
    );

    if (idx == -1) {
      entries.add(entry);
    } else {
      entries[idx] = entry;
    }
  }

  bool removeEntry(String alias) {
    final int before = entries.length;
    entries.removeWhere((e) => e.alias == alias);
    return entries.length != before;
  }

  Uint8List toBytes({required String password}) {
    return BksCodec.encode(this, password: password);
  }
}

enum BksEntryType {
  certificate,
  key,
  secret,
  sealed,
}

class BksEncodedCertificate {
  BksEncodedCertificate({required this.type, required this.encoded});

  final String type;
  final Uint8List encoded;
}

class BksEntry {
  BksEntry({
    required this.type,
    required this.alias,
    required this.date,
    required this.chain,
    this.certificate,
    this.keyAlgorithm,
    this.keyData,
    this.secretData,
    this.sealedData,
  });

  factory BksEntry.certificate({
    required String alias,
    required DateTime date,
    List<BksEncodedCertificate> chain = const <BksEncodedCertificate>[],
    required BksEncodedCertificate certificate,
  }) {
    return BksEntry(
      type: BksEntryType.certificate,
      alias: alias,
      date: date,
      chain: List<BksEncodedCertificate>.from(chain),
      certificate: certificate,
    );
  }

  final BksEntryType type;
  final String alias;
  final DateTime date;
  final List<BksEncodedCertificate> chain;

  final BksEncodedCertificate? certificate;

  // KEY
  final String? keyAlgorithm;
  final Uint8List? keyData;

  // SECRET
  final Uint8List? secretData;

  // SEALED
  final Uint8List? sealedData;
}

class BksCodec {
  static const int storeVersion = 2;
  static const int _hmacSize = 20; // SHA-1
  static const int _derivedMacKeySizeParamV2 = _hmacSize * 8;

  // Entry types (1 byte)
  static const int _typeCertificate = 1;
  static const int _typeKey = 2;
  static const int _typeSecret = 3;
  static const int _typeSealed = 4;

  static Uint8List generateSalt([int length = 20]) {
    final Random r = Random.secure();
    final Uint8List salt = Uint8List(length);
    for (int i = 0; i < salt.length; i++) {
      salt[i] = r.nextInt(256);
    }
    return salt;
  }

  static BksStore decode(
    Uint8List data, {
    required String password,
    bool strictMac = true,
  }) {
    final _BksBytesReader r = _BksBytesReader(data);

    final int version = r.readInt32();
    if (version != storeVersion) {
      throw StateError('Unsupported BKS version: $version (expected $storeVersion).');
    }

    final int saltLen = r.readInt32();
    if (saltLen <= 0 || saltLen > 4096) {
      throw StateError('Invalid salt length: $saltLen');
    }
    final Uint8List salt = r.readBytes(saltLen);
    final int iterationCount = r.readInt32();
    if (iterationCount <= 0) {
      throw StateError('Invalid iteration count: $iterationCount');
    }

    final int bodyStart = r.offset;
    final int bodyLength = data.length - bodyStart - _hmacSize;
    if (bodyLength < 0) {
      throw StateError('File too short for BKS body+HMAC.');
    }
    final Uint8List bodyBytes = Uint8List.sublistView(data, bodyStart, bodyStart + bodyLength);
    final Uint8List storedMac = Uint8List.sublistView(data, data.length - _hmacSize);
    // BouncyCastle's BKS v2 uses PKCS12ParametersGenerator with
    // generateDerivedMacParameters(hMacSize * 8) (size in bits).
    // Some implementations/libraries historically interpret this parameter
    // differently, so for compatibility we accept either interpretation.
    final Uint8List calculatedMacBits = _calculateMac(
      password: password,
      salt: salt,
      iterationCount: iterationCount,
      bodyBytes: bodyBytes,
      derivedMacKeySizeParam: _derivedMacKeySizeParamV2,
    );
    final Uint8List calculatedMacBytes = _calculateMac(
      password: password,
      salt: salt,
      iterationCount: iterationCount,
      bodyBytes: bodyBytes,
      derivedMacKeySizeParam: _hmacSize,
    );

    final bool macOk =
        _constantTimeEquals(calculatedMacBits, storedMac) ||
        _constantTimeEquals(calculatedMacBytes, storedMac);
    if (!macOk && strictMac) {
      throw StateError('BKS integrity check failed (HMAC mismatch).');
    }

    final int endOfBody = bodyStart + bodyLength;
    final List<BksEntry> entries = <BksEntry>[];

    while (r.offset < endOfBody) {
      final int type = r.readUint8();
      if (type == 0) {
        break;
      }
      final String alias = r.readModifiedUtf8();
      final DateTime date = DateTime.fromMillisecondsSinceEpoch(
        r.readInt64(),
        isUtc: true,
      );

      final int chainLen = r.readInt32();
      if (chainLen < 0 || chainLen > 10000) {
        throw StateError('Invalid certificate chain length: $chainLen');
      }

      final List<BksEncodedCertificate> chain = <BksEncodedCertificate>[];
      for (int i = 0; i < chainLen; i++) {
        chain.add(_readCertificate(r));
      }

      if (type == _typeCertificate) {
        final BksEncodedCertificate cert = _readCertificate(r);
        entries.add(
          BksEntry(
            type: BksEntryType.certificate,
            alias: alias,
            date: date,
            chain: chain,
            certificate: cert,
          ),
        );
        continue;
      }

      if (type == _typeKey) {
        final String keyAlg = r.readModifiedUtf8();
        final int len = r.readInt32();
        final Uint8List keyData = r.readBytes(len);
        entries.add(
          BksEntry(
            type: BksEntryType.key,
            alias: alias,
            date: date,
            chain: chain,
            keyAlgorithm: keyAlg,
            keyData: keyData,
          ),
        );
        continue;
      }

      if (type == _typeSecret) {
        final int len = r.readInt32();
        final Uint8List secret = r.readBytes(len);
        entries.add(
          BksEntry(
            type: BksEntryType.secret,
            alias: alias,
            date: date,
            chain: chain,
            secretData: secret,
          ),
        );
        continue;
      }

      if (type == _typeSealed) {
        final int len = r.readInt32();
        final Uint8List sealed = r.readBytes(len);
        entries.add(
          BksEntry(
            type: BksEntryType.sealed,
            alias: alias,
            date: date,
            chain: chain,
            sealedData: sealed,
          ),
        );
        continue;
      }

      throw StateError('Unknown BKS entry type: $type');
    }

    return BksStore(
      version: version,
      salt: Uint8List.fromList(salt),
      iterationCount: iterationCount,
      entries: entries,
    );
  }

  static Uint8List encode(
    BksStore store, {
    required String password,
  }) {
    if (store.version != storeVersion) {
      throw StateError('Only BKS v$storeVersion is supported for writing.');
    }
    if (store.salt.isEmpty) {
      throw StateError('Store salt must not be empty.');
    }

    final BytesBuilder out = BytesBuilder(copy: false);
    final _BksBytesWriter w = _BksBytesWriter(out);

    w.writeInt32(store.version);
    w.writeInt32(store.salt.length);
    w.writeBytes(store.salt);
    w.writeInt32(store.iterationCount);

    final BytesBuilder body = BytesBuilder(copy: false);
    final _BksBytesWriter bw = _BksBytesWriter(body);

    for (final BksEntry e in store.entries) {
      bw.writeUint8(_encodeType(e.type));
      bw.writeModifiedUtf8(e.alias);
      bw.writeInt64(e.date.toUtc().millisecondsSinceEpoch);

      bw.writeInt32(e.chain.length);
      for (final BksEncodedCertificate c in e.chain) {
        _writeCertificate(bw, c);
      }

      switch (e.type) {
        case BksEntryType.certificate:
          final cert = e.certificate;
          if (cert == null) {
            throw StateError('Certificate entry ${e.alias} is missing certificate data.');
          }
          _writeCertificate(bw, cert);
          break;
        case BksEntryType.key:
          if (e.keyAlgorithm == null || e.keyData == null) {
            throw StateError('Key entry ${e.alias} is missing keyAlgorithm/keyData.');
          }
          bw.writeModifiedUtf8(e.keyAlgorithm!);
          bw.writeInt32(e.keyData!.length);
          bw.writeBytes(e.keyData!);
          break;
        case BksEntryType.secret:
          if (e.secretData == null) {
            throw StateError('Secret entry ${e.alias} is missing secretData.');
          }
          bw.writeInt32(e.secretData!.length);
          bw.writeBytes(e.secretData!);
          break;
        case BksEntryType.sealed:
          if (e.sealedData == null) {
            throw StateError('Sealed entry ${e.alias} is missing sealedData.');
          }
          bw.writeInt32(e.sealedData!.length);
          bw.writeBytes(e.sealedData!);
          break;
      }
    }

    // Terminator.
    bw.writeUint8(0);

    final Uint8List bodyBytes = body.toBytes();
    w.writeBytes(bodyBytes);

    final Uint8List mac = _calculateMac(
      password: password,
      salt: store.salt,
      iterationCount: store.iterationCount,
      bodyBytes: bodyBytes,
      derivedMacKeySizeParam: _derivedMacKeySizeParamV2,
    );
    w.writeBytes(mac);
    return out.toBytes();
  }

  static int _encodeType(BksEntryType t) {
    switch (t) {
      case BksEntryType.certificate:
        return _typeCertificate;
      case BksEntryType.key:
        return _typeKey;
      case BksEntryType.secret:
        return _typeSecret;
      case BksEntryType.sealed:
        return _typeSealed;
    }
  }

  static BksEncodedCertificate _readCertificate(_BksBytesReader r) {
    final String type = r.readModifiedUtf8();
    final int len = r.readInt32();
    final Uint8List bytes = r.readBytes(len);
    return BksEncodedCertificate(type: type, encoded: bytes);
  }

  static void _writeCertificate(_BksBytesWriter w, BksEncodedCertificate c) {
    w.writeModifiedUtf8(c.type);
    w.writeInt32(c.encoded.length);
    w.writeBytes(c.encoded);
  }

  static Uint8List _calculateMac({
    required String password,
    required Uint8List salt,
    required int iterationCount,
    required Uint8List bodyBytes,
    required int derivedMacKeySizeParam,
  }) {
    final PKCS12ParametersGenerator generator =
        PKCS12ParametersGenerator(Digest('SHA-1'));
    final Uint8List passBytes = _pkcs12PasswordToBytes(password);
    generator.init(passBytes, salt, iterationCount);

    final CipherParameters macParams =
        generator.generateDerivedMacParameters(derivedMacKeySizeParam);
    if (macParams is! KeyParameter) {
      throw StateError('Unexpected MAC parameters type: ${macParams.runtimeType}');
    }

    final HMac hmac = HMac(Digest('SHA-1'), 64);
    hmac.init(macParams);
    hmac.update(bodyBytes, 0, bodyBytes.length);
    final Uint8List out = Uint8List(_hmacSize);
    hmac.doFinal(out, 0);
    return out;
  }

  static bool _constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    int diff = 0;
    for (int i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  static Uint8List _pkcs12PasswordToBytes(String password) {
    // PKCS#12 password bytes are UTF-16BE code units + a two-byte null terminator.
    // Even an empty password yields a 2-byte terminator (not an empty array).
    if (password.isEmpty) return Uint8List(2);
    final List<int> units = password.codeUnits;
    final Uint8List out = Uint8List((units.length + 1) * 2);
    for (int i = 0; i < units.length; i++) {
      final int c = units[i];
      out[i * 2] = (c >> 8) & 0xFF;
      out[i * 2 + 1] = c & 0xFF;
    }
    return out;
  }
}

/// Backwards-compatible wrapper.
///
/// Existing code can keep using `BksReader(bytes, password).readCertificates()`.
class BksReader {
  BksReader(this._data, this.password);

  final Uint8List _data;
  final String password;

  /// Reads all certificate DER blobs (trusted + chain certificates).
  ///
  /// Throws on HMAC mismatch (strict).
  List<Uint8List> readCertificates({bool strictMac = true}) {
    final BksStore store = BksCodec.decode(
      _data,
      password: password,
      strictMac: strictMac,
    );
    return store.allCertificatesDer();
  }

  BksStore readStore({bool strictMac = true}) {
    return BksCodec.decode(
      _data,
      password: password,
      strictMac: strictMac,
    );
  }
}

class _BksBytesReader {
  _BksBytesReader(this._data) : _bd = ByteData.sublistView(_data);

  final Uint8List _data;
  final ByteData _bd;
  int offset = 0;

  int readUint8() {
    _ensure(1);
    return _data[offset++];
  }

  int readInt32() {
    _ensure(4);
    final int v = _bd.getInt32(offset, Endian.big);
    offset += 4;
    return v;
  }

  int readInt64() {
    _ensure(8);
    final int v = _bd.getInt64(offset, Endian.big);
    offset += 8;
    return v;
  }

  Uint8List readBytes(int length) {
    if (length < 0) throw StateError('Negative length');
    _ensure(length);
    final Uint8List b = Uint8List.sublistView(_data, offset, offset + length);
    offset += length;
    return Uint8List.fromList(b);
  }

  String readModifiedUtf8() {
    _ensure(2);
    final int len = _bd.getUint16(offset, Endian.big);
    offset += 2;
    final Uint8List bytes = Uint8List.sublistView(_data, offset, offset + len);
    offset += len;
    return _ModifiedUtf8.decode(bytes);
  }

  void _ensure(int n) {
    if (offset + n > _data.length) {
      throw StateError('Unexpected EOF while reading BKS');
    }
  }
}

class _BksBytesWriter {
  _BksBytesWriter(this._out);

  final BytesBuilder _out;

  void writeUint8(int v) {
    _out.add(<int>[v & 0xFF]);
  }

  void writeInt32(int v) {
    final ByteData bd = ByteData(4);
    bd.setInt32(0, v, Endian.big);
    _out.add(bd.buffer.asUint8List());
  }

  void writeInt64(int v) {
    final ByteData bd = ByteData(8);
    bd.setInt64(0, v, Endian.big);
    _out.add(bd.buffer.asUint8List());
  }

  void writeBytes(Uint8List bytes) {
    _out.add(bytes);
  }

  void writeModifiedUtf8(String s) {
    final Uint8List encoded = _ModifiedUtf8.encode(s);
    if (encoded.length > 0xFFFF) {
      throw StateError('String too long for modified UTF-8: ${encoded.length} bytes');
    }
    final ByteData bd = ByteData(2);
    bd.setUint16(0, encoded.length, Endian.big);
    _out.add(bd.buffer.asUint8List());
    _out.add(encoded);
  }
}

/// Java DataInput/DataOutput "modified UTF-8" codec.
///
/// - U+0000 is encoded as 0xC0 0x80 (not 0x00)
/// - Surrogates are encoded as 3-byte sequences each (no pair-combining)
class _ModifiedUtf8 {
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
