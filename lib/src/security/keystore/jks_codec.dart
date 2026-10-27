import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'java_modified_utf8.dart';
import 'keystore_int64.dart';

/// Java KeyStore codec for the JKS (`0xFEEDFEED`) and JCEKS (`0xCECECECE`)
/// formats, as written by `sun.security.provider.JavaKeyStore` and
/// `com.sun.crypto.provider.JceKeyStore`.
///
/// Layout (big-endian):
///
///     magic · version (1 or 2) · count · entries · SHA-1 digest
///
/// - private key (tag 1): alias · date · protected key · chain
/// - trusted certificate (tag 2): alias · date · certificate
/// - certificate: type (version 2 only) · length · DER
///
/// The digest is `SHA-1(UTF-16BE(password) · "Mighty Aphrodite" · body)`.
/// Private keys stay protected in [JksEntry.protectedKey]; [JksKeyProtector]
/// recovers and protects them. JCEKS secret keys (tag 3, a Java-serialized
/// SealedObject) are not supported. Stores are written as version 2.
class JksStore {
  JksStore({required this.type, required this.entries});

  factory JksStore.empty({JksStoreType type = JksStoreType.jks}) =>
      JksStore(type: type, entries: <JksEntry>[]);

  final JksStoreType type;
  final List<JksEntry> entries;

  Iterable<JksEntry> get trustedCertificateEntries =>
      entries.where((e) => e.type == JksEntryType.trustedCertificate);

  /// Raw DER of every certificate: trusted entries and private key chains.
  List<Uint8List> allCertificatesDer() => <Uint8List>[
        for (final e in entries) ...[
          for (final c in e.chain) Uint8List.fromList(c.encoded),
          if (e.certificate != null) Uint8List.fromList(e.certificate!.encoded),
        ],
      ];

  /// Adds or replaces a trusted certificate entry.
  void upsertTrustedCertificate({
    required String alias,
    required Uint8List certificateDer,
    String certificateType = 'X.509',
    DateTime? date,
  }) {
    final JksEntry entry = JksEntry.trustedCertificate(
      alias: alias,
      date: date ?? DateTime.now().toUtc(),
      certificate: JksEncodedCertificate(
        type: certificateType,
        encoded: Uint8List.fromList(certificateDer),
      ),
    );
    final int idx = entries.indexWhere((e) => e.alias == alias);
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

  Uint8List toBytes({required String password}) =>
      JksCodec.encode(this, password: password);
}

enum JksStoreType { jks, jceks }

enum JksEntryType { privateKey, trustedCertificate }

class JksEncodedCertificate {
  JksEncodedCertificate({required this.type, required this.encoded});

  final String type;
  final Uint8List encoded;
}

class JksEntry {
  JksEntry({
    required this.type,
    required this.alias,
    required this.date,
    this.certificate,
    this.protectedKey,
    List<JksEncodedCertificate>? chain,
  }) : chain = chain ?? <JksEncodedCertificate>[];

  factory JksEntry.trustedCertificate({
    required String alias,
    required DateTime date,
    required JksEncodedCertificate certificate,
  }) =>
      JksEntry(
        type: JksEntryType.trustedCertificate,
        alias: alias,
        date: date,
        certificate: certificate,
      );

  /// [protectedKey] is an EncryptedPrivateKeyInfo, see [JksKeyProtector].
  factory JksEntry.privateKey({
    required String alias,
    required DateTime date,
    required Uint8List protectedKey,
    required List<JksEncodedCertificate> chain,
  }) =>
      JksEntry(
        type: JksEntryType.privateKey,
        alias: alias,
        date: date,
        protectedKey: protectedKey,
        chain: chain,
      );

  final JksEntryType type;
  final String alias;
  final DateTime date;

  /// Trusted certificate entries only.
  final JksEncodedCertificate? certificate;

  /// Private key entries only.
  final Uint8List? protectedKey;
  final List<JksEncodedCertificate> chain;
}

class JksCodec {
  static const int jksMagic = 0xFEEDFEED;
  static const int jceksMagic = 0xCECECECE;
  static const int _digestSize = 20;

  static const int _tagPrivateKey = 1;
  static const int _tagTrustedCert = 2;
  static const int _tagSecretKey = 3;

  /// Decodes a JKS or JCEKS store.
  ///
  /// With a non-empty [password] the integrity digest is checked, as
  /// `KeyStore.load` does; with an empty one it is skipped.
  static JksStore decode(Uint8List data, {required String password}) {
    final _Reader r = _Reader(data);
    final int magic = r.readUint32();
    if (magic != jksMagic && magic != jceksMagic) {
      throw StateError('Not a JKS/JCEKS store (magic 0x${magic.toRadixString(16)}).');
    }
    final JksStoreType type =
        magic == jceksMagic ? JksStoreType.jceks : JksStoreType.jks;
    final int version = r.readUint32();
    if (version != 1 && version != 2) {
      throw StateError('Unsupported JKS version: $version');
    }
    final int count = r.readUint32();

    JksEncodedCertificate readCertificate() {
      // Version 1 has no certificate type: it is always X.509.
      final String certType = version == 2 ? r.readUtf() : 'X.509';
      return JksEncodedCertificate(type: certType, encoded: r.readBlob());
    }

    final List<JksEntry> entries = <JksEntry>[];
    for (int i = 0; i < count; i++) {
      final int tag = r.readUint32();
      final String alias = r.readUtf();
      final DateTime date =
          DateTime.fromMillisecondsSinceEpoch(r.readInt64(), isUtc: true);

      if (tag == _tagPrivateKey) {
        final Uint8List protectedKey = r.readBlob();
        final int chainLength = r.readUint32();
        if (chainLength > 10000) {
          throw StateError('Invalid certificate chain length: $chainLength');
        }
        entries.add(JksEntry.privateKey(
          alias: alias,
          date: date,
          protectedKey: protectedKey,
          chain: <JksEncodedCertificate>[
            for (int j = 0; j < chainLength; j++) readCertificate(),
          ],
        ));
      } else if (tag == _tagTrustedCert) {
        entries.add(JksEntry.trustedCertificate(
          alias: alias,
          date: date,
          certificate: readCertificate(),
        ));
      } else if (tag == _tagSecretKey && type == JksStoreType.jceks) {
        // A Java-serialized SealedObject with no length prefix: the rest of
        // the file cannot be located without a Java deserializer.
        throw StateError('JCEKS secret key entry "$alias" is not supported.');
      } else {
        throw StateError('Unknown JKS entry tag: $tag');
      }
    }

    if (password.isNotEmpty) {
      final int bodyEnd = r.offset;
      // KeyStore.load reads the digest right after the entries; a missing
      // digest is a corrupt store, not a reason to skip the check.
      final Uint8List stored = r.readBytes(_digestSize);
      final Uint8List computed =
          _storeDigest(password, Uint8List.sublistView(data, 0, bodyEnd));
      if (!_constantTimeEquals(computed, stored)) {
        throw StateError(
            'JKS integrity check failed: wrong password or corrupted store.');
      }
    }

    return JksStore(type: type, entries: entries);
  }

  static Uint8List encode(JksStore store, {required String password}) {
    final _Writer w = _Writer();
    w.writeUint32(store.type == JksStoreType.jceks ? jceksMagic : jksMagic);
    w.writeUint32(2);
    w.writeUint32(store.entries.length);

    for (final JksEntry e in store.entries) {
      switch (e.type) {
        case JksEntryType.privateKey:
          final Uint8List? protectedKey = e.protectedKey;
          if (protectedKey == null) {
            throw StateError('Private key entry ${e.alias} has no protectedKey.');
          }
          w.writeUint32(_tagPrivateKey);
          w.writeUtf(e.alias);
          w.writeInt64(e.date.toUtc().millisecondsSinceEpoch);
          w.writeBlob(protectedKey);
          w.writeUint32(e.chain.length);
          for (final JksEncodedCertificate c in e.chain) {
            w.writeUtf(c.type);
            w.writeBlob(c.encoded);
          }
          break;
        case JksEntryType.trustedCertificate:
          final JksEncodedCertificate? cert = e.certificate;
          if (cert == null) {
            throw StateError('Trusted certificate entry ${e.alias} has no certificate.');
          }
          w.writeUint32(_tagTrustedCert);
          w.writeUtf(e.alias);
          w.writeInt64(e.date.toUtc().millisecondsSinceEpoch);
          w.writeUtf(cert.type);
          w.writeBlob(cert.encoded);
          break;
      }
    }

    final Uint8List body = w.toBytes();
    return (BytesBuilder(copy: false)
          ..add(body)
          ..add(_storeDigest(password, body)))
        .toBytes();
  }

  /// `JavaKeyStore.getPreKeyedHash`, fed with the store body.
  static Uint8List _storeDigest(String password, Uint8List body) {
    final Digest sha1 = Digest('SHA-1');
    final Uint8List passwordBytes = _utf16Be(password);
    sha1.update(passwordBytes, 0, passwordBytes.length);
    final Uint8List whitener = ascii.encode('Mighty Aphrodite');
    sha1.update(whitener, 0, whitener.length);
    sha1.update(body, 0, body.length);
    final Uint8List out = Uint8List(_digestSize);
    sha1.doFinal(out, 0);
    return out;
  }
}

/// Private key protection of JKS (`sun.security.provider.KeyProtector`) and
/// JCEKS (`com.sun.crypto.provider.KeyProtector`, PBEWithMD5AndTripleDES).
/// Both wrap the key in an EncryptedPrivateKeyInfo; the OID tells them apart.
class JksKeyProtector {
  const JksKeyProtector._();

  static const String jksOid = '1.3.6.1.4.1.42.2.17.1.1';
  static const String jceksOid = '1.3.6.1.4.1.42.2.19.1';

  static const List<int> _jksOidBytes = <int>[
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02, 0x11, 0x01, 0x01, //
  ];
  static const List<int> _jceksOidBytes = <int>[
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02, 0x13, 0x01, //
  ];
  static const int _jceksIterations = 200000; // JceKeyStore default

  /// Returns the PKCS#8 PrivateKeyInfo inside [protectedKey].
  static Uint8List recover(Uint8List protectedKey, String password) {
    final _Der top = _Der.parse(protectedKey).single(0x30);
    final List<_Der> parts = top.children();
    if (parts.length != 2) {
      throw StateError('Invalid EncryptedPrivateKeyInfo.');
    }
    final List<_Der> algorithm = parts[0].expect(0x30).children();
    final String oid = algorithm[0].expect(0x06).oid;
    final Uint8List encrypted = parts[1].expect(0x04).value;

    if (oid == jksOid) {
      return _jksRecover(encrypted, password);
    }
    if (oid == jceksOid) {
      final List<_Der> params = algorithm[1].expect(0x30).children();
      return _jceksCrypt(
        false,
        encrypted,
        password,
        params[0].expect(0x04).value,
        params[1].expect(0x02).intValue,
      );
    }
    throw StateError('Unsupported key protection algorithm: $oid');
  }

  /// Protects a PKCS#8 PrivateKeyInfo the way the given store type does.
  static Uint8List protect(
    Uint8List pkcs8,
    String password, {
    JksStoreType type = JksStoreType.jks,
  }) {
    final Random random = Random.secure();
    if (type == JksStoreType.jks) {
      final Uint8List salt = _randomBytes(random, 20);
      final Uint8List passwordBytes = _utf16Be(password);
      final Uint8List protectedKey = (BytesBuilder(copy: false)
            ..add(salt)
            ..add(_jksXor(pkcs8, passwordBytes, salt))
            ..add(_sha1(<Uint8List>[passwordBytes, pkcs8])))
          .toBytes();
      return _derSequence(<Uint8List>[
        _derSequence(<Uint8List>[
          _derTlv(0x06, Uint8List.fromList(_jksOidBytes)),
          _derTlv(0x05, Uint8List(0)),
        ]),
        _derTlv(0x04, protectedKey),
      ]);
    }

    // Equal salt halves get special treatment in the JDK key derivation;
    // drawing again keeps this writer out of that corner.
    Uint8List salt;
    do {
      salt = _randomBytes(random, 8);
    } while (_constantTimeEquals(salt.sublist(0, 4), salt.sublist(4)));
    final Uint8List encrypted =
        _jceksCrypt(true, pkcs8, password, salt, _jceksIterations);
    return _derSequence(<Uint8List>[
      _derSequence(<Uint8List>[
        _derTlv(0x06, Uint8List.fromList(_jceksOidBytes)),
        _derSequence(<Uint8List>[
          _derTlv(0x04, salt),
          _derTlv(0x02, _unsignedInteger(_jceksIterations)),
        ]),
      ]),
      _derTlv(0x04, encrypted),
    ]);
  }

  /// `salt[20] · key XOR keystream · SHA-1(UTF-16BE(password) · key)`.
  static Uint8List _jksRecover(Uint8List blob, String password) {
    if (blob.length < 40) {
      throw StateError('Invalid JKS protected key length.');
    }
    final Uint8List passwordBytes = _utf16Be(password);
    final Uint8List salt = blob.sublist(0, 20);
    final Uint8List key =
        _jksXor(blob.sublist(20, blob.length - 20), passwordBytes, salt);
    final Uint8List stored = blob.sublist(blob.length - 20);
    if (!_constantTimeEquals(_sha1(<Uint8List>[passwordBytes, key]), stored)) {
      throw StateError('Wrong key password or corrupted private key.');
    }
    return key;
  }

  /// Keystream `d0 = salt`, `d(i) = SHA-1(UTF-16BE(password) · d(i-1))`.
  static Uint8List _jksXor(
      Uint8List input, Uint8List passwordBytes, Uint8List salt) {
    Uint8List digest = salt;
    final Uint8List out = Uint8List(input.length);
    for (int offset = 0; offset < input.length; offset += 20) {
      digest = _sha1(<Uint8List>[passwordBytes, digest]);
      final int n = min(20, input.length - offset);
      for (int i = 0; i < n; i++) {
        out[offset + i] = input[offset + i] ^ digest[i];
      }
    }
    return out;
  }

  /// PBEWithMD5AndTripleDES (`PBES1Core`): each salt half is hashed with the
  /// ASCII password, `iterations` MD5 rounds; 24 bytes of key and 8 of IV.
  static Uint8List _jceksCrypt(bool encrypt, Uint8List input, String password,
      Uint8List salt, int iterations) {
    if (salt.length != 8) {
      throw StateError('JCEKS salt must be 8 bytes, got ${salt.length}.');
    }
    final Uint8List passwordBytes = Uint8List.fromList(password.codeUnits);
    final Uint8List derived = Uint8List(32);
    for (int half = 0; half < 2; half++) {
      Uint8List block = salt.sublist(half * 4, half * 4 + 4);
      for (int i = 0; i < iterations; i++) {
        block = _md5(<Uint8List>[block, passwordBytes]);
      }
      derived.setRange(half * 16, half * 16 + 16, block);
    }
    final PaddedBlockCipher cipher =
        PaddedBlockCipherImpl(PKCS7Padding(), CBCBlockCipher(DESedeEngine()))
          ..init(
            encrypt,
            PaddedBlockCipherParameters<CipherParameters, CipherParameters?>(
              ParametersWithIV<KeyParameter>(
                KeyParameter(derived.sublist(0, 24)),
                derived.sublist(24, 32),
              ),
              null,
            ),
          );
    return cipher.process(input);
  }

  static Uint8List _randomBytes(Random random, int length) =>
      Uint8List.fromList(List<int>.generate(length, (_) => random.nextInt(256)));
}

Uint8List _sha1(List<Uint8List> parts) => _hash(Digest('SHA-1'), parts);

Uint8List _md5(List<Uint8List> parts) => _hash(Digest('MD5'), parts);

Uint8List _hash(Digest digest, List<Uint8List> parts) {
  for (final Uint8List p in parts) {
    digest.update(p, 0, p.length);
  }
  final Uint8List out = Uint8List(digest.digestSize);
  digest.doFinal(out, 0);
  return out;
}

Uint8List _utf16Be(String s) {
  final Uint8List out = Uint8List(s.length * 2);
  for (int i = 0; i < s.length; i++) {
    final int c = s.codeUnitAt(i);
    out[i * 2] = c >> 8;
    out[i * 2 + 1] = c & 0xFF;
  }
  return out;
}

bool _constantTimeEquals(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  int diff = 0;
  for (int i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

Uint8List _unsignedInteger(int value) {
  final List<int> bytes = <int>[];
  for (int v = value; v > 0; v >>= 8) {
    bytes.insert(0, v & 0xFF);
  }
  if (bytes.isEmpty || bytes.first & 0x80 != 0) bytes.insert(0, 0);
  return Uint8List.fromList(bytes);
}

Uint8List _derTlv(int tag, Uint8List value) {
  final BytesBuilder b = BytesBuilder(copy: false)..addByte(tag);
  final int length = value.length;
  if (length < 0x80) {
    b.addByte(length);
  } else {
    final List<int> octets = <int>[];
    for (int v = length; v > 0; v >>= 8) {
      octets.insert(0, v & 0xFF);
    }
    b
      ..addByte(0x80 | octets.length)
      ..add(octets);
  }
  b.add(value);
  return b.toBytes();
}

Uint8List _derSequence(List<Uint8List> items) {
  final BytesBuilder b = BytesBuilder(copy: false);
  for (final Uint8List item in items) {
    b.add(item);
  }
  return _derTlv(0x30, b.toBytes());
}

/// Minimal DER reader for the EncryptedPrivateKeyInfo structures above.
class _Der {
  _Der(this.tag, this.value);

  final int tag;
  final Uint8List value;

  static List<_Der> _parseAll(Uint8List bytes) {
    final List<_Der> out = <_Der>[];
    int p = 0;
    while (p < bytes.length) {
      if (p + 2 > bytes.length) throw StateError('Truncated DER.');
      final int tag = bytes[p++];
      int length = bytes[p++];
      if (length & 0x80 != 0) {
        final int n = length & 0x7F;
        if (n == 0 || n > 4 || p + n > bytes.length) {
          throw StateError('Invalid DER length.');
        }
        length = 0;
        for (int i = 0; i < n; i++) {
          length = (length << 8) | bytes[p++];
        }
      }
      if (p + length > bytes.length) throw StateError('Truncated DER.');
      out.add(_Der(tag, Uint8List.sublistView(bytes, p, p + length)));
      p += length;
    }
    return out;
  }

  static _ParsedDer parse(Uint8List bytes) => _ParsedDer(_parseAll(bytes));

  List<_Der> children() => _parseAll(value);

  _Der expect(int expectedTag) {
    if (tag != expectedTag) {
      throw StateError('DER: expected tag 0x${expectedTag.toRadixString(16)}, '
          'got 0x${tag.toRadixString(16)}.');
    }
    return this;
  }

  int get intValue {
    int n = 0;
    for (final int b in value) {
      n = (n << 8) | b;
    }
    return n;
  }

  String get oid {
    final List<int> parts = <int>[value[0] ~/ 40, value[0] % 40];
    int v = 0;
    for (int i = 1; i < value.length; i++) {
      v = (v << 7) | (value[i] & 0x7F);
      if (value[i] & 0x80 == 0) {
        parts.add(v);
        v = 0;
      }
    }
    return parts.join('.');
  }
}

class _ParsedDer {
  _ParsedDer(this._items);

  final List<_Der> _items;

  _Der single(int tag) {
    if (_items.length != 1) throw StateError('DER: expected one element.');
    return _items.single.expect(tag);
  }
}

class _Reader {
  _Reader(this._data) : _bd = ByteData.sublistView(_data);

  final Uint8List _data;
  final ByteData _bd;
  int offset = 0;

  void _ensure(int n) {
    if (n < 0 || offset + n > _data.length) {
      throw StateError('Unexpected end of JKS data.');
    }
  }

  int readUint32() {
    _ensure(4);
    final int v = _bd.getUint32(offset);
    offset += 4;
    return v;
  }

  int readInt64() {
    _ensure(8);
    final int v = keystoreReadInt64(_bd, offset);
    offset += 8;
    return v;
  }

  Uint8List readBytes(int length) {
    _ensure(length);
    final Uint8List b =
        Uint8List.fromList(Uint8List.sublistView(_data, offset, offset + length));
    offset += length;
    return b;
  }

  Uint8List readBlob() => readBytes(readUint32());

  String readUtf() {
    _ensure(2);
    final int length = _bd.getUint16(offset);
    offset += 2;
    return JavaModifiedUtf8.decode(readBytes(length));
  }
}

class _Writer {
  final BytesBuilder _b = BytesBuilder(copy: false);

  Uint8List toBytes() => _b.toBytes();

  void writeUint32(int v) {
    final ByteData bd = ByteData(4)..setUint32(0, v);
    _b.add(bd.buffer.asUint8List());
  }

  void writeInt64(int v) {
    final ByteData bd = ByteData(8);
    keystoreWriteInt64(bd, 0, v);
    _b.add(bd.buffer.asUint8List());
  }

  void writeBlob(Uint8List bytes) {
    writeUint32(bytes.length);
    _b.add(bytes);
  }

  void writeUtf(String s) {
    final Uint8List encoded = JavaModifiedUtf8.encode(s);
    if (encoded.length > 0xFFFF) {
      throw StateError('String too long for modified UTF-8: ${encoded.length} bytes');
    }
    final ByteData bd = ByteData(2)..setUint16(0, encoded.length);
    _b
      ..add(bd.buffer.asUint8List())
      ..add(encoded);
  }
}
