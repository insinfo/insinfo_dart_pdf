import 'dart:typed_data';

import 'package:dart_pdf/src/security/keystore/bks_reader.dart';
import 'package:dart_pdf/src/security/keystore/jks_codec.dart';
import 'package:test/test.dart';

import 'keystore_fixtures.dart';

/// JKS, JCEKS and BKS without `dart:io`, so they also run in the browser:
///
///   dart test -p vm,chrome test/keystore_browser_test.dart
///
/// What breaks in JavaScript and not on the VM: 64-bit integers (entry dates,
/// `ByteData.getInt64`/`setInt64` throw, `>> 32` truncates) and the crypto
/// (SHA-1, MD5, 3DES, PKCS#12 KDF) as compiled by dart2js.
const String _jksPassword = 'senha-loja';
const String _bksPassword = 'fredfred';

/// A date whose upper 32 bits are in use, which a truncating `>> 32` loses.
final DateTime _date2026 = DateTime.fromMillisecondsSinceEpoch(1793000000000,
    isUtc: true);

void main() {
  for (final (type, store, key) in <(JksStoreType, Uint8List, Uint8List)>[
    (JksStoreType.jks, fixtureJks, chaveJksPkcs8),
    (JksStoreType.jceks, fixtureJceks, chaveJceksPkcs8),
  ]) {
    group('JKS in the browser - keytool ${type.name}', () {
      test('decodes, checks the digest and recovers the key', () {
        final decoded = JksCodec.decode(store, password: _jksPassword);
        expect(decoded.type, type);
        final privateKey = decoded.entries
            .singleWhere((e) => e.type == JksEntryType.privateKey);
        expect(JksKeyProtector.recover(privateKey.protectedKey!, _jksPassword),
            key);
      });

      test('encode gives back the Java file byte for byte', () {
        final decoded = JksCodec.decode(store, password: _jksPassword);
        expect(decoded.toBytes(password: _jksPassword), store,
            reason: '64-bit entry dates must come back unchanged');
      });

      test('a key protected again opens with the new password', () {
        final reprotected = JksKeyProtector.protect(key, 'outra', type: type);
        expect(JksKeyProtector.recover(reprotected, 'outra'), key);
      });
    });
  }

  group('JKS in the browser - built from scratch', () {
    test('a 2026 date survives encode and decode', () {
      final store = JksStore.empty()
        ..upsertTrustedCertificate(
          alias: 'a',
          certificateDer: Uint8List.fromList(<int>[0x30, 0x00]),
          date: _date2026,
        );
      final decoded =
          JksCodec.decode(store.toBytes(password: 's'), password: 's');
      expect(decoded.entries.single.date, _date2026);
    });
  });

  group('BKS in the browser - Bouncy Castle samples', () {
    for (final (name, sample, version) in <(String, Uint8List, int)>[
      ('V1', bksV1BouncyCastle, 1),
      ('V2', bksV2BouncyCastle, 2),
    ]) {
      test('decodes the $name sample and checks its MAC', () {
        final store = BksCodec.decode(sample, password: _bksPassword);
        expect(store.version, version);
        expect(store.entries.single.alias, 'android');
        expect(store.entries.single.date.year, 2012);
      });
    }

    test('re-encoded V2 sample decodes with the same entries', () {
      final store = BksCodec.decode(bksV2BouncyCastle, password: _bksPassword);
      final again = BksCodec.decode(store.toBytes(password: _bksPassword),
          password: _bksPassword);
      expect(again.entries.single.sealedData, store.entries.single.sealedData);
      expect(again.entries.single.date, store.entries.single.date);
    });

    test('a 2026 date survives encode and decode', () {
      final store = BksStore.empty()
        ..upsertTrustedCertificate(
          alias: 'a',
          certificateDer: Uint8List.fromList(<int>[0x30, 0x00]),
          date: _date2026,
        );
      final decoded =
          BksCodec.decode(store.toBytes(password: 's'), password: 's');
      expect(decoded.entries.single.date, _date2026);
    });
  });
}
