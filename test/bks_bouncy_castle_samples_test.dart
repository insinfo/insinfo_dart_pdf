import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_pdf/src/security/keystore/bks_reader.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

/// `v1BKS` and `v2BKS` from Bouncy Castle's own
/// `prov/src/test/java/org/bouncycastle/jce/provider/test/KeyStoreTest.java`
/// (password `fredfred`, one sealed key under alias `android`).
const String _v1Bks = 'AAAAAQAAABTqZbNMyPjsFazhFplWWDMBLPRdRAAABcYEAAdhbmRyb2lkAAAB'
    'NOifkPwAAAAAAAAAPAAAABTZOLhcyhB0gKyfoDvyQbpzftB7GgAABEYPrZP8'
    'q20AJLETjDv0K9C5rIl1erpyvpv20bqcbghK6wD0b8OP5/XzOz/8knhxmqJZ'
    '3yRJMw==';
const String _v2Bks = 'AAAAAgAAABSkmTXz4VIznO1SSUqsIHdxWcxsuQAABFMEAAdhbmRyb2lkAAABN'
    'OifkPwAAAAAAAAAPAAAABTZOLhcyhB0gKyfoDvyQbpzftB7GgAABEYPrZP8q2'
    '0AJLETjDv0K9C5rIl1erpyvpv20bqcbghK6wBO59KOGPvSrmJpd32P6ZAh9qLZJw==';

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// Empty store (just the terminator) with salt 00..13 and 1024 iterations.
Uint8List _emptyStore(String password) => BksStore(
      version: 2,
      salt: Uint8List.fromList(List<int>.generate(20, (i) => i)),
      iterationCount: 1024,
      entries: <BksEntry>[],
    ).toBytes(password: password);

void main() {
  group('BKS - Bouncy Castle samples', () {
    test('decodes the V1 sample with a 2-byte MAC key', () {
      final store = BksCodec.decode(base64.decode(_v1Bks), password: 'fredfred');
      expect(store.version, 1);
      expect(store.entries.single.alias, 'android');
      expect(store.entries.single.type, BksEntryType.sealed);
    });

    test('decodes the V2 sample', () {
      final store = BksCodec.decode(base64.decode(_v2Bks), password: 'fredfred');
      expect(store.version, 2);
      expect(store.entries.single.alias, 'android');
    });

    test('rejects the V2 sample with the wrong password', () {
      expect(
        () => BksCodec.decode(base64.decode(_v2Bks), password: 'wrong'),
        throwsStateError,
      );
    });
  });

  group('BKS - MAC key derivation', () {
    // Reference MACs computed outside Dart with the PKCS#12 KDF and
    // PBEParametersGenerator.PKCS12PasswordToBytes rules of Bouncy Castle.
    test('non-empty password matches the reference', () {
      expect(_hex(_emptyStore('fredfred').sublist(33)),
          '2ed8e064ba096e2bc0c41c3332185ab233bf1217');
    });

    test('empty password uses no terminator, as Bouncy Castle does', () {
      expect(_hex(_emptyStore('').sublist(33)),
          '68b0a155eb2351c77f2568229c457282075a4071');
    });

    test('still reads stores written with the old 160-byte MAC key', () {
      final bytes = _emptyStore('p');
      final salt = bytes.sublist(8, 28);
      final generator = PKCS12ParametersGenerator(Digest('SHA-1'))
        ..init(Uint8List.fromList(<int>[0, 0x70, 0, 0]), salt, 1024);
      final hmac = HMac(Digest('SHA-1'), 64)
        ..init(generator.generateDerivedMacParameters(160));
      final legacy = Uint8List.fromList(bytes);
      legacy.setRange(33, 53, hmac.process(bytes.sublist(32, 33)));

      expect(BksCodec.decode(legacy, password: 'p').version, 2);
      expect(() => BksCodec.decode(legacy, password: 'q'), throwsStateError);
    });
  });

  group('BKS - KEY entries', () {
    test('keep keyType and format, in BcKeyStoreSpi.encodeKey order', () {
      final store = BksStore.empty()
        ..entries.add(BksEntry(
          type: BksEntryType.key,
          alias: 'k',
          date: DateTime.utc(2026),
          chain: <BksEncodedCertificate>[],
          keyType: 1,
          keyFormat: 'X.509',
          keyAlgorithm: 'RSA',
          keyData: Uint8List.fromList(<int>[9, 8, 7]),
        ));

      final bytes = store.toBytes(password: 'p');
      // After header (4 + 4 + 20 + 4): type, alias "k", date, chain length.
      const keyStart = 32 + 1 + 3 + 8 + 4;
      expect(bytes[keyStart], 1, reason: 'keyType comes first');
      expect(
        utf8.decode(bytes.sublist(keyStart + 3, keyStart + 3 + 5)),
        'X.509',
      );

      final entry = BksCodec.decode(bytes, password: 'p').entries.single;
      expect(entry.keyType, 1);
      expect(entry.keyFormat, 'X.509');
      expect(entry.keyAlgorithm, 'RSA');
      expect(entry.keyData, <int>[9, 8, 7]);
    });
  });
}
