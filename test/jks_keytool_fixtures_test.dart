import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/src/security/keystore/jks_codec.dart';
import 'package:test/test.dart';

/// Stores written by Java 8 `keytool` (`test/assets/keystore`), password
/// `senha-loja` for store and key:
///
///   keytool -genkeypair -alias chave -keyalg RSA -keysize 2048
///           -dname "CN=Fixture pdf_plus" -storetype JKS|JCEKS ...
///   keytool -importcert -alias confiavel -file ICP-Brasilv12.crt ...
///
/// `chave_*.pk8.der` is each private key as PKCS#8, exported by Java
/// (`-importkeystore` to PKCS#12) and OpenSSL.
const String _password = 'senha-loja';
const String _dir = 'test/assets/keystore';

Uint8List _read(String name) => File('$_dir/$name').readAsBytesSync();

void main() {
  for (final (type, file, key) in <(JksStoreType, String, String)>[
    (JksStoreType.jks, 'fixture.jks', 'chave_jks.pk8.der'),
    (JksStoreType.jceks, 'fixture.jceks', 'chave_jceks.pk8.der'),
  ]) {
    group('JKS - keytool ${type.name}', () {
      test('decodes the private key and the trusted certificate', () {
        final store = JksCodec.decode(_read(file), password: _password);

        expect(store.type, type);
        expect(store.trustedCertificateEntries.single.alias, 'confiavel');
        final privateKey =
            store.entries.singleWhere((e) => e.type == JksEntryType.privateKey);
        expect(privateKey.chain.single.type, 'X.509');
        expect(JksKeyProtector.recover(privateKey.protectedKey!, _password),
            _read(key));
      });

      test('encode reproduces the Java file byte for byte', () {
        final original = _read(file);
        final store = JksCodec.decode(original, password: _password);
        expect(store.toBytes(password: _password), original);
      });

      test('a key protected again opens with the new password only', () {
        final store = JksCodec.decode(_read(file), password: _password);
        final privateKey =
            store.entries.singleWhere((e) => e.type == JksEntryType.privateKey);
        final pkcs8 = JksKeyProtector.recover(privateKey.protectedKey!, _password);

        final reprotected =
            JksKeyProtector.protect(pkcs8, 'outra', type: type);

        expect(() => JksKeyProtector.recover(reprotected, _password),
            throwsA(anything));
        expect(JksKeyProtector.recover(reprotected, 'outra'), _read(key));
      });
    });
  }

  group('JKS - integrity', () {
    test('rejects the wrong password', () {
      expect(() => JksCodec.decode(_read('fixture.jks'), password: 'x'),
          throwsStateError);
    });

    test('rejects a store whose digest was cut off', () {
      final bytes = _read('fixture.jks');
      expect(
        () => JksCodec.decode(
            Uint8List.sublistView(bytes, 0, bytes.length - 20),
            password: _password),
        throwsStateError,
      );
    });

    test('ITI keystore survives decode and encode unchanged', () {
      final original = File(
              'assets/truststore/keystore_icp_brasil/keystore_ICP_Brasil.jks')
          .readAsBytesSync();
      final store = JksCodec.decode(original, password: '12345678');
      expect(store.toBytes(password: '12345678'), original);
    });

    test('a store built from scratch decodes back', () {
      final store = JksStore.empty()
        ..upsertTrustedCertificate(
          alias: 'a',
          certificateDer: Uint8List.fromList(<int>[0x30, 0x00]),
          date: DateTime.utc(2026, 10, 27),
        );
      final decoded =
          JksCodec.decode(store.toBytes(password: 's'), password: 's');
      expect(decoded.entries.single.date, DateTime.utc(2026, 10, 27));
    });
  });
}
