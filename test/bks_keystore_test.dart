import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/src/security/keystore/bks_reader.dart';
import 'package:test/test.dart';

void main() {
  test('Decode ICP-Brasil BKS truststore (strict MAC)', () {
    final Uint8List bytes = File(
      'assets/truststore/icp_brasil/cadeiasicpbrasil.bks',
    ).readAsBytesSync();

    final BksStore store = BksCodec.decode(
      bytes,
      password: 'serprosigner',
      strictMac: true,
    );

    expect(store.version, 2);
    expect(store.salt.length, greaterThan(0));
    expect(store.iterationCount, greaterThan(0));
    expect(store.entries, isNotEmpty);
    expect(store.certificateEntries, isNotEmpty);

    final certs = store.allCertificatesDer();
    expect(certs, isNotEmpty);
    expect(certs.first, isNotEmpty);
  });

  test('Roundtrip encode/decode preserves certificate entries', () {
    final Uint8List bytes = File(
      'assets/truststore/icp_brasil/cadeiasicpbrasil.bks',
    ).readAsBytesSync();

    final BksStore store = BksCodec.decode(
      bytes,
      password: 'serprosigner',
      strictMac: true,
    );

    final Uint8List encoded = BksCodec.encode(store, password: 'serprosigner');
    final BksStore decoded = BksCodec.decode(
      encoded,
      password: 'serprosigner',
      strictMac: true,
    );

    expect(decoded.entries.length, store.entries.length);

    final orig = store.certificateEntries
        .map((e) => '${e.alias}:${e.certificate?.encoded.length ?? 0}')
        .toList();
    final rt = decoded.certificateEntries
        .map((e) => '${e.alias}:${e.certificate?.encoded.length ?? 0}')
        .toList();

    expect(rt, orig);
  });
}
