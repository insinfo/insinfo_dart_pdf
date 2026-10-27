@TestOn('vm')
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/kms/revocation_data_client.dart';
import 'package:dart_pdf/src/pki/pki_builder.dart';
import 'package:test/test.dart';

/// CRL downloads during online revocation checking.
///
/// A validation runs the same checks for each trust profile, and an
/// ICP-Brasil CRL mirror took 7 s to answer: a two-signature PDF spent 21 s on
/// revocation before 1.0.7. Mirrors are now tried until the first readable
/// CRL, the result is cached until its nextUpdate, and every request has a
/// timeout.
void main() {
  late HttpServer server;
  late Uint8List crl;
  final Map<String, int> hits = <String, int>{};
  late Completer<void> releaseSilent;

  setUpAll(() async {
    final caKey = PkiUtils.generateRsaKeyPair(bitStrength: 1024);
    final now = DateTime.now().toUtc();
    crl = PkiBuilder.createCRL(
      issuerKeyPair: caKey,
      issuerDn: 'CN=Cache CA',
      revokedCertificates: const <RevokedCertificate>[],
      thisUpdate: now.subtract(const Duration(hours: 1)),
      nextUpdate: now.add(const Duration(days: 1)),
      crlNumber: 1,
    );
    releaseSilent = Completer<void>();
    server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) async {
      final path = request.uri.path;
      hits[path] = (hits[path] ?? 0) + 1;
      if (path == '/silent.crl') {
        // Never answers within the timeout.
        await releaseSilent.future;
      }
      request.response.add(crl);
      await request.response.close();
    });
  });

  tearDownAll(() async {
    if (!releaseSilent.isCompleted) releaseSilent.complete();
    await server.close(force: true);
  });

  setUp(() {
    hits.clear();
    RevocationDataClient.clearCache();
  });

  X509Certificate certWithCrls(List<String> paths) {
    final caKey = PkiUtils.generateRsaKeyPair(bitStrength: 1024);
    final userKey = PkiUtils.generateRsaKeyPair(bitStrength: 1024);
    final der = PkiBuilder.createUserCertificate(
      keyPair: userKey,
      issuerKeyPair: caKey,
      subjectDn: 'CN=Cache User',
      issuerDn: 'CN=Cache CA',
      serialNumber: 5,
      crlUrls: <String>[
        for (final path in paths) 'http://127.0.0.1:${server.port}$path',
      ],
    );
    return X509Utils.parsePemCertificate(X509Utils.derToPem(der));
  }

  test('the first readable mirror is enough', () async {
    final cert = certWithCrls(<String>['/a.crl', '/b.crl']);
    final crls = await RevocationDataClient.fetchCrls(cert);
    expect(crls, hasLength(1));
    expect(hits, <String, int>{'/a.crl': 1},
        reason: 'mirrors serve the same list; the second is not needed');
  });

  test('a second check reuses the cached CRL', () async {
    final cert = certWithCrls(<String>['/a.crl']);
    await RevocationDataClient.fetchCrls(cert);
    await RevocationDataClient.fetchCrls(cert);
    expect(hits['/a.crl'], 1);
  });

  test('a silent mirror is abandoned at the timeout', () async {
    final previous = RevocationDataClient.crlTimeout;
    RevocationDataClient.crlTimeout = const Duration(milliseconds: 300);
    try {
      final cert = certWithCrls(<String>['/silent.crl', '/b.crl']);
      final sw = Stopwatch()..start();
      final crls = await RevocationDataClient.fetchCrls(cert);
      expect(crls, hasLength(1), reason: 'the next mirror answers');
      expect(sw.elapsed, lessThan(const Duration(seconds: 5)));
      expect(hits['/b.crl'], 1);
    } finally {
      RevocationDataClient.crlTimeout = previous;
    }
  });
}
