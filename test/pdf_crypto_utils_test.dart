import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart' as pdf;
import 'package:test/test.dart';

void main() {
  test('PdfCryptoUtils parses RSA private key + certificate from PEM', () {
    if (!_hasOpenSsl()) return;

    final Directory testDir = Directory.systemTemp.createTempSync('pem_parse_');
    try {
      _runCmdSync('openssl', <String>[
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-keyout',
        '${testDir.path}/user_key.pem',
        '-out',
        '${testDir.path}/user_cert.pem',
        '-days',
        '365',
        '-nodes',
        '-subj',
        '/CN=Jane Doe',
      ]);

      final String privateKeyPem =
          File('${testDir.path}/user_key.pem').readAsStringSync();
      final String certificatePem =
          File('${testDir.path}/user_cert.pem').readAsStringSync();

      final pdf.RsaPrivateKeyParam key =
          pdf.PdfCryptoUtils.rsaPrivateKeyFromPem(privateKeyPem);
      final Uint8List certDer =
          pdf.PdfCryptoUtils.certificateDerFromPem(certificatePem);

      expect(key.modulus, isNotNull);
      expect(key.exponent, isNotNull);
      expect(certDer, isNotEmpty);
    } finally {
      if (testDir.existsSync()) {
        testDir.deleteSync(recursive: true);
      }
    }
  });
}

bool _hasOpenSsl() {
  try {
    final ProcessResult result =
        Process.runSync('openssl', <String>['version']);
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}

void _runCmdSync(String exe, List<String> args) {
  final ProcessResult result = Process.runSync(exe, args);
  if (result.exitCode != 0) {
    throw StateError(
      'Command failed: $exe ${args.join(' ')}\n'
      'stdout: ${result.stdout}\n'
      'stderr: ${result.stderr}',
    );
  }
}
