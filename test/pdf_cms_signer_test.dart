import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:dart_pdf/pdf.dart' as pdf;
import 'package:test/test.dart';

void main() {
  group('PdfCmsSigner', () {
    test('signDetachedSha256RsaFromCertificate produces a valid CMS signature',
        () {
      if (!_hasOpenSsl()) return;

      final Directory testDir = Directory.systemTemp.createTempSync('cms_pem_');
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
          '/CN=John Doe',
          '-addext',
          'keyUsage=digitalSignature'
        ]);

        final String privateKeyPem =
            File('${testDir.path}/user_key.pem').readAsStringSync();
        final String certificatePem =
            File('${testDir.path}/user_cert.pem').readAsStringSync();

        final Uint8List content = Uint8List.fromList(
          utf8.encode('cms-detached-test-content'),
        );
        final Uint8List digest =
            Uint8List.fromList(sha256.convert(content).bytes);

        final Uint8List cmsDer = pdf.PdfCmsSigner.signDetachedSha256RsaFromPem(
          contentDigest: digest,
          privateKeyPem: privateKeyPem,
          certificatePem: certificatePem,
          chainPem: const <String>[],
        );

        expect(cmsDer, isNotEmpty);

        final pdf.PdfSignatureValidation validator =
            pdf.PdfSignatureValidation();
        final result = validator.validateCmsSignedData(cmsDer);
        expect(result.cmsSignatureValid, isTrue);
        expect(result.certsPem, isNotEmpty);
      } finally {
        if (testDir.existsSync()) {
          testDir.deleteSync(recursive: true);
        }
      }
    });

    test('signDetachedSha256EcdsaFromPem produces a valid CMS signature', () {
      if (!_hasOpenSsl()) return;

      final Directory testDir = Directory.systemTemp.createTempSync('cms_ec_');
      try {
        _runCmdSync('openssl', <String>[
          'ecparam',
          '-name',
          'prime256v1',
          '-genkey',
          '-noout',
          '-out',
          '${testDir.path}/ec_key.pem',
        ]);

        _runCmdSync('openssl', <String>[
          'req',
          '-x509',
          '-new',
          '-key',
          '${testDir.path}/ec_key.pem',
          '-out',
          '${testDir.path}/ec_cert.pem',
          '-days',
          '365',
          '-subj',
          '/CN=EC User',
          '-addext',
          'keyUsage=digitalSignature'
        ]);

        final String privateKeyPem =
            File('${testDir.path}/ec_key.pem').readAsStringSync();
        final String certificatePem =
            File('${testDir.path}/ec_cert.pem').readAsStringSync();

        final Uint8List content = Uint8List.fromList(
          utf8.encode('cms-detached-test-content-ec'),
        );
        final Uint8List digest =
            Uint8List.fromList(sha256.convert(content).bytes);

        final Uint8List cmsDer = pdf.PdfCmsSigner.signDetachedSha256EcdsaFromPem(
          contentDigest: digest,
          privateKeyPem: privateKeyPem,
          certificatePem: certificatePem,
          chainPem: const <String>[],
        );

        expect(cmsDer, isNotEmpty);

        final pdf.PdfSignatureValidation validator =
            pdf.PdfSignatureValidation();
        final result = validator.validateCmsSignedData(cmsDer);
        expect(result.cmsSignatureValid, isTrue);
        expect(result.certsPem, isNotEmpty);
      } finally {
        if (testDir.existsSync()) {
          testDir.deleteSync(recursive: true);
        }
      }
    });

    test('signDetachedSha256RsaFromPem supports ENCRYPTED PRIVATE KEY', () {
      if (!_hasOpenSsl()) return;

      final Directory testDir = Directory.systemTemp.createTempSync('cms_enc_');
      try {
        const String password = 'secret123';
        _runCmdSync('openssl', <String>[
          'genpkey',
          '-algorithm',
          'RSA',
          '-pkeyopt',
          'rsa_keygen_bits:2048',
          '-aes-256-cbc',
          '-pass',
          'pass:$password',
          '-out',
          '${testDir.path}/enc_key.pem',
        ]);

        _runCmdSync('openssl', <String>[
          'req',
          '-x509',
          '-new',
          '-key',
          '${testDir.path}/enc_key.pem',
          '-passin',
          'pass:$password',
          '-out',
          '${testDir.path}/enc_cert.pem',
          '-days',
          '365',
          '-subj',
          '/CN=Encrypted RSA User',
          '-addext',
          'keyUsage=digitalSignature'
        ]);

        final String privateKeyPem =
            File('${testDir.path}/enc_key.pem').readAsStringSync();
        final String certificatePem =
            File('${testDir.path}/enc_cert.pem').readAsStringSync();

        final Uint8List content = Uint8List.fromList(
          utf8.encode('cms-detached-test-content-enc'),
        );
        final Uint8List digest =
            Uint8List.fromList(sha256.convert(content).bytes);

        final Uint8List cmsDer = pdf.PdfCmsSigner.signDetachedSha256RsaFromPem(
          contentDigest: digest,
          privateKeyPem: privateKeyPem,
          privateKeyPassword: password,
          certificatePem: certificatePem,
          chainPem: const <String>[],
        );

        expect(cmsDer, isNotEmpty);

        final pdf.PdfSignatureValidation validator =
            pdf.PdfSignatureValidation();
        final result = validator.validateCmsSignedData(cmsDer);
        expect(result.cmsSignatureValid, isTrue);
        expect(result.certsPem, isNotEmpty);
      } finally {
        if (testDir.existsSync()) {
          testDir.deleteSync(recursive: true);
        }
      }
    });
  });

  group('PdfSignatureUtils.extractPkcs7FromOffsets', () {
    test('decodes hex string and trims null padding', () {
      const String pdfText =
          '%PDF-1.7\n1 0 obj\n<< /Contents <01 02 03 04 00 00> >>\nendobj\n';
      final List<int> bytes = ascii.encode(pdfText);

      final List<int> marker = ascii.encode('/Contents <');
      final int markerIndex = _indexOfBytes(bytes, marker);
      expect(markerIndex, isNonNegative);

      final int start = markerIndex + marker.length - 1; // '<'
      final int end = bytes.indexOf(62, start + 1) + 1; // after '>'
      expect(start, isNonNegative);
      expect(end, greaterThan(start));

      final pdf.PdfSignatureOffsets offsets = pdf.PdfSignatureOffsets(
        byteRange: const <int>[0, 0, 0, 0],
        byteRangeOffsets: const <int>[0, 0],
        contentsOffsets: <int>[start, end],
      );

      final Uint8List pkcs7 = pdf.PdfSignatureUtils.extractPkcs7FromOffsets(
        pdfBytes: bytes,
        offsets: offsets,
      );
      expect(pkcs7, Uint8List.fromList(<int>[1, 2, 3, 4]));
    });

    test('handles odd number of hex nibbles', () {
      const String pdfText =
          '%PDF-1.7\n1 0 obj\n<< /Contents <0A1> >>\nendobj\n';
      final List<int> bytes = ascii.encode(pdfText);

      final List<int> marker = ascii.encode('/Contents <');
      final int markerIndex = _indexOfBytes(bytes, marker);
      expect(markerIndex, isNonNegative);

      final int start = markerIndex + marker.length - 1; // '<'
      final int end = bytes.indexOf(62, start + 1) + 1; // after '>'

      final pdf.PdfSignatureOffsets offsets = pdf.PdfSignatureOffsets(
        byteRange: const <int>[0, 0, 0, 0],
        byteRangeOffsets: const <int>[0, 0],
        contentsOffsets: <int>[start, end],
      );

      final Uint8List pkcs7 = pdf.PdfSignatureUtils.extractPkcs7FromOffsets(
        pdfBytes: bytes,
        offsets: offsets,
      );

      // 0A 10 (ultimo nibble vira 0)
      expect(pkcs7, Uint8List.fromList(<int>[0x0A, 0x10]));
    });
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

int _indexOfBytes(List<int> haystack, List<int> needle) {
  if (needle.isEmpty) return 0;
  if (haystack.length < needle.length) return -1;
  for (int i = 0; i <= haystack.length - needle.length; i++) {
    bool ok = true;
    for (int j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) {
        ok = false;
        break;
      }
    }
    if (ok) return i;
  }
  return -1;
}
