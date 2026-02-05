import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart' as pdf;
import 'package:test/test.dart';

void main() {
  final bool hasOpenSsl = _hasOpenSsl();
  final bool isCi = _isCiEnvironment();

  test(
    'govbr integration flow signs PDF with mock server',
    () async {
      if (!hasOpenSsl || isCi) {
        return;
      }

      final Directory tempDir =
          await Directory.systemTemp.createTemp('govbr_integration_');
      HttpServer? server;
      try {
        final _CertChain chain = await _generateCertificateChain(tempDir);

        final pdf.PdfDocument doc = pdf.PdfDocument();
        doc.pages.add().graphics.drawString(
              'Gov.br integration test',
              pdf.PdfStandardFont(pdf.PdfFontFamily.helvetica, 12),
            );
        final Uint8List inputBytes = Uint8List.fromList(await doc.save());
        doc.dispose();

      final pdf.PdfExternalSigningResult prepared =
          await pdf.PdfExternalSigning.preparePdf(
        inputBytes: inputBytes,
        pageNumber: 1,
        bounds: pdf.Rect.fromLTWH(100, 100, 200, 50),
        fieldName: 'GovBr_Signature',
      );

      final List<int> byteRange =
          pdf.PdfExternalSigning.extractByteRange(prepared.preparedPdfBytes);
        final Uint8List dataToSign =
            _extractDataByRange(prepared.preparedPdfBytes, byteRange);
        final String expectedHashBase64 =
            pdf.PdfExternalSigning.computeByteRangeHashBase64(
          prepared.preparedPdfBytes,
          byteRange,
        );

        server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        final Uri baseUri =
            Uri.parse('http://127.0.0.1:${server.port}/externo/v2/');

        server.listen((HttpRequest request) async {
          try {
            if (request.method == 'GET' &&
                request.uri.path.endsWith('/certificadoPublico')) {
              final String pem = await File(chain.leafCertPath).readAsString();
              request.response.statusCode = HttpStatus.ok;
              request.response.headers.contentType =
                  ContentType('text', 'plain');
              request.response.write(pem);
              await request.response.close();
              return;
            }

            if (request.method == 'POST' &&
                request.uri.path.endsWith('/assinarPKCS7')) {
              final String body = await utf8.decoder.bind(request).join();
              final Map<String, dynamic> jsonBody =
                  jsonDecode(body) as Map<String, dynamic>;
              final String hashBase64 =
                  (jsonBody['hashBase64'] ?? '').toString();
              if (hashBase64 != expectedHashBase64) {
                request.response.statusCode = HttpStatus.badRequest;
                request.response.write('invalid hash');
                await request.response.close();
                return;
              }

              final String dataPath =
                  '${tempDir.path}${Platform.pathSeparator}data.bin';
              await File(dataPath).writeAsBytes(dataToSign, flush: true);

              final String sigPath =
                  '${tempDir.path}${Platform.pathSeparator}sig.der';
              await _runCmd('openssl', [
                'cms',
                '-sign',
                '-binary',
                '-in',
                dataPath,
                '-signer',
                chain.leafCertPath,
                '-inkey',
                chain.leafKeyPath,
                '-certfile',
                chain.chainCertPath,
                '-outform',
                'DER',
                '-out',
                sigPath,
              ]);

              final Uint8List sigBytes = await File(sigPath).readAsBytes();
              request.response.statusCode = HttpStatus.ok;
              request.response.headers.contentType =
                  ContentType('application', 'octet-stream');
              request.response.add(sigBytes);
              await request.response.close();
              return;
            }

            request.response.statusCode = HttpStatus.notFound;
            await request.response.close();
          } catch (e) {
            request.response.statusCode = HttpStatus.internalServerError;
            request.response.write('error: $e');
            await request.response.close();
          }
        });

        final pdf.GovBrSignatureApi api = pdf.GovBrSignatureApi(
          baseUri: baseUri,
        );

        final String certPem =
            await api.getPublicCertificatePem('mock_access_token');
        expect(certPem.contains('BEGIN CERTIFICATE'), isTrue);

        final Uint8List pkcs7 = await api.signHashPkcs7(
          accessToken: 'mock_access_token',
          hashBase64: prepared.hashBase64,
        );
        expect(pkcs7.isNotEmpty, isTrue);

      final Uint8List signedPdf = pdf.PdfExternalSigning.embedSignature(
        preparedPdfBytes: prepared.preparedPdfBytes,
        pkcs7Bytes: pkcs7,
      );
      expect(signedPdf.length, equals(prepared.preparedPdfBytes.length));

        final String verifyDataPath =
            '${tempDir.path}${Platform.pathSeparator}verify_data.bin';
        await File(verifyDataPath).writeAsBytes(dataToSign, flush: true);
        final String verifySigPath =
            '${tempDir.path}${Platform.pathSeparator}verify_sig.der';
        await File(verifySigPath).writeAsBytes(pkcs7, flush: true);

      await _runCmd('openssl', [
        'cms',
        '-verify',
        '-binary',
        '-in',
        verifySigPath,
        '-inform',
        'DER',
        '-content',
        verifyDataPath,
        '-CAfile',
        chain.rootCertPath,
      ]);
    } finally {
      await server?.close(force: true);
      await tempDir.delete(recursive: true);
    }
  },
  timeout: const Timeout(Duration(minutes: 3)),
  skip: !hasOpenSsl
      ? 'openssl not available'
      : (isCi ? 'Skip in CI environment' : false),
  );

  test(
    'govbr integration flow signs PDF with 5-level chain',
    () async {
      if (!hasOpenSsl || isCi) {
        return;
      }

      final Directory tempDir =
          await Directory.systemTemp.createTemp('govbr_chain5_');
      HttpServer? server;
      try {
        final _CertChain chain = await _generateCertificateChainFiveLevels(
          tempDir,
        );

        final pdf.PdfDocument doc = pdf.PdfDocument();
        doc.pages.add().graphics.drawString(
              'Gov.br integration test (5-level chain)',
              pdf.PdfStandardFont(pdf.PdfFontFamily.helvetica, 12),
            );
        final Uint8List inputBytes = Uint8List.fromList(await doc.save());
        doc.dispose();

        final pdf.PdfExternalSigningResult prepared =
            await pdf.PdfExternalSigning.preparePdf(
          inputBytes: inputBytes,
          pageNumber: 1,
          bounds: pdf.Rect.fromLTWH(100, 100, 200, 50),
          fieldName: 'GovBr_Signature_5Levels',
        );

        final List<int> byteRange =
            pdf.PdfExternalSigning.extractByteRange(prepared.preparedPdfBytes);
        final Uint8List dataToSign =
            _extractDataByRange(prepared.preparedPdfBytes, byteRange);
        final String expectedHashBase64 =
            pdf.PdfExternalSigning.computeByteRangeHashBase64(
          prepared.preparedPdfBytes,
          byteRange,
        );

        server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        final Uri baseUri =
            Uri.parse('http://127.0.0.1:${server.port}/externo/v2/');

        server.listen((HttpRequest request) async {
          try {
            if (request.method == 'GET' &&
                request.uri.path.endsWith('/certificadoPublico')) {
              final String pem =
                  await File(chain.leafCertPath).readAsString();
              request.response.statusCode = HttpStatus.ok;
              request.response.headers.contentType =
                  ContentType('text', 'plain');
              request.response.write(pem);
              await request.response.close();
              return;
            }

            if (request.method == 'POST' &&
                request.uri.path.endsWith('/assinarPKCS7')) {
              final String body = await utf8.decoder.bind(request).join();
              final Map<String, dynamic> jsonBody =
                  jsonDecode(body) as Map<String, dynamic>;
              final String hashBase64 =
                  (jsonBody['hashBase64'] ?? '').toString();
              if (hashBase64 != expectedHashBase64) {
                request.response.statusCode = HttpStatus.badRequest;
                request.response.write('invalid hash');
                await request.response.close();
                return;
              }

              final String dataPath =
                  '${tempDir.path}${Platform.pathSeparator}data.bin';
              await File(dataPath).writeAsBytes(dataToSign, flush: true);

              final String sigPath =
                  '${tempDir.path}${Platform.pathSeparator}sig.der';
              await _runCmd('openssl', [
                'cms',
                '-sign',
                '-binary',
                '-in',
                dataPath,
                '-signer',
                chain.leafCertPath,
                '-inkey',
                chain.leafKeyPath,
                '-certfile',
                chain.chainCertPath,
                '-outform',
                'DER',
                '-out',
                sigPath,
              ]);

              final Uint8List sigBytes = await File(sigPath).readAsBytes();
              request.response.statusCode = HttpStatus.ok;
              request.response.headers.contentType =
                  ContentType('application', 'octet-stream');
              request.response.add(sigBytes);
              await request.response.close();
              return;
            }

            request.response.statusCode = HttpStatus.notFound;
            await request.response.close();
          } catch (e) {
            request.response.statusCode = HttpStatus.internalServerError;
            request.response.write('error: $e');
            await request.response.close();
          }
        });

        final pdf.GovBrSignatureApi api = pdf.GovBrSignatureApi(
          baseUri: baseUri,
        );

        final String certPem =
            await api.getPublicCertificatePem('mock_access_token');
        expect(certPem.contains('BEGIN CERTIFICATE'), isTrue);

        final Uint8List pkcs7 = await api.signHashPkcs7(
          accessToken: 'mock_access_token',
          hashBase64: prepared.hashBase64,
        );
        expect(pkcs7.isNotEmpty, isTrue);

        final Uint8List signedPdf = pdf.PdfExternalSigning.embedSignature(
          preparedPdfBytes: prepared.preparedPdfBytes,
          pkcs7Bytes: pkcs7,
        );
        expect(signedPdf.length, equals(prepared.preparedPdfBytes.length));

        final String verifyDataPath =
            '${tempDir.path}${Platform.pathSeparator}verify_data.bin';
        await File(verifyDataPath).writeAsBytes(dataToSign, flush: true);
        final String verifySigPath =
            '${tempDir.path}${Platform.pathSeparator}verify_sig.der';
        await File(verifySigPath).writeAsBytes(pkcs7, flush: true);

        await _runCmd('openssl', [
          'cms',
          '-verify',
          '-binary',
          '-in',
          verifySigPath,
          '-inform',
          'DER',
          '-content',
          verifyDataPath,
          '-CAfile',
          chain.rootCertPath,
        ]);
      } finally {
        await server?.close(force: true);
        await tempDir.delete(recursive: true);
      }
    },
    timeout: const Timeout(Duration(minutes: 3)),
    skip: !hasOpenSsl
        ? 'openssl not available'
        : (isCi ? 'Skip in CI environment' : false),
  );

  test(
    'internal parser flags resolve ByteRange and Contents',
    () async {
      final doc = pdf.PdfDocument();
      doc.pages.add().graphics.drawString(
            'Internal parser test',
            pdf.PdfStandardFont(pdf.PdfFontFamily.helvetica, 12),
          );
      final Uint8List inputBytes = Uint8List.fromList(await doc.save());
      doc.dispose();

      pdf.PdfExternalSigning.useInternalByteRangeParser = true;
      pdf.PdfExternalSigning.useInternalContentsParser = true;
      try {
        final prepared = await pdf.PdfExternalSigning.preparePdf(
          inputBytes: inputBytes,
          pageNumber: 1,
          bounds: pdf.Rect.fromLTWH(100, 100, 200, 50),
          fieldName: 'Internal_Signature',
        );

        final byteRange =
            pdf.PdfExternalSigning.extractByteRange(prepared.preparedPdfBytes);
        expect(byteRange.length, equals(4));

        final contents =
            pdf.PdfExternalSigning.findContentsRange(prepared.preparedPdfBytes);
        expect(contents.end, greaterThan(contents.start));
      } finally {
        pdf.PdfExternalSigning.useInternalByteRangeParser = false;
        pdf.PdfExternalSigning.useInternalContentsParser = false;
      }
    },
  );
}

bool _hasOpenSsl() {
  try {
    final ProcessResult result =
        Process.runSync('openssl', const ['version']);
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}

bool _isCiEnvironment() {
  final String? ci = Platform.environment['CI'];
  if (ci != null && ci.toLowerCase() == 'true') return true;
  final String? gha = Platform.environment['GITHUB_ACTIONS'];
  return gha != null && gha.toLowerCase() == 'true';
}

Uint8List _extractDataByRange(Uint8List pdfBytes, List<int> byteRange) {
  if (byteRange.length != 4) {
    throw ArgumentError.value(byteRange, 'byteRange', 'Invalid length');
  }
  final int start1 = byteRange[0];
  final int len1 = byteRange[1];
  final int start2 = byteRange[2];
  final int len2 = byteRange[3];
  final BytesBuilder builder = BytesBuilder();
  builder.add(pdfBytes.sublist(start1, start1 + len1));
  builder.add(pdfBytes.sublist(start2, start2 + len2));
  return builder.takeBytes();
}

Future<void> _runCmd(String cmd, List<String> args) async {
  final ProcessResult result = await Process.run(cmd, args);
  if (result.exitCode != 0) {
    throw Exception(
      'Command failed: $cmd ${args.join(' ')}\n'
      'stdout: ${result.stdout}\n'
      'stderr: ${result.stderr}',
    );
  }
}

Future<_CertChain> _generateCertificateChain(Directory dir) async {
  final String rootKey = '${dir.path}${Platform.pathSeparator}root_key.pem';
  final String rootCert = '${dir.path}${Platform.pathSeparator}root_cert.pem';
  await _runCmd('openssl', [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    rootKey,
    '-out',
    rootCert,
    '-days',
    '3650',
    '-subj',
    '/CN=Test Root CA',
    '-addext',
    'basicConstraints=CA:TRUE',
    '-addext',
    'keyUsage=keyCertSign,cRLSign',
    '-addext',
    'subjectKeyIdentifier=hash',
  ]);

  final String intermediateKey =
      '${dir.path}${Platform.pathSeparator}intermediate_key.pem';
  final String intermediateCsr =
      '${dir.path}${Platform.pathSeparator}intermediate.csr';
  final String intermediateCert =
      '${dir.path}${Platform.pathSeparator}intermediate_cert.pem';
  await _runCmd('openssl', [
    'req',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    intermediateKey,
    '-out',
    intermediateCsr,
    '-subj',
    '/CN=Test Intermediate CA',
  ]);

  final String intermediateExt =
      '${dir.path}${Platform.pathSeparator}intermediate_ext.cnf';
  await File(intermediateExt).writeAsString('''
[v3_ca]
basicConstraints=CA:TRUE,pathlen:0
keyUsage=keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
''');
  await _runCmd('openssl', [
    'x509',
    '-req',
    '-in',
    intermediateCsr,
    '-CA',
    rootCert,
    '-CAkey',
    rootKey,
    '-CAcreateserial',
    '-out',
    intermediateCert,
    '-days',
    '3650',
    '-sha256',
    '-extfile',
    intermediateExt,
    '-extensions',
    'v3_ca',
  ]);

  final String leafKey = '${dir.path}${Platform.pathSeparator}leaf_key.pem';
  final String leafCsr = '${dir.path}${Platform.pathSeparator}leaf.csr';
  final String leafCert = '${dir.path}${Platform.pathSeparator}leaf_cert.pem';
  await _runCmd('openssl', [
    'req',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    leafKey,
    '-out',
    leafCsr,
    '-subj',
    '/CN=Test User',
  ]);

  final String leafExt =
      '${dir.path}${Platform.pathSeparator}leaf_ext.cnf';
  await File(leafExt).writeAsString('''
[usr_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,nonRepudiation
extendedKeyUsage=emailProtection
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
''');
  await _runCmd('openssl', [
    'x509',
    '-req',
    '-in',
    leafCsr,
    '-CA',
    intermediateCert,
    '-CAkey',
    intermediateKey,
    '-CAcreateserial',
    '-out',
    leafCert,
    '-days',
    '365',
    '-sha256',
    '-extfile',
    leafExt,
    '-extensions',
    'usr_cert',
  ]);

  final String chainCert = '${dir.path}${Platform.pathSeparator}chain.pem';
  final String chainContent = [
    await File(intermediateCert).readAsString(),
    await File(rootCert).readAsString(),
  ].join('\n');
  await File(chainCert).writeAsString(chainContent);

  return _CertChain(
    rootCertPath: rootCert,
    leafCertPath: leafCert,
    leafKeyPath: leafKey,
    chainCertPath: chainCert,
  );
}

Future<_CertChain> _generateCertificateChainFiveLevels(Directory dir) async {
  final String rootKey = '${dir.path}${Platform.pathSeparator}root_key.pem';
  final String rootCert = '${dir.path}${Platform.pathSeparator}root_cert.pem';
  await _runCmd('openssl', [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    rootKey,
    '-out',
    rootCert,
    '-days',
    '3650',
    '-subj',
    '/CN=Test Root CA (L1)',
    '-addext',
    'basicConstraints=CA:TRUE',
    '-addext',
    'keyUsage=keyCertSign,cRLSign',
    '-addext',
    'subjectKeyIdentifier=hash',
  ]);

  final _Intermediate issuer1 = await _createIntermediate(
    dir,
    name: 'Intermediate CA (L2)',
    issuerCert: rootCert,
    issuerKey: rootKey,
    pathLen: 3,
  );
  final _Intermediate issuer2 = await _createIntermediate(
    dir,
    name: 'Intermediate CA (L3)',
    issuerCert: issuer1.certPath,
    issuerKey: issuer1.keyPath,
    pathLen: 2,
  );
  final _Intermediate issuer3 = await _createIntermediate(
    dir,
    name: 'Intermediate CA (L4)',
    issuerCert: issuer2.certPath,
    issuerKey: issuer2.keyPath,
    pathLen: 1,
  );

  final String leafKey = '${dir.path}${Platform.pathSeparator}leaf_key.pem';
  final String leafCsr = '${dir.path}${Platform.pathSeparator}leaf.csr';
  final String leafCert = '${dir.path}${Platform.pathSeparator}leaf_cert.pem';
  await _runCmd('openssl', [
    'req',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    leafKey,
    '-out',
    leafCsr,
    '-subj',
    '/CN=Test User (L5)',
  ]);

  final String leafExt =
      '${dir.path}${Platform.pathSeparator}leaf_ext.cnf';
  await File(leafExt).writeAsString('''
[usr_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,nonRepudiation
extendedKeyUsage=emailProtection
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
''');
  await _runCmd('openssl', [
    'x509',
    '-req',
    '-in',
    leafCsr,
    '-CA',
    issuer3.certPath,
    '-CAkey',
    issuer3.keyPath,
    '-CAcreateserial',
    '-out',
    leafCert,
    '-days',
    '365',
    '-sha256',
    '-extfile',
    leafExt,
    '-extensions',
    'usr_cert',
  ]);

  final String chainCert = '${dir.path}${Platform.pathSeparator}chain.pem';
  final String chainContent = [
    await File(issuer3.certPath).readAsString(),
    await File(issuer2.certPath).readAsString(),
    await File(issuer1.certPath).readAsString(),
    await File(rootCert).readAsString(),
  ].join('\n');
  await File(chainCert).writeAsString(chainContent);

  return _CertChain(
    rootCertPath: rootCert,
    leafCertPath: leafCert,
    leafKeyPath: leafKey,
    chainCertPath: chainCert,
  );
}

class _Intermediate {
  _Intermediate({required this.keyPath, required this.certPath});

  final String keyPath;
  final String certPath;
}

Future<_Intermediate> _createIntermediate(
  Directory dir, {
  required String name,
  required String issuerCert,
  required String issuerKey,
  required int pathLen,
}) async {
  final String safeName = name.replaceAll(' ', '_');
  final String keyPath =
      '${dir.path}${Platform.pathSeparator}${safeName}_key.pem';
  final String csrPath =
      '${dir.path}${Platform.pathSeparator}${safeName}.csr';
  final String certPath =
      '${dir.path}${Platform.pathSeparator}${safeName}_cert.pem';

  await _runCmd('openssl', [
    'req',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    keyPath,
    '-out',
    csrPath,
    '-subj',
    '/CN=$name',
  ]);

  final String extPath =
      '${dir.path}${Platform.pathSeparator}${safeName}_ext.cnf';
  await File(extPath).writeAsString('''
[v3_ca]
basicConstraints=CA:TRUE,pathlen:$pathLen
keyUsage=keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
''');

  await _runCmd('openssl', [
    'x509',
    '-req',
    '-in',
    csrPath,
    '-CA',
    issuerCert,
    '-CAkey',
    issuerKey,
    '-CAcreateserial',
    '-out',
    certPath,
    '-days',
    '3650',
    '-sha256',
    '-extfile',
    extPath,
    '-extensions',
    'v3_ca',
  ]);

  return _Intermediate(keyPath: keyPath, certPath: certPath);
}

class _CertChain {
  _CertChain({
    required this.rootCertPath,
    required this.leafCertPath,
    required this.leafKeyPath,
    required this.chainCertPath,
  });

  final String rootCertPath;
  final String leafCertPath;
  final String leafKeyPath;
  final String chainCertPath;
}
