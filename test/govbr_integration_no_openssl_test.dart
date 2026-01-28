import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart' as pdf;
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

import 'package:dart_pdf/src/pki/pki_builder.dart';
import 'package:dart_pdf/src/pki/pki_pem_utils.dart';

void main() {
  test(
    'govbr integration flow signs PDF without OpenSSL',
    () async {
      final _ChainData chain = _generateFiveLevelChain();

      final pdf.PdfDocument doc = pdf.PdfDocument();
      doc.pages.add().graphics.drawString(
            'Gov.br integration test (no OpenSSL)',
            pdf.PdfStandardFont(pdf.PdfFontFamily.helvetica, 12),
          );
      final Uint8List inputBytes = Uint8List.fromList(await doc.save());
      doc.dispose();

      final pdf.PdfExternalSigningResult prepared =
          await pdf.PdfExternalSigning.preparePdf(
        inputBytes: inputBytes,
        pageNumber: 1,
        bounds: pdf.Rect.fromLTWH(100, 100, 200, 50),
        fieldName: 'GovBr_Signature_NoOpenSSL',
      );

      final String expectedHashBase64 = prepared.hashBase64;

      final String leafCertPem =
          PkiPemUtils.certificateDerToPem(chain.leafCert);
      final String rootCertPem =
          PkiPemUtils.certificateDerToPem(chain.rootCert);
      final List<String> chainPem = PkiPemUtils.certificateChainDerToPem(
        <Uint8List>[
          chain.intermediate3Cert,
          chain.intermediate2Cert,
          chain.intermediate1Cert,
          chain.rootCert,
        ],
      );

      final RSAPrivateKey leafPrivate =
          chain.leafKey.privateKey as RSAPrivateKey;
      final RSAPublicKey leafPublic =
          chain.leafKey.publicKey as RSAPublicKey;
      final String leafKeyPem = PkiPemUtils.rsaPrivateKeyToPem(
        leafPrivate,
        publicExponent: leafPublic.exponent,
      );

      final HttpServer server =
          await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final Uri baseUri =
          Uri.parse('http://127.0.0.1:${server.port}/externo/v2/');

      server.listen((HttpRequest request) async {
        try {
          if (request.method == 'GET' &&
              request.uri.path.endsWith('/certificadoPublico')) {
            request.response.statusCode = HttpStatus.ok;
            request.response.headers.contentType =
                ContentType('text', 'plain');
            request.response.write(leafCertPem);
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

            final Uint8List hashBytes =
                Uint8List.fromList(base64Decode(hashBase64));

            final Uint8List pkcs7 =
                pdf.PdfCmsSigner.signDetachedSha256RsaFromPem(
              contentDigest: hashBytes,
              privateKeyPem: leafKeyPem,
              certificatePem: leafCertPem,
              chainPem: chainPem,
            );

            request.response.statusCode = HttpStatus.ok;
            request.response.headers.contentType =
                ContentType('application', 'octet-stream');
            request.response.add(pkcs7);
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

      try {
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

        final pdf.PdfSignatureValidationReport report =
            await pdf.PdfSignatureValidator().validateAllSignatures(
          signedPdf,
          trustedRootsPem: [rootCertPem],
          fetchCrls: false,
          useEmbeddedIcpBrasil: false,
        );

        expect(report.signatures, isNotEmpty);
        final pdf.PdfSignatureValidationItem sig = report.signatures.first;
        expect(sig.validation.certsPem.length, greaterThanOrEqualTo(5));
        expect(sig.validation.cmsSignatureValid, isTrue);
        expect(sig.validation.byteRangeDigestOk, isTrue);
      } finally {
        await server.close(force: true);
      }
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );
}

class _ChainData {
  _ChainData({
    required this.rootKey,
    required this.rootCert,
    required this.intermediate1Key,
    required this.intermediate1Cert,
    required this.intermediate2Key,
    required this.intermediate2Cert,
    required this.intermediate3Key,
    required this.intermediate3Cert,
    required this.leafKey,
    required this.leafCert,
  });

  final AsymmetricKeyPair<PublicKey, PrivateKey> rootKey;
  final Uint8List rootCert;

  final AsymmetricKeyPair<PublicKey, PrivateKey> intermediate1Key;
  final Uint8List intermediate1Cert;

  final AsymmetricKeyPair<PublicKey, PrivateKey> intermediate2Key;
  final Uint8List intermediate2Cert;

  final AsymmetricKeyPair<PublicKey, PrivateKey> intermediate3Key;
  final Uint8List intermediate3Cert;

  final AsymmetricKeyPair<PublicKey, PrivateKey> leafKey;
  final Uint8List leafCert;
}

_ChainData _generateFiveLevelChain() {
  final AsymmetricKeyPair<PublicKey, PrivateKey> rootKey =
      PkiUtils.generateRsaKeyPair(bitStrength: 2048);
  final AsymmetricKeyPair<PublicKey, PrivateKey> inter1Key =
      PkiUtils.generateRsaKeyPair(bitStrength: 2048);
  final AsymmetricKeyPair<PublicKey, PrivateKey> inter2Key =
      PkiUtils.generateRsaKeyPair(bitStrength: 2048);
  final AsymmetricKeyPair<PublicKey, PrivateKey> inter3Key =
      PkiUtils.generateRsaKeyPair(bitStrength: 2048);
  final AsymmetricKeyPair<PublicKey, PrivateKey> leafKey =
      PkiUtils.generateRsaKeyPair(bitStrength: 2048);

  final Uint8List rootCert = PkiBuilder.createRootCertificate(
    keyPair: rootKey,
    dn: 'CN=Test Root CA,O=DartPDF',
  );

  final Uint8List inter1Cert = PkiBuilder.createIntermediateCertificate(
    keyPair: inter1Key,
    issuerKeyPair: rootKey,
    subjectDn: 'CN=Intermediate CA 1,O=DartPDF',
    issuerDn: 'CN=Test Root CA,O=DartPDF',
    serialNumber: 1001,
  );

  final Uint8List inter2Cert = PkiBuilder.createIntermediateCertificate(
    keyPair: inter2Key,
    issuerKeyPair: inter1Key,
    subjectDn: 'CN=Intermediate CA 2,O=DartPDF',
    issuerDn: 'CN=Intermediate CA 1,O=DartPDF',
    serialNumber: 1002,
  );

  final Uint8List inter3Cert = PkiBuilder.createIntermediateCertificate(
    keyPair: inter3Key,
    issuerKeyPair: inter2Key,
    subjectDn: 'CN=Intermediate CA 3,O=DartPDF',
    issuerDn: 'CN=Intermediate CA 2,O=DartPDF',
    serialNumber: 1003,
  );

  final Uint8List leafCert = PkiBuilder.createUserCertificate(
    keyPair: leafKey,
    issuerKeyPair: inter3Key,
    subjectDn: 'CN=Test User,O=DartPDF',
    issuerDn: 'CN=Intermediate CA 3,O=DartPDF',
    serialNumber: 2001,
  );

  return _ChainData(
    rootKey: rootKey,
    rootCert: rootCert,
    intermediate1Key: inter1Key,
    intermediate1Cert: inter1Cert,
    intermediate2Key: inter2Key,
    intermediate2Cert: inter2Cert,
    intermediate3Key: inter3Key,
    intermediate3Cert: inter3Cert,
    leafKey: leafKey,
    leafCert: leafCert,
  );
}
