import 'dart:io';

import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/kms/revocation_data_client.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/x509/ocsp.dart';
import 'package:test/test.dart';

/// Revocation data for a real ICP-Brasil e-CPF (AC OAB G4, the signer of memo
/// 507/2026), captured from Certisign on 27/10/2026:
///
/// - `ac_oab_g4_ocsp_good.der`: the OCSP response, status good, produced at
///   21:36:55 UTC, valid until 22:06:55 UTC;
/// - `ac_oab_g4_signer.cer` and `ac_oab_g4.cer`: the signer and its CA.
///
/// The memo was signed at 17:03 UTC, before the response window.
X509Certificate _cert(String name) => X509Utils.parsePemCertificate(
    X509Utils.derToPem(File('test/assets/ocsp/$name').readAsBytesSync()));

void main() {
  final signer = _cert('ac_oab_g4_signer.cer');
  final ca = _cert('ac_oab_g4.cer');
  final response = File('test/assets/ocsp/ac_oab_g4_ocsp_good.der')
      .readAsBytesSync();
  final signedAt = DateTime.utc(2026, 10, 27, 17, 3, 5);
  final insideWindow = DateTime.utc(2026, 10, 27, 21, 40);

  group('OCSP parseValidated', () {
    test('accepts a full OCSPResponse, not only its inner basic response',
        () {
      // Before 1.0.6 the whole OCSPResponse went to the BasicOCSPResponse
      // parser and every responder answer came back null in strict mode.
      final parsed = OcspResponse.parseValidated(
        response,
        cert: signer,
        issuer: ca,
        validationTime: insideWindow,
      );
      expect(parsed, isNotNull);
      expect(parsed!.status, OcspCertificateStatus.good);
      expect(parsed.signatureValid, isTrue);
    });

    test('a response produced after signing is unknown at signing time',
        () {
      final parsed = OcspResponse.parseValidated(
        response,
        cert: signer,
        issuer: ca,
        validationTime: signedAt,
      );
      expect(parsed!.status, OcspCertificateStatus.unknown);
      expect(parsed.details, contains('outside validity window'));
    });

    test('alsoValidAt accepts a fresh response for an older signature', () {
      final parsed = OcspResponse.parseValidated(
        response,
        cert: signer,
        issuer: ca,
        validationTime: signedAt,
        alsoValidAt: insideWindow,
      );
      expect(parsed!.status, OcspCertificateStatus.good);
      expect(parsed.signatureValid, isTrue);
    });
  });

  test('CRL distribution points of an ICP-Brasil e-CPF are found', () {
    // The previous parser returned nothing for this certificate, so no CRL
    // was downloaded.
    expect(RevocationDataClient.getCrlDistributionPoints(signer), <String>[
      'http://icp-brasil.certisign.com.br/repositorio/lcr/ACOABG4/LatestCRL.crl',
      'http://icp-brasil.outralcr.com.br/repositorio/lcr/ACOABG4/LatestCRL.crl',
    ]);
  });
}
