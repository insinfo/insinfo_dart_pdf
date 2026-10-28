import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pki/pki_builder.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

/// Revocation of a signature whose PDF carries only the signer certificate.
///
/// The CRL must be verified with the issuing CA's key, and OCSP needs the
/// issuer too. Before 1.0.6 the revocation check looked for the issuer only
/// among the self-signed roots and the certificates inside the PDF, never among
/// the intermediate CAs the validator already knew — the ones the providers
/// supplied and the ones downloaded through AIA. ICP-Brasil e-CPF signatures
/// usually embed only the signer, so they always ended as "unknown", even with
/// a trusted chain and fetching enabled.
class _RawRsaSigner implements IPdfExternalSigner {
  _RawRsaSigner(this._key);

  final RSAPrivateKey _key;

  @override
  DigestAlgorithm get hashAlgorithm => DigestAlgorithm.sha256;

  @override
  Future<SignerResult?> sign(List<int> message) async => signSync(message);

  @override
  SignerResult? signSync(List<int> message) =>
      SignerResult(PkiBuilder.signData(Uint8List.fromList(message), _key));
}

class _DerRoots implements TrustedRootsProvider {
  _DerRoots(this._certs);

  final List<Uint8List> _certs;

  @override
  Future<List<Uint8List>> getTrustedRootsDer() async => _certs;
}

typedef _KeyPair = AsymmetricKeyPair<PublicKey, PrivateKey>;

void main() {
  late _KeyPair caKey;
  late Uint8List root;
  late Uint8List ca;
  late Uint8List signed;
  const int userSerial = 77;

  setUpAll(() async {
    final rootKey = PkiUtils.generateRsaKeyPair(bitStrength: 1024);
    caKey = PkiUtils.generateRsaKeyPair(bitStrength: 1024);
    final userKey = PkiUtils.generateRsaKeyPair(bitStrength: 1024);
    root = PkiBuilder.createRootCertificate(
        keyPair: rootKey, dn: 'CN=Revocation Root', validityYears: 2);
    ca = PkiBuilder.createIntermediateCertificate(
      keyPair: caKey,
      issuerKeyPair: rootKey,
      subjectDn: 'CN=Revocation CA',
      issuerDn: 'CN=Revocation Root',
      serialNumber: 2,
      validityYears: 2,
    );
    final user = PkiBuilder.createUserCertificate(
      keyPair: userKey,
      issuerKeyPair: caKey,
      subjectDn: 'CN=Revocation User',
      issuerDn: 'CN=Revocation CA',
      serialNumber: userSerial,
    );

    final document = PdfDocument();
    document.pages.add();
    final signature = PdfSignature(
      cryptographicStandard: CryptographicStandard.cms,
      digestAlgorithm: DigestAlgorithm.sha256,
    );
    document.form.fields.add(PdfSignatureField(
      document.pages[0],
      'Signature1',
      signature: signature,
      bounds: Rect.fromLTWH(0, 0, 200, 50),
    ));
    // Only the signer certificate goes into the PDF, as in most e-CPF files.
    signature.addExternalSigner(
        _RawRsaSigner(userKey.privateKey as RSAPrivateKey), <List<int>>[user]);
    signed = Uint8List.fromList(await document.save());
    document.dispose();
  });

  Uint8List crl(List<int> revokedSerials, {Duration? expiredFor}) {
    final now = DateTime.now().toUtc();
    final nextUpdate = expiredFor == null
        ? now.add(const Duration(days: 7))
        : now.subtract(expiredFor);
    return PkiBuilder.createCRL(
      issuerKeyPair: caKey,
      issuerDn: 'CN=Revocation CA',
      revokedCertificates: <RevokedCertificate>[
        for (final serial in revokedSerials)
          RevokedCertificate(
            serialNumber: BigInt.from(serial),
            revocationDate: now.subtract(const Duration(hours: 1)),
          ),
      ],
      thisUpdate: now.subtract(const Duration(days: 1)),
      nextUpdate: nextUpdate,
      crlNumber: 1,
    );
  }

  Future<PdfSignatureValidationItem> validate({
    required List<Uint8List> trusted,
    required Uint8List crlBytes,
  }) async {
    final report = await PdfSignatureValidator().validateAllSignatures(
      signed,
      trustedRootsProviders: <TrustedRootsProvider>[_DerRoots(trusted)],
      crlBytes: <Uint8List>[crlBytes],
      strictRevocation: true,
    );
    return report.signatures.single;
  }

  test('a CRL listing the signer marks it revoked', () async {
    final sig = await validate(
      trusted: <Uint8List>[root, ca],
      crlBytes: crl(<int>[userSerial]),
    );
    expect(sig.chainTrusted, isTrue);
    expect(sig.revocationStatus.isRevoked, isTrue);
    expect(sig.revocationStatus.status, 'revoked');
    expect(sig.revocationStatus.source, 'crl');
  });

  test('a CRL without the signer proves it not revoked', () async {
    final sig = await validate(
      trusted: <Uint8List>[root, ca],
      crlBytes: crl(<int>[]),
    );
    expect(sig.revocationStatus.status, 'good',
        reason: 'the CRL is verified with the CA found among intermediates');
    expect(sig.revocationStatus.source, 'crl');
  });

  test('without the issuing CA the CRL cannot be verified', () async {
    final sig = await validate(
      trusted: <Uint8List>[root],
      crlBytes: crl(<int>[userSerial]),
    );
    expect(sig.revocationStatus.status, 'unknown',
        reason: 'a CRL is never trusted without its issuer key');
    final gap = sig.revocationStatus.gaps
        .firstWhere((g) => g.subject.contains('Revocation User'));
    expect(gap.reason, PdfRevocationGapReason.issuerNotFound);
  });

  test('an expired CRL leaves the signer unknown and says why', () async {
    final sig = await validate(
      trusted: <Uint8List>[root, ca],
      crlBytes: crl(<int>[], expiredFor: const Duration(minutes: 10)),
    );
    expect(sig.revocationStatus.status, 'unknown');
    final gap = sig.revocationStatus.gaps
        .firstWhere((g) => g.subject.contains('Revocation User'));
    expect(gap.reason, PdfRevocationGapReason.crlExpired,
        reason: 'a mirror serving the previous list right after the reissue');
    expect(gap.crlIssuer, contains('Revocation CA'));
    expect(
        DateTime.now().toUtc().difference(gap.crlNextUpdate!).inMinutes, 10);
    expect(sig.revocationStatus.details, contains('crlExpired'));
  });

  test('a CRL inside the clock skew still counts', () async {
    final sig = await validate(
      trusted: <Uint8List>[root, ca],
      crlBytes: crl(<int>[], expiredFor: const Duration(minutes: 2)),
    );
    expect(
        sig.revocationStatus.gaps
            .where((g) => g.subject.contains('Revocation User')),
        isEmpty,
        reason: 'five minutes of tolerance for the clocks');
  });
}
