import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pki/pki_builder.dart' show PkiBuilder;
import 'package:pointycastle/pointycastle.dart'
    show AsymmetricKeyPair, PublicKey, PrivateKey;
import 'package:test/test.dart';

/// An end-entity certificate must not act as a CA.
///
/// Before 1.0.5 `X509Utils.verifyChainPem` checked every signature in the
/// chain but not whether each issuer was a CA. Anyone holding an ordinary
/// ICP-Brasil e-CPF could sign a certificate in someone else's name with their
/// own key, and the chain "victim → e-CPF → CA → root" was reported trusted.
typedef _KeyPair = AsymmetricKeyPair<PublicKey, PrivateKey>;

void main() {
  late _KeyPair rootKey;
  late _KeyPair caKey;
  late Uint8List root;
  late Uint8List ca;
  int serial = 10;

  Uint8List user(_KeyPair key, _KeyPair issuerKey, String subject,
          String issuer) =>
      PkiBuilder.createUserCertificate(
        keyPair: key,
        issuerKeyPair: issuerKey,
        subjectDn: subject,
        issuerDn: issuer,
        serialNumber: serial++,
      );

  _KeyPair newKey() => PkiUtils.generateRsaKeyPair(bitStrength: 1024);

  setUpAll(() {
    rootKey = newKey();
    caKey = newKey();
    root = PkiBuilder.createRootCertificate(
        keyPair: rootKey, dn: 'CN=Test Root', validityYears: 2);
    ca = PkiBuilder.createIntermediateCertificate(
      keyPair: caKey,
      issuerKeyPair: rootKey,
      subjectDn: 'CN=Test CA',
      issuerDn: 'CN=Test Root',
      serialNumber: 2,
      validityYears: 2,
    );
  });

  X509ChainValidationResult verify(
    List<Uint8List> chain,
    List<Uint8List> roots,
  ) =>
      X509Utils.verifyChainPem(
        chainPem: chain.map(X509Utils.derToPem).toList(),
        trustedRootsPem: roots.map(X509Utils.derToPem).toList(),
      );

  test('a user certificate issued by the CA is trusted', () {
    final key = newKey();
    final result = verify(
      <Uint8List>[user(key, caKey, 'CN=Legit User', 'CN=Test CA'), ca],
      <Uint8List>[root],
    );
    expect(result.trusted, isTrue, reason: result.errors.join('; '));
  });

  test('an end-entity certificate cannot issue certificates', () {
    final userKey = newKey();
    final endEntity = user(userKey, caKey, 'CN=Ordinary User', 'CN=Test CA');
    final forgedKey = newKey();
    final forged =
        user(forgedKey, userKey, 'CN=Someone Else', 'CN=Ordinary User');

    final result = verify(<Uint8List>[forged, endEntity, ca], <Uint8List>[root]);

    expect(result.trusted, isFalse,
        reason: 'every signature verifies, but the issuer is not a CA');
    expect(result.errors, contains('issuer_not_a_ca'));
  });

  test('the same attack fails with the CA among the trusted roots', () {
    // ICP-Brasil truststores list the intermediate CAs as roots too.
    final userKey = newKey();
    final endEntity = user(userKey, caKey, 'CN=Ordinary User', 'CN=Test CA');
    final forgedKey = newKey();
    final forged =
        user(forgedKey, userKey, 'CN=Someone Else', 'CN=Ordinary User');

    final result =
        verify(<Uint8List>[forged, endEntity], <Uint8List>[root, ca]);
    expect(result.trusted, isFalse);
  });
}
