
import 'dart:math';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/export.dart';

/// Utilities for cryptographic operations and random data.
class PkiUtils {
  static final SecureRandom _secureRandom = _initSecureRandom();

  static SecureRandom _initSecureRandom() {
    final secureRandom = SecureRandom('Fortuna')
      ..seed(KeyParameter(Uint8List.fromList(List.generate(32, (_) => Random.secure().nextInt(255)))));
    return secureRandom;
  }

  static SecureRandom getSecureRandom() => _secureRandom;

  static AsymmetricKeyPair<PublicKey, PrivateKey> generateRsaKeyPair({int bitStrength = 2048}) {
    final keyGen = KeyGenerator('RSA')
      ..init(ParametersWithRandom(
          RSAKeyGeneratorParameters(BigInt.parse('65537'), bitStrength, 64),
          _secureRandom));
    return keyGen.generateKeyPair();
  }
}

/// A builder for creating X.509 certificates and PKI chains (Root, Intermediate, Leaf).
class PkiBuilder {
  static const String oidCommonName = '2.5.4.3';
  static const String oidOrganizationName = '2.5.4.10';
  static const String oidCountryName = '2.5.4.6';
  
  static const String oidKeyUsage = '2.5.29.15';
  static const String oidBasicConstraints = '2.5.29.19';
  static const String oidSubjectKeyIdentifier = '2.5.29.14';
  static const String oidAuthorityKeyIdentifier = '2.5.29.35';
  static const String oidExtKeyUsage = '2.5.29.37';
  static const String oidCrlDistributionPoints = '2.5.29.31';
  static const String oidAuthorityInfoAccess = '1.3.6.1.5.5.7.1.1';
  
  /// Algorithms
  static const String sha256WithRSAEncryption = '1.2.840.113549.1.1.11';
  static const String rsaEncryption = '1.2.840.113549.1.1.1';

  /// Generates a Self-Signed Root CA Certificate.
  static Uint8List createRootCertificate({
    required AsymmetricKeyPair<PublicKey, PrivateKey> keyPair,
    required String dn,
    int validityYears = 10,
  }) {
    final now = DateTime.now();
    return createCertificate(
      keyPair: keyPair,
      issuerKeyPair: keyPair, // Self-signed
      subjectDn: dn,
      issuerDn: dn,
      serialNumber: 1,
      notBefore: now,
      notAfter: now.add(Duration(days: 365 * validityYears)),
      isCa: true,
    );
  }

  /// Generates an Intermediate CA Certificate signed by [issuerKeyPair].
  static Uint8List createIntermediateCertificate({
    required AsymmetricKeyPair<PublicKey, PrivateKey> keyPair,
    required AsymmetricKeyPair<PublicKey, PrivateKey> issuerKeyPair,
    required String subjectDn,
    required String issuerDn,
    required int serialNumber,
    List<String>? crlUrls,
    List<String>? ocspUrls,
    int validityYears = 5,
  }) {
    final now = DateTime.now();
    return createCertificate(
      keyPair: keyPair,
      issuerKeyPair: issuerKeyPair,
      subjectDn: subjectDn,
      issuerDn: issuerDn,
      serialNumber: serialNumber,
      notBefore: now,
      notAfter: now.add(Duration(days: 365 * validityYears)),
      isCa: true, // It is a CA
      crlUrls: crlUrls,
      ocspUrls: ocspUrls,
    );
  }

  /// Generates a User (End-Entity) Certificate signed by [issuerKeyPair].
  static Uint8List createUserCertificate({
    required AsymmetricKeyPair<PublicKey, PrivateKey> keyPair,
    required AsymmetricKeyPair<PublicKey, PrivateKey> issuerKeyPair,
    required String subjectDn,
    required String issuerDn,
    required int serialNumber,
    List<String>? crlUrls,
    List<String>? ocspUrls,
    int validityDays = 365,
  }) {
    final now = DateTime.now();
    return createCertificate(
      keyPair: keyPair,
      issuerKeyPair: issuerKeyPair,
      subjectDn: subjectDn,
      issuerDn: issuerDn,
      serialNumber: serialNumber,
      notBefore: now,
      notAfter: now.add(Duration(days: validityDays)),
      isCa: false, // End entity
      crlUrls: crlUrls,
      ocspUrls: ocspUrls,
    );
  }

  /// Low-level X.509 Certificate creation.
  static Uint8List createCertificate({
    required AsymmetricKeyPair<PublicKey, PrivateKey> keyPair,
    required AsymmetricKeyPair<PublicKey, PrivateKey> issuerKeyPair,
    required String subjectDn,
    required String issuerDn,
    required int serialNumber,
    required DateTime notBefore,
    required DateTime notAfter,
    bool isCa = false,
    List<String>? crlUrls,
    List<String>? ocspUrls,
  }) {
    // 1. Create TBSCertificate
    final tbs = ASN1Sequence();

    // Version (v3 = 2) - [0] EXPLICIT wrapping INTEGER 2
    final versionWrapper = ASN1Sequence(tag: 0xA0); 
    versionWrapper.add(ASN1Integer(BigInt.from(2)));
    tbs.add(versionWrapper);

    // Serial Number
    tbs.add(ASN1Integer(BigInt.from(serialNumber)));

    // Algorithm ID
    tbs.add(createAlgorithmIdentifier(sha256WithRSAEncryption));

    // Issuer
    tbs.add(createName(issuerDn));

    // Validity
    final validity = ASN1Sequence();
    validity.add(ASN1UtcTime(notBefore));
    validity.add(ASN1UtcTime(notAfter));
    tbs.add(validity);

    // Subject
    tbs.add(createName(subjectDn));

    // Subject Public Key Info
    tbs.add(createSubjectPublicKeyInfo(keyPair.publicKey as RSAPublicKey));
    
    // Extensions
    final extensions = ASN1Sequence();
    
    // Basic Constraints
    extensions.add(createExtension(
      oidBasicConstraints,
      createBasicConstraints(isCa),
      critical: true,
    ));

    // Key Usage
    extensions.add(createExtension(
      oidKeyUsage,
      createKeyUsage(isCa),
      critical: true,
    ));

    // Subject Key Identifier (SKID)
    final subjectKeyBytes = _encodePublicKeyInfo(keyPair.publicKey as RSAPublicKey);
    final subjectKeyId = _calculateSha1(subjectKeyBytes);
    extensions.add(createExtension(
      oidSubjectKeyIdentifier,
      ASN1OctetString(subjectKeyId),
    ));

    // Authority Key Identifier (AKID)
    // RFC 5280: The authority key identifier extension ... MUST be present in all certificates 
    // ... EXCEPT ... self-signed CA certificates.
    if (subjectDn != issuerDn) { 
        final issuerKeyBytes = _encodePublicKeyInfo(issuerKeyPair.publicKey as RSAPublicKey);
        final issuerKeyId = _calculateSha1(issuerKeyBytes);
        
        final akiSeq = ASN1Sequence();
        // keyIdentifier [0] IMPLICIT KeyIdentifier
        // KeyIdentifier is OCTET STRING. Implicit tag replaces it with [0] (0x80).
        final keyIdOctet = ASN1OctetString(issuerKeyId, tag: 0x80);
        akiSeq.add(keyIdOctet);
    
        extensions.add(createExtension(
          oidAuthorityKeyIdentifier,
          akiSeq,
        ));
    }

    if (crlUrls != null && crlUrls.isNotEmpty) {
      extensions.add(createExtension(
        oidCrlDistributionPoints,
        createCrlDistributionPoints(crlUrls),
      ));
    }
    
    if (ocspUrls != null && ocspUrls.isNotEmpty) {
       extensions.add(createExtension(
        oidAuthorityInfoAccess,
        _createAuthorityInfoAccess(ocspUrls),
       ));
    }

    // Wrap extensions in [3] Explicit
    final extWrapper = ASN1Sequence(tag: 0xA3);
    extWrapper.add(extensions);
    tbs.add(extWrapper);

    // 2. Sign
    final signature = signData(tbs.encodedBytes, issuerKeyPair.privateKey as RSAPrivateKey);

    // 3. Assemble Certificate
    final cert = ASN1Sequence();
    cert.add(tbs);
    cert.add(createAlgorithmIdentifier(sha256WithRSAEncryption)); 
    cert.add(ASN1BitString(signature));

    return cert.encodedBytes;
  }

  static Uint8List _encodePublicKeyInfo(RSAPublicKey publicKey) {
    final keySeq = ASN1Sequence();
    keySeq.add(ASN1Integer(publicKey.modulus!));
    keySeq.add(ASN1Integer(publicKey.exponent!));
    return keySeq.encodedBytes;
  }

  static Uint8List _calculateSha1(Uint8List data) {
    final digest = SHA1Digest();
    return digest.process(data);
  }

  static ASN1Sequence createAlgorithmIdentifier(String oid) {
    final seq = ASN1Sequence();
    seq.add(ASN1ObjectIdentifier.fromComponentString(oid));
    seq.add(ASN1Null());
    return seq;
  }

  static ASN1Sequence createName(String dn) {
    final seq = ASN1Sequence();
    final parts = dn.split(',');
    for (final part in parts) {
      final kv = part.trim().split('=');
      if (kv.length != 2) continue;
      
      final type = kv[0].trim().toUpperCase();
      final value = kv[1].trim();

      String? oid;
      if (type == 'CN') oid = oidCommonName;
      else if (type == 'O') oid = oidOrganizationName;
      else if (type == 'C') oid = oidCountryName;

      if (oid != null) {
        final set = ASN1Set();
        final attrSeq = ASN1Sequence();
        attrSeq.add(ASN1ObjectIdentifier.fromComponentString(oid));
        attrSeq.add(ASN1PrintableString(value));
        set.add(attrSeq);
        seq.add(set);
      }
    }
    return seq;
  }

  static ASN1Sequence createSubjectPublicKeyInfo(RSAPublicKey publicKey) {
    final seq = ASN1Sequence();
    seq.add(createAlgorithmIdentifier(rsaEncryption)); 
    
    final keySeq = ASN1Sequence();
    keySeq.add(ASN1Integer(publicKey.modulus!));
    keySeq.add(ASN1Integer(publicKey.exponent!));
    
    seq.add(ASN1BitString(keySeq.encodedBytes));
    return seq;
  }
  
  static ASN1Sequence createExtension(String oid, ASN1Object value, {bool critical = false}) {
    final seq = ASN1Sequence();
    seq.add(ASN1ObjectIdentifier.fromComponentString(oid));
    if (critical) {
      seq.add(ASN1Boolean(true));
    }
    seq.add(ASN1OctetString(value.encodedBytes));
    return seq;
  }

  static ASN1Sequence createBasicConstraints(bool isCa) {
    final seq = ASN1Sequence();
    if (isCa) {
      seq.add(ASN1Boolean(true));
    }
    return seq;
  }

   static ASN1BitString createKeyUsage(bool isCa) {
    if (isCa) {
      return ASN1BitString(Uint8List.fromList([0x06])); 
    } else {
      return ASN1BitString(Uint8List.fromList([0xC0]));
    }
  }

  static ASN1Sequence createCrlDistributionPoints(List<String> urls) {
     final points = ASN1Sequence();
     for (final url in urls) {
       final dp = ASN1Sequence(); // DistributionPoint
       
       // fullName [0] IMPLICIT GeneralNames
       final fullName = ASN1Sequence(tag: 0xA0); 
       // GeneralNames SEQUENCE
       final gn = ASN1IA5String(url, tag: 0x86); // [6] IMPLICIT IA5String (URL)
       // Add gn to fullName (which is acting as GeneralNames sequence but tagged A0)
       fullName.add(gn);
       
       // distributionPoint [0] EXPLICIT DistributionPointName
       // Since DistributionPointName is CHOICE { fullName [0] ... }
       // It seems complex. Let's simplify and make distributionPoint [0] EXPLICIT containing fullName
       
       final dpField = ASN1Sequence(tag: 0xA0);
       dpField.add(fullName);
       
       dp.add(dpField);
       points.add(dp);
     }
     return points;
  }
  
  static ASN1Sequence _createAuthorityInfoAccess(List<String> urls) {
    final seq = ASN1Sequence();
    for (final url in urls) {
      final accessDesc = ASN1Sequence();
      accessDesc.add(ASN1ObjectIdentifier.fromComponentString('1.3.6.1.5.5.7.48.1')); // OCSP
      final gn = ASN1IA5String(url, tag: 0x86);
      accessDesc.add(gn);
      seq.add(accessDesc);
    }
    return seq;
  }

  static Uint8List signData(Uint8List data, RSAPrivateKey key) {
    final signer = Signer('SHA-256/RSA');
    signer.init(true, PrivateKeyParameter<RSAPrivateKey>(key)); 
    final sig = signer.generateSignature(data);
    return (sig as RSASignature).bytes;
  }
}

