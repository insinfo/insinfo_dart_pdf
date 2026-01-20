import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;
// import 'package:pointycastle/pointycastle.dart' as pc_base; // Removed unused

import '../asn1/asn1.dart';
import '../asn1/der.dart';
import '../pkcs/pfx_data.dart'; // For Algorithms
import 'x509_name.dart'; // For X509Name


/// Utilities for generating X.509 artifacts (Keys, CSRs, Certificates).
class X509GeneratorUtils {
  
  /// Generates a new RSA Key Pair.
  static pc.AsymmetricKeyPair<pc.RSAPublicKey, pc.RSAPrivateKey> generateRsaKeyPair({int bitStrength = 2048}) {
    final keyGen = pc.KeyGenerator('RSA');
    final secureRandom = pc.SecureRandom('Fortuna')
      ..seed(pc.KeyParameter(Uint8List.fromList(List.generate(32, (_) => Random.secure().nextInt(255)))));
    
    keyGen.init(pc.ParametersWithRandom(
      pc.RSAKeyGeneratorParameters(BigInt.from(65537), bitStrength, 64),
      secureRandom
    ));
    
    final pair = keyGen.generateKeyPair();
    return pc.AsymmetricKeyPair(pair.publicKey as pc.RSAPublicKey, pair.privateKey as pc.RSAPrivateKey);
  }

  /// Generates a PEM Encoded CSR (Certificate Signing Request).
  static String generateRsaCsrPem(
    Map<String, String> attributes,
    pc.RSAPrivateKey privateKey,
    pc.RSAPublicKey publicKey,
  ) {
    // 1. Version: 0
    final version = DerInteger.fromNumber(BigInt.zero);

    // 2. Subject Name
    final subject = _buildName(attributes);

    // 3. Subject Public Key Info
    final pubKeySeq = _buildRsaPublicKey(publicKey);
    final pubKeyBytes = pubKeySeq.getDerEncoded();
    if (pubKeyBytes == null) throw Exception("Failed to encode Public Key");

    // Manual SubjectPublicKeyInfo structure to avoid potential issues with internal wrapper's DerBitString logic
    final spkiAlg = Algorithms(DerObjectID('1.2.840.113549.1.1.1'), DerNull());
    final spkiKey = DerBitString(pubKeyBytes, 0); // 0 unused bits
    final spki = DerSequence(array: [spkiAlg, spkiKey]);

    // 4. Attributes (Empty for now)
    final attributesSet = DerSet(array: []); 
    // Use DerTag instead of Asn1Tag because Asn1Tag.encode is not implemented
    final attributesTagged = DerTag(0, attributesSet, false); // Implicit [0]

    final csrInfoAnnotations = [
      version,
      subject.getAsn1(),
      spki,
      attributesTagged
    ];
    final csrInfoSeq = DerSequence(array: csrInfoAnnotations);
    
    // Sign
    final sigAlg = Algorithms(DerObjectID('1.2.840.113549.1.1.11'), DerNull()); // sha256WithRSAEncryption
    final signatureBytes = _signData(csrInfoSeq, privateKey, 'SHA-256/RSA');
    final signatureBitString = DerBitString(signatureBytes, 0);

    final csrSeq = DerSequence(array: [
      csrInfoSeq,
      sigAlg,
      signatureBitString
    ]);

    return _toPem(csrSeq.getDerEncoded()!, 'CERTIFICATE REQUEST');
  }

  /// NOTE: This is a simplified implementation of Self-Signed Certificate generation.
  static String generateSelfSignedCertificate(
    pc.AsymmetricKeyPair<pc.RSAPublicKey, pc.RSAPrivateKey> keyPair,
    String subjectDn,
    int days, {
    String issuerDn = '',
    String signatureAlgorithm = 'SHA-256/RSA',
  }) {
    // If issuerDn is empty, it is self-signed, so Issuer = Subject.
    final finalIssuerDn = issuerDn.isEmpty ? subjectDn : issuerDn;

    // 1. TBS Certificate construction
    // Version 3 (2)
    final versionTag = DerTag(0, DerInteger.fromNumber(BigInt.from(2)), true);
    
    // Serial Number (Random)
    final serialNumber = DerInteger.fromNumber(BigInt.from(DateTime.now().millisecondsSinceEpoch));

    // Signature Algorithm (Inside TBS)
    final algOid = _getSignatureOid(signatureAlgorithm);
    final sigAlg = Algorithms(DerObjectID(algOid), DerNull());

    // Issuer
    final issuerName = _parseDn(finalIssuerDn);

    // Validity
    final startDate = DateTime.now();
    final endDate = startDate.add(Duration(days: days));
    final validity = DerSequence(array: [
      DerUtcTime(_dateTimeToUtcTimeBytes(startDate)),
      DerUtcTime(_dateTimeToUtcTimeBytes(endDate))
    ]);

    // Subject
    final subjectName = _parseDn(subjectDn);

    // Subject Public Key Info
    final pubKeySeq = _buildRsaPublicKey(keyPair.publicKey);
    final pubKeyBytes = pubKeySeq.getDerEncoded();
    if (pubKeyBytes == null) throw Exception("Failed to encode Public Key");
    
    final spkiAlg = Algorithms(DerObjectID('1.2.840.113549.1.1.1'), DerNull());
    final spkiKey = DerBitString(pubKeyBytes, 0);
    final spki = DerSequence(array: [spkiAlg, spkiKey]);

    // Extensions (Optional but recommended for V3)
    // BasicConstraines, KeyUsage, SubjectKeyIdentifier
    // We will omit complex extensions for this basic version unless strictly required.
    // For V3, extensions are [3] EXPLICIT Extensions.
    
    final tbsParts = <Asn1Encode?>[
      versionTag,
      serialNumber,
      sigAlg,
      issuerName.getAsn1(),
      validity,
      subjectName.getAsn1(),
      spki,
      // Extensions?
    ];
    
    final tbsSeq = DerSequence(array: tbsParts);

    // Sign TBS
    final signatureBytes = _signData(tbsSeq, keyPair.privateKey, signatureAlgorithm);

    // Final Certificate Structure
    final certificateSeq = DerSequence(array: [
      tbsSeq,
      sigAlg, // Signature Algorithm again
      DerBitString(signatureBytes, 0)
    ]);

    return _toPem(certificateSeq.getDerEncoded()!, 'CERTIFICATE');
  }

  // --- Helpers ---

  static List<int> _dateTimeToUtcTimeBytes(DateTime date) {
    // YYMMDDHHMMSSZ
    final utc = date.toUtc();
    String twoDigits(int n) => n.toString().padLeft(2, '0');
    final y = twoDigits(utc.year % 100);
    final m = twoDigits(utc.month);
    final d = twoDigits(utc.day);
    final h = twoDigits(utc.hour);
    final min = twoDigits(utc.minute);
    final s = twoDigits(utc.second);
    return utf8.encode('$y$m$d$h$min$s' 'Z');
  }
  static X509Name _buildName(Map<String, String> attributes) {
    // Convert Map to X509Name compatible sequence
    // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
    final rdnList = <Asn1Encode>[];
    
    attributes.forEach((key, value) {
      final oid = _getOidForAttribute(key);
      if (oid != null) {
        final attrType = DerObjectID(oid);
        final attrValue = DerPrintableString(value); // Try Printable first, or UTF8
        final attrSeq = DerSequence(array: [attrType, attrValue]);
        final rdnSet = DerSet(array: [attrSeq]);
        rdnList.add(rdnSet);
      }
    });
    
    return X509Name(DerSequence(array: rdnList));
  }

  static X509Name _parseDn(String dn) {
    // Simple parser: "CN=User, O=Org"
    final attributes = <String, String>{};
    final parts = dn.split(',');
    for (var part in parts) {
      final kv = part.trim().split('=');
      if (kv.length == 2) {
        attributes[kv[0].trim()] = kv[1].trim();
      }
    }
    return _buildName(attributes);
  }

  static String? _getOidForAttribute(String attr) {
    switch (attr.toUpperCase()) {
      case 'CN': return '2.5.4.3';
      case 'C': return '2.5.4.6';
      case 'O': return '2.5.4.10';
      case 'OU': return '2.5.4.11';
      case 'ST': return '2.5.4.8';
      case 'L': return '2.5.4.7';
      case 'E': 
      case 'EMAIL': return '1.2.840.113549.1.9.1';
      default: return null;
    }
  }

  static Asn1Encode _buildRsaPublicKey(pc.RSAPublicKey key) {
    return DerSequence(array: [
      DerInteger.fromNumber(key.modulus),
      DerInteger.fromNumber(key.publicExponent)
    ]);
  }

  static String _getSignatureOid(String algo) {
    if (algo == 'SHA-256/RSA' || algo == 'SHA256withRSA') {
      return '1.2.840.113549.1.1.11';
    }
    // Default to SHA256withRSA
    return '1.2.840.113549.1.1.11';
  }

  static List<int> _signData(Asn1Encode data, pc.RSAPrivateKey key, String algo) {
    final encoded = data.getDerEncoded()!;
    final signer = pc.Signer(algo);
    signer.init(true, pc.PrivateKeyParameter<pc.RSAPrivateKey>(key)); 
    final signature = signer.generateSignature(Uint8List.fromList(encoded));
    if (signature is pc.RSASignature) {
      return signature.bytes;
    }
    throw ArgumentError('Signature generation failed to produce RSASignature bytes');
  }

  static String _toPem(List<int> der, String type) {
    final base64Cert = base64.encode(der);
    final buffer = StringBuffer();
    buffer.writeln('-----BEGIN $type-----');
    for (int i = 0; i < base64Cert.length; i += 64) {
      buffer.writeln(base64Cert.substring(i, (i + 64 < base64Cert.length) ? i + 64 : base64Cert.length));
    }
    buffer.writeln('-----END $type-----');
    return buffer.toString();
  }
}
