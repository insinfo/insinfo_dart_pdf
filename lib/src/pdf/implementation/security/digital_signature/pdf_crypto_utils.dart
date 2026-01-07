import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/asn1/asn1.dart';
import 'package:pointycastle/export.dart' as pc;

import '../../io/stream_reader.dart';
import 'asn1/asn1_stream.dart';
import 'asn1/der.dart';
import 'cryptography/cipher_block_chaining_mode.dart'
  show RsaPrivateKeyParam, EcPrivateKeyParam;

/// Helpers to parse common crypto inputs (PEM/DER) into the internal
/// structures used by the digital-signature implementation.
class PdfCryptoUtils {
  const PdfCryptoUtils._();

  /// Parses an RSA private key from PEM and returns the internal key type.
  ///
  /// Supports:
  /// - `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1)
  /// - `-----BEGIN PRIVATE KEY-----` (PKCS#8 unencrypted)
  ///
  /// Supports encrypted PKCS#8 (`ENCRYPTED PRIVATE KEY`) when [password] is provided.
  static RsaPrivateKeyParam rsaPrivateKeyFromPem(String pem, {String? password}) {
    final List<Uint8List> pkcs1 = _pemBlocksToDer(pem, 'RSA PRIVATE KEY');
    if (pkcs1.isNotEmpty) {
      return _rsaPrivateKeyFromPkcs1Der(pkcs1.first);
    }

    final List<Uint8List> pkcs8 = _pemBlocksToDer(pem, 'PRIVATE KEY');
    if (pkcs8.isNotEmpty) {
      return _rsaPrivateKeyFromPkcs8Der(pkcs8.first);
    }

    final List<Uint8List> encrypted = _pemBlocksToDer(pem, 'ENCRYPTED PRIVATE KEY');
    if (encrypted.isNotEmpty) {
      if (password == null) {
        throw ArgumentError(
          'Encrypted private key provided but no password was supplied.',
        );
      }
      final Uint8List decrypted = _decryptEncryptedPkcs8PrivateKeyDer(
        encrypted.first,
        password,
      );
      return _rsaPrivateKeyFromPkcs8Der(decrypted);
    }

    throw ArgumentError('Unsupported private key PEM format.');
  }

  /// Parses an EC private key from PEM and returns the internal key type.
  ///
  /// Supports:
  /// - `-----BEGIN EC PRIVATE KEY-----` (SEC1)
  /// - `-----BEGIN PRIVATE KEY-----` (PKCS#8 unencrypted)
  /// - `-----BEGIN ENCRYPTED PRIVATE KEY-----` (PKCS#8 PBES2) when [password] is provided.
  static EcPrivateKeyParam ecPrivateKeyFromPem(String pem, {String? password}) {
    final List<Uint8List> sec1 = _pemBlocksToDer(pem, 'EC PRIVATE KEY');
    if (sec1.isNotEmpty) {
      return _ecPrivateKeyFromSec1Der(sec1.first, curveOidFromPkcs8: null);
    }

    final List<Uint8List> pkcs8 = _pemBlocksToDer(pem, 'PRIVATE KEY');
    if (pkcs8.isNotEmpty) {
      return _ecPrivateKeyFromPkcs8Der(pkcs8.first);
    }

    final List<Uint8List> encrypted = _pemBlocksToDer(pem, 'ENCRYPTED PRIVATE KEY');
    if (encrypted.isNotEmpty) {
      if (password == null) {
        throw ArgumentError(
          'Encrypted private key provided but no password was supplied.',
        );
      }
      final Uint8List decrypted = _decryptEncryptedPkcs8PrivateKeyDer(
        encrypted.first,
        password,
      );
      return _ecPrivateKeyFromPkcs8Der(decrypted);
    }

    throw ArgumentError('Unsupported private key PEM format.');
  }

  /// Decodes a certificate PEM into its DER bytes.
  ///
  /// Accepts a string containing one or more `CERTIFICATE` PEM blocks;
  /// returns the first one.
  static Uint8List certificateDerFromPem(String pem) {
    final List<Uint8List> certs = _pemBlocksToDer(pem, 'CERTIFICATE');
    if (certs.isEmpty) {
      throw ArgumentError('No CERTIFICATE PEM block found.');
    }
    return certs.first;
  }

  /// Decodes a list of certificate PEM strings into DER.
  ///
  /// Each entry may contain one or more `CERTIFICATE` blocks; all blocks
  /// are returned, in order.
  static List<Uint8List> certificateChainDerFromPem(List<String> pemList) {
    final List<Uint8List> out = <Uint8List>[];
    for (final String pem in pemList) {
      out.addAll(_pemBlocksToDer(pem, 'CERTIFICATE'));
    }
    return out;
  }

  /// Extracts all PEM blocks with the given [label] and base64-decodes them.
  ///
  /// Example labels: `CERTIFICATE`, `RSA PRIVATE KEY`, `PRIVATE KEY`.
  static List<Uint8List> _pemBlocksToDer(String pem, String label) {
    // Match blocks even if the PEM contains extra spaces or \r\n.
    final String escaped = RegExp.escape(label);
    final RegExp re = RegExp(
      '-----BEGIN $escaped-----([\\s\\S]*?)-----END $escaped-----',
      multiLine: true,
    );

    final Iterable<RegExpMatch> matches = re.allMatches(pem);
    final List<Uint8List> out = <Uint8List>[];

    for (final RegExpMatch m in matches) {
      final String body = (m.group(1) ?? '').replaceAll(RegExp(r'\s+'), '');
      if (body.isEmpty) continue;
      out.add(Uint8List.fromList(base64Decode(body)));
    }

    return out;
  }

  static Uint8List _decryptEncryptedPkcs8PrivateKeyDer(
    Uint8List encryptedPrivateKeyInfoDer,
    String password,
  ) {
    final dynamic parsed =
        Asn1Stream(PdfStreamReader(encryptedPrivateKeyInfoDer)).readAsn1();
    if (parsed is! Asn1Sequence || parsed.count < 2) {
      throw ArgumentError('Invalid EncryptedPrivateKeyInfo DER.');
    }

    // EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm AlgorithmIdentifier, encryptedData OCTET STRING }
    final Asn1Sequence? algId = Asn1Sequence.getSequence(parsed[0]);
    if (algId == null || algId.count < 1) {
      throw ArgumentError('Invalid EncryptedPrivateKeyInfo.algorithm.');
    }

    final DerObjectID? algOid = DerObjectID.getID(algId[0]);
    if (algOid?.id != '1.2.840.113549.1.5.13') {
      // PBES2
      throw ArgumentError(
        'Unsupported encrypted PKCS#8 algorithm OID: ${algOid?.id ?? 'unknown'}',
      );
    }

    final Asn1? pbes2ParamsAsn1 = algId.count >= 2 ? algId[1]?.getAsn1() : null;
    if (pbes2ParamsAsn1 is! Asn1Sequence || pbes2ParamsAsn1.count < 2) {
      throw ArgumentError('Invalid PBES2 parameters.');
    }

    final Asn1Sequence? kdfAlg = Asn1Sequence.getSequence(pbes2ParamsAsn1[0]);
    final Asn1Sequence? encScheme = Asn1Sequence.getSequence(pbes2ParamsAsn1[1]);
    if (kdfAlg == null || encScheme == null) {
      throw ArgumentError('Invalid PBES2 params sequence.');
    }

    // PBKDF2
    final DerObjectID? kdfOid = DerObjectID.getID(kdfAlg[0]);
    if (kdfOid?.id != '1.2.840.113549.1.5.12') {
      throw ArgumentError(
        'Unsupported PBES2 KDF OID: ${kdfOid?.id ?? 'unknown'}',
      );
    }

    final Asn1? pbkdf2ParamsAsn1 = kdfAlg.count >= 2 ? kdfAlg[1]?.getAsn1() : null;
    if (pbkdf2ParamsAsn1 is! Asn1Sequence || pbkdf2ParamsAsn1.count < 2) {
      throw ArgumentError('Invalid PBKDF2 parameters.');
    }

    // PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iterationCount INTEGER, keyLength INTEGER OPTIONAL, prf AlgorithmIdentifier DEFAULT hmacWithSHA1 }
    final Asn1? saltAsn1 = pbkdf2ParamsAsn1[0]?.getAsn1();
    if (saltAsn1 is! DerOctet) {
      throw ArgumentError('Unsupported PBKDF2 salt type (expected OCTET STRING).');
    }
    final Uint8List salt = Uint8List.fromList(saltAsn1.getOctets() ?? const <int>[]);
    final int iterations = _requireDerInteger(pbkdf2ParamsAsn1[1]).positiveValue.toInt();

    int? keyLength;
    DerObjectID prfOid = DerObjectID('1.2.840.113549.2.7'); // hmacWithSHA1

    int idx = 2;
    if (pbkdf2ParamsAsn1.count > idx) {
      final Asn1? maybeKeyLen = pbkdf2ParamsAsn1[idx]?.getAsn1();
      if (maybeKeyLen is DerInteger) {
        keyLength = maybeKeyLen.positiveValue.toInt();
        idx++;
      }
    }

    if (pbkdf2ParamsAsn1.count > idx) {
      final Asn1Sequence? prfAlg = Asn1Sequence.getSequence(pbkdf2ParamsAsn1[idx]);
      if (prfAlg != null && prfAlg.count >= 1) {
        final DerObjectID? o = DerObjectID.getID(prfAlg[0]);
        if (o?.id != null) prfOid = DerObjectID(o!.id);
      }
    }

    // encryptionScheme: expect AES-CBC with IV
    final DerObjectID? encOid = DerObjectID.getID(encScheme[0]);
    final Asn1? ivAsn1 = encScheme.count >= 2 ? encScheme[1]?.getAsn1() : null;
    if (encOid?.id == null || ivAsn1 is! DerOctet) {
      throw ArgumentError('Unsupported PBES2 encryption scheme.');
    }

    final ({int keyBytes, String oid}) cipher = _aesKeyLengthForOid(encOid!.id!);
    final int klen = keyLength ?? cipher.keyBytes;
    final Uint8List iv = Uint8List.fromList(ivAsn1.getOctets() ?? const <int>[]);

    final Asn1Octet encryptedOctet = _requireOctet(parsed[1]);
    final Uint8List encryptedData = encryptedOctet.getOctets() == null
      ? Uint8List(0)
      : Uint8List.fromList(encryptedOctet.getOctets()!);
    if (encryptedData.isEmpty) {
      throw ArgumentError('Missing encryptedData OCTET STRING.');
    }

    final Uint8List key = _pbkdf2(
      password: password,
      salt: salt,
      iterations: iterations,
      keyLength: klen,
      prfOid: prfOid.id!,
    );

    final pc.PaddedBlockCipherImpl cipherImpl = pc.PaddedBlockCipherImpl(
      pc.PKCS7Padding(),
      pc.CBCBlockCipher(pc.AESEngine()),
    );

    cipherImpl.init(
      false,
      pc.PaddedBlockCipherParameters<pc.ParametersWithIV<pc.KeyParameter>, Null>(
        pc.ParametersWithIV<pc.KeyParameter>(pc.KeyParameter(key), iv),
        null,
      ),
    );

    try {
      final Uint8List out = cipherImpl.process(encryptedData);
      return out;
    } catch (e) {
      throw ArgumentError('Failed to decrypt ENCRYPTED PRIVATE KEY: $e');
    }
  }

  static Uint8List _pbkdf2({
    required String password,
    required Uint8List salt,
    required int iterations,
    required int keyLength,
    required String prfOid,
  }) {
    final pc.Mac mac = switch (prfOid) {
      '1.2.840.113549.2.7' => pc.HMac(pc.SHA1Digest(), 64),
      '1.2.840.113549.2.9' => pc.HMac(pc.SHA256Digest(), 64),
      '1.2.840.113549.2.10' => pc.HMac(pc.SHA384Digest(), 128),
      '1.2.840.113549.2.11' => pc.HMac(pc.SHA512Digest(), 128),
      _ => throw ArgumentError('Unsupported PBKDF2 PRF OID: $prfOid'),
    };

    final pc.PBKDF2KeyDerivator derivator = pc.PBKDF2KeyDerivator(mac);
    derivator.init(pc.Pbkdf2Parameters(salt, iterations, keyLength));
    final Uint8List pwBytes = Uint8List.fromList(utf8.encode(password));
    return derivator.process(pwBytes);
  }

  static ({int keyBytes, String oid}) _aesKeyLengthForOid(String oid) {
    switch (oid) {
      case '2.16.840.1.101.3.4.1.2':
        return (keyBytes: 16, oid: oid); // aes-128-cbc
      case '2.16.840.1.101.3.4.1.22':
        return (keyBytes: 24, oid: oid); // aes-192-cbc
      case '2.16.840.1.101.3.4.1.42':
        return (keyBytes: 32, oid: oid); // aes-256-cbc
    }
    throw ArgumentError('Unsupported PBES2 AES cipher OID: $oid');
  }

  static RsaPrivateKeyParam _rsaPrivateKeyFromPkcs8Der(Uint8List der) {
    final dynamic parsed = Asn1Stream(PdfStreamReader(der)).readAsn1();
    if (parsed is! Asn1Sequence) {
      throw ArgumentError('Invalid PKCS#8 DER: expected SEQUENCE.');
    }
    if (parsed.count < 3) {
      throw ArgumentError('Invalid PKCS#8 DER: too few elements.');
    }

    final Asn1Sequence? algorithm = Asn1Sequence.getSequence(parsed[1]);
    final DerObjectID? oid = (algorithm != null)
        ? DerObjectID.getID(algorithm[0])
        : null;

    // rsaEncryption OID
    if (oid?.id != '1.2.840.113549.1.1.1') {
      throw ArgumentError(
        'Unsupported private key algorithm OID: ${oid?.id ?? 'unknown'}',
      );
    }

    final Asn1Octet? oct = Asn1Octet.getOctetStringFromObject(parsed[2]);
    final List<int>? pkcs1Bytes = oct?.getOctets();
    if (pkcs1Bytes == null || pkcs1Bytes.isEmpty) {
      throw ArgumentError('Invalid PKCS#8 DER: missing privateKey OCTET STRING.');
    }

    return _rsaPrivateKeyFromPkcs1Der(Uint8List.fromList(pkcs1Bytes));
  }

  static EcPrivateKeyParam _ecPrivateKeyFromPkcs8Der(Uint8List der) {
    final dynamic parsed = Asn1Stream(PdfStreamReader(der)).readAsn1();
    if (parsed is! Asn1Sequence) {
      throw ArgumentError('Invalid PKCS#8 DER: expected SEQUENCE.');
    }
    if (parsed.count < 3) {
      throw ArgumentError('Invalid PKCS#8 DER: too few elements.');
    }

    final Asn1Sequence? algorithm = Asn1Sequence.getSequence(parsed[1]);
    final DerObjectID? oid = (algorithm != null)
        ? DerObjectID.getID(algorithm[0])
        : null;

    // id-ecPublicKey OID
    if (oid?.id != '1.2.840.10045.2.1') {
      throw ArgumentError(
        'Unsupported EC private key algorithm OID: ${oid?.id ?? 'unknown'}',
      );
    }

    // Named curve OID in AlgorithmIdentifier parameters.
    String? curveOid;
    if (algorithm != null && algorithm.count >= 2) {
      final Asn1? params = algorithm[1]?.getAsn1();
      if (params is DerObjectID) {
        curveOid = params.id;
      }
    }

    final Asn1Octet? oct = Asn1Octet.getOctetStringFromObject(parsed[2]);
    final List<int>? sec1Bytes = oct?.getOctets();
    if (sec1Bytes == null || sec1Bytes.isEmpty) {
      throw ArgumentError('Invalid PKCS#8 DER: missing privateKey OCTET STRING.');
    }

    return _ecPrivateKeyFromSec1Der(
      Uint8List.fromList(sec1Bytes),
      curveOidFromPkcs8: curveOid,
    );
  }

  static EcPrivateKeyParam _ecPrivateKeyFromSec1Der(
    Uint8List der, {
    required String? curveOidFromPkcs8,
  }) {
    final dynamic parsed = Asn1Stream(PdfStreamReader(der)).readAsn1();
    if (parsed is! Asn1Sequence || parsed.count < 2) {
      throw ArgumentError('Invalid SEC1 ECPrivateKey DER.');
    }

    // ECPrivateKey ::= SEQUENCE { version INTEGER, privateKey OCTET STRING, parameters [0] OPTIONAL, publicKey [1] OPTIONAL }
    final Asn1? privOctAsn1 = parsed[1]?.getAsn1();
    if (privOctAsn1 is! DerOctet) {
      throw ArgumentError('Invalid ECPrivateKey: expected privateKey OCTET STRING.');
    }
    final Uint8List dBytes = Uint8List.fromList(privOctAsn1.getOctets() ?? const <int>[]);
    if (dBytes.isEmpty) {
      throw ArgumentError('Invalid ECPrivateKey: empty privateKey bytes.');
    }
    final BigInt d = _bigIntFromUnsignedBytes(dBytes);

    String? curveOid = curveOidFromPkcs8;
    for (int i = 2; i < parsed.count; i++) {
      final Asn1? element = parsed[i]?.getAsn1();
      if (element is Asn1Tag || element is DerTag) {
        final Asn1Tag tag = element as Asn1Tag;
        if ((tag.tagNumber ?? 0) == 0) {
          final Asn1? inner = tag.getObject();
          if (inner is DerObjectID) curveOid = inner.id;
        }
      }
    }

    if (curveOid == null) {
      throw ArgumentError(
        'Unsupported EC private key: missing named curve OID. Provide a PKCS#8 key with named curve parameters.',
      );
    }

    final String domainName = _ecDomainNameForOid(curveOid);
    final pc.ECDomainParameters domain = pc.ECDomainParameters(domainName);
    final pc.ECPrivateKey key = pc.ECPrivateKey(d, domain);
    return EcPrivateKeyParam(key);
  }

  static String _ecDomainNameForOid(String oid) {
    switch (oid) {
      // prime256v1 == secp256r1
      case '1.2.840.10045.3.1.7':
        return 'prime256v1';
      case '1.3.132.0.10':
        return 'secp256k1';
      case '1.3.132.0.34':
        return 'secp384r1';
      case '1.3.132.0.35':
        return 'secp521r1';
    }
    throw ArgumentError.value(oid, 'oid', 'Unsupported named curve OID');
  }

  static RsaPrivateKeyParam _rsaPrivateKeyFromPkcs1Der(Uint8List der) {
    final dynamic parsed = Asn1Stream(PdfStreamReader(der)).readAsn1();
    if (parsed is! Asn1Sequence) {
      throw ArgumentError('Invalid PKCS#1 DER: expected SEQUENCE.');
    }
    if (parsed.count < 9) {
      throw ArgumentError('Invalid PKCS#1 DER: too few integers.');
    }

    // RSAPrivateKey ::= SEQUENCE {
    //  version, n, e, d, p, q, dP, dQ, qInv, ... }
    final BigInt modulus = _requireDerInteger(parsed[1]).positiveValue;
    final BigInt publicExponent = _requireDerInteger(parsed[2]).positiveValue;
    final BigInt privateExponent = _requireDerInteger(parsed[3]).positiveValue;
    final BigInt p = _requireDerInteger(parsed[4]).positiveValue;
    final BigInt q = _requireDerInteger(parsed[5]).positiveValue;
    final BigInt dP = _requireDerInteger(parsed[6]).positiveValue;
    final BigInt dQ = _requireDerInteger(parsed[7]).positiveValue;
    final BigInt qInv = _requireDerInteger(parsed[8]).positiveValue;

    return RsaPrivateKeyParam(
      modulus,
      publicExponent,
      privateExponent,
      p,
      q,
      dP,
      dQ,
      qInv,
    );
  }

  static DerInteger _requireDerInteger(dynamic obj) {
    final DerInteger? n = DerInteger.getNumber(obj);
    if (n == null) {
      throw ArgumentError('Expected INTEGER in ASN.1 sequence.');
    }
    return n;
  }

  static Asn1Octet _requireOctet(dynamic obj) {
    final Asn1Octet? o = Asn1Octet.getOctetStringFromObject(obj);
    if (o == null) {
      throw ArgumentError('Expected OCTET STRING in ASN.1 structure.');
    }
    return o;
  }

  static BigInt _bigIntFromUnsignedBytes(Uint8List bytes) {
    BigInt result = BigInt.zero;
    for (final int b in bytes) {
      result = (result << 8) | BigInt.from(b);
    }
    return result;
  }
}
