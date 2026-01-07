import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import '../../../io/stream_reader.dart';
import '../asn1/asn1.dart' as internal_asn1;
import '../asn1/asn1_stream.dart' as internal_asn1_stream;
import '../asn1/der.dart' as internal_der;
import '../pkcs/pfx_data.dart';
import 'x509_certificates.dart';

/// Verifies signatures for revocation objects (OCSP/CRL) using the signer's
/// certificate public key.
///
/// This intentionally supports the common algorithms seen in ICP-Brasil:
/// - RSA PKCS#1 v1.5 (sha{1,256,384,512}WithRSAEncryption)
/// - ECDSA with SHA{1,224,256,384,512}
/// - RSASSA-PSS (best-effort params parse)
class RevocationSignatureVerifier {
  static bool verify({
    required String signatureAlgorithmOid,
    internal_asn1.Asn1Encode? signatureAlgorithmParameters,
    required Uint8List signedDataDer,
    required Uint8List signatureBytes,
    required X509Certificate signerCert,
  }) {
    // RSASSA-PSS
    if (signatureAlgorithmOid == '1.2.840.113549.1.1.10') {
      return _verifyRsassaPss(
        params: signatureAlgorithmParameters,
        signedData: signedDataDer,
        signature: signatureBytes,
        signerCert: signerCert,
      );
    }

    // ECDSA-with-SHA*
    if (_isEcdsaSignatureOid(signatureAlgorithmOid)) {
      return _verifyEcdsa(
        sigOid: signatureAlgorithmOid,
        signedData: signedDataDer,
        signature: signatureBytes,
        signerCert: signerCert,
      );
    }

    // RSA PKCS#1 v1.5 (shaXWithRSAEncryption)
    final pc.RSAPublicKey? rsaKey = _tryBuildRsaPublicKey(signerCert);
    if (rsaKey == null) return false;

    final String signerName = _pcSignerNameForRsaPkcs1(signatureAlgorithmOid);
    final pc.Signer signer = pc.Signer(signerName);
    signer.init(false, pc.PublicKeyParameter<pc.RSAPublicKey>(rsaKey));
    return signer.verifySignature(
      signedDataDer,
      pc.RSASignature(Uint8List.fromList(signatureBytes)),
    );
  }

  static bool _isEcdsaSignatureOid(String oid) {
    return oid == '1.2.840.10045.4.1' ||
        oid == '1.2.840.10045.4.3.1' ||
        oid == '1.2.840.10045.4.3.2' ||
        oid == '1.2.840.10045.4.3.3' ||
        oid == '1.2.840.10045.4.3.4';
  }

  static pc.Digest _pcDigestForEcdsaSignatureOid(String oid) {
    switch (oid) {
      case '1.2.840.10045.4.1':
        return pc.SHA1Digest();
      case '1.2.840.10045.4.3.1':
        return pc.SHA224Digest();
      case '1.2.840.10045.4.3.2':
        return pc.SHA256Digest();
      case '1.2.840.10045.4.3.3':
        return pc.SHA384Digest();
      case '1.2.840.10045.4.3.4':
        return pc.SHA512Digest();
    }
    throw ArgumentError.value(oid, 'oid', 'Unsupported ECDSA signature OID');
  }

  static String _pcSignerNameForRsaPkcs1(String oid) {
    switch (oid) {
      case '1.2.840.113549.1.1.5':
        return 'SHA-1/RSA';
      case '1.2.840.113549.1.1.11':
        return 'SHA-256/RSA';
      case '1.2.840.113549.1.1.12':
        return 'SHA-384/RSA';
      case '1.2.840.113549.1.1.13':
        return 'SHA-512/RSA';
    }
    throw ArgumentError.value(oid, 'oid', 'Unsupported RSA signature OID');
  }

  static pc.RSAPublicKey? _tryBuildRsaPublicKey(X509Certificate cert) {
    try {
      final PublicKeyInformation? spki = cert.c?.subjectPublicKeyInfo;
      final Algorithms? alg = spki?.algorithm;
      final internal_der.DerObjectID? algOid = alg?.id;
      if (algOid?.id == null) return null;
      if (algOid!.id != PkcsObjectId.rsaEncryption.id &&
          algOid.id != X509Objects.idEARsa.id) {
        return null;
      }

      final internal_asn1.Asn1? pk = spki?.getPublicKey();
      final RsaPublicKey? rsa = pk == null ? null : RsaPublicKey.getPublicKey(pk);
      if (rsa?.modulus == null || rsa?.publicExponent == null) return null;
      return pc.RSAPublicKey(rsa!.modulus!, rsa.publicExponent!);
    } catch (_) {
      return null;
    }
  }

  static pc.ECPublicKey? _tryBuildEcPublicKey(X509Certificate cert) {
    try {
      final PublicKeyInformation? spki = cert.c?.subjectPublicKeyInfo;
      final Algorithms? alg = spki?.algorithm;
      final internal_der.DerObjectID? algOid = alg?.id;
      if (algOid?.id != '1.2.840.10045.2.1') {
        return null;
      }
      final internal_asn1.Asn1Encode? params = alg?.parameters;
      final internal_der.DerObjectID? curveOid = params is internal_der.DerObjectID ? params : null;
      if (curveOid?.id == null) return null;

      final String domainName = _ecDomainNameForOid(curveOid!.id!);
      final pc.ECDomainParameters domain = pc.ECDomainParameters(domainName);

      final List<int>? qEncoded = spki?.publicKey?.getBytes();
      if (qEncoded == null || qEncoded.isEmpty) return null;
      final pc.ECPoint? q = domain.curve.decodePoint(Uint8List.fromList(qEncoded));
      if (q == null) return null;
      return pc.ECPublicKey(q, domain);
    } catch (_) {
      return null;
    }
  }

  static String _ecDomainNameForOid(String oid) {
    switch (oid) {
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

  static bool _verifyEcdsa({
    required String sigOid,
    required Uint8List signedData,
    required Uint8List signature,
    required X509Certificate signerCert,
  }) {
    final pc.ECPublicKey? pub = _tryBuildEcPublicKey(signerCert);
    if (pub == null) return false;

    // Signature value is DER SEQUENCE { r INTEGER, s INTEGER }
    final internal_asn1.Asn1? parsed = internal_asn1_stream.Asn1Stream(
      PdfStreamReader(signature),
    ).readAsn1();
    if (parsed is! internal_asn1.Asn1Sequence || parsed.count < 2) return false;
    final internal_asn1.Asn1? rObj = parsed[0]?.getAsn1();
    final internal_asn1.Asn1? sObj = parsed[1]?.getAsn1();
    if (rObj is! internal_der.DerInteger || sObj is! internal_der.DerInteger) return false;

    final pc.Digest digest = _pcDigestForEcdsaSignatureOid(sigOid);
    final pc.ECDSASigner signer = pc.ECDSASigner(digest);
    signer.init(false, pc.PublicKeyParameter<pc.ECPublicKey>(pub));
    return signer.verifySignature(
      signedData,
      pc.ECSignature(rObj.value, sObj.value),
    );
  }

  static bool _verifyRsassaPss({
    required internal_asn1.Asn1Encode? params,
    required Uint8List signedData,
    required Uint8List signature,
    required X509Certificate signerCert,
  }) {
    final pc.RSAPublicKey? rsaKey = _tryBuildRsaPublicKey(signerCert);
    if (rsaKey == null) return false;

    final ({String hashOid, String mgfHashOid, int saltLength}) pss =
        _parseRsassaPssParamsBestEffort(params);

    final pc.Digest hashDigest = _pcDigestForOid(pss.hashOid);
    final pc.Digest mgfDigest = _pcDigestForOid(pss.mgfHashOid);

    final pc.SecureRandom random = pc.FortunaRandom()..seed(pc.KeyParameter(Uint8List(32)));
    final pc.PSSSigner signer = pc.PSSSigner(
      pc.RSAEngine(),
      hashDigest,
      mgfDigest,
    );
    signer.init(
      false,
      pc.ParametersWithSaltConfiguration(
        pc.PublicKeyParameter<pc.RSAPublicKey>(rsaKey),
        random,
        pss.saltLength,
      ),
    );

    return signer.verifySignature(signedData, pc.PSSSignature(signature));
  }

  static pc.Digest _pcDigestForOid(String oid) {
    switch (oid) {
      case '1.3.14.3.2.26':
        return pc.SHA1Digest();
      case '2.16.840.1.101.3.4.2.4':
        return pc.SHA224Digest();
      case '2.16.840.1.101.3.4.2.1':
        return pc.SHA256Digest();
      case '2.16.840.1.101.3.4.2.2':
        return pc.SHA384Digest();
      case '2.16.840.1.101.3.4.2.3':
        return pc.SHA512Digest();
    }
    throw ArgumentError.value(oid, 'oid', 'Unsupported digest OID');
  }

  static ({String hashOid, String mgfHashOid, int saltLength})
      _parseRsassaPssParamsBestEffort(internal_asn1.Asn1Encode? params) {
    // Defaults per RFC 4055.
    String hashOid = '1.3.14.3.2.26'; // sha1
    String mgfHashOid = '1.3.14.3.2.26'; // sha1
    int saltLen = 20;

    try {
      final List<int>? der = params?.getDerEncoded();
      if (der == null || der.isEmpty) {
        return (hashOid: hashOid, mgfHashOid: mgfHashOid, saltLength: saltLen);
      }

      final internal_asn1.Asn1? top = internal_asn1_stream.Asn1Stream(
        PdfStreamReader(Uint8List.fromList(der)),
      ).readAsn1();
      final internal_asn1.Asn1Sequence? seq = top is internal_asn1.Asn1Sequence ? top : null;
      if (seq == null) {
        return (hashOid: hashOid, mgfHashOid: mgfHashOid, saltLength: saltLen);
      }

      for (int i = 0; i < seq.count; i++) {
        final internal_asn1.IAsn1? el = seq[i];
        if (el is! internal_asn1.Asn1Tag) continue;
        final int tagNo = el.tagNumber ?? -1;
        if (tagNo < 0) continue;
        final internal_asn1.Asn1? inner = el.getObject();

        if (tagNo == 0) {
          final String? oid = _tryParseAlgorithmIdentifierOidInternal(inner);
          if (oid != null) hashOid = oid;
          continue;
        }

        if (tagNo == 1) {
          final String? mgf = _tryParseMgf1HashOidInternal(inner);
          if (mgf != null) mgfHashOid = mgf;
          continue;
        }

        if (tagNo == 2) {
          if (inner is internal_der.DerInteger) {
            saltLen = inner.value.toInt();
          }
          continue;
        }
      }
      return (hashOid: hashOid, mgfHashOid: mgfHashOid, saltLength: saltLen);
    } catch (_) {
      return (hashOid: hashOid, mgfHashOid: mgfHashOid, saltLength: saltLen);
    }
  }

  static String? _tryParseAlgorithmIdentifierOidInternal(internal_asn1.Asn1? obj) {
    if (obj is! internal_asn1.Asn1Sequence || obj.count < 1) return null;
    final internal_asn1.Asn1? first = obj[0]?.getAsn1();
    if (first is internal_der.DerObjectID) {
      return first.id;
    }
    return null;
  }

  static String? _tryParseMgf1HashOidInternal(internal_asn1.Asn1? obj) {
    if (obj is! internal_asn1.Asn1Sequence || obj.count < 2) return null;
    final internal_asn1.Asn1? mgfOid = obj[0]?.getAsn1();
    if (mgfOid is! internal_der.DerObjectID) return null;
    if (mgfOid.id != '1.2.840.113549.1.1.8') return null;
    final internal_asn1.Asn1? params = obj[1]?.getAsn1();
    return _tryParseAlgorithmIdentifierOidInternal(params);
  }
}
