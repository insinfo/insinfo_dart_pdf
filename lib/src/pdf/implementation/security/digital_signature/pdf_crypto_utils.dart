import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/asn1/asn1.dart';

import '../../io/stream_reader.dart';
import 'asn1/asn1_stream.dart';
import 'asn1/der.dart';
import 'cryptography/cipher_block_chaining_mode.dart' show RsaPrivateKeyParam;

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
  /// Does **not** support encrypted keys (`ENCRYPTED PRIVATE KEY`).
  static RsaPrivateKeyParam rsaPrivateKeyFromPem(String pem) {
    final List<Uint8List> pkcs1 = _pemBlocksToDer(pem, 'RSA PRIVATE KEY');
    if (pkcs1.isNotEmpty) {
      return _rsaPrivateKeyFromPkcs1Der(pkcs1.first);
    }

    final List<Uint8List> pkcs8 = _pemBlocksToDer(pem, 'PRIVATE KEY');
    if (pkcs8.isNotEmpty) {
      return _rsaPrivateKeyFromPkcs8Der(pkcs8.first);
    }

    if (pem.contains('BEGIN ENCRYPTED PRIVATE KEY')) {
      throw ArgumentError(
        'Encrypted private keys are not supported. Provide an unencrypted PEM.',
      );
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
}
