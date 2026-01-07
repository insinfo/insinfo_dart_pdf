import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../../../io/stream_reader.dart';
import '../asn1/asn1.dart';
import '../asn1/asn1_stream.dart';
import '../asn1/der.dart';
import 'revocation_signature_verifier.dart';
import 'x509_certificates.dart';
import 'x509_name.dart';
import 'x509_time.dart';

/// Represents the status of a certificate in an OCSP response.
enum OcspCertificateStatus { good, revoked, unknown }

/// Helpers for creating OCSP Requests and parsing OCSP Responses.
/// Support RFC 6960.
class OcspRequest {
  /// Generates a basic OCSP Request (no signature) for the given [cert] issued by [issuer].
  ///
  /// The request structure is:
  /// OCSPRequest ::= SEQUENCE {
  ///    tbsRequest TBSRequest,
  ///    optionalSignature [0] EXPLICIT Signature OPTIONAL }
  ///
  /// TBSRequest ::= SEQUENCE {
  ///    version [0] EXPLICIT Version DEFAULT v1,
  ///    requestorName [1] EXPLICIT GeneralName OPTIONAL,
  ///    requestList SEQUENCE OF Request,
  ///    requestExtensions [2] EXPLICIT Extensions OPTIONAL }
  ///
  /// Request ::= SEQUENCE {
  ///    reqCert CertID,
  ///    singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL }
  ///
  /// CertID ::= SEQUENCE {
  ///    hashAlgorithm AlgorithmIdentifier,
  ///    issuerNameHash OCTET STRING, -- Hash of Issuer's DN
  ///    issuerKeyHash OCTET STRING,  -- Hash of Issuer's public key
  ///    serialNumber CertificateSerialNumber }
  static List<int> generate({
    required X509Certificate cert,
    required X509Certificate issuer,
  }) {
    // 1. Create CertID
    // Hash Algo: SHA1 (1.3.14.3.2.26)
    final AlgorithmIdentifier hashAlgo = AlgorithmIdentifier(
      DerObjectID('1.3.14.3.2.26'), // sha1
    );

    // Issuer Name Hash: SHA1(DER-encoded verify name)
    // We need the raw DER of the issuer's subject DN.
    // X509Certificate.subject is X509Name.
    final X509Name issuerSubject = issuer.c!.subject!;
    final List<int> issuerNameDer = issuerSubject.getAsn1()!.getDerEncoded()!;
    final List<int> issuerNameHash = sha1.convert(issuerNameDer).bytes;

    // Issuer Key Hash: SHA1(bit string of public key, excluding tag/length/unused bits?)
    // RFC 6960: "The hash of the issuer's public key. The hash is calculated over the value (excluding tag and length) of the subject public key field in the issuer's certificate."
    // verify: "value of the BIT STRING" usually means the bytes content.
    final PublicKeyInformation keyInfo = issuer.c!.subjectPublicKeyInfo!;
    final DerBitString publicKeyBitString = keyInfo.publicKey!;
    final List<int> publicKeyBytes = publicKeyBitString.getBytes()!;
    final List<int> issuerKeyHash = sha1.convert(publicKeyBytes).bytes;

    // Serial Number
    final DerInteger serialNumber = cert.c!.serialNumber!;

    final Asn1Sequence certId = DerSequence(
      array: [
        hashAlgo.getAsn1(),
        DerOctet(issuerNameHash),
        DerOctet(issuerKeyHash),
        serialNumber,
      ],
    );

    // 2. Create Request
    final Asn1Sequence request = DerSequence(
      array: [certId],
    );

    // 3. Create TBSRequest
    // We omit version (default v1), requestorName, extensions.
    final Asn1Sequence requestList = DerSequence(array: [request]);
    final Asn1Sequence tbsRequest = DerSequence(
      array: [
        requestList,
      ],
    );

    // 4. Create OCSPRequest
    final Asn1Sequence ocspRequest = DerSequence(
      array: [tbsRequest],
    );

    return ocspRequest.getDerEncoded()!;
  }
}

class OcspResponse {
  OcspResponse({
    required this.status,
    this.revocationTime,
    this.signatureValid,
    this.thisUpdate,
    this.nextUpdate,
    this.producedAt,
    this.signatureAlgorithmOid,
    this.details,
  });

  final OcspCertificateStatus status;
  final DateTime? revocationTime;

  /// True if the BasicOCSPResponse signature was verified.
  /// Null when signature validation was not performed.
  final bool? signatureValid;

  /// thisUpdate from SingleResponse.
  final DateTime? thisUpdate;

  /// nextUpdate from SingleResponse (optional).
  final DateTime? nextUpdate;

  /// producedAt from ResponseData.
  final DateTime? producedAt;

  /// Signature algorithm OID from BasicOCSPResponse.signatureAlgorithm.
  final String? signatureAlgorithmOid;

  /// Human-readable details when parsing/validation is partial.
  final String? details;

  /// Parses and validates an OCSP response for a specific [cert] and [issuer].
  ///
  /// Validation includes:
  /// - response status == successful
  /// - SingleResponse serial matches [cert]
  /// - time window checks against [validationTime]
  /// - signature verification using included responder cert (preferred) or [issuer]
  static OcspResponse? parseValidated(
    List<int> bytes, {
    required X509Certificate cert,
    required X509Certificate issuer,
    required DateTime validationTime,
    Duration maxClockSkew = const Duration(minutes: 5),
  }) {
    final _BasicOcspParsed? basic = _parseBasic(bytes);
    if (basic == null) return null;

    // Pick the first SingleResponse that matches the cert serial.
    final BigInt? wantedSerial = cert.c?.serialNumber?.value;
    _OcspSingle? single;
    if (wantedSerial != null) {
      for (final _OcspSingle s in basic.singles) {
        if (s.serial != null && s.serial == wantedSerial) {
          single = s;
          break;
        }
      }
    }
    single ??= basic.singles.isNotEmpty ? basic.singles.first : null;

    if (single == null) {
      return OcspResponse(
        status: OcspCertificateStatus.unknown,
        signatureValid: false,
        signatureAlgorithmOid: basic.signatureAlgorithmOid,
        details: 'OCSP: no SingleResponse found',
      );
    }

    // Time window checks.
    bool timeOk = true;
    final DateTime now = validationTime.toUtc();
    final DateTime? thisUp = single.thisUpdate?.toUtc();
    final DateTime? nextUp = single.nextUpdate?.toUtc();
    if (thisUp != null && now.isBefore(thisUp.subtract(maxClockSkew))) {
      timeOk = false;
    }
    if (nextUp != null && now.isAfter(nextUp.add(maxClockSkew))) {
      timeOk = false;
    }

    // Responder cert selection: prefer embedded certs.
    X509Certificate? responder;
    if (basic.certs.isNotEmpty) {
      responder = _pickResponderCertificate(basic, issuer);
    }
    responder ??= issuer; // fallback

    bool? sigOk;
    try {
      sigOk = RevocationSignatureVerifier.verify(
        signatureAlgorithmOid: basic.signatureAlgorithmOid ?? '',
        signatureAlgorithmParameters: basic.signatureAlgorithmParameters,
        signedDataDer: Uint8List.fromList(basic.tbsResponseDataDer),
        signatureBytes: Uint8List.fromList(basic.signatureBytes),
        signerCert: responder,
      );
    } catch (_) {
      sigOk = false;
    }

    if (sigOk != true || !timeOk) {
      return OcspResponse(
        status: OcspCertificateStatus.unknown,
        signatureValid: sigOk,
        thisUpdate: single.thisUpdate,
        nextUpdate: single.nextUpdate,
        producedAt: basic.producedAt,
        signatureAlgorithmOid: basic.signatureAlgorithmOid,
        details: !timeOk ? 'OCSP: response outside validity window' : 'OCSP: signature invalid',
      );
    }

    return OcspResponse(
      status: single.status,
      revocationTime: single.revocationTime,
      signatureValid: sigOk,
      thisUpdate: single.thisUpdate,
      nextUpdate: single.nextUpdate,
      producedAt: basic.producedAt,
      signatureAlgorithmOid: basic.signatureAlgorithmOid,
    );
  }

  /// Parses an OCSP Response bytes.
  ///
  /// OCSPResponse ::= SEQUENCE {
  ///    responseStatus OCSPResponseStatus, -- ENUMERATED
  ///    responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }
  static OcspResponse? parse(List<int> bytes) {
    try {
      final Asn1 asn1 = Asn1Stream(PdfStreamReader(Uint8List.fromList(bytes))).readAsn1()!;
      if (asn1 is! Asn1Sequence) return null;
      final Asn1Sequence seq = asn1;

      if (seq.count < 1) return null;

      // responseStatus
      final dynamic statusObj = seq[0];
      int statusCode = -1;
      if (statusObj is DerCatalogue) {
         if (statusObj.bytes != null && statusObj.bytes!.isNotEmpty) {
             statusCode = statusObj.bytes![0];
         }
      } else if (statusObj is DerInteger) {
        statusCode = statusObj.value.toInt();
      }
      
      // 0 = success
      if (statusCode != 0) {
        return OcspResponse(status: OcspCertificateStatus.unknown, details: 'OCSPResponseStatus=$statusCode');
      }

      // responseBytes
      if (seq.count < 2) return null;
      final IAsn1? respBytesWrap = seq[1];
      if (respBytesWrap is Asn1Tag && respBytesWrap.tagNumber == 0) {
          // Explicit [0] ResponseBytes
          // ResponseBytes ::= SEQUENCE {
          //     responseType OBJECT IDENTIFIER,
          //     response OCTET STRING }
          final Asn1? rbSeqObj = respBytesWrap.getObject();
          if (rbSeqObj is Asn1Sequence && rbSeqObj.count == 2) {
             final Asn1Sequence rbSeq = rbSeqObj;
             final DerObjectID respType = DerObjectID.getID(rbSeq[0]!.getAsn1())!;
             
             if (respType.id == '1.3.6.1.5.5.7.48.1.1') { // id-pkix-ocsp-basic
                 final Asn1Octet respOctet = Asn1Octet.getOctetStringFromObject(rbSeq[1]!.getAsn1())!;
                 return _parseBasicOcspResponse(respOctet.getOctets()!);
             }
          }
      }

    } catch (e) {
      // parse error
    }
    return null;
  }

  static OcspResponse? _parseBasicOcspResponse(List<int> bytes) {
      final _BasicOcspParsed? basic = _parseBasic(bytes);
      if (basic == null) return null;
      if (basic.singles.isEmpty) {
        return OcspResponse(
          status: OcspCertificateStatus.unknown,
          signatureAlgorithmOid: basic.signatureAlgorithmOid,
          details: 'OCSP: no SingleResponse',
        );
      }
      final _OcspSingle s = basic.singles.first;
      return OcspResponse(
        status: s.status,
        revocationTime: s.revocationTime,
        thisUpdate: s.thisUpdate,
        nextUpdate: s.nextUpdate,
        producedAt: basic.producedAt,
        signatureAlgorithmOid: basic.signatureAlgorithmOid,
      );
  }
}

class _OcspSingle {
  _OcspSingle({
    required this.status,
    this.serial,
    this.revocationTime,
    this.thisUpdate,
    this.nextUpdate,
  });

  final OcspCertificateStatus status;
  final BigInt? serial;
  final DateTime? revocationTime;
  final DateTime? thisUpdate;
  final DateTime? nextUpdate;
}

class _BasicOcspParsed {
  _BasicOcspParsed({
    required this.tbsResponseDataDer,
    required this.signatureAlgorithmOid,
    required this.signatureAlgorithmParameters,
    required this.signatureBytes,
    required this.certs,
    required this.singles,
    required this.responderIdByKey,
    required this.responderIdByName,
    required this.producedAt,
  });

  final List<int> tbsResponseDataDer;
  final String? signatureAlgorithmOid;
  final Asn1Encode? signatureAlgorithmParameters;
  final List<int> signatureBytes;
  final List<X509Certificate> certs;
  final List<_OcspSingle> singles;
  final Uint8List? responderIdByKey;
  final X509Name? responderIdByName;
  final DateTime? producedAt;
}

_BasicOcspParsed? _parseBasic(List<int> bytes) {
  try {
    final Asn1 asn1 = Asn1Stream(PdfStreamReader(Uint8List.fromList(bytes))).readAsn1()!;
    if (asn1 is! Asn1Sequence || asn1.count < 3) return null;
    final Asn1Sequence seq = asn1;

    final Asn1? tbsObj = seq[0]?.getAsn1();
    final Asn1Sequence? tbs = Asn1Sequence.getSequence(tbsObj);
    if (tbs == null) return null;
    final List<int>? tbsDer = (tbs as Asn1Encode).getDerEncoded();
    if (tbsDer == null || tbsDer.isEmpty) return null;

    // signatureAlgorithm AlgorithmIdentifier
    final Asn1? algObj = seq[1]?.getAsn1();
    final Asn1Sequence? algSeq = Asn1Sequence.getSequence(algObj);
    String? algOid;
    Asn1Encode? algParams;
    if (algSeq != null && algSeq.count >= 1) {
      final Asn1? oidAsn1 = algSeq[0]?.getAsn1();
      if (oidAsn1 is DerObjectID) {
        algOid = oidAsn1.id;
      }
      if (algSeq.count >= 2) {
        algParams = algSeq[1] as Asn1Encode?;
      }
    }

    // signature BIT STRING
    final Asn1? sigObj = seq[2]?.getAsn1();
    final DerBitString? sigBits = sigObj is DerBitString ? sigObj : DerBitString.getDetBitString(sigObj);
    final List<int>? sigBytes = sigBits?.getBytes();
    if (sigBytes == null) return null;

    // certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
    final List<X509Certificate> certs = <X509Certificate>[];
    if (seq.count >= 4) {
      final Asn1? maybeTag = seq[3]?.getAsn1();
      if (maybeTag is Asn1Tag && maybeTag.tagNumber == 0) {
        final Asn1? certsObj = maybeTag.getObject();
        final Asn1Sequence? certSeq = Asn1Sequence.getSequence(certsObj);
        if (certSeq != null) {
          for (int i = 0; i < certSeq.count; i++) {
            final Asn1? c = certSeq[i]?.getAsn1();
            if (c is! Asn1Sequence) continue;
            final X509CertificateStructure? s = X509CertificateStructure.getInstance(c);
            if (s == null) continue;
            certs.add(X509Certificate(s));
          }
        }
      }
    }

    // Parse ResponseData
    int idx = 0;
    if (tbs.count > 0 && tbs[0] is Asn1Tag && (tbs[0] as Asn1Tag).tagNumber == 0) {
      idx++; // version
    }

    Uint8List? responderKeyHash;
    X509Name? responderName;
    if (idx < tbs.count) {
      final Asn1? rid = tbs[idx]?.getAsn1();
      if (rid is Asn1Tag) {
        if (rid.tagNumber == 2) {
          final Asn1Octet? oct = Asn1Octet.getOctetStringFromObject(rid.getObject());
          final List<int>? key = oct?.getOctets();
          if (key != null) responderKeyHash = Uint8List.fromList(key);
        } else if (rid.tagNumber == 1) {
          final Asn1? nm = rid.getObject();
          final Asn1Sequence? nmSeq = Asn1Sequence.getSequence(nm);
          if (nmSeq != null) responderName = X509Name(nmSeq);
        }
      }
      idx++;
    }

    DateTime? producedAt;
    if (idx < tbs.count) {
      final Asn1? p = tbs[idx]?.getAsn1();
      if (p is GeneralizedTime) {
        producedAt = p.toDateTime();
      }
      idx++;
    }

    final List<_OcspSingle> singles = <_OcspSingle>[];
    if (idx < tbs.count) {
      final Asn1Sequence? responses = Asn1Sequence.getSequence(tbs[idx]?.getAsn1());
      if (responses != null) {
        for (int i = 0; i < responses.count; i++) {
          final Asn1Sequence? single = Asn1Sequence.getSequence(responses[i]?.getAsn1());
          if (single == null || single.count < 3) continue;

          // certID
          BigInt? serial;
          final Asn1Sequence? certId = Asn1Sequence.getSequence(single[0]?.getAsn1());
          if (certId != null && certId.count >= 4) {
            final Asn1? serialAsn1 = certId[3]?.getAsn1();
            if (serialAsn1 is DerInteger) {
              serial = serialAsn1.value;
            }
          }

          // certStatus CHOICE
          OcspCertificateStatus st = OcspCertificateStatus.unknown;
          DateTime? revTime;
          final Asn1? statusAsn1 = single[1]?.getAsn1();
          if (statusAsn1 is Asn1Tag) {
            if (statusAsn1.tagNumber == 0) {
              st = OcspCertificateStatus.good;
            } else if (statusAsn1.tagNumber == 1) {
              st = OcspCertificateStatus.revoked;
              final Asn1? ri = statusAsn1.getObject();
              final Asn1Sequence? revokedInfo = Asn1Sequence.getSequence(ri);
              if (revokedInfo != null && revokedInfo.count >= 1) {
                final Asn1? t = revokedInfo[0]?.getAsn1();
                revTime = X509Time.getTime(t)?.toDateTime();
              }
            } else {
              st = OcspCertificateStatus.unknown;
            }
          }

          // thisUpdate
          DateTime? thisUpdate;
          final Asn1? thisUpAsn1 = single[2]?.getAsn1();
          thisUpdate = X509Time.getTime(thisUpAsn1)?.toDateTime();

          // nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL
          DateTime? nextUpdate;
          if (single.count >= 4) {
            final Asn1? maybeNext = single[3]?.getAsn1();
            if (maybeNext is Asn1Tag && maybeNext.tagNumber == 0) {
              final Asn1? inner = maybeNext.getObject();
              nextUpdate = X509Time.getTime(inner)?.toDateTime();
            }
          }

          singles.add(
            _OcspSingle(
              status: st,
              serial: serial,
              revocationTime: revTime,
              thisUpdate: thisUpdate,
              nextUpdate: nextUpdate,
            ),
          );
        }
      }
    }

    return _BasicOcspParsed(
      tbsResponseDataDer: tbsDer,
      signatureAlgorithmOid: algOid,
      signatureAlgorithmParameters: algParams,
      signatureBytes: sigBytes,
      certs: certs,
      singles: singles,
      responderIdByKey: responderKeyHash,
      responderIdByName: responderName,
      producedAt: producedAt,
    );
  } catch (_) {
    return null;
  }
}

X509Certificate? _pickResponderCertificate(_BasicOcspParsed basic, X509Certificate issuer) {
  // ResponderID byKey is SHA-1 hash of responder public key BIT STRING contents.
  if (basic.responderIdByKey != null) {
    for (final X509Certificate c in basic.certs) {
      try {
        final PublicKeyInformation? spki = c.c?.subjectPublicKeyInfo;
        final DerBitString? pk = spki?.publicKey;
        final List<int>? pkBytes = pk?.getBytes();
        if (pkBytes == null) continue;
        final List<int> h = sha1.convert(pkBytes).bytes;
        if (Uint8List.fromList(h).length == basic.responderIdByKey!.length) {
          bool eq = true;
          for (int i = 0; i < h.length; i++) {
            if (h[i] != basic.responderIdByKey![i]) {
              eq = false;
              break;
            }
          }
          if (eq) return c;
        }
      } catch (_) {
        // ignore
      }
    }
  }

  if (basic.responderIdByName != null) {
    final String wanted = basic.responderIdByName!.toString();
    for (final X509Certificate c in basic.certs) {
      final String? subj = c.c?.subject?.toString();
      if (subj != null && subj == wanted) return c;
    }
  }

  // Fallback: prefer a cert issued by the issuer.
  for (final X509Certificate c in basic.certs) {
    try {
      c.verify(issuer.getPublicKey());
      return c;
    } catch (_) {
      // ignore
    }
  }

  return basic.certs.isNotEmpty ? basic.certs.first : null;
}

class AlgorithmIdentifier extends Asn1Encode {
  AlgorithmIdentifier(this.objectId, [this.parameters]);

  final DerObjectID objectId;
  final Asn1Encode? parameters;

  @override
  Asn1 getAsn1() {
    if (parameters != null) {
      return DerSequence(array: [objectId, parameters]);
    } else {
      // For SHA-1, parameters are often NULL
      return DerSequence(array: [objectId, DerNull()]);
    }
  }
}
