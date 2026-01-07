import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../../../io/stream_reader.dart';
import '../asn1/asn1.dart';
import '../asn1/asn1_stream.dart';
import '../asn1/der.dart';
import 'x509_certificates.dart';
import 'x509_name.dart';

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
  OcspResponse({required this.status, this.revocationTime});

  final OcspCertificateStatus status;
  final DateTime? revocationTime;

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
        return OcspResponse(status: OcspCertificateStatus.unknown);
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
      // BasicOCSPResponse ::= SEQUENCE {
      //    tbsResponseData ResponseData,
      //    signatureAlgorithm AlgorithmIdentifier,
      //    signature BIT STRING,
      //    certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
      final Asn1 asn1 = Asn1Stream(PdfStreamReader(Uint8List.fromList(bytes))).readAsn1()!;
      if (asn1 is! Asn1Sequence) return null;
      final Asn1Sequence seq = asn1;
      
      // ResponseData ::= SEQUENCE {
      //   version [0] EXPLICIT Version DEFAULT v1,
      //   responderID ResponderID,
      //   producedAt GeneralizedTime,
      //   responses SEQUENCE OF SingleResponse,
      //   responseExtensions [1] EXPLICIT Extensions OPTIONAL }
      final Asn1Sequence tbsResp = Asn1Sequence.getSequence(seq[0]!.getAsn1())!;
      
      // We need to find 'responses' sequence.
      // version and extensions are tagged.
      // responderID is CHOICE (Name or KeyHash).
      // producedAt is GeneralizedTime.
      
      // Simple parse strategy: find the first SEQUENCE OF SEQUENCE that looks like responses.
      for(int i=0; i<tbsResp.count; i++) {
         final IAsn1? el = tbsResp[i];
         if (el is Asn1Sequence) {
            // Check if this is 'responses'
            // SingleResponse ::= SEQUENCE {
            //    certID CertID,
            //    certStatus CertStatus,
            //    thisUpdate GeneralizedTime,
            //    nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL,
            //    singleExtensions [1] EXPLICIT Extensions OPTIONAL }
            
            // Just scan for first SingleResponse
            if (el.count > 0 && el[0] is Asn1Sequence) {
               final Asn1Sequence singleResp = el[0] as Asn1Sequence;
               // Parse SingleResponse
               // index 1 is certStatus
               if (singleResp.count > 1) {
                   final IAsn1? statusObj = singleResp[1];
                   if (statusObj is Asn1Tag) {
                      // CertStatus ::= CHOICE {
                      //   good [0] IMPLICIT NULL,
                      //   revoked [1] IMPLICIT RevokedInfo,
                      //   unknown [2] IMPLICIT UnknownInfo }
                      if (statusObj.tagNumber == 0) {
                          return OcspResponse(status: OcspCertificateStatus.good);
                      } else if (statusObj.tagNumber == 1) {
                          return OcspResponse(status: OcspCertificateStatus.revoked);
                      } else {
                          return OcspResponse(status: OcspCertificateStatus.unknown);
                      }
                   }
               }
            }
         }
      }

      return OcspResponse(status: OcspCertificateStatus.unknown);
  }
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
