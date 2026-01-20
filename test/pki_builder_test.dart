
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:dart_pdf/src/pki/pki_builder.dart';
import 'package:pointycastle/pointycastle.dart' hide ASN1Parser, ASN1Sequence, ASN1Integer, ASN1OctetString, ASN1Null, ASN1Object;
import 'package:asn1lib/asn1lib.dart';

void main() {
  group('PkiBuilder Tests', () {
    late AsymmetricKeyPair<PublicKey, PrivateKey> issuerKeyPair;
    late AsymmetricKeyPair<PublicKey, PrivateKey> responderKeyPair;

    setUpAll(() {
      issuerKeyPair = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
      responderKeyPair = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
    });

    test('createCRL generates a valid ASN.1 sequence', () {
      final now = DateTime.now().toUtc();
      final nextUpdate = now.add(Duration(days: 1));
      
      final revoked = [
        RevokedCertificate(
          serialNumber: BigInt.from(1001),
          revocationDate: now,
          reasonCode: 0, // unspecified
        ),
         RevokedCertificate(
          serialNumber: BigInt.from(1002),
          revocationDate: now,
        ),
      ];

      final crlBytes = PkiBuilder.createCRL(
        issuerKeyPair: issuerKeyPair,
        issuerDn: 'CN=Test CA,C=BR',
        revokedCertificates: revoked,
        thisUpdate: now,
        nextUpdate: nextUpdate,
        crlNumber: 1,
      );

      expect(crlBytes, isNotEmpty);

      // Basic ASN.1 Validation
      final parser = ASN1Parser(crlBytes);
      final seq = parser.nextObject();
      expect(seq, isA<ASN1Sequence>());
      final seqObj = seq as ASN1Sequence;
      
      // TBSCertList, AlgorithmIdentifier, Signature
      expect(seqObj.elements.length, equals(3));
    });

    test('createCRL handles empty revoked list', () {
      final now = DateTime.now().toUtc();
      final nextUpdate = now.add(Duration(days: 1));
      
      final crlBytes = PkiBuilder.createCRL(
        issuerKeyPair: issuerKeyPair,
        issuerDn: 'CN=Test CA,C=BR',
        revokedCertificates: [],
        thisUpdate: now,
        nextUpdate: nextUpdate,
        crlNumber: 2,
      );

      expect(crlBytes, isNotEmpty);
      final parser = ASN1Parser(crlBytes);
      final seq = parser.nextObject() as ASN1Sequence;
      expect(seq.elements.length, 3);
    });

    test('createOCSPResponse generates a valid response', () {
      // Mock an OCSP Request structure (minimal for testing)
      // OCSPRequest ::= SEQUENCE {
      //     tbsRequest      TBSRequest,
      //     optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
      
      // TBSRequest ::= SEQUENCE {
      //     version             [0]     EXPLICIT Version DEFAULT v1,
      //     requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
      //     requestList                 SEQUENCE OF Request,
      //     requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }

      // We need a helper to generate a dummy request or manually construct one.
      // Let's construct a minimal valid request for serial 12345.
      
      final certId = ASN1Sequence();
      certId.add(ASN1Sequence()); // algorithm hash (dummy)
      certId.add(ASN1OctetString(Uint8List(0))); // issuerNameHash
      certId.add(ASN1OctetString(Uint8List(0))); // issuerKeyHash
      certId.add(ASN1Integer(BigInt.from(12345))); // Serial Number to check

      final req = ASN1Sequence();
      req.add(certId);

      final reqList = ASN1Sequence();
      reqList.add(req);

      final tbsReq = ASN1Sequence();
      // version default
      // requestorName optional
      tbsReq.add(reqList);

      final ocspReq = ASN1Sequence();
      ocspReq.add(tbsReq);

      final requestBytes = ocspReq.encodedBytes;

      final respBytes = PkiBuilder.createOCSPResponse(
        responderKeyPair: responderKeyPair,
        issuerKeyPair: issuerKeyPair,
        requestBytes: requestBytes,
        checkStatus: (serial) {
          if (serial == BigInt.from(12345)) {
             return OcspEntryStatus(status: 0); // Good
          }
           return OcspEntryStatus(status: 2); // Unknown
        },
      );

      expect(respBytes, isNotEmpty);

      final parser = ASN1Parser(respBytes);
      final seq = parser.nextObject() as ASN1Sequence;
      
      // OCSPResponse ::= SEQUENCE {
      //    responseStatus         OCSPResponseStatus,
      //    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
      
      // We expect successful (0)
      final status = seq.elements[0] as ASN1Integer; // Actually it's ASN1Object with tag 0x0A (ENUMERATED) but asn1lib might parse as generic object or Integer depending on impl.
      // The code used ASN1Integer(BigInt.zero, tag: 0x0A);
      
      expect(status.tag, 0x0A);
      expect(status.valueAsBigInteger, BigInt.zero);

      expect(seq.elements.length, 2); // Status + ResponseBytes
    });
  });
}
