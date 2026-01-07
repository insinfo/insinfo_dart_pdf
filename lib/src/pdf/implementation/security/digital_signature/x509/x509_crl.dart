import 'dart:typed_data';
import '../../../io/stream_reader.dart';
import '../asn1/asn1.dart';
import '../asn1/asn1_stream.dart';
import '../asn1/der.dart';
import 'revocation_signature_verifier.dart';
import 'x509_certificates.dart';
import 'x509_time.dart';
import 'x509_name.dart';

/// Represents an X.509 Certificate Revocation List (CRL).
///
/// See RFC 5280.
class X509Crl {
  X509Crl(this._crl);

  final Asn1Sequence _crl;
  
  static X509Crl? fromBytes(List<int> bytes) {
    try {
      final Asn1Stream reader = Asn1Stream(PdfStreamReader(Uint8List.fromList(bytes)));
      final Asn1? asn1 = reader.readAsn1();
      if (asn1 is Asn1Sequence) {
        return X509Crl(asn1);
      }
    } catch (_) {}
    return null;
  }

  Asn1Sequence? get _tbsCertList {
     if (_crl.count > 0 && _crl[0] is Asn1Sequence) {
       return _crl[0] as Asn1Sequence;
     }
     return null;
  }

  /// Signature algorithm OID from the outer CRL structure.
  String? get signatureAlgorithmOid {
    if (_crl.count < 2) return null;
    final Asn1? algObj = _crl[1]?.getAsn1();
    final Asn1Sequence? algSeq = Asn1Sequence.getSequence(algObj);
    if (algSeq == null || algSeq.count < 1) return null;
    final Asn1? oid = algSeq[0]?.getAsn1();
    return oid is DerObjectID ? oid.id : null;
  }

  /// Signature algorithm parameters (best-effort).
  Asn1Encode? get signatureAlgorithmParameters {
    if (_crl.count < 2) return null;
    final Asn1? algObj = _crl[1]?.getAsn1();
    final Asn1Sequence? algSeq = Asn1Sequence.getSequence(algObj);
    if (algSeq == null || algSeq.count < 2) return null;
    return algSeq[1] as Asn1Encode?;
  }

  /// DER of tbsCertList.
  Uint8List? get tbsDer {
    final Asn1Sequence? tbs = _tbsCertList;
    final List<int>? der = (tbs as Asn1Encode?)?.getDerEncoded();
    return der == null ? null : Uint8List.fromList(der);
  }

  /// Signature bytes from outer signatureValue BIT STRING.
  Uint8List? get signatureBytes {
    if (_crl.count < 3) return null;
    final Asn1? sigObj = _crl[2]?.getAsn1();
    final DerBitString? bits = sigObj is DerBitString ? sigObj : DerBitString.getDetBitString(sigObj);
    final List<int>? b = bits?.getBytes();
    return b == null ? null : Uint8List.fromList(b);
  }
  
  /// returns the issuer Distinguished Name
  X509Name? get issuer {
     final Asn1Sequence? tbs = _tbsCertList;
     if (tbs != null) {
       // TBSCertList: version(opt), signature, issuer, thisUpdate, nextUpdate, revokedCertificates...
       int index = 0;
       if (index < tbs.count && tbs[index] is DerInteger) {
         index++; // skip version
       }
       index++; // skip signature algo
       
       if (index < tbs.count && tbs[index] is Asn1Sequence) {
         return X509Name(tbs[index] as Asn1Sequence);
       }
     }
     return null;
  }

  DateTime? get thisUpdate {
    final Asn1Sequence? tbs = _tbsCertList;
    if (tbs == null) return null;
    int index = 0;
    if (index < tbs.count && tbs[index] is DerInteger) {
      index++;
    }
    index++; // signature algo
    index++; // issuer
    if (index >= tbs.count) return null;
    return X509Time.getTime(tbs[index])?.toDateTime();
  }

  DateTime? get nextUpdate {
    final Asn1Sequence? tbs = _tbsCertList;
    if (tbs == null) return null;
    int index = 0;
    if (index < tbs.count && tbs[index] is DerInteger) {
      index++;
    }
    index++; // signature algo
    index++; // issuer
    index++; // thisUpdate
    if (index >= tbs.count) return null;
    final IAsn1? maybe = tbs[index];
    final X509Time? t = X509Time.getTime(maybe);
    return t?.toDateTime();
  }

  /// Verifies the CRL signature using the [issuerCert] public key.
  bool verifySignature(X509Certificate issuerCert) {
    final String? oid = signatureAlgorithmOid;
    final Uint8List? tbs = tbsDer;
    final Uint8List? sig = signatureBytes;
    if (oid == null || tbs == null || sig == null) return false;
    try {
      return RevocationSignatureVerifier.verify(
        signatureAlgorithmOid: oid,
        signatureAlgorithmParameters: signatureAlgorithmParameters,
        signedDataDer: tbs,
        signatureBytes: sig,
        signerCert: issuerCert,
      );
    } catch (_) {
      return false;
    }
  }
  
  /// Checks if a certificate serial number is present in the revoked list.
  bool isRevoked(BigInt serialNumber) {
    final Set<BigInt> revoked = revokedSimpleList;
    return revoked.contains(serialNumber);
  }

  Set<BigInt>? _cachedRevoked;

  Set<BigInt> get revokedSimpleList {
    if (_cachedRevoked != null) return _cachedRevoked!;

    final Set<BigInt> result = <BigInt>{};
    
    final Asn1Sequence? tbs = _tbsCertList;
    if (tbs != null) {
       int index = 0;
       if (index < tbs.count && tbs[index] is DerInteger) {
         index++;
       }
       index++; // signature
       index++; // issuer
       index++; // thisUpdate
       
       // thisUpdate/nextUpdate can be UtcTime or GeneralizedTime
       bool isTime(IAsn1? obj) => obj is DerUtcTime || obj is GeneralizedTime;
       
       if (index < tbs.count && isTime(tbs[index])) {
          // nextUpdate is optional
          final IAsn1? nextMaybe = index + 1 < tbs.count ? tbs[index+1] : null;
           if (isTime(nextMaybe)) {
             index++; 
           }
       }
       index++; // move past last date
       
       // revokedCertificates SEQUENCE OF SEQUENCE { userCertificate, revocationDate, extensions }
       if (index < tbs.count && tbs[index] is Asn1Sequence) {
          final Asn1Sequence revokedSeq = tbs[index] as Asn1Sequence;
          for(int i=0; i < revokedSeq.count; i++) {
             final IAsn1? entryObj = revokedSeq[i];
             if (entryObj is Asn1Sequence) {
                final Asn1Sequence entry = entryObj;
                if (entry.count > 0 && entry[0] is DerInteger) {
                   final DerInteger serial = entry[0] as DerInteger;
                   result.add(serial.value);
                }
             }
          }
       }
    }
    
    _cachedRevoked = result;
    return result;
  }
}
