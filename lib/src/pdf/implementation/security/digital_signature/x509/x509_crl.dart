import 'dart:typed_data';
import '../../../io/stream_reader.dart';
import '../asn1/asn1.dart';
import '../asn1/asn1_stream.dart';
import '../asn1/der.dart';
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
