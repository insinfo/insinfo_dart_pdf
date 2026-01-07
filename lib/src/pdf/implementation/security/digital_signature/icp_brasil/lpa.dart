import '../asn1/asn1.dart';
import '../asn1/asn1_stream.dart';
import '../asn1/der.dart';
import '../x509/x509_time.dart';
import '../../../io/stream_reader.dart';


/// Represents the ICP-Brasil LPA (Lista de Políticas de Assinatura)
/// defined by DOC-ICP-15.03.
///
/// Structure:
/// LPA ::= SEQUENCE {
///    policyInfos  SEQUENCE OF PolicyInfo,
///    nextUpdate   Time
/// }
class Lpa {
  Lpa({required this.policyInfos, required this.nextUpdate});

  final List<PolicyInfo> policyInfos;
  final DateTime nextUpdate;

  static Lpa? fromAsn1(Asn1 asn1) {
    if (asn1 is! Asn1Sequence || asn1.count < 2) return null;

    // 0: policyInfos SEQUENCE OF PolicyInfo
    final Asn1Sequence? infosSeq = asn1[0]?.getAsn1() as Asn1Sequence?;
    if (infosSeq == null) return null;

    final List<PolicyInfo> infos = [];
    for (int i = 0; i < infosSeq.count; i++) {
        final Asn1? item = infosSeq[i]?.getAsn1();
        if (item != null) {
            final pi = PolicyInfo.fromAsn1(item);
            if (pi != null) infos.add(pi);
        }
    }

    // 1: nextUpdate Time
    final DateTime? nextUp = X509Time.getTime(asn1[1])?.toDateTime();

    if (nextUp == null) return null; // Mandatory?

    return Lpa(policyInfos: infos, nextUpdate: nextUp);
  }

  static Lpa? fromBytes(List<int> bytes) {
      final Asn1Stream s = Asn1Stream(PdfStreamReader(bytes));
      return fromAsn1(s.readAsn1()!);
  }
}

/// Represents a PolicyInfo entry in the LPA.
///
/// PolicyInfo ::= SEQUENCE {
///    policyName          DirectoryString, -- OID usually here or fieldOfApplication
///    fieldOfApplication  DirectoryString,
///    signingPeriod       SigningPeriod,
///    revocationDate      Time OPTIONAL,
///    policiesURI         PoliciesURI,
///    policiesDigest      PoliciesDigest
/// }
class PolicyInfo {
  PolicyInfo({
      required this.policyName, 
      required this.fieldOfApplication, 
      required this.signingPeriod,
      this.revocationDate,
      this.policyUri
  });

  final String policyName; // Often the OID textual description or the OID itself?
  final String fieldOfApplication;
  final SigningPeriod signingPeriod;
  final DateTime? revocationDate;
  final String? policyUri; // Simplification of PoliciesURI

  static PolicyInfo? fromAsn1(Asn1 asn1) {
      if (asn1 is! Asn1Sequence) return null;
      
      // Index tracking
      int idx = 0;

      // 0: policyName DirectoryString
      final String? pName = _readDirectoryString(asn1[idx++]);
      if (pName == null) return null;

      // 1: fieldOfApplication DirectoryString
      final String? fApp = _readDirectoryString(asn1[idx++]);
      if (fApp == null) return null;

      // 2: signingPeriod SigningPeriod
      final SigningPeriod? sPeriod = SigningPeriod.fromAsn1(asn1[idx++]?.getAsn1());
      if (sPeriod == null) return null;

      // 3: revocationDate Time OPTIONAL
      DateTime? rDate;
      // Heuristic: Check if next item implies Time or is the URI/Digest struct
      // But standard ASN.1 parsing usually checks tags.
      // SigningPeriod is SEQUENCE. Time is CHOICE (GeneralizedTime/UTCTime).
      // PoliciesURI is CHOICE or SEQUENCE (defined in diff file).
      
      // Let's inspect signature-master:
      // if (!(secondObject instanceof DERTaggedObject)) { indice = 4; }
      // Checks for optional revocation fields.
      
      Asn1? next = asn1[idx]?.getAsn1();
      
      // X509Time handling
      final X509Time? timeObj = X509Time.getTime(next);
      if (timeObj != null && (next is DerUtcTime || next is GeneralizedTime)) {
          rDate = timeObj.toDateTime();
          idx++;
      }
      
      // 4: policiesURI (simplification: we just want the URI string if possible)
      // Implementation pending detailed PoliciesURI structure analysis.
      
      return PolicyInfo(
          policyName: pName,
          fieldOfApplication: fApp,
          signingPeriod: sPeriod,
          revocationDate: rDate,
      );
  }

  static String? _readDirectoryString(dynamic obj) {
      if (obj == null) return null;
      final Asn1? asn = obj.getAsn1();
      // DirectoryString is CHOICE { teletexString, printableString, universalString, utf8String, bmpString }
      if (asn is DerPrintableString) return asn.getString();
      if (asn is DerUtf8String) return asn.getString();
      if (asn is DerOctet) return String.fromCharCodes(asn.getOctets()!); // Fallback
      // Add other internal string types if available
      return asn.toString();
  }
}

/// SigningPeriod ::= SEQUENCE {
///    notBefore Time,
///    notAfter Time OPTIONAL
/// }
class SigningPeriod {
    SigningPeriod({required this.notBefore, this.notAfter});
    
    final DateTime notBefore;
    final DateTime? notAfter;

    static SigningPeriod? fromAsn1(Asn1? asn1) {
        if (asn1 is! Asn1Sequence) return null;
        
        final DateTime? nb = X509Time.getTime(asn1[0])?.toDateTime();
        if (nb == null) return null;
        
        DateTime? na;
        if (asn1.count > 1) {
            na = X509Time.getTime(asn1[1])?.toDateTime();
        }
        
        return SigningPeriod(notBefore: nb, notAfter: na);
    }
}
