import 'package:http/http.dart' as http;

import '../../../io/stream_reader.dart';
import '../asn1/asn1.dart';
import '../asn1/asn1_stream.dart';
import '../asn1/der.dart';
import '../x509/ocsp.dart';
import '../x509/x509_certificates.dart';

/// Helper to fetch revocation data
class RevocationDataClient {
  /// Check OCSP status
  static Future<OcspResponse?> checkOcsp(X509Certificate cert, X509Certificate issuer) async {
    final List<int>? bytes = await fetchOcspResponseBytes(cert, issuer);
    if (bytes != null) {
      return OcspResponse.parse(bytes);
    }
    return null;
  }

  /// Fetch raw OCSP response bytes
  static Future<List<int>?> fetchOcspResponseBytes(X509Certificate cert, X509Certificate issuer) async {
    final String? url = getOcspUrl(cert);
    if (url == null) return null;

    try {
      final List<int> req = OcspRequest.generate(cert: cert, issuer: issuer);

      final http.Response response = await http.post(
        Uri.parse(url),
        headers: <String, String>{'Content-Type': 'application/ocsp-request'},
        body: req,
      );

      if (response.statusCode == 200) {
        return response.bodyBytes;
      }
    } catch (e) {
      // ignore
    }
    return null;
  }

  /// Fetch CRL for the given certificate
  static Future<List<List<int>>> fetchCrls(X509Certificate cert) async {
    final List<String> urls = getCrlDistributionPoints(cert);
    final List<List<int>> crls = <List<int>>[];
    for (final String url in urls) {
      try {
        final http.Response response = await http.get(Uri.parse(url));
        if (response.statusCode == 200) {
          crls.add(response.bodyBytes);
        }
      } catch (e) {
        // ignore fetch errors
      }
    }
    return crls;
  }

  /// Parse CRL Distribution Points extension (OID 2.5.29.31)
  static List<String> getCrlDistributionPoints(X509Certificate cert) {
    final List<String> urls = <String>[];
    try {
      final Asn1Octet? extensionValue =
          cert.getExtension(DerObjectID('2.5.29.31'));
      if (extensionValue == null) {
        return urls;
      }

      final Asn1 asn1 =
          Asn1Stream(PdfStreamReader(extensionValue.getOctets())).readAsn1()!;
      final Asn1Sequence seq = Asn1Sequence.getSequence(asn1)!;

      // DistributionPoint ::= SEQUENCE
      //   distributionPoint [0] DistributionPointName OPTIONAL
      //   reasons [1] ReasonFlags OPTIONAL
      //   cRLIssuer [2] GeneralNames OPTIONAL
      
      for(int i=0; i<seq.count; i++) {
          final IAsn1? dpObj = seq[i];
          if (dpObj == null) continue;
          final Asn1Sequence dp = Asn1Sequence.getSequence(dpObj.getAsn1())!;
          
          for(int j=0; j<dp.count; j++) {
             final IAsn1? elementI = dp[j];
             if (elementI == null) continue;
             final Asn1 element = elementI.getAsn1()!;
             
             if (element is Asn1Tag && element.tagNumber == 0) {
                 // distributionPoint [0]
                 // content is DistributionPointName
                 final Asn1? content = element.getObject();
                 
                 // DistributionPointName ::= CHOICE { fullName [0] GeneralNames, ... }
                 if (content is Asn1Tag && content.tagNumber == 0) {
                     // fullName [0] GeneralNames
                     // GeneralNames ::= SEQUENCE OF GeneralName
                     final Asn1? gnObj = content.getObject();
                     if (gnObj is Asn1Sequence) {
                         final Asn1Sequence generalNames = gnObj;
                         for(int k=0; k<generalNames.count; k++) {
                             final IAsn1? gnI = generalNames[k];
                             if (gnI == null) continue;
                             final Asn1 gn = gnI.getAsn1()!;
                             
                             // GeneralName ::= CHOICE { ... uniformResourceIdentifier [6] ... }
                             if (gn is Asn1Tag && gn.tagNumber == 6) {
                                 // Context specific 6. Implicit OCTET STRING (IA5String)
                                 final Asn1Octet? uriOctet = Asn1Octet.getOctetString(gn, false);
                                 if (uriOctet != null && uriOctet.getOctets() != null) {
                                      final String url = String.fromCharCodes(uriOctet.getOctets()!);
                                      urls.add(url);
                                 }
                             }
                         }
                     }
                 }
             }
          }
      }

    } catch (e) {
      // Parsing error
    }
    return urls;
  }
  
  /// Get OCSP URL from Authority Info Access extension (OID 1.3.6.1.5.5.7.1.1)
  static String? getOcspUrl(X509Certificate cert) {
      try {
          final Asn1Octet? extensionValue = cert.getExtension(DerObjectID('1.3.6.1.5.5.7.1.1'));
          if (extensionValue == null) return null;
          
          final Asn1 asn1 = Asn1Stream(PdfStreamReader(extensionValue.getOctets())).readAsn1()!;
          final Asn1Sequence seq = Asn1Sequence.getSequence(asn1)!;
          
          for(int i=0; i<seq.count; i++) {
              final IAsn1? adI = seq[i];
              if (adI == null) continue;
              final Asn1Sequence accessDescription = Asn1Sequence.getSequence(adI.getAsn1())!;
              
              if (accessDescription.count >= 2) {
                  final IAsn1? methodI = accessDescription[0];
                  final DerObjectID accessMethod = DerObjectID.getID(methodI!.getAsn1())!;
                  
                  // id-ad-ocsp 1.3.6.1.5.5.7.48.1
                  if (accessMethod.id == '1.3.6.1.5.5.7.48.1') {
                      final IAsn1? locI = accessDescription[1];
                      final Asn1 accessLocation = locI!.getAsn1()!;
                      
                      if (accessLocation is Asn1Tag && accessLocation.tagNumber == 6) {
                           // uniformResourceIdentifier [6]
                           final Asn1Octet? uriOctet = Asn1Octet.getOctetString(accessLocation, false);
                           if (uriOctet != null && uriOctet.getOctets() != null) {
                               return String.fromCharCodes(uriOctet.getOctets()!);
                           }
                      }
                  }
              }
          }
      } catch (e) {
          // ignore
      }
      return null;
  }
}
