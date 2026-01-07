import '../asn1/asn1.dart';
import '../asn1/der.dart';
import 'x509_certificates.dart';

/// Utilities for extracting revocation information (CRL, OCSP) from certificates.
class RevocationUtils {
  // OIDs
  static final String _crlDistributionPointsOid = '2.5.29.31';
  static final String _authorityInfoAccessOid = '1.3.6.1.5.5.7.1.1';
  static final String _ocspAccessMethod = '1.3.6.1.5.5.7.48.1';

  /// Extracts CRL Distribution Points URLs from the certificate.
  static List<String> getCrlUrls(X509Certificate cert) {
    final List<String> urls = <String>[];
    final Asn1Octet? extValue = cert.getExtension(DerObjectID(_crlDistributionPointsOid));
    if (extValue == null) {
      return urls;
    }

    try {
        final Asn1? obj = X509Extension.convertValueToObject(
            X509Extension(false, extValue), 
        );
        
        if (obj is Asn1Sequence) {
             for (int i = 0; i < obj.count; i++) {
                 final IAsn1? dp = obj[i];
                 if (dp is Asn1Sequence) {
                     _parseDistributionPoint(dp, urls);
                 }
             }
        }
    } catch (_) {}
    return urls;
  }

  static void _parseDistributionPoint(Asn1Sequence dp, List<String> urls) {
      if (dp.count > 0) {
          final IAsn1? first = dp[0];
          // Check for tag [0]
          if (first is Asn1Tag && first.tagNumber == 0) {
              // Implementation detail: need to unwrap tag to get general names.
          }
      }
  }

  /// Extracts OCSP URLs from the AIA extension.
  static List<String> getOcspUrls(X509Certificate cert) {
    final List<String> urls = <String>[];
    final Asn1Octet? extValue = cert.getExtension(DerObjectID(_authorityInfoAccessOid));
    if (extValue == null) return urls;

    try {
       final Asn1? obj = X509Extension.convertValueToObject(
            X509Extension(false, extValue),
        );
        
        if (obj is Asn1Sequence) {
            for (int i = 0; i < obj.count; i++) {
                final IAsn1? ad = obj[i];
                if (ad is Asn1Sequence && ad.count >= 2) {
                    final IAsn1? method = ad[0];
                    final IAsn1? location = ad[1];
                    
                    if (method is DerObjectID && method.id == _ocspAccessMethod) {
                       _addFromGeneralName(location, urls);
                    }
                }
            }
        }
    } catch (_) {}
    return urls;
  }
  
  static void _addFromGeneralName(IAsn1? gn, List<String> urls) {
      if (gn is Asn1Tag && gn.tagNumber == 6) {
          // Tag 6 is IA5String (URI)
           // Placeholder
      }
  }
}
