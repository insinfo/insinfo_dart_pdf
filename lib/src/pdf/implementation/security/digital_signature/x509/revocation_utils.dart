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
        // DistributionPoint ::= SEQUENCE {
        //   distributionPoint [0] DistributionPointName OPTIONAL,
        //   reasons [1] ReasonFlags OPTIONAL,
        //   cRLIssuer [2] GeneralNames OPTIONAL }
        if (dp.count == 0) return;

        for (int i = 0; i < dp.count; i++) {
            final IAsn1? el = dp[i];
            if (el is! Asn1Tag) continue;
            if (el.tagNumber != 0) continue;

            // distributionPoint [0] EXPLICIT DistributionPointName
            final Asn1? dpNameObj = el.getObject();
            if (dpNameObj is! Asn1Tag) continue;

            // DistributionPointName ::= CHOICE { fullName [0] GeneralNames, ... }
            if (dpNameObj.tagNumber != 0) continue;
            final Asn1? fullName = dpNameObj.getObject();
            if (fullName is! Asn1Sequence) continue;

            // GeneralNames ::= SEQUENCE OF GeneralName
            for (int j = 0; j < fullName.count; j++) {
                _addFromGeneralName(fullName[j], urls);
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
        // GeneralName ::= CHOICE { uniformResourceIdentifier [6] IA5String, ... }
        if (gn is! Asn1Tag || gn.tagNumber != 6) return;

        try {
            // In many encodings the [6] is implicit IA5String; try common string types.
            final Asn1? inner = gn.getObject();
            String? url;
            if (inner is DerAsciiString) {
                url = inner.getString();
            } else if (inner is DerUtf8String) {
                url = inner.getString();
            } else if (inner is DerPrintableString) {
                url = inner.getString();
            } else if (inner is Asn1Octet) {
                final List<int>? octets = inner.getOctets();
                if (octets != null) url = String.fromCharCodes(octets);
            }

            // Fallback: tag may contain raw bytes.
            url ??= gn.getAsn1().toString();

            final String trimmed = url.trim();
            if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
                urls.add(trimmed);
            }
        } catch (_) {
            // ignore
        }
  }
}
