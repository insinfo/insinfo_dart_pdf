import 'dart:convert';

import 'package:http/http.dart' as http;

import '../../../io/stream_reader.dart';
import '../asn1/asn1.dart';
import '../asn1/asn1_stream.dart';
import '../asn1/der.dart';
import '../x509/ocsp.dart';
import '../x509/ocsp_utils.dart' show CertificateUtililty;
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

  /// CRL Distribution Points (OID 2.5.29.31) as URLs.
  ///
  /// Delegates to the parser [X509Utils] uses. The one that lived here
  /// returned nothing for ICP-Brasil certificates (the AC OAB G4 e-CPFs, for
  /// one) and swallowed the error, so no CRL was ever downloaded for them.
  static List<String> getCrlDistributionPoints(X509Certificate cert) {
    try {
      return CertificateUtililty().getCrlUrls(cert) ?? <String>[];
    } catch (_) {
      return <String>[];
    }
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

  /// Get CA Issuers URLs from Authority Info Access extension (OID 1.3.6.1.5.5.7.1.1)
  ///
  /// These URLs often point to an intermediate certificate (DER) or a PKCS#7 (.p7c) bundle.
  static List<String> getCaIssuersUrls(X509Certificate cert) {
    final List<String> urls = <String>[];
    try {
      final Asn1Octet? extensionValue =
          cert.getExtension(DerObjectID('1.3.6.1.5.5.7.1.1'));
      if (extensionValue == null) return urls;

      final Asn1 asn1 =
          Asn1Stream(PdfStreamReader(extensionValue.getOctets())).readAsn1()!;
      final Asn1Sequence seq = Asn1Sequence.getSequence(asn1)!;

      for (int i = 0; i < seq.count; i++) {
        final IAsn1? adI = seq[i];
        if (adI == null) continue;
        final Asn1Sequence accessDescription =
            Asn1Sequence.getSequence(adI.getAsn1())!;

        if (accessDescription.count < 2) continue;
        final IAsn1? methodI = accessDescription[0];
        final DerObjectID accessMethod =
            DerObjectID.getID(methodI!.getAsn1())!;

        // id-ad-caIssuers 1.3.6.1.5.5.7.48.2
        if (accessMethod.id != '1.3.6.1.5.5.7.48.2') continue;

        final IAsn1? locI = accessDescription[1];
        final Asn1 accessLocation = locI!.getAsn1()!;
        if (accessLocation is Asn1Tag && accessLocation.tagNumber == 6) {
          final Asn1Octet? uriOctet =
              Asn1Octet.getOctetString(accessLocation, false);
          if (uriOctet != null && uriOctet.getOctets() != null) {
            urls.add(String.fromCharCodes(uriOctet.getOctets()!));
          }
        }
      }
    } catch (_) {
      // ignore
    }
    return urls;
  }

  /// Fetches certificates from CA Issuers URLs in AIA.
  ///
  /// Returns a list of PEM-encoded certificates (may include intermediates and roots).
  static Future<List<String>> fetchCaIssuersCertificatesPem(
    X509Certificate cert,
  ) async {
    final List<String> urls = getCaIssuersUrls(cert);
    if (urls.isEmpty) return const <String>[];

    final Set<String> out = <String>{};
    for (final String url in urls) {
      try {
        final http.Response response = await http.get(Uri.parse(url));
        if (response.statusCode != 200) continue;
        final List<int> body = response.bodyBytes;
        if (body.isEmpty) continue;

        final List<List<int>> ders = _extractDerCertificatesFromAiaBody(body);
        for (final List<int> der in ders) {
          if (der.isEmpty) continue;
          out.add(X509CertificateUtil.derToPem(der));
        }
      } catch (_) {
        // ignore
      }
    }
    return out.toList(growable: false);
  }

  static List<List<int>> _extractDerCertificatesFromAiaBody(List<int> body) {
    // Common case: a single DER certificate.
    // Alternate case: PKCS#7 SignedData (.p7c) containing a certificates SET.
    try {
      final Asn1? top = Asn1Stream(PdfStreamReader(body)).readAsn1();
      if (top is! Asn1Sequence || top.count == 0) {
        return const <List<int>>[];
      }

      final Asn1? first = top[0]?.getAsn1();
      if (first is DerObjectID && first.id == '1.2.840.113549.1.7.2') {
        // ContentInfo for SignedData
        if (top.count < 2) return const <List<int>>[];
        final Asn1? tagged = top[1]?.getAsn1();
        if (tagged is! Asn1Tag) return const <List<int>>[];
        final Asn1? signedDataObj = tagged.getObject();
        final Asn1Sequence? signedData = Asn1Sequence.getSequence(signedDataObj);
        if (signedData == null) return const <List<int>>[];

        // Find certificates [0] IMPLICIT
        for (int i = 0; i < signedData.count; i++) {
          final Asn1? el = signedData[i]?.getAsn1();
          if (el is! Asn1Tag) continue;
          if (el.tagNumber != 0) continue;
          final Asn1Set? certsSet = Asn1Set.getAsn1Set(el, false);
          if (certsSet == null || certsSet.objects.isEmpty) {
            return const <List<int>>[];
          }
          final List<List<int>> out = <List<int>>[];
          for (final Asn1Encode? enc in certsSet.objects) {
            final Asn1? item = enc?.getAsn1();
            if (item is! Asn1Sequence) continue;
            final List<int>? der = item.getDerEncoded();
            if (der == null || der.isEmpty) continue;
            out.add(der);
          }
          return out;
        }

        return const <List<int>>[];
      }

      // Not a PKCS#7 SignedData envelope: assume it's a single certificate DER.
      return <List<int>>[body];
    } catch (_) {
      return const <List<int>>[];
    }
  }
}

/// Local helper to avoid importing more public utilities here.
class X509CertificateUtil {
  static String derToPem(List<int> der) {
    final String base64Cert = base64.encode(der);
    final StringBuffer buffer = StringBuffer();
    buffer.writeln('-----BEGIN CERTIFICATE-----');
    for (int i = 0; i < base64Cert.length; i += 64) {
      buffer.writeln(
        base64Cert.substring(
          i,
          (i + 64 < base64Cert.length) ? i + 64 : base64Cert.length,
        ),
      );
    }
    buffer.writeln('-----END CERTIFICATE-----');
    return buffer.toString();
  }
}
