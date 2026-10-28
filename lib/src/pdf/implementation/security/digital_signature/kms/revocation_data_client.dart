import 'dart:convert';

import 'package:http/http.dart' as http;

import '../../../io/stream_reader.dart';
import '../asn1/asn1.dart';
import '../asn1/asn1_stream.dart';
import '../asn1/der.dart';
import '../x509/ocsp.dart';
import '../x509/ocsp_utils.dart' show CertificateUtililty;
import '../x509/x509_certificates.dart';
import '../x509/x509_crl.dart';

/// Helper to fetch revocation data.
///
/// Every request has a timeout, and CRLs, OCSP responses and AIA downloads are
/// kept in memory until the evidence itself says it is stale (`nextUpdate`),
/// capped by [crlMaxAge], [ocspMaxAge] and [aiaMaxAge]. A validation runs the
/// same checks for each trust profile and a CRL can take seconds to download
/// (ICP-Brasil mirrors answered in 7 s); without the cache every profile
/// downloaded everything again, and one silent mirror held the validation
/// until the TCP timeout.
class RevocationDataClient {
  /// Timeout of a CRL download.
  static Duration crlTimeout = const Duration(seconds: 15);

  /// Timeout of an OCSP request.
  static Duration ocspTimeout = const Duration(seconds: 10);

  /// Timeout of an AIA (CA Issuers) download.
  static Duration aiaTimeout = const Duration(seconds: 10);

  /// Longest time a CRL is reused, even if its `nextUpdate` is later.
  static Duration crlMaxAge = const Duration(hours: 1);

  /// Longest time an OCSP response is reused.
  static Duration ocspMaxAge = const Duration(minutes: 10);

  /// Longest time an AIA download is reused.
  static Duration aiaMaxAge = const Duration(hours: 1);

  static final _BytesCache _crlCache = _BytesCache(64);
  static final _BytesCache _ocspCache = _BytesCache(256);
  static final _BytesCache _aiaCache = _BytesCache(128);

  /// Drops every cached CRL, OCSP response and AIA download.
  static void clearCache() {
    _crlCache.clear();
    _ocspCache.clear();
    _aiaCache.clear();
  }

  static DateTime _expiry(DateTime? nextUpdate, Duration maxAge) {
    final DateTime cap = DateTime.now().toUtc().add(maxAge);
    if (nextUpdate == null) return cap;
    final DateTime next = nextUpdate.toUtc();
    return next.isBefore(cap) ? next : cap;
  }

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

    final String key = '$url|${cert.c?.serialNumber?.value}|'
        '${issuer.c?.subject}';
    final List<int>? cached = _ocspCache.get(key);
    if (cached != null) return cached;

    try {
      final List<int> req = OcspRequest.generate(cert: cert, issuer: issuer);

      final http.Response response = await http
          .post(
            Uri.parse(url),
            headers: <String, String>{
              'Content-Type': 'application/ocsp-request',
            },
            body: req,
          )
          .timeout(ocspTimeout);

      if (response.statusCode == 200) {
        final List<int> bytes = response.bodyBytes;
        _ocspCache.put(
            key, bytes, _expiry(OcspResponse.parse(bytes)?.nextUpdate, ocspMaxAge));
        return bytes;
      }
    } catch (e) {
      // ignore: network error, timeout or unreadable response
    }
    return null;
  }

  /// Fetch the CRL for the given certificate.
  ///
  /// The distribution points of a certificate are mirrors of the same list,
  /// so the first one that answers with a current CRL is enough; the others
  /// are only tried when it fails.
  ///
  /// A mirror can still serve the previous list for some minutes after the CA
  /// reissues it — the SERPRO CAs reissue every 6 hours, and strict checking
  /// then rejected the expired list as "unknown". A CRL already past its
  /// `nextUpdate` sends the search to the next mirror; when every mirror is
  /// behind, the freshest expired list is returned (not cached), so the
  /// validator can say why it was rejected.
  static Future<List<List<int>>> fetchCrls(X509Certificate cert) async {
    List<int>? freshestExpired;
    DateTime? freshestExpiredNext;
    for (final String url in getCrlDistributionPoints(cert)) {
      final List<int>? cached = _crlCache.get(url);
      if (cached != null) return <List<int>>[cached];
      try {
        final http.Response response =
            await http.get(Uri.parse(url)).timeout(crlTimeout);
        if (response.statusCode != 200) continue;
        final List<int> bytes = response.bodyBytes;
        final X509Crl? crl = X509Crl.fromBytes(bytes);
        if (crl == null) continue;
        final DateTime? next = crl.nextUpdate?.toUtc();
        if (next != null && DateTime.now().toUtc().isAfter(next)) {
          if (freshestExpiredNext == null || next.isAfter(freshestExpiredNext)) {
            freshestExpired = bytes;
            freshestExpiredNext = next;
          }
          continue;
        }
        _crlCache.put(url, bytes, _expiry(next, crlMaxAge));
        return <List<int>>[bytes];
      } catch (e) {
        // ignore: network error or timeout; try the next mirror
      }
    }
    return freshestExpired == null
        ? const <List<int>>[]
        : <List<int>>[freshestExpired];
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
        List<int>? body = _aiaCache.get(url);
        if (body == null) {
          final http.Response response =
              await http.get(Uri.parse(url)).timeout(aiaTimeout);
          if (response.statusCode != 200) continue;
          body = response.bodyBytes;
          if (body.isEmpty) continue;
          _aiaCache.put(url, body, _expiry(null, aiaMaxAge));
        }

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

/// In-memory cache of downloaded bytes with an expiry per entry and a size
/// cap (oldest entries leave first).
class _BytesCache {
  _BytesCache(this._maxEntries);

  final int _maxEntries;
  final Map<String, _CachedBytes> _entries = <String, _CachedBytes>{};

  List<int>? get(String key) {
    final _CachedBytes? entry = _entries[key];
    if (entry == null) return null;
    if (DateTime.now().toUtc().isAfter(entry.expiresAt)) {
      _entries.remove(key);
      return null;
    }
    return entry.bytes;
  }

  void put(String key, List<int> bytes, DateTime expiresAt) {
    if (!DateTime.now().toUtc().isBefore(expiresAt)) return;
    _entries.remove(key);
    _entries[key] = _CachedBytes(bytes, expiresAt);
    while (_entries.length > _maxEntries) {
      _entries.remove(_entries.keys.first);
    }
  }

  void clear() => _entries.clear();
}

class _CachedBytes {
  _CachedBytes(this.bytes, this.expiresAt);

  final List<int> bytes;
  final DateTime expiresAt;
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
