import 'dart:convert';
import 'dart:typed_data';

import '../../../io/stream_reader.dart';
import '../asn1/asn1.dart';
import '../asn1/asn1_stream.dart';
import 'ocsp_utils.dart' show CertificateUtililty;
import 'x509_certificates.dart';

class X509ChainValidationResult {
  const X509ChainValidationResult({
    required this.trusted,
    required this.errors,
  });

  final bool trusted;
  final List<String> errors;
}

/// Public helpers around X.509 parsing and basic chain validation.
///
/// Note: this library currently supports RSA certificate signature validation.
class X509Utils {
  static Uint8List pemToDer(String pem) {
    final String normalized = pem
        .replaceAll('-----BEGIN CERTIFICATE-----', '')
        .replaceAll('-----END CERTIFICATE-----', '')
        .replaceAll(RegExp(r'\s+'), '');
    return Uint8List.fromList(base64Decode(normalized));
  }

  static X509Certificate parsePemCertificate(String pem) {
    final Uint8List der = pemToDer(pem);
    final Asn1? parsed = Asn1Stream(PdfStreamReader(der)).readAsn1();
    if (parsed is! Asn1Sequence) {
      throw StateError('Invalid certificate DER');
    }
    final X509CertificateStructure? s =
        X509CertificateStructure.getInstance(parsed);
    if (s == null) {
      throw StateError('Could not parse certificate');
    }
    return X509Certificate(s);
  }

  static bool checkX509SignaturePem({
    required String certificatePem,
    required String issuerCertificatePem,
  }) {
    final X509Certificate cert = parsePemCertificate(certificatePem);
    final X509Certificate issuer = parsePemCertificate(issuerCertificatePem);
    try {
      cert.verify(issuer.getPublicKey());
      return true;
    } catch (_) {
      return false;
    }
  }

  /// Verifies a chain where [chainPem] is expected to be ordered as:
  /// `[leaf, intermediates..., (optional root)]`.
  ///
  /// Returns `trusted=true` only if the chain can be validated up to one of the
  /// provided [trustedRootsPem].
  static X509ChainValidationResult verifyChainPem({
    required List<String> chainPem,
    required List<String> trustedRootsPem,
    DateTime? validationTime,
  }) {
    if (chainPem.isEmpty) {
      return const X509ChainValidationResult(trusted: false, errors: <String>[
        'empty_chain',
      ]);
    }

    final DateTime checkTime = validationTime ?? DateTime.now();
    final List<String> errors = <String>[];

    final List<X509Certificate> chain = <X509Certificate>[];
    for (final String pem in chainPem) {
      try {
        chain.add(parsePemCertificate(pem));
      } catch (_) {
        errors.add('invalid_chain_certificate');
      }
    }

    final List<X509Certificate> roots = <X509Certificate>[];
    for (final String pem in trustedRootsPem) {
      try {
        roots.add(parsePemCertificate(pem));
      } catch (_) {
        errors.add('invalid_trusted_root');
      }
    }

    if (chain.isEmpty || roots.isEmpty) {
      return X509ChainValidationResult(trusted: false, errors: errors);
    }

    // Build chain by following issuer->subject matches.
    X509Certificate current = chain.first;
    final Set<X509Certificate> visited = <X509Certificate>{};

    while (true) {
      if (visited.contains(current)) {
        errors.add('loop_in_chain');
        return X509ChainValidationResult(trusted: false, errors: errors);
      }
      visited.add(current);

      // Check validity period
      final DateTime? notBefore = current.c?.startDate?.toDateTime();
      final DateTime? notAfter = current.c?.endDate?.toDateTime();
      if (notBefore != null && checkTime.isBefore(notBefore)) {
        errors.add('certificate_not_yet_valid');
        return X509ChainValidationResult(trusted: false, errors: errors);
      }
      if (notAfter != null && checkTime.isAfter(notAfter)) {
        errors.add('certificate_expired');
        return X509ChainValidationResult(trusted: false, errors: errors);
      }

      // Prefer trusted roots as potential trust anchors.
        final X509Certificate? issuerFromRoots = findIssuer(current, roots);
        final X509Certificate? issuerFromChain = findIssuer(current, chain);
        final X509Certificate? issuer = issuerFromRoots ?? issuerFromChain;
        final bool issuerIsTrustAnchor = issuerFromRoots != null;

      if (issuer == null) {
        errors.add('issuer_not_found');
        return X509ChainValidationResult(trusted: false, errors: errors);
      }

      try {
        current.verify(issuer.getPublicKey());
      } catch (_) {
        errors.add('certificate_signature_invalid');
        return X509ChainValidationResult(trusted: false, errors: errors);
      }

      // If issuer comes from trusted roots, accept it as trust anchor.
      if (issuerIsTrustAnchor) {
        try {
          // Self-signed check (best-effort).
          issuer.verify(issuer.getPublicKey());
        } catch (_) {
          // Even if not self-signed, if it's explicitly in roots, we accept
          // as trust anchor.
        }
        return X509ChainValidationResult(trusted: true, errors: errors);
      }

      // Continue walking.
      current = issuer;
    }
  }

  static List<String> extractCrlUrlsFromPem(String certificatePem) {
    try {
      final X509Certificate cert = parsePemCertificate(certificatePem);
      final CertificateUtililty util = CertificateUtililty();
      return util.getCrlUrls(cert) ?? const <String>[];
    } catch (_) {
      return const <String>[];
    }
  }

  static String? extractOcspUrlFromPem(String certificatePem) {
    try {
      final X509Certificate cert = parsePemCertificate(certificatePem);
      final CertificateUtililty util = CertificateUtililty();
      return util.getOcspUrl(cert);
    } catch (_) {
      return null;
    }
  }

  static X509Certificate? findIssuer(
    X509Certificate cert,
    List<X509Certificate> candidates,
  ) {
    final String? issuer = cert.c?.issuer?.toString();
    if (issuer == null) return null;
    for (final X509Certificate candidate in candidates) {
      final String? subject = candidate.c?.subject?.toString();
      if (subject == null) continue;
      if (subject == issuer) {
        return candidate;
      }
    }
    return null;
  }
}
