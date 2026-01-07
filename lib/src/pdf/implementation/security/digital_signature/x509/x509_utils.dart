import 'dart:convert';
import 'dart:typed_data';

import '../../../io/stream_reader.dart';
import '../asn1/asn1.dart';
import '../asn1/asn1_stream.dart';
import '../asn1/der.dart';
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
  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (identical(a, b)) return true;
    if (a.lengthInBytes != b.lengthInBytes) return false;
    for (int i = 0; i < a.lengthInBytes; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  static String _toHex(Uint8List bytes) {
    final StringBuffer sb = StringBuffer();
    for (final int b in bytes) {
      sb.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }

  static Uint8List? _tryGetSubjectKeyIdentifier(X509Certificate cert) {
    try {
      final Asn1Octet? ext = cert.getExtension(DerObjectID('2.5.29.14'));
      final List<int>? extBytes = ext?.getOctets();
      if (extBytes == null || extBytes.isEmpty) return null;
      final Asn1? parsed = Asn1Stream(PdfStreamReader(extBytes)).readAsn1();
      final Asn1Octet? oct = Asn1Octet.getOctetStringFromObject(parsed);
      final List<int>? keyId = oct?.getOctets();
      if (keyId == null || keyId.isEmpty) return null;
      return Uint8List.fromList(keyId);
    } catch (_) {
      return null;
    }
  }

  static Uint8List? _tryGetAuthorityKeyIdentifierKeyId(X509Certificate cert) {
    try {
      final Asn1Octet? ext = cert.getExtension(DerObjectID('2.5.29.35'));
      final List<int>? extBytes = ext?.getOctets();
      if (extBytes == null || extBytes.isEmpty) return null;
      final Asn1? parsed = Asn1Stream(PdfStreamReader(extBytes)).readAsn1();
      final Asn1Sequence? seq = Asn1Sequence.getSequence(parsed);
      if (seq == null || seq.objects == null) return null;

      for (final dynamic obj in seq.objects!) {
        if (obj is! Asn1Tag) continue;
        if (obj.tagNumber != 0) continue;
        final Asn1Octet? oct = Asn1Octet.getOctetStringFromObject(obj.getObject());
        final List<int>? keyId = oct?.getOctets();
        if (keyId == null || keyId.isEmpty) return null;
        return Uint8List.fromList(keyId);
      }

      return null;
    } catch (_) {
      return null;
    }
  }

  static String derToPem(Uint8List der) {
    final base64Cert = base64.encode(der);
    final buffer = StringBuffer();
    buffer.writeln('-----BEGIN CERTIFICATE-----');
    for (int i = 0; i < base64Cert.length; i += 64) {
      buffer.writeln(base64Cert.substring(i, (i + 64 < base64Cert.length) ? i + 64 : base64Cert.length));
    }
    buffer.writeln('-----END CERTIFICATE-----');
    return buffer.toString();
  }

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
    List<String> extraCandidatesPem = const <String>[],
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

    final List<X509Certificate> extraCandidates = <X509Certificate>[];
    for (final String pem in extraCandidatesPem) {
      try {
        extraCandidates.add(parsePemCertificate(pem));
      } catch (_) {
        errors.add('invalid_extra_candidate');
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
      final X509Certificate? issuerFromExtra =
          extraCandidates.isNotEmpty ? findIssuer(current, extraCandidates) : null;
      final X509Certificate? issuer = issuerFromRoots ?? issuerFromChain ?? issuerFromExtra;
      final bool issuerIsTrustAnchor = issuerFromRoots != null;

      if (issuer == null) {
        final String? curSubject = current.c?.subject?.toString();
        final String? curIssuer = current.c?.issuer?.toString();
        final String? curSigOid = current.c?.signatureAlgorithm?.id?.id;
        final String? curSpkiAlgOid = current.c?.subjectPublicKeyInfo?.algorithm?.id?.id;
        final Uint8List? curAki = _tryGetAuthorityKeyIdentifierKeyId(current);
        errors.add('issuer_not_found');
        if (curSubject != null) {
          errors.add('issuer_not_found_subject=$curSubject');
        }
        if (curIssuer != null) {
          errors.add('issuer_not_found_issuer=$curIssuer');
        }
        if (curSigOid != null) {
          errors.add('issuer_not_found_subject_sig_oid=$curSigOid');
        }
        if (curSpkiAlgOid != null) {
          errors.add('issuer_not_found_subject_spki_oid=$curSpkiAlgOid');
        }
        if (curAki != null) {
          errors.add('issuer_not_found_subject_aki_keyid=${_toHex(curAki)}');
          int akiMatchesRoots = 0;
          int akiMatchesChain = 0;
          int akiMatchesExtra = 0;
          final List<String> akiMatchRootsSubjects = <String>[];
          final List<String> akiMatchChainSubjects = <String>[];
          final List<String> akiMatchExtraSubjects = <String>[];
          for (final X509Certificate c in roots) {
            final Uint8List? ski = _tryGetSubjectKeyIdentifier(c);
            if (ski != null && _bytesEqual(ski, curAki)) {
              akiMatchesRoots++;
              final String? subj = c.c?.subject?.toString();
              if (subj != null && akiMatchRootsSubjects.length < 2) {
                akiMatchRootsSubjects.add(subj);
              }
            }
          }
          for (final X509Certificate c in chain) {
            final Uint8List? ski = _tryGetSubjectKeyIdentifier(c);
            if (ski != null && _bytesEqual(ski, curAki)) {
              akiMatchesChain++;
              final String? subj = c.c?.subject?.toString();
              if (subj != null && akiMatchChainSubjects.length < 2) {
                akiMatchChainSubjects.add(subj);
              }
            }
          }
          for (final X509Certificate c in extraCandidates) {
            final Uint8List? ski = _tryGetSubjectKeyIdentifier(c);
            if (ski != null && _bytesEqual(ski, curAki)) {
              akiMatchesExtra++;
              final String? subj = c.c?.subject?.toString();
              if (subj != null && akiMatchExtraSubjects.length < 2) {
                akiMatchExtraSubjects.add(subj);
              }
            }
          }
          errors.add('issuer_not_found_aki_matches_roots=$akiMatchesRoots');
          errors.add('issuer_not_found_aki_matches_chain=$akiMatchesChain');
          errors.add('issuer_not_found_aki_matches_extra=$akiMatchesExtra');
          if (akiMatchRootsSubjects.isNotEmpty) {
            errors.add('issuer_not_found_aki_match_roots_subjects=${akiMatchRootsSubjects.join('|')}');
          }
          if (akiMatchChainSubjects.isNotEmpty) {
            errors.add('issuer_not_found_aki_match_chain_subjects=${akiMatchChainSubjects.join('|')}');
          }
          if (akiMatchExtraSubjects.isNotEmpty) {
            errors.add('issuer_not_found_aki_match_extra_subjects=${akiMatchExtraSubjects.join('|')}');
          }

          // If we have at least one AKI match, try to verify against the first
          // matching candidate and record why it failed.
          if (akiMatchesExtra > 0) {
            try {
              final X509Certificate? firstMatch = extraCandidates.firstWhere(
                (c) {
                  final Uint8List? ski = _tryGetSubjectKeyIdentifier(c);
                  return ski != null && _bytesEqual(ski, curAki);
                },
              );
              if (firstMatch != null) {
                try {
                  current.verify(firstMatch.getPublicKey());
                  errors.add('issuer_not_found_aki_match_extra_verify_unexpectedly_ok');
                } catch (e) {
                  final String msg = e.toString();
                  final String shortMsg = msg.length > 160 ? msg.substring(0, 160) : msg;
                  errors.add('issuer_not_found_aki_match_extra_verify_error=${e.runtimeType}:$shortMsg');
                }
              }
            } catch (_) {
              // ignore
            }
          }
        }
        errors.add('issuer_not_found_candidates_roots=${roots.length}');
        errors.add('issuer_not_found_candidates_chain=${chain.length}');
        errors.add('issuer_not_found_candidates_extra=${extraCandidates.length}');
        return X509ChainValidationResult(trusted: false, errors: errors);
      }

      try {
        current.verify(issuer.getPublicKey());
      } catch (_) {
        final String? curSubject = current.c?.subject?.toString();
        final String? curIssuer = current.c?.issuer?.toString();
        errors.add('certificate_signature_invalid');
        if (curSubject != null) {
          errors.add('certificate_signature_invalid_subject=$curSubject');
        }
        if (curIssuer != null) {
          errors.add('certificate_signature_invalid_issuer=$curIssuer');
        }
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

    // Prefer AKI/SKI linking when available.
    // This is the most reliable way to pick the issuer when multiple
    // candidates share the same DN or when DN string formatting differs.
    final Uint8List? akiKeyId = _tryGetAuthorityKeyIdentifierKeyId(cert);
    if (akiKeyId != null) {
      final List<X509Certificate> akiMatches = <X509Certificate>[];
      for (final X509Certificate candidate in candidates) {
        final Uint8List? ski = _tryGetSubjectKeyIdentifier(candidate);
        if (ski == null) continue;
        if (_bytesEqual(ski, akiKeyId)) {
          akiMatches.add(candidate);
        }
      }

      if (akiMatches.isNotEmpty) {
        // Try DN-matching first inside AKI matches.
        if (issuer != null) {
          for (final X509Certificate candidate in akiMatches) {
            final String? subject = candidate.c?.subject?.toString();
            if (subject == null || subject != issuer) continue;
            try {
              cert.verify(candidate.getPublicKey());
              return candidate;
            } catch (_) {
              // Try next.
            }
          }
        }

        // Then just verify against AKI matches.
        for (final X509Certificate candidate in akiMatches) {
          try {
            cert.verify(candidate.getPublicKey());
            return candidate;
          } catch (_) {
            // Try next.
          }
        }
      }
    }

    // Primeiro: tente por DN (issuer == subject), mas confirme pelo menos um
    // candidato via verificação criptográfica. Isso evita escolher o emissor
    // errado quando existem múltiplos certificados com o mesmo subject (rekey,
    // renovação, cross-cert, etc.).
    if (issuer != null) {
      final List<X509Certificate> dnMatches = <X509Certificate>[];
      for (final X509Certificate candidate in candidates) {
        final String? subject = candidate.c?.subject?.toString();
        if (subject == null) continue;
        if (subject == issuer) {
          dnMatches.add(candidate);
        }
      }

      if (dnMatches.isNotEmpty) {
        for (final X509Certificate candidate in dnMatches) {
          try {
            cert.verify(candidate.getPublicKey());
            return candidate;
          } catch (_) {
            // Try next candidate with same DN.
          }
        }
      }
    }

    // Fallback: alguns certificados podem ter representações textuais de DN
    // diferentes (ordem/canonicalização). Para evitar falso-negativo de cadeia,
    // tentamos identificar o emissor pela verificação criptográfica.
    for (final X509Certificate candidate in candidates) {
      try {
        cert.verify(candidate.getPublicKey());
        return candidate;
      } catch (_) {
        // ignore
      }
    }

    return null;
  }
}
