import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/x509/x509_utils.dart';

class SignerClassification {
  SignerClassification({
    required this.providerLabel,
    required this.subject,
    required this.issuer,
    required this.commonName,
  });

  final String providerLabel;
  final String? subject;
  final String? issuer;
  final String? commonName;
}

/// Best-effort classification of common Brazilian e-signature provider chains.
///
/// This is string-based and intentionally heuristic.
SignerClassification classifySignerFromCertificatesPem(List<String> certsPem) {
  if (certsPem.isEmpty) {
    return SignerClassification(
      providerLabel: 'desconhecido',
      subject: null,
      issuer: null,
      commonName: null,
    );
  }

  String? leafSubject;
  String? leafIssuer;
  String? leafCn;

  final List<String> dns = <String>[];

  for (int i = 0; i < certsPem.length; i++) {
    try {
      final cert = X509Utils.parsePemCertificate(certsPem[i]);
      final String? subject = cert.c?.subject?.toString();
      final String? issuer = cert.c?.issuer?.toString();
      if (subject != null) dns.add(subject);
      if (issuer != null) dns.add(issuer);

      if (i == 0) {
        leafSubject = subject;
        leafIssuer = issuer;
        leafCn = _extractCn(subject);
      }
    } catch (_) {
      // ignore
    }
  }

  final String provider = _classifyProvider(dns);

  return SignerClassification(
    providerLabel: provider,
    subject: leafSubject,
    issuer: leafIssuer,
    commonName: leafCn,
  );
}

String? _extractCn(String? dn) {
  if (dn == null) return null;
  final RegExp r1 = RegExp(r'CN=([^,]+)');
  final Match? m1 = r1.firstMatch(dn);
  if (m1 != null) return m1.group(1)?.trim();

  final RegExp r2 = RegExp(r'CommonName=([^,]+)');
  final Match? m2 = r2.firstMatch(dn);
  if (m2 != null) return m2.group(1)?.trim();

  return null;
}

String _classifyProvider(Iterable<String> dns) {
  final String hay = dns.join(' | ').toLowerCase();

  bool has(String needle) => hay.contains(needle.toLowerCase());

  // gov.br
  if (has('gov-br') || has('gov.br') || has('governo federal do brasil')) {
    return 'gov.br';
  }

  // SERPRO (RFB)
  if (has('serpro') || has('serprorfb') || has('secretaria da receita federal do brasil - rfb')) {
    return 'serpro';
  }

  // Certisign / OAB chain frequently anchored at Certisign.
  if (has('certisign') || has('cert sign') || has('certsign') || has('ac oab g3') || has('oab g3')) {
    return 'certisign';
  }

  return 'desconhecido';
}
