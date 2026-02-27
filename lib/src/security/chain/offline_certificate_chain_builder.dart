import '../../pdf/implementation/security/digital_signature/x509/x509_certificates.dart';
import '../../pdf/implementation/security/digital_signature/x509/x509_utils.dart';
import 'offline_certificate_chain_loader_stub.dart'
    if (dart.library.io) 'offline_certificate_chain_loader_io.dart'
    as cert_loader;

class OfflineCertificateChainBuilder {
  static List<X509Certificate> loadCertPoolFromDirectories(
    List<String> directories, {
    int maxAncestorLevels = 5,
  }) {
    return cert_loader.loadCertPoolFromDirectories(
      directories,
      maxAncestorLevels: maxAncestorLevels,
    );
  }

  static List<X509Certificate> buildCompleteChain({
    required List<String> signerCertsPem,
    required List<X509Certificate> certPool,
    int maxDepth = 10,
  }) {
    if (signerCertsPem.isEmpty) {
      throw ArgumentError.value(
        signerCertsPem,
        'signerCertsPem',
        'Must include at least one signer certificate',
      );
    }

    final X509Certificate leaf =
        X509Utils.parsePemCertificate(signerCertsPem.first);
    final List<X509Certificate> chain = <X509Certificate>[leaf];
    final Set<String> visitedSubjects = <String>{
      leaf.c?.subject?.toString() ?? '',
    };

    X509Certificate current = leaf;
    for (int depth = 0; depth < maxDepth; depth++) {
      final X509Certificate? issuer = X509Utils.findIssuer(current, certPool);
      if (issuer == null) {
        break;
      }

      final String issuerSubject = issuer.c?.subject?.toString() ?? '';
      if (issuerSubject.isNotEmpty && visitedSubjects.contains(issuerSubject)) {
        break;
      }

      chain.add(issuer);
      if (issuerSubject.isNotEmpty) {
        visitedSubjects.add(issuerSubject);
      }

      final String? issuerDn = issuer.c?.issuer?.toString();
      final String? subjectDn = issuer.c?.subject?.toString();
      if (issuerDn != null && subjectDn != null && issuerDn == subjectDn) {
        break;
      }

      current = issuer;
    }

    return chain;
  }
}
