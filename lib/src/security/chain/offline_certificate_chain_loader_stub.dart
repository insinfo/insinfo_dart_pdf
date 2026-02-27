import '../../pdf/implementation/security/digital_signature/x509/x509_certificates.dart';

List<X509Certificate> loadCertPoolFromDirectories(
  List<String> directories, {
  int maxAncestorLevels = 5,
}) {
  throw UnsupportedError(
    'Loading certificates from directories requires dart:io and is not '
    'available on this platform.',
  );
}
