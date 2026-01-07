import 'dart:io';
import 'dart:typed_data';

class ItiProvider {
  static const List<String> _certs = [
    'assets/truststore/iti/AutoridadeCertificadoraRaizdoGovernoFederaldoBrasilv1.crt',
    'assets/truststore/iti/ACFinaldoGovernoFederaldoBrasilv1.crt',
    'assets/truststore/iti/ACIntermediariadoGovernoFederaldoBrasilv1.crt',
  ];

  Future<List<Uint8List>> getTrustedRoots() async {
    final List<Uint8List> roots = [];
    for (final path in _certs) {
      final file = File(path);
      if (await file.exists()) {
        roots.add(await file.readAsBytes());
      } else {
        throw Exception('Certificate not found: $path');
      }
    }
    return roots;
  }
}
