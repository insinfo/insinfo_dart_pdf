import 'dart:io';
import 'dart:typed_data';

class SerproProvider {
  static const List<String> _certs = [
    'assets/truststore/serpro/AutoridadeCertificadoraAssinadorSERPROFinal.crt',
    'assets/truststore/serpro/AutoridadeCertificadoraAssinadorSERPRORaiz.crt',
    'assets/truststore/serpro/AutoridadeCertificadoraRaizdoSERPRO.crt',
    'assets/truststore/serpro/AutoridadeCertificadoraFinaldoSERPRO.crt',
    'assets/truststore/serpro/AutoridadeCertificadoraRaizdoSERPROSoftware.crt',
    'assets/truststore/serpro/AutoridadeCertificadoraFinaldoSERPROSoftware.crt',
    'assets/truststore/serpro/NeoSignerSERPRO.crt' // Was not in the java list but was in folder?
    // Java list:
    // AutoridadeCertificadoraAssinadorSERPRORaiz
    // AutoridadeCertificadoraAssinadorSERPROFinal
    // AutoridadeCertificadoraRaizdoSERPRO
    // AutoridadeCertificadoraFinaldoSERPRO
    // AutoridadeCertificadoraRaizdoSERPROSoftware
    // AutoridadeCertificadoraFinaldoSERPROSoftware
  ];

  Future<List<Uint8List>> getTrustedRoots() async {
    final List<Uint8List> roots = [];
    for (final path in _certs) {
      final file = File(path);
      if (await file.exists()) {
        roots.add(await file.readAsBytes());
      } else {
         // Some might be optional or missing depending on copy? 
         // But Java code lists them explicitly.
         // Warning instead of throw?
         print('Warning: Serpro Certificate not found: $path');
      }
    }
    return roots;
  }
}
