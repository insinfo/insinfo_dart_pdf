import 'dart:io';
import 'dart:typed_data';
import '../keystore/bks_reader.dart';

class IcpBrasilProvider {
  // Assuming the calling process runs from project root
  static const String _keystorePath = 'assets/truststore/icp_brasil/cadeiasicpbrasil.bks';
  static const String _password = 'serprosigner';

  Future<List<Uint8List>> getTrustedRoots() async {
    final file = File(_keystorePath);
    if (!await file.exists()) {
       throw Exception('ICP Brasil KeyStore not found at $_keystorePath.');
    }
    final bytes = await file.readAsBytes();
    final reader = BksReader(bytes, _password);
    return reader.readCertificates();
  }
}
