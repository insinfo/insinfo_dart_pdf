import 'dart:convert';
import 'dart:typed_data';
import 'generated/icp_brasil_trust_store.dart';
import 'trusted_roots_provider.dart';

class IcpBrasilProvider implements TrustedRootsProvider {
  Future<List<Uint8List>> getTrustedRoots() async {
    return icpBrasilTrustStore.map((pem) {
      return _pemToDer(pem);
    }).toList();
  }

  @override
  Future<List<Uint8List>> getTrustedRootsDer() => getTrustedRoots();

  Uint8List _pemToDer(String pem) {
    var lines = pem.split('\n');
    lines = lines
        .where((line) => !line.startsWith('-----'))
        .map((line) => line.trim())
        .toList();
    return base64.decode(lines.join(''));
  }
}
