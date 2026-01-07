import 'dart:convert';
import 'dart:typed_data';
import 'generated/serpro_trust_store.dart';

class SerproProvider {
  Future<List<Uint8List>> getTrustedRoots() async {
    return serproTrustStore.map((pem) {
      return _pemToDer(pem);
    }).toList();
  }

  Uint8List _pemToDer(String pem) {
    var lines = pem.split('\n');
    lines = lines
        .where((line) => !line.startsWith('-----'))
        .map((line) => line.trim())
        .toList();
    return base64.decode(lines.join(''));
  }
}
