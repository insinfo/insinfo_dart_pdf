import 'dart:convert';
import 'dart:typed_data';

import 'generated/govbr_trust_store.dart';
import 'trusted_roots_provider.dart';

/// Trusted roots for Gov.br chain.
///
/// Note: the trust store includes intermediate certificates too; the validator
/// filters self-signed certs as trust anchors and keeps the rest as candidates.
class GovBrProvider implements TrustedRootsProvider {
  Future<List<Uint8List>> getTrustedRoots() async {
    return govBrTrustStore.map(_pemToDer).toList(growable: false);
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
