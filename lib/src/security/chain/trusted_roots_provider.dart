import 'dart:typed_data';

/// Common interface for trusted root certificate providers.
///
/// This lets consumers plug in their own providers (e.g. load PEM/DER from a
/// folder, remote endpoint, OS store, etc.) and feed them into validation.
abstract class TrustedRootsProvider {
  /// Returns trusted root certificates in DER form.
  Future<List<Uint8List>> getTrustedRootsDer();
}

/// Combines multiple providers into one.
class CompositeTrustedRootsProvider implements TrustedRootsProvider {
  CompositeTrustedRootsProvider(this.providers);

  final List<TrustedRootsProvider> providers;

  @override
  Future<List<Uint8List>> getTrustedRootsDer() async {
    final List<Uint8List> out = <Uint8List>[];
    for (final TrustedRootsProvider p in providers) {
      out.addAll(await p.getTrustedRootsDer());
    }
    return out;
  }
}
