import '../enum.dart';

/// Interface for external signing to a PDF document
class IPdfExternalSigner {
  //Fields
  // ignore: prefer_final_fields
  DigestAlgorithm _hashAlgorithm = DigestAlgorithm.sha256;

  //Properties
  /// Get HashAlgorithm.
  DigestAlgorithm get hashAlgorithm => _hashAlgorithm;

  //Public methods
  /// Asynchronously returns signed message digest.
  Future<SignerResult?> sign(List<int> message) async {
    throw UnimplementedError(
      'IPdfExternalSigner.sign() must be implemented by the caller. '
      'Provide a subclass that signs the provided bytes and returns SignerResult.',
    );
  }

  /// Synchronously returns signed message digest.
  SignerResult? signSync(List<int> message) {
    throw UnimplementedError(
      'IPdfExternalSigner.signSync() must be implemented by the caller. '
      'Provide a subclass that signs the provided bytes and returns SignerResult.',
    );
  }
}

/// External signing result
class SignerResult {
  /// Initializes a new instance of the [SignerResult] class with signed data.
  SignerResult(this.signedData);

  /// Gets and sets the signed Message Digest.
  late List<int> signedData;
}
