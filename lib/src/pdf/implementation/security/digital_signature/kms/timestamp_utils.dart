import 'package:crypto/crypto.dart' as crypto;

/// Calculates the initial SHA-256 hash of the PDF document for the TSA request.
/// This mimics the behavior of how signatures are prepared, but specifically meant 
/// for sending the "imprint" to the TSA.
List<int> calculateHashForTsa(List<int> data) {
  // RFC 3161 expects MessageImprint.hashedMessage to be the digest bytes of the
  // content being timestamped. This helper returns SHA-256(data).
  //
  // Note: In a full PAdES flow, the caller must pass the *exact* bytes that must
  // be timestamped (e.g. signature value for signatureTimeStampToken, or the
  // signed ByteRange for DocTimeStamp).
  return crypto.sha256.convert(data).bytes;
}

