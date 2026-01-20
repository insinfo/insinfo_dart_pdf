import 'dart:typed_data';

import 'pdf_signature_dictionary.dart';
import 'pdf_signing_session.dart';

/// A signer implementation that uses a local private key (PEM format).
/// Uses RSA encryption and SHA-256 hashing.
class PdfLocalSigner implements IPdfSigner {
  /// Creates a signer using PEM encoded credentials.
  ///
  /// [privateKeyPem]: The RSA private key in PEM format.
  /// [certificatePem]: The signer's certificate in PEM format.
  /// [chainPems]: Optional list of CA certificates in PEM format.
  PdfLocalSigner({
    required this.privateKeyPem,
    required this.certificatePem,
    this.chainPems = const [],
  });

  final String privateKeyPem;
  final String certificatePem;
  final List<String> chainPems;

  @override
  Future<Uint8List> signDigest(Uint8List digest) async {
    return PdfCmsSigner.signDetachedSha256RsaFromPem(
      contentDigest: digest,
      privateKeyPem: privateKeyPem,
      certificatePem: certificatePem,
      chainPem: chainPems,
    );
  }
}
