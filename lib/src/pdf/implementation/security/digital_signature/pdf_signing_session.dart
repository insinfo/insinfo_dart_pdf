import 'dart:typed_data';

import '../../../../flutter/ui.dart';
import '../../graphics/pdf_graphics.dart';
import 'external_pdf_signature.dart';
import 'pdf_signature.dart';

/// Interface for a signer that produces a detached PKCS7 signature (DER).
abstract class IPdfSigner {
  /// Sign the SHA-256 [digest] of the content.
  /// Returns the CMS SignedData (PKCS#7) detached signature in DER format.
  Future<Uint8List> signDigest(Uint8List digest);
}

/// A high-level helper to transform a PDF into a signed PDF.
class PdfSigningSession {
  /// Signs a PDF document in a single flow.
  ///
  /// This method encapsulates the prepare -> digest -> sign -> embed workflow.
  ///
  /// [pdfBytes]: Input PDF.
  /// [signer]: The implementation that provides the PKCS7 signature.
  /// [pageNumber]: 1-based page number where the signature will be placed.
  /// [bounds]: Position and size of the signature field.
  /// [fieldName]: Name of the signature field.
  /// [signature]: Metadata for the signature dictionary (reason, location, etc).
  /// [drawAppearance]: Optional callback to draw the visual signature.
  /// [publicCertificates]: Optional list of certificates to embed in the DSS (if supported by external signer flow).
  static Future<Uint8List> signPdf({
    required Uint8List pdfBytes,
    required IPdfSigner signer,
    required int pageNumber,
    required Rect bounds,
    required String fieldName,
    PdfSignature? signature,
    List<List<int>>? publicCertificates,
    void Function(PdfGraphics graphics, Rect bounds)? drawAppearance,
  }) async {
    // 1. Prepare the PDF (reserve space, add field)
    final PdfExternalSigningResult result = await PdfExternalSigning.preparePdf(
      inputBytes: pdfBytes,
      pageNumber: pageNumber,
      bounds: bounds,
      fieldName: fieldName,
      signature: signature,
      publicCertificates: publicCertificates,
      drawAppearance: drawAppearance,
    );

    // 2. Compute the digest of the prepared PDF's byte range
    final Uint8List digest = PdfExternalSigning.computeByteRangeDigest(
      result.preparedPdfBytes,
      result.byteRange,
    );

    // 3. Request the signature (PKCS7) from the signer
    final Uint8List pkcs7 = await signer.signDigest(digest);

    // 4. Embed the signature
    return PdfExternalSigning.embedSignature(
      preparedPdfBytes: result.preparedPdfBytes,
      pkcs7Bytes: pkcs7,
    );
  }
}
