import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf_server.dart' as pdf;
import 'package:test/test.dart';

/// Regression coverage for legacy `/adbe.pkcs7.sha1` signatures (ISO 32000-1
/// §12.8.3.3). These are NOT detached: the PKCS#7 encapsulated content
/// (eContent) is the SHA-1 digest of the signed ByteRange. Before the fix the
/// validator compared `digest(ByteRange)` directly against the (absent)
/// `messageDigest`, so these legitimate ICP-Brasil documents were reported as
/// having an invalid CMS signature and a broken ByteRange digest.
void main() {
  group('/adbe.pkcs7.sha1 legacy signatures', () {
    // Every legacy /adbe.pkcs7.sha1 sample in the corpus. All encode the
    // signature WITHOUT signed attributes, so integrity comes from the
    // encapsulated SHA-1 and the CMS signature is verified over that eContent.
    const samples = <String>[
      'test/assets/stf-fachin-1.pdf',
      'test/assets/decisao-4874-assinada.pdf',
      'test/assets/decisao-STF-prisao-Daniel-Silveira.pdf',
      'test/assets/downloadPeca.pdf',
      'test/assets/downloadPeca2013.pdf',
    ];

    for (final path in samples) {
      test('validates encapsulated SHA-1 ByteRange digest for ${_name(path)}',
          () async {
        final file = File(path);
        expect(file.existsSync(), isTrue,
            reason: 'File not found: ${file.path}');

        final report = await pdf.PdfSignatureValidator()
            .validateAllSignatures(file.readAsBytesSync());

        expect(report.signatures, isNotEmpty);
        final item = report.signatures.first;
        expect(item.validation.cmsSignatureValid, isTrue,
            reason: 'CMS signature must validate for ${_name(path)}');
        expect(item.validation.byteRangeDigestOk, isTrue,
            reason: 'ByteRange digest must match eContent for ${_name(path)}');
        expect(item.validation.documentIntact, isTrue,
            reason: 'Document must be intact for ${_name(path)}');
      });
    }

    test('detects tampering inside the signed ByteRange (no false "intact")',
        () async {
      final file = File('test/assets/stf-fachin-1.pdf');
      final bytes = file.readAsBytesSync();

      // Flip one byte well inside the first signed span. SHA1(ByteRange) must no
      // longer match the encapsulated eContent, so integrity must break.
      final tampered = Uint8List.fromList(bytes);
      tampered[10000] ^= 0xFF;

      final report = await pdf.PdfSignatureValidator()
          .validateAllSignatures(tampered);

      expect(report.signatures, isNotEmpty);
      final item = report.signatures.first;
      expect(item.validation.byteRangeDigestOk, isFalse);
      expect(item.validation.documentIntact, isFalse);
    });
  });
}

String _name(String path) => path.split('/').last;
