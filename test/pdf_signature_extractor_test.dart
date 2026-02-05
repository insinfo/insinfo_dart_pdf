import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

void main() {
  test('PdfSignatureExtractor extracts CMS and field mapping', () {
    final File file = File('test/assets/2 ass leonardo e mauricio.pdf');
    expect(file.existsSync(), isTrue,
        reason: 'Arquivo nao encontrado: ${file.path}');

    final Uint8List bytes = file.readAsBytesSync();

    final PdfSignatureExtractionReport report =
        PdfSignatureExtractor().extract(bytes);

    expect(report.signatures.length, 2);

    for (final PdfSignatureExtraction sig in report.signatures) {
      expect(sig.field.fieldName, isNotEmpty);
      expect(sig.byteRange.length, 4);
      expect(sig.pkcs7Der.isNotEmpty, isTrue);
      expect(sig.field.pageIndex, isNotNull);
      expect(sig.field.pageNumber, isNotNull);
      expect(sig.field.pageNumber, sig.field.pageIndex! + 1);
      expect(sig.contentsStart, isNotNull);
      expect(sig.contentsEnd, isNotNull);
      expect(sig.contentsEnd! > sig.contentsStart!, isTrue);
    }
  });

  test('CMS helpers extractAllSignatureContents/extractSignatureContentsAt', () {
    final File file = File('test/assets/2 ass leonardo e mauricio.pdf');
    expect(file.existsSync(), isTrue,
        reason: 'Arquivo nao encontrado: ${file.path}');

    final Uint8List bytes = file.readAsBytesSync();

    final PdfSignatureExtractionReport report =
        PdfSignatureExtractor().extract(bytes);
    final List<Uint8List> all = extractAllSignatureContents(bytes);

    expect(all.length, report.signatures.length);

    for (int i = 0; i < all.length; i++) {
      final Uint8List fromHelper = all[i];
      final Uint8List fromReport = report.signatures[i].pkcs7Der;
      expect(_bytesEqual(fromHelper, fromReport), isTrue);
    }

    final Uint8List at0 = extractSignatureContentsAt(bytes, 0);
    expect(_bytesEqual(at0, all[0]), isTrue);

    expect(() => extractSignatureContentsAt(bytes, -1), throwsRangeError);
    expect(() => extractSignatureContentsAt(bytes, all.length), throwsRangeError);
  });
}

bool _bytesEqual(List<int> a, List<int> b) {
  if (identical(a, b)) return true;
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
