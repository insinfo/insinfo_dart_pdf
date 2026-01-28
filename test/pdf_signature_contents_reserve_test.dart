import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

void main() {
  test('PdfSignature.contentsReserveSize controls /Contents placeholder',
      () async {
    const int customReserve = 12000;

    final PdfExternalSigningResult defaultPrepared =
        await _preparePdf(PdfSignature());
    final PdfExternalSigningResult customPrepared =
        await _preparePdf(PdfSignature(contentsReserveSize: customReserve));

    final int defaultLen = _contentsHexLength(defaultPrepared);
    final int customLen = _contentsHexLength(customPrepared);

    expect(customLen, greaterThan(defaultLen));

    final int inferredDefault = (defaultLen + 2) ~/ 4;
    final int expectedDelta = (customReserve - inferredDefault) * 4;
    expect(customLen - defaultLen, equals(expectedDelta));
  });
}

Future<PdfExternalSigningResult> _preparePdf(PdfSignature signature) async {
  final PdfDocument doc = PdfDocument();
  doc.pages.add().graphics.drawString(
        'Teste reserve size',
        PdfStandardFont(PdfFontFamily.helvetica, 12),
        bounds: Rect.fromLTWH(0, 0, 200, 40),
      );

  return PdfExternalSigning.preparePdf(
    inputBytes: Uint8List.fromList(await doc.save()),
    pageNumber: 1,
    bounds: Rect.fromLTWH(0, 0, 200, 40),
    fieldName: 'Signature1',
    signature: signature,
  );
}

int _contentsHexLength(PdfExternalSigningResult prepared) {
  return prepared.contentsEnd - prepared.contentsStart;
}
