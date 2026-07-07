import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart' as pdf;
import 'package:test/test.dart';

void main() {
  group('VISTO 24822 PDF signature compliance', () {
    test('extracts CMS by DER length and validates ICP-Brasil signature',
        () async {
      final File reportFile =
          _findAssetByPrefix('Relatorio - VISTO 24822-2026 PL 055');
      expect(reportFile.existsSync(), isTrue);

      final File file = _findAssetByPrefix('VISTO 24822-2026 PL 055');

      final Uint8List bytes = file.readAsBytesSync();
      final List<Uint8List> contents = pdf.extractAllSignatureContents(bytes);

      expect(contents, hasLength(1));
      expect(
          contents.single.length, _readDerElementTotalLength(contents.single));
      expect(contents.single.last, 0x00);

      final pdf.PdfSignatureValidationReport report =
          await pdf.PdfSignatureValidator().validateAllSignatures(
        bytes,
        useEmbeddedIcpBrasil: true,
        fetchCrls: false,
        strictRevocation: false,
      );

      expect(report.signatures, hasLength(1));
      final pdf.PdfSignatureValidationItem sig = report.signatures.single;

      expect(sig.validation.cmsSignatureValid, isTrue);
      expect(sig.validation.byteRangeDigestOk, isTrue);
      expect(sig.validation.documentIntact, isTrue);
      expect(sig.chainTrusted, isTrue);
      expect(sig.validation.certsPem.length, greaterThanOrEqualTo(4));
      expect(
        sig.signerInfo?.commonName,
        contains('THAIS BRAGANCA MELLO COELHO'),
      );
    });
  });
}

File _findAssetByPrefix(String prefix) {
  return Directory('test/assets').listSync().whereType<File>().firstWhere(
        (File f) =>
            f.path.split(Platform.pathSeparator).last.startsWith(prefix),
      );
}

int _readDerElementTotalLength(Uint8List bytes) {
  var cursor = 1;
  if ((bytes[0] & 0x1F) == 0x1F) {
    while (cursor < bytes.length) {
      final int b = bytes[cursor++];
      if ((b & 0x80) == 0) break;
    }
  }

  final int lenByte = bytes[cursor++];
  if ((lenByte & 0x80) == 0) {
    return cursor + lenByte;
  }

  final int lenLen = lenByte & 0x7F;
  var length = 0;
  for (var i = 0; i < lenLen; i++) {
    length = (length << 8) | bytes[cursor++];
  }
  return cursor + length;
}
