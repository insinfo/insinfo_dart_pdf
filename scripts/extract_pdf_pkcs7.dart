import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/external_pdf_signature.dart'
    show PdfExternalSigning;

void main(List<String> args) {
  if (args.isEmpty) {
    stderr.writeln('Usage: dart run scripts/extract_pdf_pkcs7.dart <pdfPath> [outDerPath]');
    exitCode = 2;
    return;
  }

  final String pdfPath = args[0];
  final String outPath = args.length >= 2 ? args[1] : '$pdfPath.pkcs7.der';

  final File f = File(pdfPath);
  if (!f.existsSync()) {
    stderr.writeln('PDF not found: $pdfPath');
    exitCode = 2;
    return;
  }

  final Uint8List bytes = Uint8List.fromList(f.readAsBytesSync());

  final contents = PdfExternalSigning.findContentsRange(bytes);
  final int start = contents.start;
  final int end = contents.end;

  final String hex = String.fromCharCodes(bytes.sublist(start, end)).trim();
  final String cleaned = hex.replaceAll(RegExp(r'[^0-9A-Fa-f]'), '');
  final List<int> der = _hexToBytes(cleaned);

  File(outPath).writeAsBytesSync(der, flush: true);
  stdout.writeln('Wrote DER: $outPath (${der.length} bytes)');
}

List<int> _hexToBytes(String hex) {
  final String h = (hex.length.isOdd) ? '0$hex' : hex;
  final List<int> out = <int>[];
  for (int i = 0; i < h.length; i += 2) {
    final int byte = int.parse(h.substring(i, i + 2), radix: 16);
    // The placeholder is padded with hex '0' characters, which decode to 0x00 bytes.
    out.add(byte);
  }
  while (out.isNotEmpty && (out.last == 0x00 || out.last == 0x30)) {
    out.removeLast();
  }
  return out;
}
