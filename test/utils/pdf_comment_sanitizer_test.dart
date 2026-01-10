import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

void main() {
  test('sanitizePdfLeadingPercentComments scrubs verbose header comments safely',
      () {
    final path = 'test/assets/slow_pdf.pdf';
    final bytes = Uint8List.fromList(File(path).readAsBytesSync());

    final result = sanitizePdfLeadingPercentComments(bytes);

    // Must keep size identical to preserve offsets.
    expect(result.bytes.length, bytes.length);

    // Should scrub at least some header lines for this fixture.
    expect(result.scrubbedLineCount, greaterThan(0));

    // The specific verbose markers should no longer be present in the leading header area.
    final headerPrefix = String.fromCharCodes(
      result.bytes.sublist(0, 4096),
    );
    expect(headerPrefix.contains('Verbose dart_pdf'), isFalse);
    expect(headerPrefix.contains('Producer https://github.com/DavBfr/dart_pdf'),
        isFalse);

    // Must keep PDF header.
    expect(headerPrefix.startsWith('%PDF-'), isTrue);
  });
}
