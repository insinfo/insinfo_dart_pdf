import 'dart:convert';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

// Reading text out of a font that renames its characters.
//
// A `/Differences` array maps a byte in the content stream to a glyph name,
// and the extractor has to turn that name back into a character. Two hand
// written tables did most of it, and the complete Adobe glyph list -- four
// thousand entries, in font_file2.dart -- sat unused behind a branch that
// could not be reached: it asked whether a key was absent from a map the
// enclosing branch had just found it in. So a name outside the two small
// tables was read out literally, and `/uni00E7` came back as the four letters
// and four digits rather than as a c cedilla.
//
// The documents here are assembled byte by byte, because no writer in this
// library emits a `/Differences` array of glyph names; only other people's
// files do, and then the reader has to cope.

void main() {
  group('a /Differences array of glyph names', () {
    test('names the two small tables know are read as characters', () {
      expect(
        _extract(<String>['eacute', 'ccedilla', 'atilde']),
        'éçã',
      );
    });

    test('the algorithmic uniXXXX form is read as its code point', () {
      expect(_extract(<String>['uni00E7', 'uni00E9', 'uni20AC']), 'çé€');
    });

    test('the shorter uXXXX form is read too', () {
      expect(_extract(<String>['u00E7', 'u00E9']), 'çé');
    });

    test('a name only the full Adobe list knows is read', () {
      // Not in the hand written Latin or special tables, but in the glyph
      // list: this is what the dead branch was meant to catch.
      final String text = _extract(<String>['Omega', 'summation']);
      expect(
        text.runes.toList(),
        <int>[0x2126, 0x2211],
        reason:
            'the list gives Omega as the ohm sign, which is the code point '
            'the Adobe list itself names, and summation as the n-ary operator',
      );
    });

    test('a name nobody knows is left as written, not lost', () {
      final String text = _extract(<String>['glifoInventado']);
      expect(
        text,
        contains('glifoInventado'),
        reason:
            'the raw name is at least a clue about what the document meant; '
            'a null character is not',
      );
    });

    test('a mix of known and unknown names still reads the known ones', () {
      final String text = _extract(<String>[
        'eacute',
        'glifoInventado',
        'uni00E7',
      ]);
      expect(text, startsWith('é'));
      expect(text, endsWith('ç'));
    });

    test('a font whose glyphs are renamed does not break the page', () {
      final PdfDocument document = PdfDocument(
        inputBytes: _differencesDocument(<String>['eacute', 'ccedilla']),
      );
      addTearDown(document.dispose);
      expect(document.pages.count, 1);
      expect(PdfTextExtractor(document).extractTextLines(), isNotEmpty);
    });
  });

  group('a font with no /Differences', () {
    test('reads through its base encoding', () {
      final PdfDocument document = PdfDocument(
        inputBytes: _minimalDocument(
          fontDictionary:
              '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica '
              '/Encoding /WinAnsiEncoding >>',
          content: 'BT /F1 24 Tf 20 100 Td (Ola) Tj ET',
        ),
      );
      addTearDown(document.dispose);
      expect(PdfTextExtractor(document).extractText().trim(), 'Ola');
    });

    test('reads with no /Encoding entry at all', () {
      final PdfDocument document = PdfDocument(
        inputBytes: _minimalDocument(
          fontDictionary:
              '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
          content: 'BT /F1 24 Tf 20 100 Td (Ola) Tj ET',
        ),
      );
      addTearDown(document.dispose);
      expect(PdfTextExtractor(document).extractText().trim(), 'Ola');
    });
  });
}

/// Extracts the text of a document whose codes 65, 66, 67... are renamed to
/// [glyphNames], with a content stream that draws exactly those codes.
String _extract(List<String> glyphNames) {
  final PdfDocument document = PdfDocument(
    inputBytes: _differencesDocument(glyphNames),
  );
  final String text = PdfTextExtractor(document).extractText().trim();
  document.dispose();
  return text;
}

/// A one page document whose font renames the codes starting at `A` to
/// [glyphNames], and which draws one character per name.
List<int> _differencesDocument(List<String> glyphNames) {
  const int firstChar = 65; // 'A'
  final String codes = String.fromCharCodes(
    List<int>.generate(glyphNames.length, (int i) => firstChar + i),
  );
  final String differences =
      '$firstChar ${glyphNames.map((String n) => '/$n').join(' ')}';
  final String widths = List<String>.filled(glyphNames.length, '600').join(' ');
  return _minimalDocument(
    fontDictionary:
        '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica '
        '/FirstChar $firstChar /LastChar ${firstChar + glyphNames.length - 1} '
        '/Widths [$widths] '
        '/Encoding << /Type /Encoding /BaseEncoding /WinAnsiEncoding '
        '/Differences [$differences] >> >>',
    content: 'BT /F1 24 Tf 20 100 Td ($codes) Tj ET',
  );
}

/// Assembles a one page PDF around [fontDictionary] and [content], with a
/// cross reference table whose offsets are computed as it goes.
List<int> _minimalDocument({
  required String fontDictionary,
  required String content,
}) {
  final List<int> stream = latin1.encode(content);
  final List<List<int>> objects = <List<int>>[
    latin1.encode('<< /Type /Catalog /Pages 2 0 R >>'),
    latin1.encode('<< /Type /Pages /Kids [3 0 R] /Count 1 >>'),
    latin1.encode(
      '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] '
      '/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',
    ),
    <int>[
      ...latin1.encode('<< /Length ${stream.length} >>\nstream\n'),
      ...stream,
      ...latin1.encode('\nendstream'),
    ],
    latin1.encode(fontDictionary),
  ];

  final List<int> out = <int>[...latin1.encode('%PDF-1.7\n')];
  final List<int> offsets = <int>[];
  for (int i = 0; i < objects.length; i++) {
    offsets.add(out.length);
    out
      ..addAll(latin1.encode('${i + 1} 0 obj\n'))
      ..addAll(objects[i])
      ..addAll(latin1.encode('\nendobj\n'));
  }

  final int xref = out.length;
  out
    ..addAll(latin1.encode('xref\n0 ${objects.length + 1}\n'))
    ..addAll(latin1.encode('0000000000 65535 f \n'));
  for (final int offset in offsets) {
    out.addAll(
      latin1.encode('${offset.toString().padLeft(10, '0')} 00000 n \n'),
    );
  }
  out.addAll(
    latin1.encode(
      'trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\n'
      'startxref\n$xref\n%%EOF\n',
    ),
  );
  return out;
}
