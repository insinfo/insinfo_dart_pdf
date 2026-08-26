import 'dart:io';

import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_cross_table.dart';
import 'package:dart_pdf/src/pdf/implementation/pages/pdf_page.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_array.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_dictionary.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_stream.dart';
import 'package:dart_pdf/src/pdf/interfaces/pdf_interface.dart';
import 'package:test/test.dart';

import 'merge_fixtures.dart';

void main() {
  group('merge - content fidelity', () {
    test('the content stream is transferred byte for byte', () {
      final List<int> bytes = MergeFixtures.text(pageCount: 1, prefix: 'Exact');
      final PdfDocument source = reopen(bytes);
      final List<int> expected = _contentOf(source, 0);
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      source.dispose();

      final PdfDocument result = reopen(merged);
      expect(_contentOf(result, 0), equals(expected));
      result.dispose();
    });

    test('an embedded TrueType font keeps rendering after the merge', () {
      final File fontFile = File(_findFont());
      final PdfDocument document = PdfDocument();
      final PdfFont font = PdfTrueTypeFont(fontFile.readAsBytesSync(), 20);
      document.pages.add().graphics.drawString(
        'Embedded font',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(40, 40, 400, 40),
      );
      final List<int> bytes = document.saveSync();
      document.dispose();

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      final PdfDocument result = reopen(merged);
      expect(pageTextOf(result, 0), contains('Embedded font'));
      expect(
        _hasFontFile(result, 0),
        isTrue,
        reason: 'the font program travelled with the page',
      );
      result.dispose();
    });

    test('a resource shared by several pages is written once', () {
      final File fontFile = File(_findFont());
      final PdfDocument document = PdfDocument();
      final PdfFont font = PdfTrueTypeFont(fontFile.readAsBytesSync(), 20);
      for (int i = 0; i < 4; i++) {
        document.pages.add().graphics.drawString(
          'Shared $i',
          font,
          brush: PdfBrushes.black,
          bounds: const Rect.fromLTWH(40, 40, 400, 40),
        );
      }
      final List<int> bytes = document.saveSync();
      document.dispose();

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 4);
      final Set<IPdfPrimitive> fontPrograms = <IPdfPrimitive>{};
      for (int i = 0; i < result.pages.count; i++) {
        fontPrograms.addAll(_fontFilesOf(result, i));
      }
      expect(
        fontPrograms.length,
        1,
        reason: 'the four pages point at the same font program object',
      );
      result.dispose();
    });

    test('merging keeps the output smaller than the sum of the inputs', () {
      final File fontFile = File(_findFont());
      final PdfDocument document = PdfDocument();
      final PdfFont font = PdfTrueTypeFont(fontFile.readAsBytesSync(), 20);
      document.pages.add().graphics.drawString(
        'Repeated document',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(40, 40, 400, 40),
      );
      final List<int> bytes = document.saveSync();
      document.dispose();

      final List<List<int>> inputs = List<List<int>>.filled(5, bytes);
      final List<int> merged = PdfDocument.mergeSync(inputs);
      expect(
        merged.length,
        lessThan(bytes.length * 5),
        reason: 'the font program is not repeated five times',
      );
    });
  });
}

/// The concatenated content stream bytes of a page.
List<int> _contentOf(PdfDocument document, int pageIndex) {
  final PdfDictionary page =
      PdfPageHelper.getHelper(document.pages[pageIndex]).dictionary!;
  final IPdfPrimitive? contents = PdfCrossTable.dereference(page['Contents']);
  final List<int> bytes = <int>[];
  if (contents is PdfStream) {
    bytes.addAll(contents.getDecompressedData(false)!);
  } else if (contents is PdfArray) {
    for (int i = 0; i < contents.count; i++) {
      final IPdfPrimitive? entry = PdfCrossTable.dereference(contents[i]);
      if (entry is PdfStream) {
        bytes.addAll(entry.getDecompressedData(false)!);
      }
    }
  }
  return bytes;
}

/// Every `/FontFile*` stream reachable from the resources of a page.
Set<IPdfPrimitive> _fontFilesOf(PdfDocument document, int pageIndex) {
  final Set<IPdfPrimitive> programs = <IPdfPrimitive>{};
  final PdfDictionary page =
      PdfPageHelper.getHelper(document.pages[pageIndex]).dictionary!;
  final IPdfPrimitive? resources = PdfCrossTable.dereference(
    page['Resources'],
  );
  if (resources is! PdfDictionary) {
    return programs;
  }
  final IPdfPrimitive? fonts = PdfCrossTable.dereference(resources['Font']);
  if (fonts is! PdfDictionary) {
    return programs;
  }
  for (final IPdfPrimitive? value in fonts.items!.values) {
    final IPdfPrimitive? font = PdfCrossTable.dereference(value);
    if (font is PdfDictionary) {
      programs.addAll(_descendantFontFiles(font));
    }
  }
  return programs;
}

Set<IPdfPrimitive> _descendantFontFiles(PdfDictionary font) {
  final Set<IPdfPrimitive> programs = <IPdfPrimitive>{};
  final IPdfPrimitive? descendants = PdfCrossTable.dereference(
    font['DescendantFonts'],
  );
  final List<PdfDictionary> candidates = <PdfDictionary>[font];
  if (descendants is PdfArray) {
    for (int i = 0; i < descendants.count; i++) {
      final IPdfPrimitive? entry = PdfCrossTable.dereference(descendants[i]);
      if (entry is PdfDictionary) {
        candidates.add(entry);
      }
    }
  }
  for (final PdfDictionary candidate in candidates) {
    final IPdfPrimitive? descriptor = PdfCrossTable.dereference(
      candidate['FontDescriptor'],
    );
    if (descriptor is! PdfDictionary) {
      continue;
    }
    for (final String key in <String>[
      'FontFile',
      'FontFile2',
      'FontFile3',
    ]) {
      final IPdfPrimitive? program = PdfCrossTable.dereference(
        descriptor[key],
      );
      if (program != null) {
        programs.add(program);
      }
    }
  }
  return programs;
}

bool _hasFontFile(PdfDocument document, int pageIndex) =>
    _fontFilesOf(document, pageIndex).isNotEmpty;

/// A TrueType file available on the machine running the tests.
String _findFont() {
  const List<String> candidates = <String>[
    r'C:\Windows\Fonts\arial.ttf',
    r'C:\Windows\Fonts\calibri.ttf',
    r'C:\Windows\Fonts\segoeui.ttf',
    '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
    '/System/Library/Fonts/Supplemental/Arial.ttf',
  ];
  for (final String candidate in candidates) {
    if (File(candidate).existsSync()) {
      return candidate;
    }
  }
  throw StateError('No TrueType font found for the test.');
}
