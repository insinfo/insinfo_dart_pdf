import 'dart:convert';

import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_cross_table.dart';
import 'package:dart_pdf/src/pdf/implementation/pages/pdf_page.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_dictionary.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_name.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_number.dart';
import 'package:dart_pdf/src/pdf/interfaces/pdf_interface.dart';
import 'package:test/test.dart';

/// An 8x8 RGB PNG checkerboard, built byte by byte so the test carries no
/// binary asset.
const String _png =
    'iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAIAAABLbSncAAAAGUlEQVR42mO4o6GhEXAHk2TA'
    'KgokGQalDgBCmVABTq24VAAAAABJRU5ErkJggg==';

/// A 16x16 baseline grayscale JPEG, likewise built by hand.
const String _jpeg =
    '/9j/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB'
    'AQEBAQEBAQEBAQEBAQEBAQH/wAALCAAQABABAREA/8QAFAABAAAAAAAAAAAAAAAAAAAAAP/E'
    'ABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AAP/Z';

void main() {
  group('image decoders', () {
    test('a PNG is read and reports its size', () {
      final PdfBitmap bitmap = PdfBitmap(base64.decode(_png));
      expect(bitmap.width, 8);
      expect(bitmap.height, 8);
    });

    test('a JPEG is read and reports its size', () {
      final PdfBitmap bitmap = PdfBitmap(base64.decode(_jpeg));
      expect(bitmap.width, 16);
      expect(bitmap.height, 16);
    });

    test('a drawn PNG becomes an XObject on the page', () {
      final List<int> bytes = _documentWithImage(base64.decode(_png));
      final PdfDocument document = PdfDocument(inputBytes: bytes);
      addTearDown(document.dispose);
      final Map<String, PdfDictionary> images = _imageXObjectsOf(document, 0);
      expect(images, isNotEmpty);
      final PdfDictionary image = images.values.first;
      expect((image['Width']! as PdfNumber).value, 8);
      expect((image['Height']! as PdfNumber).value, 8);
    });

    test('a drawn JPEG keeps its DCTDecode filter', () {
      final List<int> bytes = _documentWithImage(base64.decode(_jpeg));
      final PdfDocument document = PdfDocument(inputBytes: bytes);
      addTearDown(document.dispose);
      final PdfDictionary image = _imageXObjectsOf(document, 0).values.first;
      expect(
        _filterNamesOf(image),
        contains('DCTDecode'),
        reason: 'JPEG data is embedded as is, not re-encoded',
      );
    });

    test('images survive a merge', () {
      final List<int> png = _documentWithImage(base64.decode(_png));
      final List<int> jpeg = _documentWithImage(base64.decode(_jpeg));
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[png, jpeg]);

      final PdfDocument result = PdfDocument(inputBytes: merged);
      addTearDown(result.dispose);
      expect(result.pages.count, 2);
      expect(_imageXObjectsOf(result, 0), isNotEmpty);
      expect(_imageXObjectsOf(result, 1), isNotEmpty);
      expect(
        _filterNamesOf(_imageXObjectsOf(result, 1).values.first),
        contains('DCTDecode'),
      );
    });

    test('the same image drawn twice is stored once', () {
      final PdfDocument document = PdfDocument();
      final PdfBitmap bitmap = PdfBitmap(base64.decode(_png));
      final PdfPage page = document.pages.add();
      page.graphics.drawImage(bitmap, const Rect.fromLTWH(0, 0, 50, 50));
      page.graphics.drawImage(bitmap, const Rect.fromLTWH(60, 0, 50, 50));
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      expect(_imageXObjectsOf(result, 0).length, 1);
    });
  });

  group('lists', () {
    test('an ordered list renders its items numbered', () {
      final List<int> bytes = _documentWithList(
        PdfOrderedList(
          text: 'first\nsecond\nthird',
          font: PdfStandardFont(PdfFontFamily.helvetica, 12),
        ),
      );
      final PdfDocument document = PdfDocument(inputBytes: bytes);
      addTearDown(document.dispose);
      final String text = PdfTextExtractor(
        document,
      ).extractText(startPageIndex: 0, endPageIndex: 0);
      expect(text, contains('first'));
      expect(text, contains('third'));
      expect(text, contains('1'));
    });

    test('an unordered list renders its items', () {
      final List<int> bytes = _documentWithList(
        PdfUnorderedList(
          text: 'alpha\nbeta',
          font: PdfStandardFont(PdfFontFamily.helvetica, 12),
        ),
      );
      final PdfDocument document = PdfDocument(inputBytes: bytes);
      addTearDown(document.dispose);
      final String text = PdfTextExtractor(
        document,
      ).extractText(startPageIndex: 0, endPageIndex: 0);
      expect(text, contains('alpha'));
      expect(text, contains('beta'));
    });

    test('the numbering style is honoured', () {
      final List<int> bytes = _documentWithList(
        PdfOrderedList(
          text: 'one\ntwo',
          style: PdfNumberStyle.upperRoman,
          font: PdfStandardFont(PdfFontFamily.helvetica, 12),
        ),
      );
      final PdfDocument document = PdfDocument(inputBytes: bytes);
      addTearDown(document.dispose);
      final String text = PdfTextExtractor(
        document,
      ).extractText(startPageIndex: 0, endPageIndex: 0);
      expect(text, contains('II'), reason: 'the second item is roman two');
    });

    test('a nested list draws both levels', () {
      final PdfOrderedList outer = PdfOrderedList(
        text: 'parent one\nparent two',
        font: PdfStandardFont(PdfFontFamily.helvetica, 12),
      );
      outer.items[0].subList = PdfUnorderedList(
        text: 'child a\nchild b',
        font: PdfStandardFont(PdfFontFamily.helvetica, 10),
      );
      final List<int> bytes = _documentWithList(outer);

      final PdfDocument document = PdfDocument(inputBytes: bytes);
      addTearDown(document.dispose);
      final String text = PdfTextExtractor(
        document,
      ).extractText(startPageIndex: 0, endPageIndex: 0);
      expect(text, contains('parent one'));
      expect(text, contains('child a'));
      expect(text, contains('parent two'));
    });

    test('a list survives a merge', () {
      final List<int> bytes = _documentWithList(
        PdfOrderedList(
          text: 'kept one\nkept two',
          font: PdfStandardFont(PdfFontFamily.helvetica, 12),
        ),
      );
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      final PdfDocument result = PdfDocument(inputBytes: merged);
      addTearDown(result.dispose);
      expect(
        PdfTextExtractor(
          result,
        ).extractText(startPageIndex: 0, endPageIndex: 0),
        contains('kept two'),
      );
    });
  });
}

List<int> _documentWithImage(List<int> imageBytes) {
  final PdfDocument document = PdfDocument();
  document.pages.add().graphics.drawImage(
    PdfBitmap(imageBytes),
    const Rect.fromLTWH(20, 20, 100, 100),
  );
  final List<int> bytes = document.saveSync();
  document.dispose();
  return bytes;
}

List<int> _documentWithList(PdfList list) {
  final PdfDocument document = PdfDocument();
  list.draw(
    page: document.pages.add(),
    bounds: const Rect.fromLTWH(20, 20, 400, 500),
  );
  final List<int> bytes = document.saveSync();
  document.dispose();
  return bytes;
}

/// The `/XObject` entries of a page whose subtype is `/Image`.
Map<String, PdfDictionary> _imageXObjectsOf(PdfDocument document, int index) {
  final Map<String, PdfDictionary> images = <String, PdfDictionary>{};
  final PdfDictionary page =
      PdfPageHelper.getHelper(document.pages[index]).dictionary!;
  final IPdfPrimitive? resources = PdfCrossTable.dereference(
    page['Resources'],
  );
  if (resources is! PdfDictionary) {
    return images;
  }
  final IPdfPrimitive? xObjects = PdfCrossTable.dereference(
    resources['XObject'],
  );
  if (xObjects is! PdfDictionary) {
    return images;
  }
  xObjects.items!.forEach((PdfName? name, IPdfPrimitive? value) {
    final IPdfPrimitive? object = PdfCrossTable.dereference(value);
    if (object is! PdfDictionary) {
      return;
    }
    final IPdfPrimitive? subtype = PdfCrossTable.dereference(
      object['Subtype'],
    );
    if (subtype is PdfName && subtype.name == 'Image') {
      images[name!.name!] = object;
    }
  });
  return images;
}

List<String> _filterNamesOf(PdfDictionary image) {
  final IPdfPrimitive? filter = PdfCrossTable.dereference(image['Filter']);
  if (filter is PdfName) {
    return <String>[filter.name!];
  }
  return <String>[];
}
