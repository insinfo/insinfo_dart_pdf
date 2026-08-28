import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

// Everything this library claims it can do to a document that came from a
// file, proved the only way that counts: change it, save it, open the saved
// bytes again, and read the change back.
//
// Checking the in-memory object after the change proves nothing — the object
// is the one that was just assigned to. The question is always whether the
// change reached the bytes and can be found again by a reader that never saw
// the editing session.
//
// Nothing here reaches into the implementation: `package:dart_pdf/pdf.dart`
// is the whole import list, so each test doubles as the example for the
// capability it covers.

/// A font belongs to the document it is drawn into and is disposed with it,
/// so every test builds its own.
PdfFont get font => PdfStandardFont(PdfFontFamily.helvetica, 18);

void main() {
  group('drawing over a loaded page', () {
    test('appendGraphics adds content without losing what was there', () {
      final PdfDocument document = _load(_textDocument(pageCount: 2));
      document.pages[0].appendGraphics().drawString(
        'OVERLAY',
        font,
        brush: PdfBrushes.red,
        bounds: const Rect.fromLTWH(60, 300, 300, 40),
      );
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      expect(_textOf(result, 0), contains('OVERLAY'));
      expect(
        _textOf(result, 0),
        contains('Page 1'),
        reason: 'the content the page arrived with is still there',
      );
      expect(
        _textOf(result, 1),
        isNot(contains('OVERLAY')),
        reason: 'only the page that was drawn on changed',
      );
    });

    test('the appended drawing starts from a clean graphics state', () {
      // A page whose content stream ends inside an unrestored `q`: anything
      // appended without a guard would inherit that transform and land
      // somewhere else entirely.
      final PdfDocument document = _load(_pageWithUnbalancedState());
      document.pages[0].appendGraphics().drawString(
        'GUARDED',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(20, 40, 200, 24),
      );
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      expect(_textOf(result, 0), contains('GUARDED'));
      final List<TextGlyph> placed = PdfTextExtractor(result)
          .extractTextLines(startPageIndex: 0, endPageIndex: 0)
          .expand((TextLine line) => line.wordCollection)
          .expand((TextWord word) => word.glyphs)
          .where((TextGlyph glyph) => glyph.text.trim().isNotEmpty)
          .where(
            (TextGlyph glyph) =>
                glyph.bounds.top > 30 && glyph.bounds.top < 75,
          )
          .toList();
      expect(
        placed,
        isNotEmpty,
        reason:
            'the string sits where it was asked to, not where the state the '
            'page left open would have dragged it',
      );
    });

    test('it can be called more than once, and again after a round trip', () {
      final PdfDocument first = _load(_textDocument(pageCount: 1));
      first.pages[0].appendGraphics().drawString(
        'FIRST',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(40, 200, 200, 24),
      );
      first.pages[0].appendGraphics().drawString(
        'SECOND',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(40, 260, 200, 24),
      );
      final List<int> once = first.saveSync();
      first.dispose();

      final PdfDocument second = _load(once);
      second.pages[0].appendGraphics().drawString(
        'THIRD',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(40, 320, 200, 24),
      );
      final PdfDocument result = _saveAndReopen(second);
      addTearDown(result.dispose);

      final String text = _textOf(result, 0);
      expect(text, contains('Page 1'));
      expect(text, contains('FIRST'));
      expect(text, contains('SECOND'));
      expect(
        text,
        contains('THIRD'),
        reason: 'a document already stamped once can be stamped again',
      );
    });

    test('page.graphics also draws on a loaded page', () {
      // The older path, kept working: it joins the page's default layer
      // instead of opening a new one.
      final PdfDocument document = _load(_textDocument(pageCount: 1));
      document.pages[0].graphics.drawString(
        'DEFAULT LAYER',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(40, 400, 300, 24),
      );
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      expect(_textOf(result, 0), contains('DEFAULT LAYER'));
      expect(_textOf(result, 0), contains('Page 1'));
    });
  });

  group('inserting a page', () {
    test('the new page lands at the index asked for', () {
      final PdfDocument document = _load(_textDocument(pageCount: 3));
      document.pages.insert(1).graphics.drawString(
        'INSERTED',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(40, 40, 300, 24),
      );
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      expect(result.pages.count, 4);
      expect(_textOf(result, 0), contains('Page 1'));
      expect(_textOf(result, 1), contains('INSERTED'));
      expect(
        _textOf(result, 2),
        contains('Page 2'),
        reason: 'the pages after the insertion point only shifted',
      );
      expect(_textOf(result, 3), contains('Page 3'));
    });

    test('a page can be inserted before the first one', () {
      final PdfDocument document = _load(_textDocument(pageCount: 2));
      document.pages.insert(0).graphics.drawString(
        'COVER',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(40, 40, 300, 24),
      );
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      expect(result.pages.count, 3);
      expect(_textOf(result, 0), contains('COVER'));
      expect(_textOf(result, 1), contains('Page 1'));
    });
  });

  group('removing a page', () {
    test('removeAt drops the page and the content it carried', () {
      final PdfDocument document = _load(_textDocument(pageCount: 3));
      document.pages.removeAt(1);
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      expect(result.pages.count, 2);
      expect(_textOf(result, 0), contains('Page 1'));
      expect(_textOf(result, 1), contains('Page 3'));
      expect(
        PdfTextExtractor(result).extractText(),
        isNot(contains('Page 2')),
        reason: 'the removed page is gone from the whole document, not just '
            'from the page list',
      );
    });

    test('remove drops the page object it is given', () {
      final PdfDocument document = _load(_textDocument(pageCount: 3));
      document.pages.remove(document.pages[2]);
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      expect(result.pages.count, 2);
      expect(PdfTextExtractor(result).extractText(), isNot(contains('Page 3')));
    });
  });

  group('rotating a page', () {
    for (final PdfPageRotateAngle angle in <PdfPageRotateAngle>[
      PdfPageRotateAngle.rotateAngle90,
      PdfPageRotateAngle.rotateAngle180,
      PdfPageRotateAngle.rotateAngle270,
    ]) {
      test('$angle survives the round trip', () {
        final PdfDocument document = _load(_textDocument(pageCount: 2));
        document.pages[0].rotation = angle;
        final PdfDocument result = _saveAndReopen(document);
        addTearDown(result.dispose);

        expect(result.pages[0].rotation, angle);
        expect(
          result.pages[1].rotation,
          PdfPageRotateAngle.rotateAngle0,
          reason: 'rotation applies to the page it was set on, not the file',
        );
      });
    }

    test('the rotated page keeps its content', () {
      final PdfDocument document = _load(_textDocument(pageCount: 1));
      document.pages[0].rotation = PdfPageRotateAngle.rotateAngle90;
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      expect(_textOf(result, 0), contains('Page 1'));
    });
  });

  group('changing a form field value', () {
    test('a text box written on a loaded document keeps the new text', () {
      final PdfDocument document = _load(_formDocument());
      (_fieldsByName(document)['nome']! as PdfTextBoxField).text = 'depois';
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      final PdfTextBoxField field =
          _fieldsByName(result)['nome']! as PdfTextBoxField;
      expect(field.text, 'depois');
    });

    test('a checkbox keeps the state it was toggled to', () {
      final PdfDocument document = _load(_formDocument());
      (_fieldsByName(document)['aceite']! as PdfCheckBoxField).isChecked = true;
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      expect(
        (_fieldsByName(result)['aceite']! as PdfCheckBoxField).isChecked,
        isTrue,
      );
    });

    test('a combo box keeps the item that was selected', () {
      final PdfDocument document = _load(_formDocument());
      (_fieldsByName(document)['cidade']! as PdfComboBoxField).selectedIndex =
          1;
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      final PdfComboBoxField combo =
          _fieldsByName(result)['cidade']! as PdfComboBoxField;
      expect(combo.selectedIndex, 1);
      expect(combo.selectedValue, 'macae');
    });

    test('the other fields are left alone', () {
      final PdfDocument document = _load(_formDocument());
      (_fieldsByName(document)['nome']! as PdfTextBoxField).text = 'so este';
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      final Map<String, PdfField> fields = _fieldsByName(result);
      expect(fields.keys, containsAll(<String>['nome', 'aceite', 'cidade']));
      expect((fields['aceite']! as PdfCheckBoxField).isChecked, isFalse);
      expect((fields['cidade']! as PdfComboBoxField).selectedIndex, 0);
    });
  });

  group('annotations on a loaded page', () {
    test('an annotation added to a loaded page is in the saved file', () {
      final PdfDocument document = _load(_textDocument(pageCount: 2));
      document.pages[0].annotations.add(
        PdfRectangleAnnotation(
          const Rect.fromLTWH(40, 500, 160, 60),
          'added after loading',
          color: PdfColor(255, 0, 0),
          setAppearance: true,
        ),
      );
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      expect(result.pages[0].annotations.count, 1);
      expect(result.pages[0].annotations[0].text, 'added after loading');
      expect(
        result.pages[1].annotations.count,
        0,
        reason: 'the annotation belongs to the page it was added to',
      );
    });

    test('an annotation removed from a loaded page is gone from the file', () {
      final PdfDocument document = _load(_annotatedDocument());
      expect(
        document.pages[0].annotations.count,
        2,
        reason: 'the fixture is what the removal has to work from',
      );
      final PdfAnnotation doomed = document.pages[0].annotations[0];
      document.pages[0].annotations.remove(doomed);
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      expect(result.pages[0].annotations.count, 1);
      expect(
        result.pages[0].annotations[0].text,
        'segunda',
        reason: 'the one that was not removed is the one that stayed',
      );
    });
  });

  group('document metadata', () {
    test('every information field survives the round trip', () {
      final PdfDocument document = _load(_textDocument(pageCount: 1));
      document.documentInformation
        ..title = 'Processo 24822'
        ..author = 'Isaque Neves'
        ..subject = 'Fase 0'
        ..keywords = 'pdf, edicao, round trip'
        ..creator = 'dart_pdf';
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      expect(result.documentInformation.title, 'Processo 24822');
      expect(result.documentInformation.author, 'Isaque Neves');
      expect(result.documentInformation.subject, 'Fase 0');
      expect(result.documentInformation.keywords, 'pdf, edicao, round trip');
      expect(result.documentInformation.creator, 'dart_pdf');
    });

    test('a value already in the file can be replaced', () {
      final PdfDocument source = PdfDocument();
      source.pages.add();
      source.documentInformation.title = 'antes';
      final List<int> bytes = source.saveSync();
      source.dispose();

      final PdfDocument document = _load(bytes);
      expect(document.documentInformation.title, 'antes');
      document.documentInformation.title = 'depois';
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      expect(result.documentInformation.title, 'depois');
    });

    test('the modification date can be set on a loaded document', () {
      final DateTime moment = DateTime(2026, 8, 27, 14, 30);
      final PdfDocument document = _load(_textDocument(pageCount: 1));
      document.documentInformation.modificationDate = moment;
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      expect(
        result.documentInformation.modificationDate.toUtc(),
        moment.toUtc(),
        reason: 'the date is written with its offset, so what comes back is '
            'the same instant expressed in UTC rather than the same wall '
            'clock reading',
      );
    });
  });

  group('several changes in one session', () {
    test('page, form, annotation and metadata edits all land together', () {
      final PdfDocument document = _load(_formDocument());
      document.pages[0].appendGraphics().drawString(
        'PROTOCOLADO',
        font,
        brush: PdfBrushes.red,
        bounds: const Rect.fromLTWH(240, 40, 300, 30),
      );
      document.pages.insert(1).graphics.drawString(
        'ANEXO',
        font,
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(40, 40, 300, 24),
      );
      (_fieldsByName(document)['nome']! as PdfTextBoxField).text = 'Maria';
      document.pages[0].annotations.add(
        PdfRectangleAnnotation(
          const Rect.fromLTWH(40, 400, 120, 40),
          'carimbo',
          color: PdfColor(0, 0, 255),
          setAppearance: true,
        ),
      );
      document.documentInformation.title = 'tudo junto';
      final PdfDocument result = _saveAndReopen(document);
      addTearDown(result.dispose);

      expect(result.pages.count, 2);
      expect(_textOf(result, 0), contains('PROTOCOLADO'));
      expect(_textOf(result, 1), contains('ANEXO'));
      expect(
        (_fieldsByName(result)['nome']! as PdfTextBoxField).text,
        'Maria',
      );
      expect(result.pages[0].annotations.count, 1);
      expect(result.documentInformation.title, 'tudo junto');
    });
  });
}

/// Opens bytes as a document the way an application would.
PdfDocument _load(List<int> bytes) => PdfDocument(inputBytes: bytes);

/// Saves [document], disposes it, and hands back the saved bytes reopened.
///
/// Disposing before reading is deliberate: whatever the assertions find came
/// out of the file, not out of the objects that produced it.
PdfDocument _saveAndReopen(PdfDocument document) {
  final List<int> bytes = document.saveSync();
  document.dispose();
  return PdfDocument(inputBytes: bytes);
}

/// The text of page [index], as a reader would recover it.
String _textOf(PdfDocument document, int index) => PdfTextExtractor(
      document,
    ).extractText(startPageIndex: index, endPageIndex: index);

/// The form fields of [document], keyed by name.
Map<String, PdfField> _fieldsByName(PdfDocument document) {
  final Map<String, PdfField> fields = <String, PdfField>{};
  for (int i = 0; i < document.form.fields.count; i++) {
    final PdfField field = document.form.fields[i];
    fields[field.name!] = field;
  }
  return fields;
}

/// A document of [pageCount] pages, each carrying a line that names it.
List<int> _textDocument({int pageCount = 1}) {
  final PdfDocument document = PdfDocument();
  final PdfFont pageFont = PdfStandardFont(PdfFontFamily.helvetica, 24);
  for (int i = 0; i < pageCount; i++) {
    document.pages.add().graphics.drawString(
      'Page ${i + 1}',
      pageFont,
      brush: PdfBrushes.black,
      bounds: const Rect.fromLTWH(40, 40, 400, 40),
    );
  }
  final List<int> bytes = document.saveSync();
  document.dispose();
  return bytes;
}

/// A one page form with a text box, a checkbox and a combo box, all in the
/// state the round trip tests expect to change.
List<int> _formDocument() {
  final PdfDocument document = PdfDocument();
  final PdfPage page = document.pages.add();
  document.form.fields
    ..add(
      PdfTextBoxField(
        page,
        'nome',
        const Rect.fromLTWH(40, 100, 200, 24),
        text: 'antes',
      ),
    )
    ..add(
      PdfCheckBoxField(
        page,
        'aceite',
        const Rect.fromLTWH(40, 140, 20, 20),
      ),
    )
    ..add(
      PdfComboBoxField(
        page,
        'cidade',
        const Rect.fromLTWH(40, 180, 200, 24),
        items: <PdfListFieldItem>[
          PdfListFieldItem('Rio das Ostras', 'rio'),
          PdfListFieldItem('Macae', 'macae'),
        ],
        selectedIndex: 0,
      ),
    );
  final List<int> bytes = document.saveSync();
  document.dispose();
  return bytes;
}

/// A one page document that already carries two annotations, so removal has
/// something loaded from a file to remove.
List<int> _annotatedDocument() {
  final PdfDocument document = PdfDocument();
  final PdfPage page = document.pages.add();
  page.annotations.add(
    PdfRectangleAnnotation(
      const Rect.fromLTWH(40, 40, 120, 40),
      'primeira',
      color: PdfColor(255, 0, 0),
      setAppearance: true,
    ),
  );
  page.annotations.add(
    PdfRectangleAnnotation(
      const Rect.fromLTWH(40, 120, 120, 40),
      'segunda',
      color: PdfColor(0, 128, 0),
      setAppearance: true,
    ),
  );
  final List<int> bytes = document.saveSync();
  document.dispose();
  return bytes;
}

/// A one page document whose content stream ends inside an unrestored `q`.
List<int> _pageWithUnbalancedState() {
  final PdfDocument document = PdfDocument();
  final PdfGraphics graphics = document.pages.add().graphics;
  graphics.save();
  graphics.translateTransform(140, 260);
  graphics.rotateTransform(15);
  graphics.drawString(
    'skewed body',
    PdfStandardFont(PdfFontFamily.helvetica, 12),
    brush: PdfBrushes.black,
    bounds: const Rect.fromLTWH(0, 0, 200, 16),
  );
  // Deliberately no restore: the state is still open at the end of the stream.
  final List<int> bytes = document.saveSync();
  document.dispose();
  return bytes;
}
