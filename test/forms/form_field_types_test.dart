import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_cross_table.dart';
import 'package:dart_pdf/src/pdf/implementation/pages/pdf_page.dart';
import 'package:dart_pdf/src/pdf/implementation/pdf_document/pdf_document.dart'
    show PdfDocumentHelper;
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_array.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_dictionary.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_name.dart';
import 'package:dart_pdf/src/pdf/interfaces/pdf_interface.dart';
import 'package:test/test.dart';

// Every interactive field type the library can build, taken through the round
// trip that matters: create it, save, reload, and read the value back the way
// an application would. Several of these types had no test at all.

void main() {
  group('text box', () {
    test('text survives the round trip', () {
      final PdfDocument result = _reopen(
        _withFields((PdfPage page, PdfForm form) {
          form.fields.add(
            PdfTextBoxField(
              page,
              'nome',
              const Rect.fromLTWH(20, 20, 200, 24),
              text: 'Isaque Neves',
              font: PdfStandardFont(PdfFontFamily.helvetica, 12),
            ),
          );
        }),
      );
      addTearDown(result.dispose);
      final PdfTextBoxField field =
          result.form.fields[0] as PdfTextBoxField;
      expect(field.name, 'nome');
      expect(field.text, 'Isaque Neves');
    });

    test('multiline, password and readonly flags survive', () {
      final PdfDocument result = _reopen(
        _withFields((PdfPage page, PdfForm form) {
          form.fields.add(
            PdfTextBoxField(
              page,
              'notas',
              const Rect.fromLTWH(20, 60, 200, 80),
              text: 'linha um',
              multiline: true,
              maxLength: 120,
            ),
          );
          form.fields.add(
            PdfTextBoxField(
              page,
              'senha',
              const Rect.fromLTWH(20, 150, 200, 24),
              isPassword: true,
            )..readOnly = true,
          );
        }),
      );
      addTearDown(result.dispose);
      final Map<String, PdfField> byName = _byName(result);
      final PdfTextBoxField notes = byName['notas']! as PdfTextBoxField;
      expect(notes.multiline, isTrue);
      expect(notes.maxLength, 120);
      final PdfTextBoxField password = byName['senha']! as PdfTextBoxField;
      expect(password.isPassword, isTrue);
      expect(password.readOnly, isTrue);
    });

    test('the value can be changed on a loaded document', () {
      final List<int> bytes = _withFields((PdfPage page, PdfForm form) {
        form.fields.add(
          PdfTextBoxField(
            page,
            'campo',
            const Rect.fromLTWH(20, 20, 200, 24),
            text: 'antes',
          ),
        );
      });
      final PdfDocument loaded = PdfDocument(inputBytes: bytes);
      (loaded.form.fields[0] as PdfTextBoxField).text = 'depois';
      final List<int> updated = loaded.saveSync();
      loaded.dispose();

      final PdfDocument result = PdfDocument(inputBytes: updated);
      addTearDown(result.dispose);
      expect((result.form.fields[0] as PdfTextBoxField).text, 'depois');
    });
  });

  group('check box', () {
    test('checked state survives', () {
      final PdfDocument result = _reopen(
        _withFields((PdfPage page, PdfForm form) {
          form.fields.add(
            PdfCheckBoxField(
              page,
              'aceito',
              const Rect.fromLTWH(20, 20, 20, 20),
              isChecked: true,
            ),
          );
          form.fields.add(
            PdfCheckBoxField(
              page,
              'recuso',
              const Rect.fromLTWH(60, 20, 20, 20),
            ),
          );
        }),
      );
      addTearDown(result.dispose);
      final Map<String, PdfField> byName = _byName(result);
      expect((byName['aceito']! as PdfCheckBoxField).isChecked, isTrue);
      expect((byName['recuso']! as PdfCheckBoxField).isChecked, isFalse);
    });

    test('the style is recorded', () {
      final PdfDocument result = _reopen(
        _withFields((PdfPage page, PdfForm form) {
          form.fields.add(
            PdfCheckBoxField(
              page,
              'estrela',
              const Rect.fromLTWH(20, 20, 20, 20),
              style: PdfCheckBoxStyle.star,
              isChecked: true,
            ),
          );
        }),
      );
      addTearDown(result.dispose);
      expect(result.form.fields.count, 1);
      expect(_fieldTypesOf(result), contains('Btn'));
    });
  });

  group('combo box', () {
    test('items and the selected value survive', () {
      final PdfDocument result = _reopen(
        _withFields((PdfPage page, PdfForm form) {
          form.fields.add(
            PdfComboBoxField(
              page,
              'cidade',
              const Rect.fromLTWH(20, 20, 200, 24),
              items: <PdfListFieldItem>[
                PdfListFieldItem('Rio das Ostras', 'rio'),
                PdfListFieldItem('Macae', 'macae'),
                PdfListFieldItem('Campos', 'campos'),
              ],
              selectedIndex: 1,
            ),
          );
        }),
      );
      addTearDown(result.dispose);
      final PdfComboBoxField field =
          result.form.fields[0] as PdfComboBoxField;
      expect(field.items.count, 3);
      expect(field.selectedValue, 'macae');
      expect(field.items[0].text, 'Rio das Ostras');
    });

    test('an editable combo box records the flag', () {
      final PdfDocument result = _reopen(
        _withFields((PdfPage page, PdfForm form) {
          form.fields.add(
            PdfComboBoxField(
              page,
              'livre',
              const Rect.fromLTWH(20, 20, 200, 24),
              items: <PdfListFieldItem>[PdfListFieldItem('a', 'a')],
              editable: true,
            ),
          );
        }),
      );
      addTearDown(result.dispose);
      expect((result.form.fields[0] as PdfComboBoxField).editable, isTrue);
    });
  });

  group('list box', () {
    test('items and a single selection survive', () {
      final PdfDocument result = _reopen(
        _withFields((PdfPage page, PdfForm form) {
          form.fields.add(
            PdfListBoxField(
              page,
              'lista',
              const Rect.fromLTWH(20, 20, 200, 80),
              items: <PdfListFieldItem>[
                PdfListFieldItem('um', '1'),
                PdfListFieldItem('dois', '2'),
                PdfListFieldItem('tres', '3'),
              ],
              selectedIndexes: <int>[2],
            ),
          );
        }),
      );
      addTearDown(result.dispose);
      final PdfListBoxField field = result.form.fields[0] as PdfListBoxField;
      expect(field.items.count, 3);
      expect(field.selectedValues, contains('3'));
    });

    test('a multi select list keeps every selection', () {
      final PdfDocument result = _reopen(
        _withFields((PdfPage page, PdfForm form) {
          form.fields.add(
            PdfListBoxField(
              page,
              'multi',
              const Rect.fromLTWH(20, 20, 200, 80),
              items: <PdfListFieldItem>[
                PdfListFieldItem('um', '1'),
                PdfListFieldItem('dois', '2'),
                PdfListFieldItem('tres', '3'),
              ],
              multiSelect: true,
              selectedIndexes: <int>[0, 2],
            ),
          );
        }),
      );
      addTearDown(result.dispose);
      final PdfListBoxField field = result.form.fields[0] as PdfListBoxField;
      expect(field.multiSelect, isTrue);
      expect(field.selectedValues.length, 2);
    });
  });

  group('radio button list', () {
    test('the selected item survives', () {
      final PdfDocument result = _reopen(
        _withFields((PdfPage page, PdfForm form) {
          final PdfRadioButtonListField field = PdfRadioButtonListField(
            page,
            'opcao',
            items: <PdfRadioButtonListItem>[
              PdfRadioButtonListItem('sim', const Rect.fromLTWH(20, 20, 16, 16)),
              PdfRadioButtonListItem('nao', const Rect.fromLTWH(60, 20, 16, 16)),
            ],
            selectedIndex: 1,
          );
          form.fields.add(field);
        }),
      );
      addTearDown(result.dispose);
      final PdfRadioButtonListField field =
          result.form.fields[0] as PdfRadioButtonListField;
      expect(field.items.count, 2);
      expect(field.selectedValue, 'nao');
    });

    test('the group is one field with two widgets', () {
      final List<int> bytes = _withFields((PdfPage page, PdfForm form) {
        form.fields.add(
          PdfRadioButtonListField(
            page,
            'grupo',
            items: <PdfRadioButtonListItem>[
              PdfRadioButtonListItem('a', const Rect.fromLTWH(20, 20, 16, 16)),
              PdfRadioButtonListItem('b', const Rect.fromLTWH(60, 20, 16, 16)),
            ],
          ),
        );
      });
      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      expect(result.form.fields.count, 1);
      expect(
        _annotationCountOf(result, 0),
        2,
        reason: 'each option is its own widget on the page',
      );
    });
  });

  group('button', () {
    test('the caption survives', () {
      final PdfDocument result = _reopen(
        _withFields((PdfPage page, PdfForm form) {
          form.fields.add(
            PdfButtonField(
              page,
              'enviar',
              const Rect.fromLTWH(20, 20, 120, 28),
              text: 'Enviar',
              font: PdfStandardFont(PdfFontFamily.helvetica, 12),
              backColor: PdfColor(220, 220, 220),
              borderColor: PdfColor(0, 0, 0),
              borderWidth: 1,
            ),
          );
        }),
      );
      addTearDown(result.dispose);
      final PdfButtonField field = result.form.fields[0] as PdfButtonField;
      expect(field.name, 'enviar');
      expect(field.text, 'Enviar');
    });

    test('a URL action can be attached', () {
      final PdfDocument result = _reopen(
        _withFields((PdfPage page, PdfForm form) {
          final PdfButtonField button = PdfButtonField(
            page,
            'site',
            const Rect.fromLTWH(20, 60, 120, 28),
            text: 'Abrir',
          );
          button.actions.mouseDown = PdfUriAction('https://example.org/');
          form.fields.add(button);
        }),
      );
      addTearDown(result.dispose);
      expect(result.form.fields.count, 1);
    });
  });

  group('signature field', () {
    test('an empty signature field is a /Sig field', () {
      final List<int> bytes = _withFields((PdfPage page, PdfForm form) {
        form.fields.add(
          PdfSignatureField(
            page,
            'assinatura',
            bounds: const Rect.fromLTWH(20, 20, 200, 60),
          ),
        );
      });
      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      expect(_fieldTypesOf(result), contains('Sig'));
    });
  });

  group('the form as a whole', () {
    test('fields of every type coexist and count correctly', () {
      final PdfDocument result = _reopen(_kitchenSink());
      addTearDown(result.dispose);
      expect(result.form.fields.count, 5);
      expect(
        _byName(result).keys,
        containsAll(<String>['texto', 'caixa', 'combo', 'lista', 'botao']),
      );
    });

    test('a field can be removed', () {
      final PdfDocument loaded = PdfDocument(inputBytes: _kitchenSink());
      final int before = loaded.form.fields.count;
      loaded.form.fields.removeAt(0);
      final List<int> updated = loaded.saveSync();
      loaded.dispose();

      final PdfDocument result = PdfDocument(inputBytes: updated);
      addTearDown(result.dispose);
      expect(result.form.fields.count, before - 1);
    });

    test('flattening leaves no fields but keeps the drawing', () {
      final PdfDocument loaded = PdfDocument(inputBytes: _kitchenSink());
      loaded.form.flattenAllFields();
      final List<int> flattened = loaded.saveSync();
      loaded.dispose();

      final PdfDocument result = PdfDocument(inputBytes: flattened);
      addTearDown(result.dispose);
      expect(result.form.fields.count, 0);
      expect(result.pages.count, 1);
    });

    test('setDefaultAppearance is honoured', () {
      final PdfDocument document = PdfDocument();
      final PdfPage page = document.pages.add();
      document.form.setDefaultAppearance(false);
      document.form.fields.add(
        PdfTextBoxField(
          page,
          'campo',
          const Rect.fromLTWH(20, 20, 200, 24),
          text: 'x',
        ),
      );
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument result = PdfDocument(inputBytes: bytes);
      addTearDown(result.dispose);
      expect(result.form.fields.count, 1);
    });
  });

  group('forms survive a merge', () {
    test('every type comes across with its value', () {
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        _kitchenSink(),
      ]);
      final PdfDocument result = PdfDocument(inputBytes: merged);
      addTearDown(result.dispose);
      expect(result.form.fields.count, 5);
      final Map<String, PdfField> byName = _byName(result);
      expect((byName['texto']! as PdfTextBoxField).text, 'valor');
      expect((byName['caixa']! as PdfCheckBoxField).isChecked, isTrue);
      expect((byName['combo']! as PdfComboBoxField).selectedValue, 'b');
    });

    test('a radio group stays one field after merging', () {
      final List<int> bytes = _withFields((PdfPage page, PdfForm form) {
        form.fields.add(
          PdfRadioButtonListField(
            page,
            'grupo',
            items: <PdfRadioButtonListItem>[
              PdfRadioButtonListItem('a', const Rect.fromLTWH(20, 20, 16, 16)),
              PdfRadioButtonListItem('b', const Rect.fromLTWH(60, 20, 16, 16)),
            ],
            selectedIndex: 0,
          ),
        );
      });
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      final PdfDocument result = PdfDocument(inputBytes: merged);
      addTearDown(result.dispose);
      expect(
        result.form.fields.count,
        1,
        reason: 'the two options belong to a single field, not to two',
      );
      expect(_annotationCountOf(result, 0), 2);
    });
  });
}

/// Builds a one page document whose form is filled in by [build].
List<int> _withFields(void Function(PdfPage, PdfForm) build) {
  final PdfDocument document = PdfDocument();
  final PdfPage page = document.pages.add();
  build(page, document.form);
  final List<int> bytes = document.saveSync();
  document.dispose();
  return bytes;
}

PdfDocument _reopen(List<int> bytes) => PdfDocument(inputBytes: bytes);

/// One document carrying five field types.
List<int> _kitchenSink() {
  return _withFields((PdfPage page, PdfForm form) {
    form.fields
      ..add(
        PdfTextBoxField(
          page,
          'texto',
          const Rect.fromLTWH(20, 20, 200, 24),
          text: 'valor',
        ),
      )
      ..add(
        PdfCheckBoxField(
          page,
          'caixa',
          const Rect.fromLTWH(20, 60, 20, 20),
          isChecked: true,
        ),
      )
      ..add(
        PdfComboBoxField(
          page,
          'combo',
          const Rect.fromLTWH(20, 100, 200, 24),
          items: <PdfListFieldItem>[
            PdfListFieldItem('A', 'a'),
            PdfListFieldItem('B', 'b'),
          ],
          selectedIndex: 1,
        ),
      )
      ..add(
        PdfListBoxField(
          page,
          'lista',
          const Rect.fromLTWH(20, 140, 200, 60),
          items: <PdfListFieldItem>[
            PdfListFieldItem('X', 'x'),
            PdfListFieldItem('Y', 'y'),
          ],
          selectedIndexes: <int>[0],
        ),
      )
      ..add(
        PdfButtonField(
          page,
          'botao',
          const Rect.fromLTWH(20, 220, 120, 28),
          text: 'OK',
        ),
      );
  });
}

Map<String, PdfField> _byName(PdfDocument document) {
  final Map<String, PdfField> fields = <String, PdfField>{};
  for (int i = 0; i < document.form.fields.count; i++) {
    final PdfField field = document.form.fields[i];
    final String? name = field.name;
    if (name != null) {
      fields[name] = field;
    }
  }
  return fields;
}

/// The `/FT` of every field in `/AcroForm /Fields`.
Set<String> _fieldTypesOf(PdfDocument document) {
  final Set<String> types = <String>{};
  final IPdfPrimitive? acroForm = PdfCrossTable.dereference(
    PdfDocumentHelper.getHelper(document).catalog['AcroForm'],
  );
  if (acroForm is! PdfDictionary) {
    return types;
  }
  final IPdfPrimitive? fields = PdfCrossTable.dereference(acroForm['Fields']);
  if (fields is! PdfArray) {
    return types;
  }
  for (int i = 0; i < fields.count; i++) {
    final IPdfPrimitive? field = PdfCrossTable.dereference(fields[i]);
    if (field is! PdfDictionary) {
      continue;
    }
    final IPdfPrimitive? type = PdfCrossTable.dereference(field['FT']);
    if (type is PdfName && type.name != null) {
      types.add(type.name!);
    }
  }
  return types;
}

/// Entries in the page `/Annots` array.
///
/// Not `page.annotations.count`: that collection deliberately leaves out form
/// widgets, which belong to the form rather than to the page markup. The
/// widgets are on the page all the same, and for a field spanning several
/// options that is exactly what has to be checked.
int _annotationCountOf(PdfDocument document, int pageIndex) {
  final PdfDictionary page =
      PdfPageHelper.getHelper(document.pages[pageIndex]).dictionary!;
  final IPdfPrimitive? annots = PdfCrossTable.dereference(page['Annots']);
  return annots is PdfArray ? annots.count : 0;
}
