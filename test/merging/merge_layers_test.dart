import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_cross_table.dart';
import 'package:dart_pdf/src/pdf/implementation/pdf_document/pdf_document.dart'
    show PdfDocumentHelper;
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_array.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_dictionary.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_string.dart';
import 'package:dart_pdf/src/pdf/interfaces/pdf_interface.dart';
import 'package:test/test.dart';

import 'merge_fixtures.dart';

void main() {
  group('merge - optional content groups', () {
    test('layers are declared in the merged /OCProperties', () {
      final List<int> bytes = _layered();
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);

      final PdfDocument result = reopen(merged);
      final List<String> names = _layerNames(result);
      expect(names, containsAll(<String>['Visible layer', 'Hidden layer']));
      result.dispose();
    });

    test('merging two layered documents keeps both sets of layers', () {
      final List<int> bytes = _layered();
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        bytes,
        bytes,
      ]);

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 2);
      expect(_layerNames(result).length, 4);
      result.dispose();
    });

    test('the hidden layer stays in /OFF', () {
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[_layered()]);

      final PdfDocument result = reopen(merged);
      expect(_stateNames(result, 'OFF'), <String>['Hidden layer']);
      expect(_stateNames(result, 'ON'), <String>['Visible layer']);
      result.dispose();
    });

    test('importLayers: false leaves /OCProperties out', () {
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        _layered(),
      ], options: PdfMergeOptions(importLayers: false));

      final PdfDocument result = reopen(merged);
      expect(_layerNames(result), isEmpty);
      result.dispose();
    });
  });
}

/// A one page document with a visible and a hidden layer.
List<int> _layered() {
  final PdfDocument document = PdfDocument();
  final PdfPage page = document.pages.add();
  final PdfFont font = PdfStandardFont(PdfFontFamily.helvetica, 18);
  final PdfLayer visible = document.layers.add(name: 'Visible layer');
  visible.createGraphics(page).drawString(
    'On',
    font,
    brush: PdfBrushes.black,
    bounds: const Rect.fromLTWH(40, 40, 200, 30),
  );
  final PdfLayer hidden = document.layers.add(
    name: 'Hidden layer',
    visible: false,
  );
  hidden.createGraphics(page).drawString(
    'Off',
    font,
    brush: PdfBrushes.red,
    bounds: const Rect.fromLTWH(40, 100, 200, 30),
  );
  final List<int> bytes = document.saveSync();
  document.dispose();
  return bytes;
}

List<String> _layerNames(PdfDocument document) {
  final PdfDictionary? properties = _optionalContent(document);
  if (properties == null) {
    return <String>[];
  }
  final IPdfPrimitive? groups = PdfCrossTable.dereference(properties['OCGs']);
  return _namesOf(groups);
}

List<String> _stateNames(PdfDocument document, String state) {
  final PdfDictionary? properties = _optionalContent(document);
  if (properties == null) {
    return <String>[];
  }
  final IPdfPrimitive? configuration = PdfCrossTable.dereference(
    properties['D'],
  );
  if (configuration is! PdfDictionary) {
    return <String>[];
  }
  return _namesOf(PdfCrossTable.dereference(configuration[state]));
}

List<String> _namesOf(IPdfPrimitive? groups) {
  final List<String> names = <String>[];
  if (groups is! PdfArray) {
    return names;
  }
  for (int i = 0; i < groups.count; i++) {
    final IPdfPrimitive? group = PdfCrossTable.dereference(groups[i]);
    if (group is! PdfDictionary) {
      continue;
    }
    final IPdfPrimitive? name = PdfCrossTable.dereference(group['Name']);
    if (name is PdfString && name.value != null) {
      names.add(name.value!);
    }
  }
  return names;
}

PdfDictionary? _optionalContent(PdfDocument document) {
  final IPdfPrimitive? properties = PdfCrossTable.dereference(
    PdfDocumentHelper.getHelper(document).catalog['OCProperties'],
  );
  return properties is PdfDictionary ? properties : null;
}
