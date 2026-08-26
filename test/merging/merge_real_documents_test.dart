import 'dart:io';

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

import 'merge_fixtures.dart';

/// Targeted checks on the documents of `test/assets` that carry the features
/// worth exercising one at a time: a real outline, a 63 field form, optional
/// content, many signatures, pure annotations.
void main() {
  group('merge - outline of a real report', () {
    // 94 pages, six top level bookmarks with nested children.
    const String asset = 'test/assets/paginador.pdf';

    test('the whole bookmark tree is rebuilt and still navigates', () {
      final List<int>? bytes = _read(asset);
      if (bytes == null) {
        return;
      }
      final PdfDocument source = reopen(bytes);
      final List<_Node> expected = _outlineOf(source);
      source.dispose();
      expect(expected, isNotEmpty, reason: 'the fixture has bookmarks');

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(_outlineOf(result), equals(expected));
    });

    test('two copies keep their bookmarks pointing inside themselves', () {
      final List<int>? bytes = _read(asset);
      if (bytes == null) {
        return;
      }
      final PdfDocument source = reopen(bytes);
      final int pages = source.pages.count;
      final int roots = source.bookmarks.count;
      source.dispose();

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        bytes,
        bytes,
      ]);
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(result.pages.count, pages * 2);
      expect(result.bookmarks.count, roots * 2);

      for (int i = 0; i < result.bookmarks.count; i++) {
        final PdfDestination? destination = result.bookmarks[i].destination;
        if (destination == null) {
          continue;
        }
        final int target = result.pages.indexOf(destination.page);
        expect(target, greaterThanOrEqualTo(0));
        expect(
          target < pages,
          i < roots,
          reason:
              'bookmark $i belongs to the ${i < roots ? "first" : "second"} '
              'copy and must point into it',
        );
      }
    });
  });

  group('merge - form of a real document', () {
    // 366 pages, 63 form fields, 412 annotations, optional content.
    const String asset = 'test/assets/sample3.pdf';

    test('every field name survives with its value', () {
      final List<int>? bytes = _read(asset);
      if (bytes == null) {
        return;
      }
      final PdfDocument source = reopen(bytes);
      final Map<String, String?> expected = _fieldValues(source);
      source.dispose();
      expect(expected, isNotEmpty, reason: 'the fixture has form fields');

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(_fieldValues(result), equals(expected));
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('merging it twice renames every colliding field', () {
      final List<int>? bytes = _read(asset);
      if (bytes == null) {
        return;
      }
      final PdfDocument source = reopen(bytes);
      final Set<String> names = _fieldValues(source).keys.toSet();
      source.dispose();

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        bytes,
        bytes,
      ]);
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      final Set<String> after = _fieldValues(result).keys.toSet();
      expect(after.length, names.length * 2);
      for (final String name in names) {
        expect(after, contains(name));
        expect(after, contains('${name}_2'));
      }
    }, timeout: const Timeout(Duration(minutes: 10)));

    test('an /OCProperties without /OCGs does not produce a broken one', () {
      // This document declares /OCProperties carrying only a default
      // configuration, no group list. Nothing can be registered from it, and
      // the merge must not invent an empty declaration either.
      final List<int>? bytes = _read(asset);
      if (bytes == null) {
        return;
      }
      final PdfDocument source = reopen(bytes);
      expect(
        _optionalContentGroupCount(source),
        0,
        reason: 'the fixture is the degenerate case this test is about',
      );
      source.dispose();

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(_optionalContentGroupCount(result), 0);
    }, timeout: const Timeout(Duration(minutes: 5)));
  });

  group('merge - annotations of a real document', () {
    // Three annotations and no form at all.
    const String asset = 'test/assets/termo.pdf';

    test('annotation subtypes and rectangles are preserved', () {
      final List<int>? bytes = _read(asset);
      if (bytes == null) {
        return;
      }
      final PdfDocument source = reopen(bytes);
      final List<String> expected = _annotationSignatures(source);
      source.dispose();
      expect(expected, isNotEmpty, reason: 'the fixture has annotations');

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(_annotationSignatures(result), equals(expected));
    });

    test('every annotation points back at its own page', () {
      final List<int>? bytes = _read(asset);
      if (bytes == null) {
        return;
      }
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        bytes,
        bytes,
      ]);
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      for (int i = 0; i < result.pages.count; i++) {
        final PdfDictionary page =
            PdfPageHelper.getHelper(result.pages[i]).dictionary!;
        final IPdfPrimitive? annots = PdfCrossTable.dereference(
          page['Annots'],
        );
        if (annots is! PdfArray) {
          continue;
        }
        for (int j = 0; j < annots.count; j++) {
          final IPdfPrimitive? annotation = PdfCrossTable.dereference(
            annots[j],
          );
          if (annotation is! PdfDictionary) {
            continue;
          }
          expect(
            PdfCrossTable.dereference(annotation['P']),
            same(page),
            reason: 'annotation $j of page $i has the right /P',
          );
        }
      }
    });
  });

  group('merge - documents with many signatures', () {
    const List<String> assets = <String>[
      'test/assets/10 assinaturas.pdf',
      'test/assets/12 assinaturas.pdf',
      'test/assets/tambem com 12 assinaturas.pdf',
      'test/assets/5 assinaturas.pdf',
    ];

    for (final String asset in assets) {
      test('${_basename(asset)} keeps one stamp per visible signature', () {
        final List<int>? bytes = _read(asset);
        if (bytes == null) {
          return;
        }
        final PdfDocument source = reopen(bytes);
        final int visible = _visibleSignatureCount(source);
        source.dispose();
        expect(visible, greaterThan(1), reason: 'the fixture is multi signed');

        final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
        final PdfDocument result = reopen(merged);
        addTearDown(result.dispose);
        expect(_stampCount(result), visible);
        expect(result.form.fields.count, 0);
      });

      test('${_basename(asset)} keeps every certificate on request', () {
        final List<int>? bytes = _read(asset);
        if (bytes == null) {
          return;
        }
        final PdfDocument source = reopen(bytes);
        final int signatures = _signatureFields(source).length;
        source.dispose();

        final List<int> merged = PdfDocument.mergeSync(
          <List<int>>[bytes],
          options: PdfMergeOptions(keepInvalidSignatures: true),
        );
        final PdfDocument result = reopen(merged);
        addTearDown(result.dispose);
        expect(
          _signatureFields(result).length,
          signatures,
          reason: 'all $signatures signature fields came across',
        );
      });
    }
  });

  group('merge - flatten mode on real documents', () {
    const List<String> assets = <String>[
      'test/assets/Invoice.pdf',
      'test/assets/paginador (3).pdf',
      'test/assets/relatorio_de_conformidade.pdf',
      'test/assets/doc_assinado_icp_brasil_thais.pdf',
    ];

    for (final String asset in assets) {
      test('${_basename(asset)} flattens with its geometry intact', () {
        final List<int>? bytes = _read(asset);
        if (bytes == null) {
          return;
        }
        final PdfDocument source = reopen(bytes);
        final int pages = source.pages.count;
        final List<Size> sizes = <Size>[
          for (int i = 0; i < pages; i++) source.pages[i].size,
        ];
        source.dispose();

        final List<int> merged = PdfDocument.mergeSync(<List<int>>[
          bytes,
        ], options: PdfMergeOptions.flatten());
        final PdfDocument result = reopen(merged);
        addTearDown(result.dispose);
        expect(result.pages.count, pages);
        for (int i = 0; i < pages; i++) {
          expect(result.pages[i].size.width, closeTo(sizes[i].width, 0.5));
          expect(result.pages[i].size.height, closeTo(sizes[i].height, 0.5));
        }
        for (int i = 0; i < pages; i++) {
          expect(
            _annotationCount(result, i),
            0,
            reason: 'flatten keeps graphical content only',
          );
        }
      });
    }
  });
}

List<int>? _read(String path) {
  final File file = File(path);
  if (!file.existsSync()) {
    markTestSkipped('$path is not available');
    return null;
  }
  return file.readAsBytesSync();
}

String _basename(String path) => path.split('/').last;

/// A bookmark tree flattened to `depth:title` lines, for comparison.
class _Node {
  _Node(this.depth, this.title);

  final int depth;
  final String title;

  @override
  bool operator ==(Object other) =>
      other is _Node && other.depth == depth && other.title == title;

  @override
  int get hashCode => Object.hash(depth, title);

  @override
  String toString() => '${'  ' * depth}$title';
}

List<_Node> _outlineOf(PdfDocument document) {
  final List<_Node> nodes = <_Node>[];
  void walk(PdfBookmarkBase parent, int depth) {
    for (int i = 0; i < parent.count; i++) {
      final PdfBookmark bookmark = parent[i];
      nodes.add(_Node(depth, bookmark.title));
      walk(bookmark, depth + 1);
    }
  }

  walk(document.bookmarks, 0);
  return nodes;
}

/// Terminal field names mapped to their string value.
Map<String, String?> _fieldValues(PdfDocument document) {
  final Map<String, String?> values = <String, String?>{};
  for (int i = 0; i < document.form.fields.count; i++) {
    final PdfField field = document.form.fields[i];
    final String? name = field.name;
    if (name == null) {
      continue;
    }
    String? value;
    if (field is PdfTextBoxField) {
      value = field.text;
    } else if (field is PdfCheckBoxField) {
      value = field.isChecked.toString();
    } else if (field is PdfComboBoxField) {
      value = field.selectedValue;
    }
    values[name] = value;
  }
  return values;
}

int _optionalContentGroupCount(PdfDocument document) {
  final IPdfPrimitive? properties = PdfCrossTable.dereference(
    PdfDocumentHelper.getHelper(document).catalog['OCProperties'],
  );
  if (properties is! PdfDictionary) {
    return 0;
  }
  final IPdfPrimitive? groups = PdfCrossTable.dereference(properties['OCGs']);
  return groups is PdfArray ? groups.count : 0;
}

/// `subtype@rect` for every annotation, in page order.
List<String> _annotationSignatures(PdfDocument document) {
  final List<String> result = <String>[];
  for (int i = 0; i < document.pages.count; i++) {
    final PdfDictionary page =
        PdfPageHelper.getHelper(document.pages[i]).dictionary!;
    final IPdfPrimitive? annots = PdfCrossTable.dereference(page['Annots']);
    if (annots is! PdfArray) {
      continue;
    }
    for (int j = 0; j < annots.count; j++) {
      final IPdfPrimitive? annotation = PdfCrossTable.dereference(annots[j]);
      if (annotation is! PdfDictionary) {
        continue;
      }
      final IPdfPrimitive? subtype = PdfCrossTable.dereference(
        annotation['Subtype'],
      );
      final IPdfPrimitive? rect = PdfCrossTable.dereference(
        annotation['Rect'],
      );
      result.add(
        '${subtype is PdfName ? subtype.name : '?'}'
        '@${rect is PdfArray ? rect.toRectangle().toString() : '?'}',
      );
    }
  }
  return result;
}

int _annotationCount(PdfDocument document, int pageIndex) {
  final PdfDictionary page =
      PdfPageHelper.getHelper(document.pages[pageIndex]).dictionary!;
  final IPdfPrimitive? annots = PdfCrossTable.dereference(page['Annots']);
  return annots is PdfArray ? annots.count : 0;
}

int _stampCount(PdfDocument document) {
  int count = 0;
  for (int i = 0; i < document.pages.count; i++) {
    final PdfDictionary page =
        PdfPageHelper.getHelper(document.pages[i]).dictionary!;
    final IPdfPrimitive? annots = PdfCrossTable.dereference(page['Annots']);
    if (annots is! PdfArray) {
      continue;
    }
    for (int j = 0; j < annots.count; j++) {
      final IPdfPrimitive? annotation = PdfCrossTable.dereference(annots[j]);
      if (annotation is! PdfDictionary) {
        continue;
      }
      final IPdfPrimitive? subtype = PdfCrossTable.dereference(
        annotation['Subtype'],
      );
      if (subtype is PdfName && subtype.name == 'Stamp') {
        count++;
      }
    }
  }
  return count;
}

int _visibleSignatureCount(PdfDocument document) {
  int count = 0;
  for (int i = 0; i < document.pages.count; i++) {
    final PdfDictionary page =
        PdfPageHelper.getHelper(document.pages[i]).dictionary!;
    final IPdfPrimitive? annots = PdfCrossTable.dereference(page['Annots']);
    if (annots is! PdfArray) {
      continue;
    }
    for (int j = 0; j < annots.count; j++) {
      final IPdfPrimitive? annotation = PdfCrossTable.dereference(annots[j]);
      if (annotation is! PdfDictionary || !_isSignature(annotation)) {
        continue;
      }
      final IPdfPrimitive? appearance = PdfCrossTable.dereference(
        annotation['AP'],
      );
      if (appearance is PdfDictionary &&
          PdfCrossTable.dereference(appearance['N']) != null) {
        count++;
      }
    }
  }
  return count;
}

bool _isSignature(PdfDictionary annotation) {
  IPdfPrimitive? node = annotation;
  final Set<IPdfPrimitive> visited = Set<IPdfPrimitive>.identity();
  while (node is PdfDictionary && visited.add(node)) {
    final IPdfPrimitive? type = PdfCrossTable.dereference(node['FT']);
    if (type != null) {
      return type is PdfName && type.name == 'Sig';
    }
    node = PdfCrossTable.dereference(node['Parent']);
  }
  return false;
}

List<PdfDictionary> _signatureFields(PdfDocument document) {
  final List<PdfDictionary> found = <PdfDictionary>[];
  final IPdfPrimitive? acroForm = PdfCrossTable.dereference(
    PdfDocumentHelper.getHelper(document).catalog['AcroForm'],
  );
  if (acroForm is! PdfDictionary) {
    return found;
  }
  final IPdfPrimitive? fields = PdfCrossTable.dereference(acroForm['Fields']);
  if (fields is! PdfArray) {
    return found;
  }
  final Set<IPdfPrimitive> visited = Set<IPdfPrimitive>.identity();
  void walk(PdfArray nodes) {
    for (int i = 0; i < nodes.count; i++) {
      final IPdfPrimitive? node = PdfCrossTable.dereference(nodes[i]);
      if (node is! PdfDictionary || !visited.add(node)) {
        continue;
      }
      final IPdfPrimitive? type = PdfCrossTable.dereference(node['FT']);
      if (type is PdfName && type.name == 'Sig') {
        found.add(node);
        continue;
      }
      final IPdfPrimitive? kids = PdfCrossTable.dereference(node['Kids']);
      if (kids is PdfArray) {
        walk(kids);
      }
    }
  }

  walk(fields);
  return found;
}
