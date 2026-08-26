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

/// Sweeps every PDF in `test/assets` through the merger.
///
/// The corpus is what the library is actually used on — ICP-Brasil signed
/// documents, court filings, government reports, scanned bundles — so it is
/// the honest check that merging does not quietly damage a real file.
void main() {
  final List<File> corpus = _corpus();

  group('merge corpus - structure and content', () {
    for (final File file in corpus) {
      test(_name(file), () {
        final List<int> bytes = file.readAsBytesSync();
        final _Profile before = _profile(bytes);

        final PdfDocument output = PdfDocument();
        final PdfDocumentMerger merger = PdfDocumentMerger(output);
        final PdfDocument source = reopen(bytes);
        merger.append(source);
        final List<int> merged = output.saveSync();
        source.dispose();
        output.dispose();

        expect(
          merger.warnings.where(_isUnexpectedWarning),
          isEmpty,
          reason: 'no warning beyond the documented signature loss',
        );

        final PdfDocument result = reopen(merged);
        addTearDown(result.dispose);

        expect(result.pages.count, before.pages, reason: 'page count');
        for (int i = 0; i < before.pages; i++) {
          expect(
            result.pages[i].size.width,
            closeTo(before.sizes[i].width, 0.5),
            reason: 'width of page $i',
          );
          expect(
            result.pages[i].size.height,
            closeTo(before.sizes[i].height, 0.5),
            reason: 'height of page $i',
          );
        }

        final _Profile after = _profile(merged);
        expect(
          after.annotations,
          before.annotations - before.invisibleSignatures,
          reason:
              'annotations are preserved; only invisible signature fields, '
              'which have nothing to show, are dropped',
        );
        expect(
          after.signatureFields,
          0,
          reason: 'signature fields are dropped by default',
        );
        expect(
          after.stamps,
          before.stamps + before.visibleSignatures,
          reason: 'every visible signature left a stamp behind',
        );
        expect(after.bookmarks, before.bookmarks, reason: 'bookmark count');
      });
    }
  });

  group('merge corpus - text fidelity', () {
    for (final File file in corpus) {
      test(_name(file), () {
        final List<int> bytes = file.readAsBytesSync();
        final PdfDocument source = reopen(bytes);
        final List<int> sampled = _sampledPages(source.pages.count);
        final Map<int, String> expected = <int, String>{};
        for (final int index in sampled) {
          expected[index] = _textOf(source, index);
        }
        source.dispose();

        final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
        final PdfDocument result = reopen(merged);
        addTearDown(result.dispose);
        for (final int index in sampled) {
          expect(
            _textOf(result, index),
            expected[index],
            reason: 'text of page $index is unchanged',
          );
        }
      });
    }
  });

  group('merge corpus - signed documents', () {
    final List<File> signed =
        corpus.where((File f) => _profileFile(f).signatureFields > 0).toList();

    test('the corpus does contain signed documents', () {
      expect(signed, isNotEmpty);
    });

    for (final File file in signed) {
      test('${_name(file)} keeps its certificates on request', () {
        final List<int> bytes = file.readAsBytesSync();
        final PdfDocument source = reopen(bytes);
        final List<String> originalBlobs = _signatureBlobs(source);
        source.dispose();
        if (originalBlobs.isEmpty) {
          markTestSkipped('no signature value to carry over');
          return;
        }

        final List<int> merged = PdfDocument.mergeSync(
          <List<int>>[bytes],
          options: PdfMergeOptions(keepInvalidSignatures: true),
        );
        final PdfDocument result = reopen(merged);
        addTearDown(result.dispose);
        expect(
          _signatureBlobs(result),
          equals(originalBlobs),
          reason: 'every CMS blob survived the merge byte for byte',
        );
      });

      test('${_name(file)} is refused when rejectSignedSources is set', () {
        expect(
          () => PdfDocument.mergeSync(
            <List<int>>[file.readAsBytesSync()],
            options: PdfMergeOptions(rejectSignedSources: true),
          ),
          throwsA(isA<PdfMergeException>()),
        );
      });
    }
  });

  group('merge corpus - combinations', () {
    test('the whole corpus merges into one document', () {
      int expected = 0;
      final PdfDocument output = PdfDocument();
      final PdfDocumentMerger merger = PdfDocumentMerger(output);
      for (final File file in corpus) {
        final PdfDocument source = reopen(file.readAsBytesSync());
        expected += source.pages.count;
        merger.append(source);
        source.dispose();
      }
      final List<int> merged = output.saveSync();
      output.dispose();

      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(result.pages.count, expected);
      expect(
        _textOf(result, 0),
        isNotEmpty,
        reason: 'the first page still renders text',
      );
    }, timeout: const Timeout(Duration(minutes: 10)));

    test('a signed and an unsigned document interleave correctly', () {
      final File? signedFile = _firstWhere(
        corpus,
        (_Profile p) => p.signatureFields > 0 && p.pages <= 8,
      );
      final File? plainFile = _firstWhere(
        corpus,
        (_Profile p) => p.signatureFields == 0 && p.pages <= 30,
      );
      if (signedFile == null || plainFile == null) {
        markTestSkipped('corpus lacks a suitable pair');
        return;
      }
      final _Profile signed = _profileFile(signedFile);
      final _Profile plain = _profileFile(plainFile);

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        plainFile.readAsBytesSync(),
        signedFile.readAsBytesSync(),
        plainFile.readAsBytesSync(),
      ]);
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(result.pages.count, plain.pages * 2 + signed.pages);
      expect(_profile(merged).signatureFields, 0);
    });

    test('importing a page range out of a large document', () {
      final File? large = _firstWhere(corpus, (_Profile p) => p.pages >= 20);
      if (large == null) {
        markTestSkipped('corpus lacks a document with 20+ pages');
        return;
      }
      final List<int> bytes = large.readAsBytesSync();
      final PdfDocument source = reopen(bytes);
      final List<String> expected = <String>[
        _textOf(source, 5),
        _textOf(source, 6),
        _textOf(source, 7),
      ];

      final PdfDocument output = PdfDocument();
      PdfDocumentMerger(output).importPageRange(source, 5, 7);
      final List<int> merged = output.saveSync();
      source.dispose();
      output.dispose();

      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(result.pages.count, 3);
      for (int i = 0; i < 3; i++) {
        expect(_textOf(result, i), expected[i], reason: 'page $i');
      }
    });
  });
}

/// The PDF files under `test/assets`, sorted for a stable test order.
List<File> _corpus() {
  final Directory directory = Directory('test/assets');
  if (!directory.existsSync()) {
    return <File>[];
  }
  return directory
      .listSync()
      .whereType<File>()
      .where((File f) => f.path.toLowerCase().endsWith('.pdf'))
      .toList()
    ..sort((File a, File b) => a.path.compareTo(b.path));
}

String _name(File file) => file.path.split(RegExp(r'[\\/]')).last;

/// A warning that would point at a real defect rather than the documented
/// consequence of merging a signed document.
bool _isUnexpectedWarning(String warning) =>
    !warning.contains('Merging invalidates signatures');

/// Pages to compare text on: the first, one in the middle and the last.
List<int> _sampledPages(int count) {
  if (count <= 3) {
    return List<int>.generate(count, (int i) => i);
  }
  return <int>[0, count ~/ 2, count - 1];
}

String _textOf(PdfDocument document, int index) {
  try {
    return PdfTextExtractor(
      document,
    ).extractText(startPageIndex: index, endPageIndex: index);
  } on Exception {
    return '';
  }
}

File? _firstWhere(List<File> corpus, bool Function(_Profile) matches) {
  for (final File file in corpus) {
    if (matches(_profileFile(file))) {
      return file;
    }
  }
  return null;
}

final Map<String, _Profile> _profileCache = <String, _Profile>{};

_Profile _profileFile(File file) =>
    _profileCache.putIfAbsent(
      file.path,
      () => _profile(file.readAsBytesSync()),
    );

/// What a document holds, as far as merging is concerned.
class _Profile {
  _Profile({
    required this.pages,
    required this.sizes,
    required this.annotations,
    required this.stamps,
    required this.visibleSignatures,
    required this.invisibleSignatures,
    required this.signatureFields,
    required this.bookmarks,
  });

  final int pages;
  final List<Size> sizes;
  final int annotations;
  final int stamps;
  final int visibleSignatures;
  final int invisibleSignatures;
  final int signatureFields;
  final int bookmarks;
}

_Profile _profile(List<int> bytes) {
  final PdfDocument document = reopen(bytes);
  final List<Size> sizes = <Size>[];
  int annotations = 0;
  int stamps = 0;
  int visibleSignatures = 0;
  int invisibleSignatures = 0;
  for (int i = 0; i < document.pages.count; i++) {
    sizes.add(document.pages[i].size);
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
      annotations++;
      if (_subtypeOf(annotation) == 'Stamp') {
        stamps++;
      }
      if (!_isSignatureAnnotation(annotation)) {
        continue;
      }
      if (_hasNormalAppearance(annotation)) {
        visibleSignatures++;
      } else {
        invisibleSignatures++;
      }
    }
  }
  final _Profile profile = _Profile(
    pages: document.pages.count,
    sizes: sizes,
    annotations: annotations,
    stamps: stamps,
    visibleSignatures: visibleSignatures,
    invisibleSignatures: invisibleSignatures,
    signatureFields: _signatureFieldCount(document),
    bookmarks: document.bookmarks.count,
  );
  document.dispose();
  return profile;
}

String? _subtypeOf(PdfDictionary annotation) {
  final IPdfPrimitive? subtype = PdfCrossTable.dereference(
    annotation['Subtype'],
  );
  return subtype is PdfName ? subtype.name : null;
}

bool _hasNormalAppearance(PdfDictionary annotation) {
  final IPdfPrimitive? appearance = PdfCrossTable.dereference(
    annotation['AP'],
  );
  return appearance is PdfDictionary &&
      PdfCrossTable.dereference(appearance['N']) != null;
}

/// Whether an annotation belongs to a signature field, looking up `/Parent`
/// because `/FT` is inheritable.
bool _isSignatureAnnotation(PdfDictionary annotation) {
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

int _signatureFieldCount(PdfDocument document) =>
    _signatureFields(document).length;

/// The signature field dictionaries reachable from `/AcroForm /Fields`,
/// including the ones nested under a non terminal parent.
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

/// The raw `/V /Contents` of every signature field, sorted so two documents
/// can be compared regardless of field order.
List<String> _signatureBlobs(PdfDocument document) {
  final List<String> blobs = <String>[];
  for (final PdfDictionary field in _signatureFields(document)) {
    final IPdfPrimitive? value = PdfCrossTable.dereference(field['V']);
    if (value is! PdfDictionary) {
      continue;
    }
    final IPdfPrimitive? contents = PdfCrossTable.dereference(
      value['Contents'],
    );
    if (contents != null) {
      blobs.add(contents.toString());
    }
  }
  blobs.sort();
  return blobs;
}
