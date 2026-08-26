import 'dart:io';

import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_cross_table.dart';
import 'package:dart_pdf/src/pdf/implementation/pages/pdf_page.dart';
import 'package:dart_pdf/src/pdf/implementation/pdf_document/pdf_document.dart'
    show PdfDocumentHelper;
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_array.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_dictionary.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_name.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_number.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_string.dart';
import 'package:dart_pdf/src/pdf/interfaces/pdf_interface.dart';
import 'package:test/test.dart';

import 'merge_fixtures.dart';

/// Unsigned real world documents kept in `test/assets`.
const List<String> _realWorldAssets = <String>[
  'test/assets/Invoice.pdf',
  'test/assets/C008_2021_4HD.pdf',
  'test/assets/sample_no_signature.pdf',
  'test/assets/paginador.pdf',
  'test/assets/example.pdf',
  'test/assets/sample3.pdf',
];

void main() {
  group('merge - real world documents', () {
    for (final String path in _realWorldAssets) {
      test('$path merges and reopens', () {
        final File file = File(path);
        if (!file.existsSync()) {
          markTestSkipped('$path is not available');
          return;
        }
        final List<int> bytes = file.readAsBytesSync();
        final PdfDocument original = reopen(bytes);
        final int pageCount = original.pages.count;
        final List<Size> sizes = <Size>[
          for (int i = 0; i < pageCount; i++) original.pages[i].size,
        ];
        original.dispose();

        final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
        final PdfDocument result = reopen(merged);
        expect(result.pages.count, pageCount);
        for (int i = 0; i < pageCount; i++) {
          expect(
            result.pages[i].size.width,
            closeTo(sizes[i].width, 0.5),
            reason: 'page $i keeps its width',
          );
          expect(
            result.pages[i].size.height,
            closeTo(sizes[i].height, 0.5),
            reason: 'page $i keeps its height',
          );
        }
        result.dispose();
      });
    }

    test('two real world documents concatenate', () {
      final List<File> files =
          _realWorldAssets
              .map(File.new)
              .where((File f) => f.existsSync())
              .take(2)
              .toList();
      if (files.length < 2) {
        markTestSkipped('not enough real world assets available');
        return;
      }
      final List<List<int>> inputs =
          files.map((File f) => f.readAsBytesSync() as List<int>).toList();
      int expected = 0;
      for (final List<int> bytes in inputs) {
        final PdfDocument document = reopen(bytes);
        expected += document.pages.count;
        document.dispose();
      }

      final List<int> merged = PdfDocument.mergeSync(inputs);
      final PdfDocument result = reopen(merged);
      expect(result.pages.count, expected);
      result.dispose();
    });
  });

  group('merge - geometry', () {
    test('page rotation is carried over', () {
      final PdfDocument document = PdfDocument();
      document.pageSettings.rotate = PdfPageRotateAngle.rotateAngle90;
      document.pages.add().graphics.drawString(
        'Rotated',
        PdfStandardFont(PdfFontFamily.helvetica, 20),
        brush: PdfBrushes.black,
        bounds: const Rect.fromLTWH(40, 40, 300, 30),
      );
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfDocument source = reopen(bytes);
      expect(source.pages[0].rotation, PdfPageRotateAngle.rotateAngle90);
      source.dispose();

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      final PdfDocument result = reopen(merged);
      expect(result.pages[0].rotation, PdfPageRotateAngle.rotateAngle90);
      result.dispose();
    });

    test('a page inheriting its MediaBox materializes it', () {
      // Build a document whose page tree carries MediaBox on the root node
      // only, the shape produced by many generators.
      final List<int> bytes = MergeFixtures.text(pageCount: 2);
      final PdfDocument source = reopen(bytes);
      for (int i = 0; i < source.pages.count; i++) {
        PdfPageHelper.getHelper(source.pages[i]).dictionary!.remove('MediaBox');
      }
      final List<int> stripped = source.saveSync();
      source.dispose();

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[stripped]);
      final PdfDocument result = reopen(merged);
      expect(result.pages.count, 2);
      for (int i = 0; i < 2; i++) {
        final IPdfPrimitive? mediaBox = PdfCrossTable.dereference(
          PdfPageHelper.getHelper(result.pages[i]).dictionary!['MediaBox'],
        );
        expect(
          mediaBox,
          isA<PdfArray>(),
          reason: 'the inherited MediaBox was written onto the page',
        );
        expect(
          ((mediaBox! as PdfArray)[2]! as PdfNumber).value,
          closeTo(PdfPageSize.a4.width, 0.5),
        );
      }
      result.dispose();
    });
  });

  group('merge - signed documents', () {
    const String signedAsset = 'test/assets/doc_assinado_icp_brasil_thais.pdf';

    List<int>? signedBytes() {
      final File file = File(signedAsset);
      return file.existsSync() ? file.readAsBytesSync() : null;
    }

    test('a signed source merges by default, without its signature', () {
      final List<int>? bytes = signedBytes();
      if (bytes == null) {
        markTestSkipped('$signedAsset is not available');
        return;
      }
      final PdfDocument original = reopen(bytes);
      final int pageCount = original.pages.count;
      original.dispose();

      final PdfDocument output = PdfDocument();
      final PdfDocumentMerger merger = PdfDocumentMerger(output);
      final PdfDocument source = reopen(bytes);
      merger.append(source);
      final List<int> merged = output.saveSync();
      expect(
        merger.warnings.any(
          (String w) => w.contains('Merging invalidates signatures'),
        ),
        isTrue,
        reason: 'the loss is reported rather than thrown',
      );
      source.dispose();
      output.dispose();

      final PdfDocument result = reopen(merged);
      expect(result.pages.count, pageCount);
      expect(result.form.fields.count, 0);
      for (int i = 0; i < result.pages.count; i++) {
        expect(
          _hasSignatureWidget(result, i),
          isFalse,
          reason: 'page $i carries no signature field',
        );
      }
      result.dispose();
    });

    test('the visible signature mark is kept as a read-only stamp', () {
      final List<int>? bytes = signedBytes();
      if (bytes == null) {
        markTestSkipped('$signedAsset is not available');
        return;
      }
      final PdfDocument source = reopen(bytes);
      final int visibleSignatures = _visibleSignatureCount(source);
      source.dispose();
      if (visibleSignatures == 0) {
        markTestSkipped('$signedAsset has no visible signature');
        return;
      }

      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      final PdfDocument result = reopen(merged);
      final List<PdfDictionary> stamps = _stampsOf(result);
      expect(
        stamps.length,
        visibleSignatures,
        reason: 'every visible signature left a stamp behind',
      );
      for (final PdfDictionary stamp in stamps) {
        expect(
          PdfCrossTable.dereference(stamp['AP']),
          isNotNull,
          reason: 'the appearance stream travelled with the stamp',
        );
        expect(stamp['FT'], isNull, reason: 'it is no longer a form field');
        expect(stamp['V'], isNull, reason: 'the signature value is gone');
        final IPdfPrimitive? flags = PdfCrossTable.dereference(stamp['F']);
        expect(
          (flags! as PdfNumber).value!.toInt() & 64,
          64,
          reason: 'the stamp is read-only',
        );
      }
      result.dispose();
    });

    test('removeSignatureAppearance removes the mark too', () {
      final List<int>? bytes = signedBytes();
      if (bytes == null) {
        markTestSkipped('$signedAsset is not available');
        return;
      }
      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[bytes],
        options: PdfMergeOptions(removeSignatureAppearance: true),
      );

      final PdfDocument result = reopen(merged);
      expect(_stampsOf(result), isEmpty);
      expect(result.form.fields.count, 0);
      result.dispose();
    });

    test('rejectSignedSources refuses the merge', () {
      final List<int>? bytes = signedBytes();
      if (bytes == null) {
        markTestSkipped('$signedAsset is not available');
        return;
      }
      expect(
        () => PdfDocument.mergeSync(
          <List<int>>[bytes],
          options: PdfMergeOptions(rejectSignedSources: true),
        ),
        throwsA(isA<PdfMergeException>()),
      );
    });

    test('keepInvalidSignatures carries the certificates over', () {
      final List<int>? bytes = signedBytes();
      if (bytes == null) {
        markTestSkipped('$signedAsset is not available');
        return;
      }
      final PdfDocument source = reopen(bytes);
      final List<String> originalContents = _signatureContentsOf(source);
      source.dispose();
      if (originalContents.isEmpty) {
        markTestSkipped('$signedAsset has no signature value to carry over');
        return;
      }

      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[bytes],
        options: PdfMergeOptions(keepInvalidSignatures: true),
      );

      final PdfDocument result = reopen(merged);
      expect(
        _signatureContentsOf(result),
        equals(originalContents),
        reason: 'the CMS blob of every signature survived byte for byte',
      );
      expect(_stampsOf(result), isEmpty, reason: 'nothing was demoted');
      expect(
        _signatureFlagsOf(result),
        isNotNull,
        reason: '/SigFlags travelled so viewers list the signatures',
      );
      result.dispose();
    });

    test('keepInvalidSignatures wins over removeSignatureAppearance', () {
      final List<int>? bytes = signedBytes();
      if (bytes == null) {
        markTestSkipped('$signedAsset is not available');
        return;
      }
      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[bytes],
        options: PdfMergeOptions(
          keepInvalidSignatures: true,
          removeSignatureAppearance: true,
        ),
      );

      final PdfDocument result = reopen(merged);
      expect(_signatureContentsOf(result), isNotEmpty);
      result.dispose();
    });

    test('rejectSignedSources wins over keepInvalidSignatures', () {
      final List<int>? bytes = signedBytes();
      if (bytes == null) {
        markTestSkipped('$signedAsset is not available');
        return;
      }
      expect(
        () => PdfDocument.mergeSync(
          <List<int>>[bytes],
          options: PdfMergeOptions(
            rejectSignedSources: true,
            keepInvalidSignatures: true,
          ),
        ),
        throwsA(isA<PdfMergeException>()),
      );
    });

    test('an unsigned document merges without any signature warning', () {
      final PdfDocument output = PdfDocument();
      final PdfDocumentMerger merger = PdfDocumentMerger(output);
      final PdfDocument source = reopen(MergeFixtures.text(pageCount: 1));
      merger.append(source);
      expect(
        merger.warnings.any((String w) => w.contains('signature')),
        isFalse,
      );
      source.dispose();
      output.dispose();
    });
  });
}

/// Signature widgets that have a visible appearance in the source document.
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
      if (annotation is! PdfDictionary) {
        continue;
      }
      if (!_isSignature(annotation)) {
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

/// Every `/Subtype /Stamp` annotation of a document.
List<PdfDictionary> _stampsOf(PdfDocument document) {
  final List<PdfDictionary> stamps = <PdfDictionary>[];
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
        stamps.add(annotation);
      }
    }
  }
  return stamps;
}

/// The raw `/V /Contents` of every signature field of a document, in order.
List<String> _signatureContentsOf(PdfDocument document) {
  final List<String> contents = <String>[];
  final IPdfPrimitive? acroForm = PdfCrossTable.dereference(
    PdfDocumentHelper.getHelper(document).catalog['AcroForm'],
  );
  if (acroForm is! PdfDictionary) {
    return contents;
  }
  final IPdfPrimitive? fields = PdfCrossTable.dereference(acroForm['Fields']);
  if (fields is! PdfArray) {
    return contents;
  }
  for (int i = 0; i < fields.count; i++) {
    final IPdfPrimitive? field = PdfCrossTable.dereference(fields[i]);
    if (field is! PdfDictionary || !_isSignature(field)) {
      continue;
    }
    final IPdfPrimitive? value = PdfCrossTable.dereference(field['V']);
    if (value is! PdfDictionary) {
      continue;
    }
    final IPdfPrimitive? blob = PdfCrossTable.dereference(value['Contents']);
    if (blob is PdfString && blob.value != null) {
      contents.add(blob.value!);
    }
  }
  contents.sort();
  return contents;
}

int? _signatureFlagsOf(PdfDocument document) {
  final IPdfPrimitive? acroForm = PdfCrossTable.dereference(
    PdfDocumentHelper.getHelper(document).catalog['AcroForm'],
  );
  if (acroForm is! PdfDictionary) {
    return null;
  }
  final IPdfPrimitive? flags = PdfCrossTable.dereference(
    acroForm['SigFlags'],
  );
  return flags is PdfNumber ? flags.value!.toInt() : null;
}

bool _isSignature(PdfDictionary annotation) {
  IPdfPrimitive? node = annotation;
  while (node is PdfDictionary) {
    final IPdfPrimitive? type = PdfCrossTable.dereference(node['FT']);
    if (type != null) {
      return type is PdfName && type.name == 'Sig';
    }
    node = PdfCrossTable.dereference(node['Parent']);
  }
  return false;
}

bool _hasSignatureWidget(PdfDocument document, int pageIndex) {
  final PdfDictionary page =
      PdfPageHelper.getHelper(document.pages[pageIndex]).dictionary!;
  final IPdfPrimitive? annots = PdfCrossTable.dereference(page['Annots']);
  if (annots is! PdfArray) {
    return false;
  }
  for (int i = 0; i < annots.count; i++) {
    final IPdfPrimitive? annotation = PdfCrossTable.dereference(annots[i]);
    if (annotation is! PdfDictionary) {
      continue;
    }
    IPdfPrimitive? node = annotation;
    while (node is PdfDictionary) {
      final IPdfPrimitive? type = PdfCrossTable.dereference(node['FT']);
      if (type != null) {
        if (type.toString().contains('Sig')) {
          return true;
        }
        break;
      }
      node = PdfCrossTable.dereference(node['Parent']);
    }
  }
  return false;
}
