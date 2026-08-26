import 'dart:io';

import 'package:crypto/crypto.dart';
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

/// Checks the merged output against the shape the SEI process system produces.
///
/// SEI ("Sistema Eletrônico de Informações", the document system used across
/// Brazilian public administration) merges the documents of a process into a
/// single PDF and **keeps the signature fields as they are**: the signature
/// dictionaries travel with their original `/ByteRange`, which no longer
/// describes the merged file, so validators report the signatures as invalid.
///
/// `test/merging/assets/sei_merged_reference.pdf` is one such output — 42 pages,
/// two signature fields, `/SigFlags 3`, byte ranges pointing at a ~20 KB
/// document inside a 238 KB file. It is the reference for
/// [PdfMergeOptions.keepInvalidSignatures].
void main() {
  const String reference = 'test/merging/assets/sei_merged_reference.pdf';

  group('SEI reference document', () {
    test('it is the documented shape: signatures kept, byte ranges stale', () {
      final List<int>? bytes = _read(reference);
      if (bytes == null) {
        return;
      }
      final PdfDocument document = reopen(bytes);
      addTearDown(document.dispose);

      expect(document.pages.count, 42);
      final List<_Signature> signatures = _signaturesOf(document);
      expect(signatures.length, 2);
      expect(
        signatures.map((_Signature s) => s.name),
        containsAll(<String>['Signature1', 'dummyFieldName1']),
      );
      expect(_signatureFlagsOf(document), 3);
      for (final _Signature signature in signatures) {
        expect(signature.subFilter, 'adbe.pkcs7.detached');
        expect(signature.contents, isNotEmpty);
        expect(
          signature.byteRange.last + signature.byteRange[2],
          lessThan(bytes.length),
          reason:
              'the byte range covers a fraction of the merged file, which is '
              'why validators reject it',
        );
      }
    });

    test('merging it again keeps its two signatures on request', () {
      final List<int>? bytes = _read(reference);
      if (bytes == null) {
        return;
      }
      final PdfDocument source = reopen(bytes);
      final List<_Signature> expected = _signaturesOf(source);
      final int pages = source.pages.count;
      source.dispose();

      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[bytes],
        options: PdfMergeOptions(keepInvalidSignatures: true),
      );
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(result.pages.count, pages);
      expect(_signaturesOf(result), equals(expected));
    });

    test('one of its two signature fields has no widget on any page', () {
      // SEI left `Signature1` in /AcroForm /Fields without an entry in any
      // page /Annots. Only `dummyFieldName1` is visible on page 40. This is
      // the shape the orphan field sweep exists for.
      final List<int>? bytes = _read(reference);
      if (bytes == null) {
        return;
      }
      final PdfDocument document = reopen(bytes);
      addTearDown(document.dispose);
      expect(_signaturesOf(document).length, 2);
      expect(_widgetSignatureNames(document), <String>['dummyFieldName1']);
    });

    test('merging it by default turns its visible signature into a stamp', () {
      final List<int>? bytes = _read(reference);
      if (bytes == null) {
        return;
      }
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(_signaturesOf(result), isEmpty);
      expect(
        _stampCount(result),
        1,
        reason:
            'the one signature that was visible on a page kept its mark; the '
            'orphan field had nothing to show',
      );
    });
  });

  group('orphan form fields', () {
    test('a signature field with no widget is still imported on request', () {
      final List<int>? bytes = _read(reference);
      if (bytes == null) {
        return;
      }
      final PdfDocument source = reopen(bytes);
      final Set<String> expected =
          _signaturesOf(source).map((_Signature s) => s.name).toSet();
      source.dispose();

      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[bytes],
        options: PdfMergeOptions(keepInvalidSignatures: true),
      );
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(
        _signaturesOf(result).map((_Signature s) => s.name).toSet(),
        expected,
        reason:
            'the field reachable only from /AcroForm /Fields came across too',
      );
    });

    test('orphan signatures are dropped by default, like the visible ones', () {
      final List<int>? bytes = _read(reference);
      if (bytes == null) {
        return;
      }
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(_signaturesOf(result), isEmpty);
    });

    test('importing two ranges of the same source does not duplicate them', () {
      final List<int>? bytes = _read(reference);
      if (bytes == null) {
        return;
      }
      final PdfDocument source = reopen(bytes);
      final PdfDocument output = PdfDocument();
      final PdfDocumentMerger merger = PdfDocumentMerger(
        output,
        options: PdfMergeOptions(keepInvalidSignatures: true),
      );
      merger.importPageRange(source, 0, 1);
      merger.importPageRange(source, 40, 41);
      final List<int> merged = output.saveSync();
      source.dispose();
      output.dispose();

      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(result.pages.count, 4);
      expect(
        _signaturesOf(result).length,
        2,
        reason: 'the orphan sweep runs once per source document',
      );
    });
  });

  group('end to end against the SEI output', () {
    // The documents of the SEI process, in the order they appear in the
    // merged reference. They are byte for byte the entries of the process ZIP
    // that SEI exports — see the checksum test below.
    //
    // The process holds a fourth document, `[4]-0009612_Despacho.html`, which
    // SEI renders to a page while merging. Rendering HTML is not something a
    // PDF library does, so the merge here produces 41 pages against its 42;
    // what is compared is the signature structure, not the page count.
    const String relatorio = 'test/merging/assets/sei_source_relatorio.pdf';
    const String invisible =
        'test/merging/assets/sei_source_signed_invisible.pdf';
    const String visible = 'test/merging/assets/sei_source_signed_visible.pdf';

    List<List<int>>? sources() {
      final List<int>? a = _read(relatorio);
      final List<int>? b = _read(invisible);
      final List<int>? c = _read(visible);
      if (a == null || b == null || c == null) {
        return null;
      }
      return <List<int>>[a, b, c];
    }

    test('the sources are byte for byte the entries of the SEI process ZIP', () {
      // Guards the provenance of the fixtures: if one is ever replaced, the
      // comparison against the SEI output stops meaning anything.
      const Map<String, String> expected = <String, String>{
        relatorio:
            'e38828e2446ae8b51f6e5b6faf5aac868afe5b0a456151888afdec3575ceaca5',
        invisible:
            'ef94161de66fd5ec00486ff3eb958de3107db27a4f79c1d2208b17fe89a2b0d9',
        visible:
            'a6c9c78258e83931b1b2838f1c0405be3f9c6bdfe5b07d4b3b133fbbd5f1cdd3',
      };
      for (final MapEntry<String, String> entry in expected.entries) {
        final List<int>? bytes = _read(entry.key);
        if (bytes == null) {
          return;
        }
        expect(
          sha256.convert(bytes).toString(),
          entry.value,
          reason: '${entry.key} is the file SEI merged',
        );
      }
    });

    test('the source documents are the shapes the reference was built from', () {
      final List<List<int>>? inputs = sources();
      if (inputs == null) {
        return;
      }
      final PdfDocument report = reopen(inputs[0]);
      expect(report.pages.count, 39);
      expect(_signaturesOf(report), isEmpty);
      report.dispose();

      final PdfDocument hidden = reopen(inputs[1]);
      expect(hidden.pages.count, 1);
      expect(_signaturesOf(hidden).length, 1);
      expect(
        _widgetSignatureNames(hidden),
        isEmpty,
        reason: 'its signature has no widget: nothing shows on the page',
      );
      hidden.dispose();

      final PdfDocument shown = reopen(inputs[2]);
      expect(shown.pages.count, 1);
      expect(_signaturesOf(shown).length, 1);
      expect(_widgetSignatureNames(shown), <String>['Signature1']);
      shown.dispose();
    });

    test('merging them keeps both signatures, as SEI does', () {
      final List<List<int>>? inputs = sources();
      if (inputs == null) {
        return;
      }
      final List<_Signature> expected = <_Signature>[
        ..._signaturesIn(inputs[1]),
        ..._signaturesIn(inputs[2]),
      ];

      final List<int> merged = PdfDocument.mergeSync(
        inputs,
        options: PdfMergeOptions(keepInvalidSignatures: true),
      );
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);

      expect(result.pages.count, 41);
      final List<_Signature> after = _signaturesOf(result);
      expect(after.length, 2, reason: 'both signature fields came across');
      expect(
        after.map((_Signature s) => s.contents).toSet(),
        expected.map((_Signature s) => s.contents).toSet(),
        reason: 'the two CMS blobs are the ones from the sources',
      );
      expect(
        after.map((_Signature s) => s.byteRange.join(',')).toSet(),
        expected.map((_Signature s) => s.byteRange.join(',')).toSet(),
        reason:
            'the byte ranges are the originals, exactly as in the SEI output',
      );
      expect(_signatureFlagsOf(result), isNotNull);
    });

    test('both sources name their field Signature1, so one is renamed', () {
      final List<List<int>>? inputs = sources();
      if (inputs == null) {
        return;
      }
      expect(_signaturesIn(inputs[1]).single.name, 'Signature1');
      expect(_signaturesIn(inputs[2]).single.name, 'Signature1');

      final List<int> merged = PdfDocument.mergeSync(
        inputs,
        options: PdfMergeOptions(keepInvalidSignatures: true),
      );
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      final List<String> names =
          _signaturesOf(result).map((_Signature s) => s.name).toList();
      expect(
        names.toSet().length,
        2,
        reason:
            'SEI renamed one of them to dummyFieldName1 for the same reason: '
            'two fields may not share a fully qualified name',
      );
      expect(names, contains('Signature1'));
    });

    test('the visible signature keeps its widget on its own page', () {
      final List<List<int>>? inputs = sources();
      if (inputs == null) {
        return;
      }
      final List<int> merged = PdfDocument.mergeSync(
        inputs,
        options: PdfMergeOptions(keepInvalidSignatures: true),
      );
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      // 0..38 report, 39 invisibly signed, 40 visibly signed.
      expect(_annotationCount(result, 39), 0);
      expect(_annotationCount(result, 40), greaterThan(0));
    });

    test('by default only the visible one leaves a mark', () {
      final List<List<int>>? inputs = sources();
      if (inputs == null) {
        return;
      }
      final List<int> merged = PdfDocument.mergeSync(inputs);
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(result.pages.count, 41);
      expect(_signaturesOf(result), isEmpty);
      expect(
        _stampCount(result),
        1,
        reason: 'the invisible signature had no mark to keep',
      );
    });
  });

  group('keepInvalidSignatures reproduces the SEI shape', () {
    // A single page ICP-Brasil signed document, the same kind of input SEI
    // merges.
    const String signed = 'test/assets/doc_assinado_icp_brasil_thais.pdf';

    test('the signature dictionary travels untouched', () {
      final List<int>? bytes = _read(signed);
      if (bytes == null) {
        return;
      }
      final PdfDocument source = reopen(bytes);
      final List<_Signature> expected = _signaturesOf(source);
      source.dispose();
      expect(expected, isNotEmpty, reason: 'the fixture is signed');

      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[MergeFixtures.text(pageCount: 2, prefix: 'Cover'), bytes],
        options: PdfMergeOptions(keepInvalidSignatures: true),
      );
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);

      final List<_Signature> after = _signaturesOf(result);
      expect(after.length, expected.length);
      for (int i = 0; i < after.length; i++) {
        expect(
          after[i].contents,
          expected[i].contents,
          reason: 'the CMS blob is byte for byte the original',
        );
        expect(
          after[i].byteRange,
          expected[i].byteRange,
          reason:
              'the byte range is carried over verbatim, exactly as SEI does; '
              'it describes the original document, not the merged one',
        );
        expect(after[i].subFilter, expected[i].subFilter);
        expect(after[i].isMergedWidget, isTrue);
      }
      expect(
        _signatureFlagsOf(result),
        isNotNull,
        reason: '/SigFlags travelled, so viewers list the signatures',
      );
    });

    test('the signature widget lands on the imported page, not the cover', () {
      final List<int>? bytes = _read(signed);
      if (bytes == null) {
        return;
      }
      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[MergeFixtures.text(pageCount: 2, prefix: 'Cover'), bytes],
        options: PdfMergeOptions(keepInvalidSignatures: true),
      );
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      expect(result.pages.count, 3);
      expect(_annotationCount(result, 0), 0);
      expect(_annotationCount(result, 1), 0);
      expect(
        _annotationCount(result, 2),
        greaterThan(0),
        reason: 'the signature widget belongs to the signed page',
      );
    });

    test('two documents signed with the same field name are disambiguated', () {
      final List<int>? bytes = _read(signed);
      if (bytes == null) {
        return;
      }
      final List<int> merged = PdfDocument.mergeSync(
        <List<int>>[bytes, bytes],
        options: PdfMergeOptions(keepInvalidSignatures: true),
      );
      final PdfDocument result = reopen(merged);
      addTearDown(result.dispose);
      final List<String> names =
          _signaturesOf(result).map((_Signature s) => s.name).toList();
      expect(names.length, 2);
      expect(
        names.toSet().length,
        2,
        reason:
            'two fields may not share a fully qualified name; the second is '
            'renamed even though both carry the same certificate',
      );
    });
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

/// What a signature field holds, reduced to the parts a merge must preserve.
class _Signature {
  _Signature({
    required this.name,
    required this.byteRange,
    required this.contents,
    required this.subFilter,
    required this.isMergedWidget,
  });

  final String name;
  final List<num> byteRange;
  final String contents;
  final String? subFilter;

  /// Whether the field dictionary is also the widget annotation, the shape
  /// both SEI and this library produce for a single visible signature.
  final bool isMergedWidget;

  @override
  bool operator ==(Object other) =>
      other is _Signature &&
      other.name == name &&
      other.contents == contents &&
      other.subFilter == subFilter &&
      other.byteRange.length == byteRange.length &&
      List<int>.generate(byteRange.length, (int i) => i).every(
        (int i) => other.byteRange[i] == byteRange[i],
      );

  @override
  int get hashCode => Object.hash(name, contents, subFilter);

  @override
  String toString() => '$name byteRange=$byteRange contents=${contents.length}b';
}

/// The signatures of a document given its bytes.
List<_Signature> _signaturesIn(List<int> bytes) {
  final PdfDocument document = reopen(bytes);
  final List<_Signature> signatures = _signaturesOf(document);
  document.dispose();
  return signatures;
}

List<_Signature> _signaturesOf(PdfDocument document) {
  final List<_Signature> signatures = <_Signature>[];
  final IPdfPrimitive? acroForm = PdfCrossTable.dereference(
    PdfDocumentHelper.getHelper(document).catalog['AcroForm'],
  );
  if (acroForm is! PdfDictionary) {
    return signatures;
  }
  final IPdfPrimitive? fields = PdfCrossTable.dereference(acroForm['Fields']);
  if (fields is! PdfArray) {
    return signatures;
  }
  for (int i = 0; i < fields.count; i++) {
    final IPdfPrimitive? field = PdfCrossTable.dereference(fields[i]);
    if (field is! PdfDictionary) {
      continue;
    }
    final IPdfPrimitive? type = PdfCrossTable.dereference(field['FT']);
    if (type is! PdfName || type.name != 'Sig') {
      continue;
    }
    final IPdfPrimitive? value = PdfCrossTable.dereference(field['V']);
    if (value is! PdfDictionary) {
      continue;
    }
    final IPdfPrimitive? name = PdfCrossTable.dereference(field['T']);
    final IPdfPrimitive? subtype = PdfCrossTable.dereference(field['Subtype']);
    final IPdfPrimitive? range = PdfCrossTable.dereference(value['ByteRange']);
    final IPdfPrimitive? contents = PdfCrossTable.dereference(
      value['Contents'],
    );
    final IPdfPrimitive? subFilter = PdfCrossTable.dereference(
      value['SubFilter'],
    );
    signatures.add(
      _Signature(
        name: name is PdfString ? name.value ?? '' : '',
        byteRange: <num>[
          if (range is PdfArray)
            for (int j = 0; j < range.count; j++)
              (range[j] as PdfNumber?)?.value ?? 0,
        ],
        contents: contents is PdfString ? contents.value ?? '' : '',
        subFilter: subFilter is PdfName ? subFilter.name : null,
        isMergedWidget: subtype is PdfName && subtype.name == 'Widget',
      ),
    );
  }
  signatures.sort((_Signature a, _Signature b) => a.name.compareTo(b.name));
  return signatures;
}

int? _signatureFlagsOf(PdfDocument document) {
  final IPdfPrimitive? acroForm = PdfCrossTable.dereference(
    PdfDocumentHelper.getHelper(document).catalog['AcroForm'],
  );
  if (acroForm is! PdfDictionary) {
    return null;
  }
  final IPdfPrimitive? flags = PdfCrossTable.dereference(acroForm['SigFlags']);
  return flags is PdfNumber ? flags.value!.toInt() : null;
}

/// Names of the signature fields that actually have a widget on some page.
List<String> _widgetSignatureNames(PdfDocument document) {
  final List<String> names = <String>[];
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
      final IPdfPrimitive? type = PdfCrossTable.dereference(annotation['FT']);
      if (type is! PdfName || type.name != 'Sig') {
        continue;
      }
      final IPdfPrimitive? name = PdfCrossTable.dereference(annotation['T']);
      names.add(name is PdfString ? name.value ?? '' : '');
    }
  }
  return names;
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
