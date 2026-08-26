import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

import 'merge_fixtures.dart';

// When the merge drops the signatures, it must leave no trace of them in the
// output bytes.
//
// Detaching the field from /AcroForm /Fields is not enough. A reader that
// walks the form tree sees nothing, but any tool that scans the file for
// signature dictionaries — several do, precisely because scanning is cheap and
// survives a broken cross-reference table — would still find the PKCS#7 blob
// sitting there as an unreachable object, and report the document as carrying
// signatures it cannot validate. It also costs tens of kilobytes.
//
// The check is therefore a binary scan of the whole file, not a structural
// walk: it is the assertion that cannot be satisfied by hiding the object.

/// Byte sequences that only appear when a signature travelled.
const Map<String, String> _traces = <String, String>{
  'ByteRange': '/ByteRange',
  'signature dictionary': '/Type /Sig',
  'signature handler': 'Adobe.PPKLite',
  'detached PKCS#7': 'adbe.pkcs7',
};

void main() {
  final List<String> signedAssets = <String>[
    'test/merging/assets/sei_source_signed_visible.pdf',
    'test/merging/assets/sei_source_signed_invisible.pdf',
    'test/merging/assets/sei_merged_reference.pdf',
    'test/assets/doc_assinado_icp_brasil_thais.pdf',
    'test/assets/duas_assinaturas.pdf',
    'test/assets/tambem com 12 assinaturas.pdf',
  ];

  group('no signature residue in the default merge', () {
    for (final String asset in signedAssets) {
      test('${_basename(asset)} leaves nothing behind', () {
        final List<int>? bytes = _read(asset);
        if (bytes == null) {
          return;
        }
        expect(
          _tracesIn(bytes),
          isNotEmpty,
          reason: 'the fixture really is signed',
        );

        final List<int> merged = PdfDocument.mergeSync(<List<int>>[bytes]);
        expect(
          _tracesIn(merged),
          isEmpty,
          reason:
              'the default merge drops the signatures; no byte of them may '
              'survive as an unreachable object',
        );
      });

      test('${_basename(asset)} leaves nothing behind without its mark', () {
        final List<int>? bytes = _read(asset);
        if (bytes == null) {
          return;
        }
        final List<int> merged = PdfDocument.mergeSync(
          <List<int>>[bytes],
          options: PdfMergeOptions(removeSignatureAppearance: true),
        );
        expect(_tracesIn(merged), isEmpty);
      });

      test('${_basename(asset)} keeps everything when asked to', () {
        final List<int>? bytes = _read(asset);
        if (bytes == null) {
          return;
        }
        final List<int> merged = PdfDocument.mergeSync(
          <List<int>>[bytes],
          options: PdfMergeOptions(keepInvalidSignatures: true),
        );
        expect(
          _tracesIn(merged),
          isNotEmpty,
          reason: 'keepInvalidSignatures is the opposite guarantee',
        );
      });
    }

    test('dropping the signature costs real bytes, not just a reference', () {
      final List<int>? bytes = _read(
        'test/merging/assets/sei_source_signed_visible.pdf',
      );
      if (bytes == null) {
        return;
      }
      final int dropped =
          PdfDocument.mergeSync(<List<int>>[bytes]).length;
      final int kept = PdfDocument.mergeSync(
        <List<int>>[bytes],
        options: PdfMergeOptions(keepInvalidSignatures: true),
      ).length;
      expect(
        dropped,
        lessThan(kept - 10000),
        reason:
            'the CMS blob is around 19 KB; if the default output is not '
            'markedly smaller, it is still carrying it',
      );
    });

    test('mixing a signed and an unsigned source leaves no trace either', () {
      final List<int>? signed = _read(
        'test/merging/assets/sei_source_signed_visible.pdf',
      );
      if (signed == null) {
        return;
      }
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[
        MergeFixtures.text(pageCount: 2),
        signed,
        MergeFixtures.form(),
      ]);
      expect(_tracesIn(merged), isEmpty);
    });
  });
}

/// Names of the signature traces present in [bytes].
List<String> _tracesIn(List<int> bytes) {
  final Uint8List data = Uint8List.fromList(bytes);
  final List<String> found = <String>[];
  _traces.forEach((String name, String needle) {
    if (_indexOf(data, needle) >= 0) {
      found.add(name);
    }
  });
  return found;
}

int _indexOf(Uint8List haystack, String needle) {
  final List<int> pattern = needle.codeUnits;
  final int limit = haystack.length - pattern.length;
  for (int i = 0; i <= limit; i++) {
    bool hit = true;
    for (int j = 0; j < pattern.length; j++) {
      if (haystack[i + j] != pattern[j]) {
        hit = false;
        break;
      }
    }
    if (hit) {
      return i;
    }
  }
  return -1;
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
