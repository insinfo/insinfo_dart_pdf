import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_repair_scanner.dart';
import 'package:test/test.dart';

import '../merging/merge_fixtures.dart';

// The scan that rebuilds a damaged object table works on bytes. These tests
// pin the three things that follow from that: it is fast, it reads the file
// the way the reference implementations do, and skipping stream bodies is a
// decision the caller makes rather than one the library takes.

void main() {
  final List<int> healthy = MergeFixtures.text(pageCount: 3, prefix: 'Scan');
  final List<int> damaged = _breakStartxref(healthy);

  PdfDocument load(
    List<int> bytes, {
    PdfRepairScan scan = PdfRepairScan.thorough,
  }) {
    final PdfDocument document = PdfDocument(
      inputBytes: bytes,
      strictness: PdfStrictnessLevel.lenient,
      repairScan: scan,
    );
    addTearDown(document.dispose);
    return document;
  }

  group('the scan finds what the file holds', () {
    test('every object header, with its offset', () {
      final PdfRepairScanResult result = PdfRepairScanner.scan(healthy);
      expect(result.objects, isNotEmpty);
      for (final MapEntry<int, PdfRepairedObject> entry
          in result.objects.entries) {
        final String header = String.fromCharCodes(
          healthy.sublist(entry.value.offset, entry.value.offset + 24),
        );
        expect(
          header,
          startsWith('${entry.key} ${entry.value.generation} obj'),
          reason: 'the offset must land on the header it claims',
        );
      }
    });

    test('the document catalog, without parsing objects back to front', () {
      final PdfRepairScanResult result = PdfRepairScanner.scan(healthy);
      expect(result.catalogNumber, isNotNull);
      final PdfRepairedObject catalog = result.objects[result.catalogNumber]!;
      final String text = String.fromCharCodes(
        healthy.sublist(catalog.offset, catalog.offset + 200),
      );
      expect(text, contains('/Catalog'));
    });

    test('every trailer keyword, so nobody searches for them twice', () {
      final PdfRepairScanResult result = PdfRepairScanner.scan(healthy);
      expect(result.trailerOffsets, isNotEmpty);
      for (final int offset in result.trailerOffsets) {
        expect(
          String.fromCharCodes(healthy.sublist(offset, offset + 7)),
          'trailer',
        );
      }
    });

    test('nothing at all in bytes that are not a PDF', () {
      final PdfRepairScanResult result = PdfRepairScanner.scan(
        List<int>.filled(4096, 0x41),
      );
      expect(result.objects, isEmpty);
      expect(result.catalogNumber, isNull);
      expect(result.trailerOffsets, isEmpty);
    });
  });

  group('the later revision of an object wins', () {
    // Scanning runs front to back, so a higher offset is a later revision —
    // the one an incremental update meant to be current. iText
    // (`gen >= xr[num][1]`), PDFBox (a `HashMap.put` per hit) and MuPDF all
    // resolve the collision this way. Keeping the *first* hit, as this library
    // did, rebuilds a revised document out of its oldest parts.
    final List<int> updated = _appendRevision(healthy);

    test('the fixture really carries two revisions', () {
      final PdfDocument document = PdfDocument(inputBytes: updated);
      addTearDown(document.dispose);
      expect(document.pages.count, 4);
      expect(
        String.fromCharCodes(updated).split('%%EOF').length - 1,
        greaterThan(1),
        reason: 'an incremental update leaves more than one %%EOF',
      );
    });

    test('recovery returns the last revision, not the first', () {
      expect(
        load(_breakStartxref(updated)).pages.count,
        4,
        reason:
            'the page added by the second revision must survive; three pages '
            'would mean the scan rebuilt the document from its first revision',
      );
    });

    test('and the same holds when stream bodies are skipped', () {
      expect(
        load(
          _breakStartxref(updated),
          scan: PdfRepairScan.skipStreams,
        ).pages.count,
        4,
      );
    });
  });

  group('objects of a generation other than zero', () {
    test('are found, instead of being dropped', () {
      final PdfRepairScanResult result = PdfRepairScanner.scan(
        _generationOnePdf,
      );
      expect(
        result.objects[4]?.generation,
        1,
        reason:
            'the previous scan registered only `marker == 0`, so an object '
            'that had been freed and reused disappeared from the document',
      );
      expect(result.objects.keys, containsAll(<int>[1, 2, 3, 4]));
    });

    test('and the document that references one loads', () {
      // The scan finding the header is half the claim; the other half is that
      // `4 1 R` still resolves to it.
      final PdfDocument document = load(_generationOnePdf);
      expect(document.pages.count, 1);
      expect(document.wasRepaired, isTrue);
    });
  });

  group('skipping stream bodies', () {
    test('is off by default', () {
      expect(PdfMergeOptions().repairScan, PdfRepairScan.thorough);
    });

    test('reaches the same document', () {
      final PdfRepairScanResult thorough = PdfRepairScanner.scan(damaged);
      final PdfRepairScanResult skipped = PdfRepairScanner.scan(
        damaged,
        mode: PdfRepairScan.skipStreams,
      );
      expect(skipped.objects.length, thorough.objects.length);
      expect(skipped.catalogNumber, thorough.catalogNumber);
      for (final int number in thorough.objects.keys) {
        expect(skipped.objects[number]!.offset, thorough.objects[number]!.offset);
      }
    });

    test('survives a stream whose /Length lies', () {
      // `/Length` is a hint. MuPDF jumps by it and checks that `endstream` is
      // really where it should be, falling back to searching when it is not,
      // so a wrong length costs time rather than correctness.
      final List<int> lying = _breakStartxref(_breakStreamLength(healthy));
      expect(
        load(lying, scan: PdfRepairScan.skipStreams).pages.count,
        3,
      );
    });

    test('survives a /Length written as an indirect reference', () {
      // `/Length 12 0 R` is legal and common in files written by iText.
      // Reading the `12` as a byte count would land in the middle of a stream.
      final List<int> indirect = _breakStartxref(_indirectLength(healthy));
      final PdfRepairScanResult result = PdfRepairScanner.scan(
        indirect,
        mode: PdfRepairScan.skipStreams,
      );
      expect(result.catalogNumber, isNotNull);
      expect(result.objects, isNotEmpty);
    });
  });

  group('the scan stays in bytes', () {
    test('a damaged 16 MB file recovers without a per byte allocation', () {
      // Wall clock, so the budget is deliberately loose: it exists to catch a
      // regression of *model* — somebody reintroducing a `String` in the loop
      // — not to grade the machine. The previous implementation spent ~8500 ms
      // in the scan plus ~3000 ms in `searchBack` on this input; the current
      // one lands around 500 ms, and the ceiling sits far enough above that to
      // survive a loaded CI running the suite in parallel.
      final List<int> big = _breakStartxref(_inflate(healthy, 16 << 20));
      final Stopwatch sw = Stopwatch()..start();
      final PdfDocument document = load(big);
      final int elapsed = sw.elapsedMilliseconds;
      expect(document.pages.count, 3);
      expect(
        elapsed,
        lessThan(3000),
        reason: 'recovering 16 MB took ${elapsed}ms',
      );
    });
  });
}

/// Blanks every `startxref` and every `xref` keyword, leaving the objects and
/// the trailers where they are: a file whose cross-reference tables are gone
/// but whose content is intact.
///
/// Blanking only the *last* `startxref` is not enough on a file that carries
/// an incremental update. The reader finds the previous revision's `startxref`,
/// its table still parses, and the document loads — as the older revision,
/// silently. Recovery is never reached because nothing looked broken.
List<int> _breakStartxref(List<int> bytes) {
  final Uint8List out = Uint8List.fromList(bytes);
  _blankAll(out, <int>[115, 116, 97, 114, 116, 120, 114, 101, 102]); // startxref
  _blankAll(out, <int>[120, 114, 101, 102]); // xref
  return out;
}

void _blankAll(Uint8List bytes, List<int> token) {
  for (int i = 0; i <= bytes.length - token.length; i++) {
    bool hit = true;
    for (int k = 0; k < token.length; k++) {
      if (bytes[i + k] != token[k]) {
        hit = false;
        break;
      }
    }
    if (hit) {
      for (int k = 0; k < token.length; k++) {
        bytes[i + k] = 0x20;
      }
      i += token.length - 1;
    }
  }
}

/// Loads [bytes] and saves an added page as an incremental update, so the file
/// carries two definitions of the page tree.
List<int> _appendRevision(List<int> bytes) {
  final PdfDocument document = PdfDocument(inputBytes: bytes);
  document.pages.add().graphics.drawString(
    'Scan 4',
    PdfStandardFont(PdfFontFamily.helvetica, 12),
  );
  final List<int> saved = document.saveSync();
  document.dispose();
  return saved;
}

/// Pads the file with a comment block, to measure the scan against size.
List<int> _inflate(List<int> bytes, int target) {
  final String source = String.fromCharCodes(bytes);
  final int header = source.indexOf('\n') + 1;
  final int padding = target - bytes.length;
  if (padding <= 0) {
    return bytes;
  }
  return <int>[
    ...bytes.sublist(0, header),
    ...('% ${'p' * 60}\n' * (padding ~/ 64)).codeUnits,
    ...bytes.sublist(header),
  ];
}

List<int> _breakStreamLength(List<int> bytes) {
  final String s = String.fromCharCodes(bytes);
  final int i = s.indexOf('/Length ');
  final int end = s.indexOf('\n', i);
  return <int>[
    ...bytes.sublist(0, i),
    ...'/Length 7'.codeUnits,
    ...bytes.sublist(end),
  ];
}

List<int> _indirectLength(List<int> bytes) {
  final String s = String.fromCharCodes(bytes);
  final int i = s.indexOf('/Length ');
  final int end = s.indexOf('\n', i);
  final String original = s.substring(i, end);
  return <int>[
    ...bytes.sublist(0, i),
    ...'/Length 99 0 R'.padRight(original.length).codeUnits,
    ...bytes.sublist(end),
  ];
}

/// A minimal document whose content stream is object `4 1 obj` — a number that
/// was freed and reused, which the previous scan discarded outright.
final List<int> _generationOnePdf =
    ('%PDF-1.7\n'
            '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'
            '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n'
            '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] '
            '/Contents 4 1 R >>\nendobj\n'
            '4 1 obj\n<< /Length 21 >>\nstream\nBT /F1 12 Tf ET\nendstream\n'
            'endobj\n'
            'trailer\n<< /Root 1 0 R /Size 5 >>\n'
            '%%EOF\n')
        .codeUnits;
