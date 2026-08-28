import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_repair_scanner.dart';
import 'package:test/test.dart';

import '../merging/merge_fixtures.dart';

// Reading through a source is what lets a document of any size be opened
// against a fixed memory ceiling, the way PDFBox, iText and MuPDF all do. The
// tests that matter are the ones that prove a windowed source reads the same
// document as the bytes it stands for -- with a window small enough that every
// read crosses a block boundary and every block is evicted.

/// A block reader over bytes, so the cache can be exercised without a file.
class _ListBlockReader implements PdfBlockReader {
  _ListBlockReader(this._bytes);

  final List<int> _bytes;
  int reads = 0;

  @override
  int get length => _bytes.length;

  @override
  Uint8List readBlock(int offset, int count) {
    reads++;
    if (offset < 0 || offset >= _bytes.length || count <= 0) {
      return Uint8List(0);
    }
    final int end =
        offset + count > _bytes.length ? _bytes.length : offset + count;
    return Uint8List.fromList(_bytes.sublist(offset, end));
  }

  @override
  void close() {}
}

void main() {
  final List<int> healthy = MergeFixtures.text(pageCount: 3, prefix: 'Src');

  group('a cached source reads what the bytes say', () {
    test('byte for byte, across block boundaries', () {
      final PdfDataSource memory = PdfMemoryDataSource(healthy);
      final PdfDataSource cached = PdfCachedDataSource(
        _ListBlockReader(healthy),
        blockSize: 7,
        maxBlocks: 2,
      );
      expect(cached.length, memory.length);
      for (int i = 0; i < healthy.length; i++) {
        expect(cached.byteAt(i), memory.byteAt(i), reason: 'offset $i');
      }
      expect(cached.byteAt(-1), -1);
      expect(cached.byteAt(healthy.length), -1);
    });

    test('range by range, spanning several blocks', () {
      final PdfDataSource cached = PdfCachedDataSource(
        _ListBlockReader(healthy),
        blockSize: 7,
        maxBlocks: 2,
      );
      for (final int count in <int>[1, 6, 7, 8, 21, 100]) {
        for (int start = 0; start + count <= healthy.length; start += 13) {
          expect(
            cached.readRange(start, count),
            healthy.sublist(start, start + count),
            reason: 'range $start..${start + count}',
          );
        }
      }
    });

    test('a range that runs off the end comes back short', () {
      final PdfDataSource cached = PdfCachedDataSource(
        _ListBlockReader(healthy),
        blockSize: 16,
      );
      final Uint8List target = Uint8List(32);
      final int copied = cached.copyInto(healthy.length - 5, 32, target, 0);
      expect(copied, 5);
      expect(target.sublist(0, 5), healthy.sublist(healthy.length - 5));
    });

    test('it keeps a ceiling, not the file', () {
      final _ListBlockReader reader = _ListBlockReader(healthy);
      final PdfDataSource cached = PdfCachedDataSource(
        reader,
        blockSize: 8,
        maxBlocks: 2,
      );
      // Walking forward past more than two blocks has to evict, which means
      // reading a block already visited costs another fetch.
      for (int i = 0; i < healthy.length; i++) {
        cached.byteAt(i);
      }
      final int firstPass = reader.reads;
      expect(cached.byteAt(0), healthy[0]);
      expect(
        reader.reads,
        firstPass + 1,
        reason: 'the first block must have been evicted, not kept forever',
      );
    });

    test('a memory source hands over its bytes, a cached one does not', () {
      expect(PdfMemoryDataSource(healthy).bytes, same(healthy));
      expect(PdfCachedDataSource(_ListBlockReader(healthy)).bytes, isNull);
    });
  });

  group('PdfDocument.fromSource', () {
    test('reads the same document as inputBytes', () {
      final PdfDocument fromBytes = PdfDocument(inputBytes: healthy);
      addTearDown(fromBytes.dispose);
      final PdfDocument fromSource = PdfDocument.fromSource(
        PdfMemoryDataSource(healthy),
      );
      addTearDown(fromSource.dispose);
      expect(fromSource.pages.count, fromBytes.pages.count);
      expect(
        PdfTextExtractor(
          fromSource,
        ).extractText(startPageIndex: 0, endPageIndex: 2),
        PdfTextExtractor(
          fromBytes,
        ).extractText(startPageIndex: 0, endPageIndex: 2),
      );
    });

    test('and the same document through a window of a few bytes', () {
      // A block of 64 bytes with two blocks kept means the parser crosses a
      // boundary constantly and nothing stays cached. If any read still
      // assumes the whole file is at hand, this is where it shows.
      final PdfDocument document = PdfDocument.fromSource(
        PdfCachedDataSource(
          _ListBlockReader(healthy),
          blockSize: 64,
          maxBlocks: 2,
        ),
      );
      addTearDown(document.dispose);
      expect(document.pages.count, 3);
      expect(
        PdfTextExtractor(
          document,
        ).extractText(startPageIndex: 0, endPageIndex: 0),
        contains('Src 1'),
      );
    });

    test('saves what it read', () {
      final PdfDocument document = PdfDocument.fromSource(
        PdfCachedDataSource(
          _ListBlockReader(healthy),
          blockSize: 64,
          maxBlocks: 2,
        ),
      );
      final List<int> saved = document.saveSync();
      document.dispose();
      final PdfDocument reloaded = PdfDocument(inputBytes: saved);
      addTearDown(reloaded.dispose);
      expect(reloaded.pages.count, 3);
      expect(
        PdfTextExtractor(
          reloaded,
        ).extractText(startPageIndex: 0, endPageIndex: 0),
        contains('Src 1'),
      );
    });

    test('recovers a damaged document too', () {
      // Recovery either walks the source through a window or reads it out
      // first, depending on the scan; either way it has to still work, and to
      // report the repair.
      final Uint8List damaged = Uint8List.fromList(healthy);
      _blank(damaged, 'startxref');
      _blank(damaged, 'xref');
      final PdfDocument document = PdfDocument.fromSource(
        PdfCachedDataSource(
          _ListBlockReader(damaged),
          blockSize: 64,
          maxBlocks: 2,
        ),
        strictness: PdfStrictnessLevel.lenient,
      );
      addTearDown(document.dispose);
      expect(document.pages.count, 3);
      expect(document.wasRepaired, isTrue);
    });
  });

  group('the recovery scan through a window', () {
    // What the window has to earn is the right to be invisible: the scan
    // through it must return the same table as the scan over the array, down
    // to the offsets. A window of 64 bytes over blocks of 64 is the harshest
    // version of that claim -- every token comparison, every `endstream`
    // search and every jump by `/Length` crosses a boundary.
    final Uint8List damaged = Uint8List.fromList(healthy);
    _blank(damaged, 'startxref');
    _blank(damaged, 'xref');

    PdfRepairScanResult windowed(
      PdfRepairScan mode, {
      PdfRepairWindow window = PdfRepairWindow.always,
    }) {
      return PdfRepairScanner.scanSource(
        PdfCachedDataSource(
          _ListBlockReader(damaged),
          blockSize: 64,
          maxBlocks: 2,
        ),
        mode: mode,
        window: window,
        windowSize: 64,
      );
    }

    test('reads a file the way the array does', () {
      _expectSameScan(
        windowed(PdfRepairScan.thorough),
        PdfRepairScanner.scan(damaged),
      );
    });

    test('and does when it skips stream bodies', () {
      _expectSameScan(
        windowed(PdfRepairScan.skipStreams, window: PdfRepairWindow.auto),
        PdfRepairScanner.scan(damaged, mode: PdfRepairScan.skipStreams),
      );
    });

    test('and when a /Length lies and `endstream` has to be hunted for', () {
      // The jump by `/Length` lands nowhere, so the scan falls back to
      // searching -- across four thousand bytes and sixty windows, with the
      // token straddling the end of most of them.
      final List<int> lying = _bigStreamPdf(4 << 10, declaredLength: 7);
      _expectSameScan(
        PdfRepairScanner.scanSource(
          PdfCachedDataSource(
            _ListBlockReader(lying),
            blockSize: 64,
            maxBlocks: 2,
          ),
          mode: PdfRepairScan.skipStreams,
          window: PdfRepairWindow.always,
          windowSize: 64,
        ),
        PdfRepairScanner.scan(lying, mode: PdfRepairScan.skipStreams),
      );
    });

    test('a source that carries its bytes is still scanned in place', () {
      // `always` is about file backed sources. Copying an array into a window
      // one page at a time buys nothing, so it does not happen.
      _expectSameScan(
        PdfRepairScanner.scanSource(
          PdfMemoryDataSource(damaged),
          window: PdfRepairWindow.always,
          windowSize: 64,
        ),
        PdfRepairScanner.scan(damaged),
      );
    });
  });

  group('what the recovery scan transfers', () {
    // The point of the window: on a file whose stream bodies dwarf its
    // headers, a scan that skips the bodies should not be paying to move them.
    // This is `mutool` repairing a 3 GB file in about a second, in miniature.
    final List<int> big = _bigStreamPdf(16 << 10);

    int blocksRead(
      PdfRepairScan mode, {
      PdfRepairWindow window = PdfRepairWindow.auto,
    }) {
      final _ListBlockReader reader = _ListBlockReader(big);
      PdfRepairScanner.scanSource(
        PdfCachedDataSource(reader, blockSize: 512, maxBlocks: 4),
        mode: mode,
        window: window,
        windowSize: 512,
      );
      return reader.reads;
    }

    test('skipping stream bodies means never fetching them', () {
      final int whole = blocksRead(PdfRepairScan.thorough);
      final int headers = blocksRead(PdfRepairScan.skipStreams);
      expect(
        headers * 4,
        lessThan(whole),
        reason:
            'the skipping scan fetched $headers blocks of the $whole the '
            'file holds, so the body was transferred after all',
      );
    });

    test('and the file is still read whole when asked for', () {
      // The way out if a source turns out to be slower to seek in than to
      // read: the scan skips the bodies, the transfer does not.
      expect(
        blocksRead(PdfRepairScan.skipStreams, window: PdfRepairWindow.never),
        blocksRead(PdfRepairScan.thorough),
      );
    });

    test('a thorough scan reads the whole file either way', () {
      expect(
        blocksRead(PdfRepairScan.thorough, window: PdfRepairWindow.always),
        blocksRead(PdfRepairScan.thorough),
      );
    });
  });
}

/// Fails unless [windowed] found exactly what [memory] found: the same objects
/// in the same order, at the same offsets, with the same catalog and the same
/// trailers.
void _expectSameScan(PdfRepairScanResult windowed, PdfRepairScanResult memory) {
  expect(windowed.objects.keys.toList(), memory.objects.keys.toList());
  for (final MapEntry<int, PdfRepairedObject> entry in memory.objects.entries) {
    final PdfRepairedObject found = windowed.objects[entry.key]!;
    expect(found.offset, entry.value.offset, reason: 'object ${entry.key}');
    expect(
      found.generation,
      entry.value.generation,
      reason: 'object ${entry.key}',
    );
  }
  expect(windowed.catalogNumber, memory.catalogNumber);
  expect(windowed.trailerOffsets, memory.trailerOffsets);
  expect(memory.objects, isNotEmpty);
  expect(memory.trailerOffsets, isNotEmpty);
}

/// A one page document with no cross-reference table and a content stream of
/// [bodySize] bytes, so that what a scan reads and what it skips are told
/// apart by the blocks its source was asked for.
///
/// The body is a run of a single letter: it carries no object header, so a
/// thorough scan and a skipping one have to agree on what is in the file.
/// [declaredLength] writes a `/Length` other than the real one, which is what
/// sends the scan looking for `endstream` a byte at a time.
List<int> _bigStreamPdf(int bodySize, {int? declaredLength}) {
  final String body = 'x' * bodySize;
  return ('%PDF-1.7\n'
          '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'
          '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n'
          '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] '
          '/Contents 4 0 R >>\nendobj\n'
          '4 0 obj\n<< /Length ${declaredLength ?? bodySize} >>\nstream\n'
          '$body\nendstream\n'
          'endobj\n'
          'trailer\n<< /Root 1 0 R /Size 5 >>\n'
          '%%EOF\n')
      .codeUnits;
}

void _blank(Uint8List bytes, String token) {
  final List<int> needle = token.codeUnits;
  for (int i = 0; i <= bytes.length - needle.length; i++) {
    bool hit = true;
    for (int k = 0; k < needle.length; k++) {
      if (bytes[i + k] != needle[k]) {
        hit = false;
        break;
      }
    }
    if (hit) {
      for (int k = 0; k < needle.length; k++) {
        bytes[i + k] = 0x20;
      }
      i += needle.length - 1;
    }
  }
}
