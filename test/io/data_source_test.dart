import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
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
      // The scan needs the whole file at once, so a windowed source is read
      // out first. It has to still work, and to report the repair.
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
