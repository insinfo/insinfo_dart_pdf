import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/io/pdf_reader.dart';
import 'package:test/test.dart';

import '../merging/merge_fixtures.dart';

// A growable `List<int>` in the Dart VM costs eight bytes per element. The
// document used to be accumulated in one while saving, and copied into one
// while loading a file with junk after the last `%%EOF`. Both are byte arrays
// now. These tests pin the shapes rather than the byte counts: memory is
// awkward to assert, but the types that caused it are not.

class _CountingSink implements PdfOutputSink {
  int calls = 0;
  int bytes = 0;
  final BytesBuilder collected = BytesBuilder();

  @override
  void add(List<int> data) {
    calls++;
    bytes += data.length;
    collected.add(data);
  }
}

void main() {
  final List<int> healthy = MergeFixtures.text(pageCount: 3, prefix: 'Mem');

  group('the saved document is a byte array', () {
    test('saveSync', () {
      final PdfDocument document = PdfDocument(inputBytes: healthy);
      addTearDown(document.dispose);
      expect(document.saveSync(), isA<Uint8List>());
    });

    test('save', () async {
      final PdfDocument document = PdfDocument(inputBytes: healthy);
      addTearDown(document.dispose);
      expect(await document.save(), isA<Uint8List>());
    });

    test('and it still reads back', () {
      final PdfDocument document = PdfDocument(inputBytes: healthy);
      final List<int> saved = document.saveSync();
      document.dispose();
      final PdfDocument reloaded = PdfDocument(inputBytes: saved);
      addTearDown(reloaded.dispose);
      expect(reloaded.pages.count, 3);
      expect(
        PdfTextExtractor(
          reloaded,
        ).extractText(startPageIndex: 0, endPageIndex: 0),
        contains('Mem 1'),
      );
    });
  });

  group('loading a file with junk after %%EOF', () {
    // The reader reprocesses only the prefix up to the last `%%EOF`, which
    // means copying the whole document. That copy went into a growable
    // `List<int>` filled one byte at a time: on a 250 MB file it cost 2 GB and
    // three seconds.
    final Uint8List junked = Uint8List(healthy.length + 8)
      ..setRange(0, healthy.length, healthy)
      ..setRange(healthy.length, healthy.length + 8, 'GARBAGE\n'.codeUnits);

    test('reads the document anyway', () {
      final PdfDocument document = PdfDocument(inputBytes: junked);
      addTearDown(document.dispose);
      expect(document.pages.count, 3);
    });

    test('and the copy it makes is typed', () {
      final PdfReader reader = PdfReader(junked);
      expect(reader.readBytes(16), isA<Uint8List>());
    });
  });

  group('saveToSink', () {
    test('writes the same document, in pieces, holding none of it', () {
      final PdfDocument document = PdfDocument(inputBytes: healthy);
      final _CountingSink sink = _CountingSink();
      document.saveToSink(sink);
      document.dispose();

      expect(sink.calls, greaterThan(1), reason: 'streamed, not one blob');
      final PdfDocument reloaded = PdfDocument(
        inputBytes: sink.collected.takeBytes(),
      );
      addTearDown(reloaded.dispose);
      expect(reloaded.pages.count, 3);
      expect(
        PdfTextExtractor(
          reloaded,
        ).extractText(startPageIndex: 0, endPageIndex: 0),
        contains('Mem 1'),
      );
    });

    test('refuses a document that patches its own output', () {
      // Signing writes the file and then fills /ByteRange and /Contents back
      // into it. A stream cannot go back, so this has to fail loudly instead
      // of emitting a placeholder that no viewer will accept.
      final PdfDocument document = PdfDocument();
      addTearDown(document.dispose);
      final PdfPage page = document.pages.add();
      final PdfSignatureField field = PdfSignatureField(page, 'sig');
      document.form.fields.add(field);
      field.signature = PdfSignature();
      expect(
        () => document.saveToSink(_CountingSink()),
        throwsA(isA<UnsupportedError>()),
      );
    });
  });
}
