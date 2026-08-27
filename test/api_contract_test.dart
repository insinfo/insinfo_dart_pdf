import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dart_pdf/pdf_server.dart';
import 'package:test/test.dart';

// The contract every public entry point that accepts a file has to keep:
//
//   bad input never escapes as an Error.
//
// `Error` means the program has a bug and must not be caught. `Exception`
// means a recoverable condition. A library whose input is a file someone
// uploaded cannot report a malformed file as an Error, because that pushes the
// caller into `catch (e)` — which also swallows StackOverflowError, TypeError
// and failed assertions, hiding real defects.
//
// The check runs the real corpus through a set of mutations rather than
// enumerating call sites: this is what tells us which paths still need work,
// and it keeps telling us as the code changes. Converting throw sites by hand
// would only ever cover the ones somebody remembered.

/// Sources to mutate: a document this library wrote, plus real files from
/// `test/assets`.
List<_Sample> _samples() {
  final List<_Sample> samples = <_Sample>[];
  const List<String> assets = <String>[
    // Written by this library and committed rather than generated on the
    // spot: saving the same document twice does not produce the same bytes,
    // because each save names its font resources with fresh UUIDs. A fuzz
    // that lands on different bytes every run cannot be reproduced, and a
    // test that fails only sometimes teaches nobody anything. Regenerate it
    // with tool/ if the shape of what this library writes ever matters here.
    'test/assets/generated_three_pages.pdf',
    'test/assets/Invoice.pdf',
    'test/assets/sample_no_signature.pdf',
    'test/assets/doc_assinado_icp_brasil_thais.pdf',
    'test/assets/example_sign.pdf',
    'test/assets/paginador (3).pdf',
  ];
  for (final String path in assets) {
    final File file = File(path);
    if (file.existsSync()) {
      samples.add(_Sample(path.split('/').last, file.readAsBytesSync()));
    }
  }
  return samples;
}

/// Ways a file arrives damaged in the field.
Map<String, List<int> Function(List<int>)> _mutations() {
  return <String, List<int> Function(List<int>)>{
    'truncated to 30%': (List<int> b) => b.sublist(0, (b.length * 0.3).floor()),
    'truncated to 80%': (List<int> b) => b.sublist(0, (b.length * 0.8).floor()),
    'tail cut': (List<int> b) => b.sublist(0, max(1, b.length - 64)),
    'head cut': (List<int> b) => b.sublist(min(200, b.length)),
    'startxref broken': _breakToken('startxref'),
    'xref keyword wiped': _breakToken('xref'),
    'trailer wiped': _breakToken('trailer'),
    'stream lengths wiped': _breakToken('/Length'),
    'filters wiped': _breakToken('/Filter'),
    'byte ranges wiped': _breakToken('/ByteRange'),
    'random bytes flipped': (List<int> b) {
      final Uint8List out = Uint8List.fromList(b);
      final Random random = Random(7);
      for (int i = 0; i < 40 && out.isNotEmpty; i++) {
        out[random.nextInt(out.length)] ^= 0xFF;
      }
      return out;
    },
    'every digit zeroed': (List<int> b) {
      final Uint8List out = Uint8List.fromList(b);
      for (int i = 0; i < out.length; i++) {
        if (out[i] >= 0x30 && out[i] <= 0x39) {
          out[i] = 0x30;
        }
      }
      return out;
    },
  };
}

/// Input that is not a document at all.
Map<String, List<int>> _garbage() {
  return <String, List<int>>{
    'empty': <int>[],
    'text file': 'this is not a PDF, it is prose'.codeUnits,
    'header only': '%PDF-1.7\n'.codeUnits,
    'header then zeros': <int>[
      ...'%PDF-1.7\n'.codeUnits,
      ...List<int>.filled(4096, 0),
    ],
    'header then letters': <int>[
      ...'%PDF-1.7\n'.codeUnits,
      ...List<int>.filled(4096, 0x41),
    ],
    'one byte': <int>[0x25],
  };
}

void main() {
  final List<_Sample> samples = _samples();
  final Map<String, List<int> Function(List<int>)> mutations = _mutations();

  group('PdfDocument load - bad input is never an Error', () {
    for (final _Sample sample in samples) {
      for (final MapEntry<String, List<int> Function(List<int>)> mutation
          in mutations.entries) {
        test('${sample.name} / ${mutation.key}', () {
          final List<int> damaged = mutation.value(sample.bytes);
          _expectNoErrorEscapes(
            () {
              final PdfDocument document = PdfDocument(inputBytes: damaged);
              // Reading pages is part of loading as far as a caller is
              // concerned: a lazily parsed page tree must not blow up later.
              final int count = document.pages.count;
              for (int i = 0; i < count && i < 3; i++) {
                document.pages[i].size;
              }
              document.dispose();
            },
            what: '${sample.name} / ${mutation.key}',
          );
        });
      }
    }

    for (final MapEntry<String, List<int>> entry in _garbage().entries) {
      test('garbage: ${entry.key}', () {
        _expectNoErrorEscapes(
          () => PdfDocument(inputBytes: entry.value).dispose(),
          what: entry.key,
          requireFormatException: true,
        );
      });
    }
  });

  group('merge - bad input is never an Error', () {
    for (final _Sample sample in samples.take(3)) {
      for (final MapEntry<String, List<int> Function(List<int>)> mutation
          in mutations.entries) {
        test('${sample.name} / ${mutation.key}', () {
          final List<int> damaged = mutation.value(sample.bytes);
          _expectNoErrorEscapes(
            () => PdfDocument.mergeSync(<List<int>>[damaged]),
            what: '${sample.name} / ${mutation.key}',
          );
        });
      }
    }

    test('a damaged document merged next to a healthy one', () {
      final List<int> healthy = samples.first.bytes;
      for (final _Sample sample in samples) {
        for (final MapEntry<String, List<int> Function(List<int>)> mutation
            in mutations.entries) {
          _expectNoErrorEscapes(
            () => PdfDocument.mergeSync(<List<int>>[
              healthy,
              mutation.value(sample.bytes),
            ]),
            what: '${sample.name} / ${mutation.key}',
          );
        }
      }
    });
  });

  group('signature reading - bad input is never an Error', () {
    for (final _Sample sample in samples) {
      for (final MapEntry<String, List<int> Function(List<int>)> mutation
          in mutations.entries) {
        test('${sample.name} / ${mutation.key}', () {
          final Uint8List damaged = Uint8List.fromList(
            mutation.value(sample.bytes),
          );
          _expectNoErrorEscapes(
            () => PdfExternalSigning.extractByteRange(damaged),
            what: 'extractByteRange ${sample.name} / ${mutation.key}',
          );
          _expectNoErrorEscapes(
            () => PdfExternalSigning.findContentsRange(damaged),
            what: 'findContentsRange ${sample.name} / ${mutation.key}',
          );
        });
      }
    }
  });

  group('signature validation - bad input is never an Error', () {
    for (final _Sample sample in samples) {
      test('${sample.name}: mutations', () async {
        for (final MapEntry<String, List<int> Function(List<int>)> mutation
            in mutations.entries) {
          final Uint8List damaged = Uint8List.fromList(
            mutation.value(sample.bytes),
          );
          try {
            await PdfSignatureValidator().validateAllSignatures(damaged);
          } on Exception {
            // Expected outcome for damaged input.
          } on Error catch (error, stack) {
            fail(
              'validateAllSignatures let an Error escape for '
              '${sample.name} / ${mutation.key}: '
              '${error.runtimeType}: $error\n$stack',
            );
          }
        }
      }, timeout: const Timeout(Duration(minutes: 5)));
    }
  });
}

/// Runs [body] and fails the test if an [Error] escapes.
///
/// Succeeding is fine: recovering from damage is the better outcome. What is
/// not fine is an `Error`, because the caller cannot catch that without also
/// catching the library's own defects.
void _expectNoErrorEscapes(
  void Function() body, {
  required String what,
  bool requireFormatException = false,
}) {
  try {
    body();
    if (requireFormatException) {
      fail('$what: expected a PdfFormatException, nothing was thrown');
    }
  } on PdfFormatException {
    // The documented failure.
  } on Exception catch (error) {
    if (requireFormatException) {
      fail(
        '$what: expected a PdfFormatException, got ${error.runtimeType}: '
        '$error',
      );
    }
  } on Error catch (error, stack) {
    fail(
      '$what: an Error escaped, so a caller cannot handle bad input without '
      'also swallowing library defects — ${error.runtimeType}: $error\n$stack',
    );
  }
}

List<int> Function(List<int>) _breakToken(String token) {
  return (List<int> bytes) {
    final String text = String.fromCharCodes(bytes);
    return text.replaceAll(token, 'x' * token.length).codeUnits;
  };
}


class _Sample {
  _Sample(this.name, this.bytes);

  final String name;
  final List<int> bytes;
}
