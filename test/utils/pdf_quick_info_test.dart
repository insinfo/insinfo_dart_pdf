import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:dart_pdf/src/utils/pdf_quick_info.dart';

Uint8List _bytes(String s) => Uint8List.fromList(utf8.encode(s));

void main() {
  group('PdfQuickInfo.version parsing', () {
    test('parses version and header metadata', () {
      final info = PdfQuickInfo.fromBytes(
        _bytes('%PDF-1.7\n%comment\n'),
        readMDPInfo: false,
      );

      expect(info.versionMajor, equals(1));
      expect(info.versionMinor, equals(7));
      expect(info.versionOffset, equals(0));
      expect(info.versionRawHeader, equals('%PDF-1.7'));
      expect(info.versionString, equals('1.7'));
    });

    test('returns nulls when header is missing', () {
      final info = PdfQuickInfo.fromBytes(
        _bytes('not a pdf'),
        readMDPInfo: false,
      );

      expect(info.versionMajor, isNull);
      expect(info.versionMinor, isNull);
      expect(info.versionOffset, isNull);
      expect(info.versionRawHeader, isNull);
      expect(info.versionString, isNull);
    });
  });

  group('PdfQuickInfo.isPdf15OrAbove', () {
    test('returns false for 1.4', () {
      final info = PdfQuickInfo.fromBytes(
        _bytes('%PDF-1.4\n'),
        readMDPInfo: false,
      );
      expect(info.isPdf15OrAbove, isFalse);
    });

    test('returns true for 1.5', () {
      final info = PdfQuickInfo.fromBytes(
        _bytes('%PDF-1.5\n'),
        readMDPInfo: false,
      );
      expect(info.isPdf15OrAbove, isTrue);
    });

    test('returns true for 2.0', () {
      final info = PdfQuickInfo.fromBytes(
        _bytes('%PDF-2.0\n'),
        readMDPInfo: false,
      );
      expect(info.isPdf15OrAbove, isTrue);
    });

    test('returns false when header is missing', () {
      final info = PdfQuickInfo.fromBytes(
        _bytes('not a pdf'),
        readMDPInfo: false,
      );
      expect(info.isPdf15OrAbove, isFalse);
    });
  });

  group('PdfQuickInfo.docMdp', () {
    test('reads DocMDP permission when present', () {
      final bytes =
          File('test/assets/generated_doc_mdp_allow_signatures.pdf')
              .readAsBytesSync();
      final info = PdfQuickInfo.fromBytes(bytes);

      expect(info.docMdpPermissionP, equals(2));
      expect(info.hasDocMdp, isTrue);
    });

    test('skips DocMDP when readMDPInfo=false', () {
      final bytes =
          File('test/assets/generated_doc_mdp_allow_signatures.pdf')
              .readAsBytesSync();
      final info = PdfQuickInfo.fromBytes(bytes, readMDPInfo: false);

      expect(info.docMdpPermissionP, isNull);
      expect(info.hasDocMdp, isFalse);
    });
  });
}
