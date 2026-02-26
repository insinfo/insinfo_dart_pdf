import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

void main() {
  group('CertificateSerial', () {
    test('fromHex canonicalizes and preserves big serial safely', () {
      const hexInput = '0x66104A9B51E5B97173334CFF137C8A5F';
      final vo = CertificateSerial.fromHex(hexInput);

      expect(vo.hex, equals('66104a9b51e5b97173334cff137c8a5f'));
      expect(vo.hexPrefixed, equals('0x66104a9b51e5b97173334cff137c8a5f'));
      expect(
        vo.decimal,
        equals(BigInt.parse('66104a9b51e5b97173334cff137c8a5f', radix: 16)
            .toString()),
      );
      expect(vo.rawBytes.length, equals(16));
    });

    test('fromDecimal round-trips to canonical hex', () {
      const decimal = '135145815711504296768213611963660036703';
      final vo = CertificateSerial.fromDecimal(decimal);
      final String expectedHex = BigInt.parse(decimal).toRadixString(16);

      expect(vo.decimal, equals(decimal));
      expect(vo.hex, equals(expectedHex));
      expect(vo.rawBytes, isNotEmpty);
    });

    test('fromDerInteger parses DER TLV and strips sign padding', () {
      final voTlv = CertificateSerial.fromDerInteger(
        Uint8List.fromList(<int>[0x02, 0x03, 0x01, 0x00, 0x01]),
      );
      expect(voTlv.hex, equals('10001'));
      expect(voTlv.decimal, equals('65537'));

      final voRawPadded = CertificateSerial.fromDerInteger(
        Uint8List.fromList(<int>[0x00, 0x80]),
      );
      expect(voRawPadded.hex, equals('80'));
      expect(voRawPadded.decimal, equals('128'));
      expect(voRawPadded.rawBytes, equals(Uint8List.fromList(<int>[0x80])));
    });

    test('equalsSerial compares decimal and hex forms robustly', () {
      expect(equalsSerial('0x01', '1'), isTrue);
      expect(equalsSerial('0x0000ff', '255'), isTrue);
      expect(equalsSerial('66104a9b', BigInt.parse('66104a9b', radix: 16).toString()), isTrue);
      expect(equalsSerial('0x100', '255'), isFalse);
    });

    test('normalizers accept either representation', () {
      expect(normalizeSerialToHex('255'), equals('ff'));
      expect(normalizeSerialToHex('0x00FF'), equals('ff'));
      expect(normalizeSerialToDecimal('0xff'), equals('255'));
      expect(normalizeSerialToDecimal('000255'), equals('255'));
    });

    test('invalid input throws', () {
      expect(() => CertificateSerial.fromHex('0x'), throwsArgumentError);
      expect(() => CertificateSerial.fromHex('0xZZ'), throwsArgumentError);
      expect(() => CertificateSerial.fromDecimal('-1'), throwsArgumentError);
      expect(() => normalizeSerialToHex(''), throwsArgumentError);
      expect(
        () => CertificateSerial.fromDerInteger(Uint8List(0)),
        throwsArgumentError,
      );
    });
  });
}
