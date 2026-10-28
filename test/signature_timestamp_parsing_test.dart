@TestOn('vm')
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf_server.dart' as pdf;
import 'package:dart_pdf/src/pdf/implementation/io/stream_reader.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/asn1/asn1_stream.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/asn1/der.dart';
import 'package:test/test.dart';

/// Reading signature timestamps (1.0.9).
///
/// Three parser faults kept every signature timestamp invisible:
/// - unsignedAttrs is `[1] IMPLICIT SET`; with the implicit tag the parser
///   handed back the first Attribute instead of the list, so the
///   `signature-time-stamp` attribute was never found — for every
///   timestamped signature, ICP-Brasil included;
/// - any BOOLEAN/ENUMERATED/OID of 16+ bytes threw RangeError
///   (`Asn1Stream.getBytes` dropped the result of `toArray()`);
/// - OID arcs past 64 bits were truncated to 32 bits.
///
/// The fixture is an internal SALI signature: timestamped by the SALI's own
/// TSA (policy `2.25.<uuid>`) with a DSS holding the chain and two CRLs.
void main() {
  const String politica = '2.25.274346185473249794239814663713756062511';

  test('the signature timestamp is found and verified', () async {
    final Uint8List bytes =
        File('test/assets/sali_interna_carimbo_tempo_dss.pdf')
            .readAsBytesSync();
    final pdf.PdfSignatureValidationReport report =
        await pdf.PdfSignatureValidator().validateAllSignatures(bytes);
    final pdf.PdfSignatureValidationItem sig = report.signatures.single;

    expect(sig.validation.cmsSignatureValid, isTrue);
    expect(sig.validation.documentIntact, isTrue,
        reason: 'the DSS update comes after the signature');
    final ts = sig.timestampStatus;
    expect(ts?.present, isTrue);
    expect(ts?.messageImprintOk, isTrue,
        reason: 'the token covers this signature value');
    expect(ts?.tokenSignatureValid, isTrue);
    expect(ts?.policyOid, politica, reason: 'the whole 128-bit arc');
    expect(ts?.genTime, isNotNull);
    expect(sig.ltv.hasDss, isTrue);
    expect(sig.ltv.dssCrlsCount, 2);
    expect(sig.ltv.dssCertsCount, 4);
  });

  test('an OID with a 128-bit arc parses whole', () {
    // DER of OBJECT IDENTIFIER 2.25.274346185473249794239814663713756062511:
    // 20 content bytes, past the 16-byte reusable buffers of the parser.
    final List<int> der = <int>[
      0x06, 0x14, //
      0x69, 0x83, 0x9C, 0xE5, 0x93, 0xD0, 0xEE, 0xE3, 0xAA, 0xBA, //
      0xEF, 0xAE, 0xE2, 0xD2, 0xCB, 0x91, 0xCB, 0xC2, 0xC6, 0x2F,
    ];
    final Object? parsed = Asn1Stream(PdfStreamReader(der)).readAsn1();

    expect(parsed, isA<DerObjectID>());
    expect((parsed! as DerObjectID).id, politica);
  });
}
