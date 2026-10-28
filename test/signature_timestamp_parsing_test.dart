@TestOn('vm')
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf_server.dart' as pdf;
import 'package:dart_pdf/src/pdf/implementation/io/pdf_cross_table.dart';
import 'package:dart_pdf/src/pdf/implementation/io/stream_reader.dart';
import 'package:dart_pdf/src/pdf/implementation/pdf_document/pdf_document.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_array.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_dictionary.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_stream.dart';
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

  test('a TSA under another root is trusted through the second pass', () async {
    // The SALI validates with the intermediate and the root as anchors; the
    // candidate picked from the signer certificate is the intermediate, and
    // the TSA certificate hangs from the root. Strict, offline: the CRLs come
    // from the DSS.
    final Uint8List bytes =
        File('test/assets/sali_interna_carimbo_tempo_dss.pdf')
            .readAsBytesSync();
    final _Dss dss = _Dss.read(bytes);
    final String raiz = dss.certificatesPem.firstWhere(_selfSigned);
    final String intermediaria = dss.certificatesPem.firstWhere((String pem) {
      final pdf.X509Certificate cert = pdf.X509Utils.parsePemCertificate(pem);
      return !_selfSigned(pem) &&
          cert.c?.issuer?.toString() ==
              pdf.X509Utils.parsePemCertificate(raiz).c?.subject?.toString() &&
          (cert.c?.subject?.toString().contains('Intermediaria') ?? false);
    });

    final pdf.PdfSignatureValidationReport report =
        await pdf.PdfSignatureValidator().validateAllSignaturesWithCandidates(
      bytes,
      candidateTrustedRootsPem: <String>[intermediaria],
      allTrustedRootsPem: <String>[intermediaria, raiz],
      crlBytes: dss.crls,
      strictRevocation: true,
    );
    final ts = report.signatures.single.timestampStatus;

    expect(report.signatures.single.chainTrusted, isTrue);
    expect(ts?.chainTrusted, isTrue, reason: 'the TSA chain closes on the root');
    expect(ts?.revocationStatus?.status, 'good',
        reason: 'the root CRL from the DSS covers the TSA certificate');
    expect(ts?.valid, isTrue);
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

bool _selfSigned(String pem) {
  final pdf.X509Certificate cert = pdf.X509Utils.parsePemCertificate(pem);
  return cert.c?.subject?.toString() == cert.c?.issuer?.toString();
}

/// Certificates and CRLs of the document-level DSS.
class _Dss {
  _Dss(this.certificatesPem, this.crls);

  factory _Dss.read(Uint8List bytes) {
    final pdf.PdfDocument doc = pdf.PdfDocument(inputBytes: bytes);
    try {
      final PdfDictionary dss = PdfCrossTable.dereference(
          PdfDocumentHelper.getHelper(doc).catalog['DSS'])! as PdfDictionary;
      return _Dss(
        <String>[
          for (final Uint8List der in _streams(dss, 'Certs'))
            pdf.X509Utils.derToPem(der),
        ],
        _streams(dss, 'CRLs'),
      );
    } finally {
      doc.dispose();
    }
  }

  static List<Uint8List> _streams(PdfDictionary dss, String key) {
    final List<Uint8List> out = <Uint8List>[];
    final Object? array = PdfCrossTable.dereference(dss[key]);
    if (array is PdfArray) {
      for (int i = 0; i < array.count; i++) {
        final Object? item = PdfCrossTable.dereference(array[i]);
        if (item is PdfStream) {
          out.add(Uint8List.fromList(item.getDecompressedData(false)!));
        }
      }
    }
    return out;
  }

  final List<String> certificatesPem;
  final List<Uint8List> crls;
}
