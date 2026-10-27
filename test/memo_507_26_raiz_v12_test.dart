import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart' as pdf;
import 'package:dart_pdf/src/security/keystore/bks_reader.dart';
import 'package:dart_pdf/src/security/keystore/jks_codec.dart';
import 'package:test/test.dart';

/// Memo 507/2026, signed on 27/10/2026 with an ICP-Brasil e-CPF from
/// AC OAB G4, whose chain is AC OAB G4 → AC Certisign G8 → Raiz Brasileira v12.
/// validar.iti.gov.br approves it; with truststores from before the v12
/// hierarchy the chain was reported as unknown. Only the signer certificate is
/// embedded in the PDF, so trust depends entirely on the local truststores.
const String _pdfPath =
    'test/assets/Memo 507-26  encaminha minuta do Decreto regulamentando TAC.pdf';

String _pem(Uint8List der) {
  final String b64 = base64.encode(der);
  final StringBuffer out = StringBuffer('-----BEGIN CERTIFICATE-----\n');
  for (int i = 0; i < b64.length; i += 64) {
    out.writeln(b64.substring(i, i + 64 > b64.length ? b64.length : i + 64));
  }
  out.write('-----END CERTIFICATE-----');
  return out.toString();
}

Future<pdf.PdfSignatureValidationItem> _validate({
  bool useEmbeddedIcpBrasil = false,
  List<String>? trustedRootsPem,
}) async {
  final pdf.PdfSignatureValidationReport report =
      await pdf.PdfSignatureValidator().validateAllSignatures(
    File(_pdfPath).readAsBytesSync(),
    useEmbeddedIcpBrasil: useEmbeddedIcpBrasil,
    trustedRootsPem: trustedRootsPem,
    fetchCrls: false,
    strictRevocation: false,
  );
  expect(report.signatures, hasLength(1));
  return report.signatures.single;
}

void _expectValid(pdf.PdfSignatureValidationItem sig, String source) {
  expect(sig.validation.cmsSignatureValid, isTrue);
  expect(sig.validation.documentIntact, isTrue);
  expect(sig.chainTrusted, isTrue,
      reason: 'AC OAB G4 → AC Certisign G8 → Raiz v12 must be in $source');
}

void main() {
  group('Memo 507/2026 - chain under Raiz Brasileira v12', () {
    test('trusted with the embedded ICP-Brasil roots', () async {
      final sig = await _validate(useEmbeddedIcpBrasil: true);
      _expectValid(sig, 'the embedded ICP-Brasil trust store');

      final List<pdf.X509Certificate> chain =
          pdf.OfflineCertificateChainBuilder.buildCompleteChain(
        signerCertsPem: sig.validation.certsPem,
        certPool: pdf.OfflineCertificateChainBuilder.loadCertPoolFromDirectories(
          const <String>['assets/truststore/cadeia_icp_brasil'],
        ),
      );
      final String subjects = chain
          .map((c) => c.c?.subject?.toString() ?? '')
          .join(' | ')
          .toUpperCase();
      expect(subjects, contains('INGRID ANTUNES AMARAL'));
      expect(subjects, contains('AC OAB G4'));
      expect(subjects, contains('AC CERTISIGN G8'));
      expect(subjects, contains('RAIZ BRASILEIRA V12'));
    });

    test('trusted with cadeiasicpbrasil.bks', () async {
      final List<Uint8List> certs = BksReader(
        File('assets/truststore/icp_brasil/cadeiasicpbrasil.bks')
            .readAsBytesSync(),
        'serprosigner',
      ).readCertificates();
      _expectValid(
        await _validate(trustedRootsPem: certs.map(_pem).toList()),
        'cadeiasicpbrasil.bks',
      );
    });

    test('trusted with keystore_ICP_Brasil.jks', () async {
      final JksStore store = JksCodec.decode(
        File('assets/truststore/keystore_icp_brasil/keystore_ICP_Brasil.jks')
            .readAsBytesSync(),
        password: '12345678',
      );
      _expectValid(
        await _validate(
            trustedRootsPem: store.allCertificatesDer().map(_pem).toList()),
        'keystore_ICP_Brasil.jks',
      );
    });
  });
}
