import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

void main() {
  test('Inspect reference PDF: 2 ass leonardo e mauricio', () async {
    final File file = File('test/assets/2 ass leonardo e mauricio.pdf');
    expect(file.existsSync(), isTrue,
        reason: 'Arquivo não encontrado: ${file.path}');

    final Uint8List bytes = file.readAsBytesSync();

    final PdfSignatureInspectionReport report =
        await PdfSignatureInspector().inspect(
      bytes,
      fetchCrls: false,
      useEmbeddedIcpBrasil: true,
    );

    expect(report.signatures.length, 2);
    expect(report.allDocumentsIntact, isTrue);

    final List<String> commonNames = report.signatures
        .map((s) => s.signer?.commonName)
        .whereType<String>()
        .toList(growable: false);

    expect(commonNames.length, 2);
    expect(commonNames, contains('LEONARDO CALHEIROS OLIVEIRA'));
    expect(commonNames, contains('MAURICIO SOARES DOS ANJOS:02094890732'));

    final List<String> cpfList = report.signatures
        .map((s) => s.signer?.cpf)
        .whereType<String>()
        .toList(growable: false);

    expect(cpfList, contains('09498269793'));
    expect(cpfList, contains('02094890732'));

    final List<DateTime> dobList = report.signatures
        .map((s) => s.signer?.dateOfBirth)
        .whereType<DateTime>()
        .toList(growable: false);

    expect(dobList, contains(DateTime(1982, 10, 25)));
    expect(dobList, contains(DateTime(1971, 3, 12)));

    final Map<String, PdfSignatureSummary> byField = {
      for (final s in report.signatures) s.fieldName: s,
    };

    final PdfSignatureSummary sig1 = byField['Signature1']!;
    final PdfSignatureSummary sig2 = byField['Signature2']!;

    expect(sig1.signingTime, isNotNull);
    expect(sig2.signingTime, isNotNull);

    final DateTime t1 = sig1.signingTime!;
    expect(t1.year, 2025);
    expect(t1.month, 12);
    expect(t1.day, 29);
    expect(t1.hour, 17);
    expect(t1.minute, 5);
    expect(t1.second, 15);

    final DateTime t2 = sig2.signingTime!;
    expect(t2.year, 2025);
    expect(t2.month, 12);
    expect(t2.day, 29);
    expect(t2.hour, 13);
    expect(t2.minute, 58);
    expect(t2.second, 22);

    expect(sig1.policyPresent, isFalse);
    expect(sig2.policyPresent, isTrue);
    expect(sig1.policyDigestOk, isNull);
    expect(sig2.policyDigestOk, isNull);

    expect(sig1.cmsSignatureValid, isTrue);
    expect(sig1.byteRangeDigestOk, isTrue);
    expect(sig1.documentIntact, isTrue);
    expect(sig2.cmsSignatureValid, isTrue);
    expect(sig2.byteRangeDigestOk, isTrue);
    expect(sig2.documentIntact, isTrue);

    expect(sig1.chainTrusted, isTrue);
    expect(sig2.chainTrusted, isTrue);

    expect(sig1.signer?.subject, isNotNull);
    expect(sig1.signer?.issuer, isNotNull);
    expect(sig1.signer?.serialNumberHex, isNotNull);
    expect(sig1.signer?.serialNumberDecimal, isNotNull);
    expect(sig1.signer?.certNotBefore, isNotNull);
    expect(sig1.signer?.certNotAfter, isNotNull);
    expect(sig1.signer!.certNotBefore!.isBefore(sig1.signer!.certNotAfter!),
        isTrue);

    expect(sig2.signer?.subject, isNotNull);
    expect(sig2.signer?.issuer, isNotNull);
    expect(sig2.signer?.serialNumberHex, isNotNull);
    expect(sig2.signer?.serialNumberDecimal, isNotNull);
    expect(sig2.signer?.certNotBefore, isNotNull);
    expect(sig2.signer?.certNotAfter, isNotNull);
    expect(sig2.signer!.certNotBefore!.isBefore(sig2.signer!.certNotAfter!),
        isTrue);
  });

  test('Inspect DocMDP allow signatures PDF', () async {
    final File file =
        File('test/assets/generated_doc_mdp_allow_signatures.pdf');
    expect(file.existsSync(), isTrue,
        reason: 'Arquivo não encontrado: ${file.path}');

    final Uint8List bytes = file.readAsBytesSync();

    final PdfSignatureValidationReport report =
        await PdfSignatureValidator().validateAllSignatures(
      bytes,
      fetchCrls: false,
    );

    expect(report.signatures.length, 1);
    final PdfSignatureValidationItem sig = report.signatures.first;

    expect(sig.docMdp.isCertificationSignature, isTrue);
    expect(sig.docMdp.permissionP, 2);
  });
}
