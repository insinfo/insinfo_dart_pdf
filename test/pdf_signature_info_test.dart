import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

void main() {
  test('Inspect reference PDF: 2 ass leonardo e mauricio', () async {
    final File file = File('test/assets/2 ass leonardo e mauricio.pdf');
    expect(file.existsSync(), isTrue, reason: 'Arquivo não encontrado: ${file.path}');

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
  });
}
