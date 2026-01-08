import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/pdf_signature_validator.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/x509/x509_utils.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/x509/x509_certificates.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/x509/x509_name.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/asn1/der.dart';

Future<void> main(List<String> args) async {
  final String filePath =
      args.isNotEmpty ? args.first : 'test/assets/generated_policy_mandated_timestamp_missing.pdf';
  final file = File(filePath);

  if (!file.existsSync()) {
    print('File not found: $filePath');
    print('Usage: dart run scripts/debug_pdf_signer.dart [pdfPath]');
    return;
  }

  print('Debugging file: $filePath');

  try {
    final Uint8List bytes = file.readAsBytesSync();
    final PdfSignatureValidator validator = PdfSignatureValidator();

    print('Validating signatures...');
    final report = await validator.validateAllSignatures(
      bytes,
      fetchCrls: false,
    );

    print('Found ${report.signatures.length} signatures.');

    final Map<DerObjectID, String> symbols = {
        X509Name.cn: 'CN',
        X509Name.o: 'O',
        X509Name.ou: 'OU',
        X509Name.emailAddress: 'E',
    };

    for (int i = 0; i < report.signatures.length; i++) {
        final sig = report.signatures[i];
        print('\nSignature #$i: ${sig.fieldName}');
        print('  Certs found: ${sig.validation.certsPem.length}');
        
        if (sig.validation.certsPem.isNotEmpty) {
             print('  Processing ${sig.validation.certsPem.length} certificates...');
             for (int j = 0; j < sig.validation.certsPem.length; j++) {
                final pem = sig.validation.certsPem[j];
                print('    Cert #$j: ${pem.length} chars');
                
                try {
                   final X509Certificate cert = X509Utils.parsePemCertificate(pem);
                   final subject = cert.c?.subject;
                   
                   if (subject != null) {
                       print('      Subject: ${subject.getString(false, symbols)}');
                   } else {
                       print('      Subject is null');
                   }
                } catch (e) {
                   print('      Error parsing individual cert: $e');
                   if (i == 0 && j == 0) {
                      File('debug_cert_0.pem').writeAsStringSync(pem);
                      print('      -> Dumped Cert #0 to debug_cert_0.pem');
                   }
                }
             }
        }
    }

  } catch (e, st) {
    print('Fatal Error: $e');
    print(st);
  }
}

