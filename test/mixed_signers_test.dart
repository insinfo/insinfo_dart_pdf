import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/pdf_signature_validator.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/x509/x509_certificates.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/x509/x509_name.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/x509/x509_utils.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/asn1/der.dart';
import 'package:test/test.dart';

void main() {
  final Map<DerObjectID, String> symbols = {
    X509Name.cn: 'CN',
    X509Name.o: 'O',
    X509Name.ou: 'OU',
    X509Name.c: 'C',
    X509Name.st: 'ST',
    X509Name.l: 'L',
    X509Name.emailAddress: 'E',
  };

  test('Validate "2 ass leonardo e mauricio.pdf"', () async {
    final File file = File('test/assets/2 ass leonardo e mauricio.pdf');
    expect(file.existsSync(), isTrue, reason: 'File not found: ${file.path}');

    final Uint8List bytes = file.readAsBytesSync();
    final PdfSignatureValidator validator = PdfSignatureValidator();

    final report = await validator.validateAllSignatures(
      bytes,
      useEmbeddedIcpBrasil: true,
      fetchCrls: false, // Turn off CRL fetching for test speed/stability unless requested
    );

    // Expect 2 signatures
    expect(report.signatures.length, equals(2));

    // Signers found state
    bool foundLeonardo = false;
    bool foundMauricio = false;

    for (var sig in report.signatures) {
      // Signature checks
      expect(sig.validation.cmsSignatureValid, isTrue, reason: 'Signature ${sig.fieldName} invalid');

      // Get the signer specific certificate (first in the list usually)
      expect(sig.validation.certsPem, isNotEmpty);
      final X509Certificate signerCert = X509Utils.parsePemCertificate(sig.validation.certsPem.first);
      
      final String subjectStr = signerCert.c!.subject!.getString(false, symbols).toLowerCase();
      final String issuerStr = signerCert.c!.issuer!.getString(false, symbols).toLowerCase();
      
      print('Signer: $subjectStr');
      print('Issuer: $issuerStr');

      // Chain validation (cripto) deve funcionar com truststore embutido.
      if (sig.chainTrusted != true) {
        print('Chain errors for ${sig.fieldName}: ${sig.chainErrors}');
      }
      expect(sig.chainTrusted, isTrue, reason: 'Chain not trusted for ${sig.fieldName}');

      if (subjectStr.contains('leonardo')) {
        foundLeonardo = true;
         // Leonardo -> Gov.br
        expect(issuerStr, contains('gov-br'), reason: 'Leonardo should be issued by Gov.BR (gov-br)');
      } else if (subjectStr.contains('mauricio')) {
        foundMauricio = true;
        // Mauricio -> Serpro
        expect(issuerStr, contains('serpro'), reason: 'Mauricio should be issued by Serpro');
      }
    }

    expect(foundLeonardo, isTrue, reason: 'Leonardo signature not found');
    expect(foundMauricio, isTrue, reason: 'Mauricio signature not found');
  });

  test('Validate "3 ass leonardo e stefan e mauricio.pdf"', () async {
    final File file = File('test/assets/3 ass leonardo e stefan e mauricio.pdf');
    expect(file.existsSync(), isTrue, reason: 'File not found: ${file.path}');

    final Uint8List bytes = file.readAsBytesSync();
    final PdfSignatureValidator validator = PdfSignatureValidator();

    final report = await validator.validateAllSignatures(
      bytes,
      useEmbeddedIcpBrasil: true,
      fetchCrls: false,
    );

    // Expect 3 signatures
    expect(report.signatures.length, equals(3));

    bool foundLeonardo = false;
    bool foundStefan = false;
    bool foundMauricio = false;

    for (var sig in report.signatures) {
      expect(sig.validation.cmsSignatureValid, isTrue);

      final X509Certificate signerCert = X509Utils.parsePemCertificate(sig.validation.certsPem.first);
      final String subjectStr = signerCert.c!.subject!.getString(false, symbols).toLowerCase();
      final String issuerStr = signerCert.c!.issuer!.getString(false, symbols).toLowerCase();
      
      print('Signer: $subjectStr');
      print('Issuer: $issuerStr');

      if (sig.chainTrusted != true) {
        print('Chain errors for ${sig.fieldName}: ${sig.chainErrors}');
      }
      expect(sig.chainTrusted, isTrue, reason: 'Chain not trusted for ${sig.fieldName}');

      if (subjectStr.contains('leonardo')) {
        foundLeonardo = true;
        expect(issuerStr, contains('gov-br'), reason: 'Leonardo should be issued by Gov.BR (gov-br)');
      } else if (subjectStr.contains('stefan')) {
        foundStefan = true;
        // Validate Stefan's issuer if known, otherwise just identity
      } else if (subjectStr.contains('mauricio')) {
        foundMauricio = true;
        expect(issuerStr, contains('serpro'), reason: 'Mauricio should be issued by Serpro');
      }
    }

    expect(foundLeonardo, isTrue, reason: 'Leonardo signature not found');
    expect(foundStefan, isTrue, reason: 'Stefan signature not found');
    expect(foundMauricio, isTrue, reason: 'Mauricio signature not found');
  });

  test('Validate "serpro_Maurício_Soares_dos_Anjos.pdf"', () async {
    final File file = File('test/assets/serpro_Maurício_Soares_dos_Anjos.pdf');
    expect(file.existsSync(), isTrue, reason: 'File not found: ${file.path}');

    final Uint8List bytes = file.readAsBytesSync();
    final PdfSignatureValidator validator = PdfSignatureValidator();

    // Use the embedded trust store directly
    final report = await validator.validateAllSignatures(
      bytes,
      useEmbeddedIcpBrasil: true, // Use library feature
      fetchCrls: false,
    );

    // Expect at least 1 signature
    expect(report.signatures, isNotEmpty);

    for (var sig in report.signatures) {
      expect(sig.validation.cmsSignatureValid, isTrue);
      print('Validating ${sig.fieldName} in ${file.path}');

      // Print signer DN to help diagnose missing issuer.
      if (sig.validation.certsPem.isNotEmpty) {
        final X509Certificate signerCert = X509Utils.parsePemCertificate(sig.validation.certsPem.first);
        final String subjectStr = signerCert.c!.subject!.getString(false, symbols).toLowerCase();
        final String issuerStr = signerCert.c!.issuer!.getString(false, symbols).toLowerCase();
        print('Signer: $subjectStr');
        print('Issuer: $issuerStr');
      }

      if (sig.chainTrusted != true) {
        print('Chain errors for ${sig.fieldName}: ${sig.chainErrors}');
      }
      expect(sig.chainTrusted, isTrue, reason: 'Chain not trusted for ${sig.fieldName}');
    }
  });

  test('Validate "sample_token_icpbrasil_assinado.pdf"', () async {
    final File file = File('test/assets/sample_token_icpbrasil_assinado.pdf');
    expect(file.existsSync(), isTrue, reason: 'File not found: ${file.path}');

    final Uint8List bytes = file.readAsBytesSync();
    final PdfSignatureValidator validator = PdfSignatureValidator();

    final report = await validator.validateAllSignatures(
      bytes,
      useEmbeddedIcpBrasil: true,
      fetchCrls: false,
    );

    expect(report.signatures, isNotEmpty);

    for (var sig in report.signatures) {
      expect(sig.validation.cmsSignatureValid, isTrue);
      print('Validating ${sig.fieldName}: Chain Trusted = ${sig.chainTrusted}');
      if (sig.chainTrusted != true) {
        print('Chain errors for ${sig.fieldName}: ${sig.chainErrors}');
      }
    }
  });
}
