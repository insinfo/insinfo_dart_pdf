import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/pdf_signature_validator.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/x509/x509_utils.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/x509/x509_certificates.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/x509/x509_name.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/asn1/der.dart';

Future<void> main(List<String> args) async {
  final String dirPath = args.isNotEmpty ? args.first : 'test/assets';
  final List<String> targetSigners = args.length >= 2
      ? args.skip(1).map((s) => s.toLowerCase()).toList(growable: false)
      : ['leonardo', 'mauricio', 'maurício'];
  
  try {
    final Directory dir = Directory(dirPath);
    if (!dir.existsSync()) {
      print('Directory not found: ${dir.path}');
      print('Usage: dart run scripts/scan_pdf_specific_signers.dart [directory] [signerSubstr...]');
      return;
    }

    print('Scanning directory: ${dir.path} ...');
    print('Looking for signers containing: ${targetSigners.join(", ")}');

    final List<File> files = [];
    try {
      files.addAll(dir
          .listSync()
          .whereType<File>()
          .where((f) => f.path.toLowerCase().endsWith('.pdf'))
          .toList());
    } catch (e) {
      print('Error listing directory: $e');
      return;
    }

    print('Found ${files.length} PDF files.');

    int processedCount = 0;
    int matchCount = 0;
    final List<String> matches = [];

    // Use a minimal symbol map for X509Name.getString if needed, 
    // although we can search in the raw string representation too.
    final Map<DerObjectID, String> symbols = {
        X509Name.cn: 'CN',
        X509Name.o: 'O',
        X509Name.ou: 'OU',
        X509Name.emailAddress: 'E',
    };

    for (final File file in files) {
      processedCount++;
      if (processedCount % 10 == 0) {
        stdout.write('\rProcessing file $processedCount/${files.length} found: $matchCount...');
      }

      try {
        final Uint8List bytes = file.readAsBytesSync();
        final PdfSignatureValidator validator = PdfSignatureValidator();
        
        // Fast validation (no CRLs)
        final report = await validator.validateAllSignatures(
          bytes,
          fetchCrls: false,
        );

        bool fileMatched = false;
        final List<String> foundSigners = [];

        for (final sig in report.signatures) {
           if (sig.validation.certsPem.isNotEmpty) {
             try {
                // The first cert is the signer's certificate
                final pem = sig.validation.certsPem.first;
                final X509Certificate cert = X509Utils.parsePemCertificate(pem);
                
                // Get Subject
                // Accessing internal structure 'c' -> 'subject'
                final subject = cert.c?.subject;
                if (subject != null) {
                    // X509Name getString returns something like "CN=Name, O=Org..."
                    // We need to implement a simple string dump since getString might act differently
                    // checking implementation of getString...
                    final String subjectStr = subject.getString(false, symbols).toLowerCase();
                    
                    for (final target in targetSigners) {
                        if (subjectStr.contains(target)) {
                            fileMatched = true;
                            // Extract just the CN for display if possible, or use full string
                            foundSigners.add(subject.getString(false, symbols));
                            break; 
                        }
                    }
                }
             } catch (_) {
               // ignore cert parsing errors
             }
           }
        }

        if (fileMatched) {
            matchCount++;
            matches.add('${file.uri.pathSegments.last} -> Signers: ${foundSigners.join(" | ")}');
        }

      } catch (e) {
        // ignore pdf errors
      }
    }

    print('\n\nScan complete.');
    print('Found $matchCount files matching the criteria:');
    for (final match in matches) {
        print(match);
    }
    
  } catch (e, stack) {
    print('\nFatal error: $e');
    print(stack);
  }
}
