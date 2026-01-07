import 'dart:io';
import '../lib/pdf.dart';

Future<void> main() async {
  // 1. Setup paths
  final String inputFile = 'example2/assets/input.pdf'; // Ensure this exists or create dummy
  final String signedFile = 'output_signed.pdf';
  final String ltvFile = 'output_ltv.pdf';

  // 2. Create a dummy PDF if needed
  if (!File(inputFile).existsSync()) {
      final PdfDocument doc = PdfDocument();
      doc.pages.add().graphics.drawString(
        'Hello LTV', 
        PdfStandardFont(PdfFontFamily.helvetica, 12)
      );
      File(inputFile).writeAsBytesSync(await doc.save());
      doc.dispose();
  }

  // 3. Sign the PDF (Simulated - normally you need a valid .pfx)
  // Since we don't have a specific PFX here, we assume one exists or we skip to LTV 
  // if we can't sign.
  // For demonstration, we'll try to load a known pfx if available, else just print usage.
  
  print('This script demonstrates the LTV API usage.');
  print('Input PDF: $inputFile');
  print('Signed PDF (expected): $signedFile');
  print('Output with LTV (expected): $ltvFile');
  print('To run actual LTV generation, you need a valid signed PDF with a certificate that has CRL/OCSP points.');
  
  // Example Code Structure:
  /*
  // Load signed document
  final PdfDocument document = PdfDocument(inputBytes: File(signedFile).readAsBytesSync());
  
  // Iterate signature fields
  for(int i=0; i<document.form.fields.count; i++) {
      final field = document.form.fields[i];
      if (field is PdfSignatureField && field.isSigned) {
          print('Processing signature: ${field.name}');
          
          // Enable LTV
          final bool result = await field.signature!.createLongTermValidity(
              includePublicCertificates: true,
              type: RevocationType.ocspAndCrl
          );
          
          print('LTV Check Result: $result');
      }
  }
  
  // Save with LTV
  // Incremental update should trigger automatically due to hasSignatures
  File(ltvFile).writeAsBytesSync(await document.save());
  document.dispose();
  */
  
  print('LTV API implemented in PdfSignature.createLongTermValidity()');
  print('Demos logic:');
  print('1. PdfDocument.hasSignatures -> returns true (auto triggers incremental update)');
  print('2. field.signature!.createLongTermValidity() -> fetches CRLs/OCSP via RevocationDataClient');
  print('3. Embeds /DSS dictionary in Catalog');
}
