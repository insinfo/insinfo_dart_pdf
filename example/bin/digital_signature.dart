import 'dart:io';

import 'package:dart_pdf/pdf.dart';


void main() async {
//Loads PDF file.
  final document =
      PdfDocument(inputBytes: File('example.pdf').readAsBytesSync());

  //Adds a new page
  PdfPage page =
      document.pages.count > 0 ? document.pages[0] : document.pages.add();

//Gets the first signature field of the PDF document.
  //var field = document.form.fields[0] as PdfSignatureField;

//Creates a digital signature and sets the signature information.
  var signature = PdfSignature(
      //Creates a certificate instance from the PFX file with a private key.
      certificate: PdfCertificate(
          File('IsaqueNevesSantAna.pfx').readAsBytesSync(), '257257'),
      contactInfo: 'insinfo@example.com',
      locationInfo: 'Rio das Ostras, Brasil',
      reason: 'Eu sou o autor deste documento.',
      signedName: 'Isaque Neves Sant Ana',
      signedDate: DateTime.now(),
      digestAlgorithm: DigestAlgorithm.sha256,
      cryptographicStandard: CryptographicStandard.cades);

  var field = PdfSignatureField(page, 'signature',
     // bounds: Rect.fromLTWH(0, 0, 200, 100), 
      signature: signature);

  //Add a signature field to the form
  document.form.fields.add(field);

  //Gets the signature field appearance graphics.
  var graphics = field.appearance.normal.graphics;

//Draws the signature image.
  // graphics!.drawImage(
  //     PdfBitmap(File('estampa1382141175514466498.png').readAsBytesSync()),
  //     Rect.fromLTWH(0, 0, field.bounds.width, field.bounds.height));

//Save and dispose the PDF document.
  File('example_sign2.pdf').writeAsBytes(await document.save());
  document.dispose();
}
