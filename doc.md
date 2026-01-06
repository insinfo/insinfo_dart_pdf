# PDF library

 feature-rich and high-performance non-UI PDF library written natively in Dart. It allows you to add robust PDF functionalities to Flutter applications.


## Overview

The PDF package is a non-UI, reusable Flutter library for creating PDF reports programmatically with formatted text, images, shapes, tables, links, lists, headers, footers, and more. The library can be used to create, read, edit, and secure PDF documents in Flutter mobile and web platforms without dependency on Adobe Acrobat. The creation of a PDF follows the most popular PDF 1.7 (ISO 32000-1) and latest PDF 2.0 (ISO 32000-2) specifications.



## Table of contents
- [Key features](#key-features)
- [Get the demo application](#get-the-demo-application)
- [Useful links](#useful-links)
- [Installation](#installation)
- [Getting started](#getting-started)
  - [Create a PDF document from simple text](#create-a-pdf-document-from-simple-text)
  - [Add text using TrueType fonts](#add-text-using-truetype-fonts)
  - [Add images to a PDF document](#add-images-to-a-pdf-document)
  - [PDF document with flow layout](#pdf-document-with-flow-layout)
  - [Add bullets and lists](#add-bullets-and-lists)
  - [Add tables](#add-tables)
  - [Add headers and footers](#add-headers-and-footers)
  - [Load and modify an existing PDF document](#load-and-modify-an-existing-pdf-document)
  - [Create and load annotations](#create-and-load-annotations)
  - [Add bookmarks](#add-bookmarks)
  - [Extract text](#extract-text)
  - [Find text](#find-text)
  - [Encryption and decryption](#encryption-and-decryption)
  - [PDF conformance](#pdf-conformance)
  - [PDF form](#pdf-form)
  - [Digital signature](#digital-signature)
- [Support and feedback](#support-and-feedback)
- [About Insinfo<sup>&reg;</sup>](#about-insinfo)

## Key features

The following are the key features of Insinfo<sup>&reg;</sup> Flutter PDF:

* Create multipage PDF files from scratch.
* Add Unicode and RTL text.
* Insert JPEG and PNG images in the PDF document.
* Generate tables in PDF files with different styles and formats.
* Add headers and footers.
* Add different shapes to PDF files.
* Add paragraphs, bullets, and lists.
* Open, modify, and save existing PDF files.
* Encrypt and decrypt PDF files with advanced standards.
* Add, modify, and remove interactive elements such as bookmarks, annotations, hyperlinks, and attachments.
* Create PDF/A-1B, PDF/A-2B, PDF/A-3B conformances.
* Digitally sign PDF documents.
* Use on mobile and web platforms.

## Get the demo application

Explore the full capability of our Flutter widgets on your device by installing our sample browser application from the following app stores and viewing the sample code in GitHub.

<p align="center">
  <a href="https://play.google.com/store/apps/details?id=com.insinfo.flutter.examples"><img src="https://cdn.insinfo.com/content/images/FTControl/google-play-store.png"/></a>
  <a href="https://flutter.insinfo.com"><img src="https://cdn.insinfo.com/content/images/FTControl/web-sample-browser.png"/></a>
  <a href="https://www.microsoft.com/en-us/p/insinfo-flutter-gallery/9nhnbwcsf85d?activetab=pivot:overviewtab"><img src="https://cdn.insinfo.com/content/images/FTControl/windows-store.png"/></a> 
</p>
<p align="center">
  <a href="https://snapcraft.io/insinfo-flutter-gallery"><img src="https://cdn.insinfo.com/content/images/FTControl/snap-store.png"/></a>
  <a href="https://github.com/insinfo/flutter-examples"><img src="https://cdn.insinfo.com/content/images/FTControl/github-samples.png"/></a>
</p>

## Other useful links

Take a look at the following to learn more about Insinfo<sup>&reg;</sup> Flutter PDF:

* [Insinfo<sup>&reg;</sup> Flutter PDF product page](https://www.insinfo.com/flutter-widgets/pdf-library)
* [User guide documentation](https://help.insinfo.com/flutter/pdf/overview)
* [Knowledge base](https://www.insinfo.com/kb)

## Installation

Install the latest version from [pub.dev](https://pub.dartlang.org/packages/insinfo_flutter_pdf#-installing-tab-).

## Getting started

Import the following package to your project to create a PDF document from scratch.

```dart
import 'package:dart_pdf/pdf.dart';
```

### Create a PDF document from simple text

Add the following code to create a simple PDF document.

```dart
// Create a new PDF document.
final PdfDocument document = PdfDocument();
// Add a PDF page and draw text.
document.pages.add().graphics.drawString(
    'Hello World!', PdfStandardFont(PdfFontFamily.helvetica, 12),
    brush: PdfSolidBrush(PdfColor(0, 0, 0)),
    bounds: const Rect.fromLTWH(0, 0, 150, 20));
// Save the document.
File('HelloWorld.pdf').writeAsBytes(await document.save());
// Dispose the document.
document.dispose();
```

### Add text using TrueType fonts

Use the following code to add a Unicode text to the PDF document.

```dart
//Create a new PDF document.
final PdfDocument document = PdfDocument();
//Read font data.
final Uint8List fontData = File('arial.ttf').readAsBytesSync();
//Create a PDF true type font object.
final PdfFont font = PdfTrueTypeFont(fontData, 12);
//Draw text using ttf font.
document.pages.add().graphics.drawString('Hello World!!!', font,
    bounds: const Rect.fromLTWH(0, 0, 200, 50));
// Save the document.
File('TrueType.pdf').writeAsBytes(await document.save());
// Dispose the document.
document.dispose();
```

### Add images to a PDF document

The PdfBitmap class is used to draw images in a PDF document. Insinfo<sup>&reg;</sup> Flutter PDF supports PNG and JPEG images. Refer to the following code to draw images in a PDF document. 

```dart
//Create a new PDF document.
final PdfDocument document = PdfDocument();
//Read image data.
final Uint8List imageData = File('input.png').readAsBytesSync();
//Load the image using PdfBitmap.
final PdfBitmap image = PdfBitmap(imageData);
//Draw the image to the PDF page.
document.pages
    .add()
    .graphics
    .drawImage(image, const Rect.fromLTWH(0, 0, 500, 200));
// Save the document.
File('ImageToPDF.pdf').writeAsBytes(await document.save());
// Dispose the document.
document.dispose();
```

### PDF document with flow layout

Add the following code to create a PDF document with flow layout.

```dart
const String paragraphText =
    'Adobe Systems Incorporated\'s Portable Document Format (PDF) is the de facto'
    'standard for the accurate, reliable, and platform-independent representation of a paged'
    'document. It\'s the only universally accepted file format that allows pixel-perfect layouts.'
    'In addition, PDF supports user interaction and collaborative workflows that are not'
    'possible with printed documents.';

// Create a new PDF document.
final PdfDocument document = PdfDocument();
// Add a new page to the document.
final PdfPage page = document.pages.add();
// Create a new PDF text element class and draw the flow layout text.
final PdfLayoutResult layoutResult = PdfTextElement(
        text: paragraphText,
        font: PdfStandardFont(PdfFontFamily.helvetica, 12),
        brush: PdfSolidBrush(PdfColor(0, 0, 0)))
    .draw(
        page: page,
        bounds: Rect.fromLTWH(
            0, 0, page.getClientSize().width, page.getClientSize().height),
        format: PdfLayoutFormat(layoutType: PdfLayoutType.paginate))!;
// Draw the next paragraph/content.
page.graphics.drawLine(
    PdfPen(PdfColor(255, 0, 0)),
    Offset(0, layoutResult.bounds.bottom + 10),
    Offset(page.getClientSize().width, layoutResult.bounds.bottom + 10));
// Save the document.
File('TextFlow.pdf').writeAsBytes(await document.save());
// Dispose the document.
document.dispose();
```

### Add bullets and lists

Add the following code to create bullets and lists in a PDF document.

```dart
// Create a new PDF document.
final PdfDocument document = PdfDocument();
// Add a new page to the document.
final PdfPage page = document.pages.add();
// Create a PDF ordered list.
final PdfOrderedList orderedList = PdfOrderedList(
    items: PdfListItemCollection(<String>[
      'Mammals',
      'Reptiles',
      'Birds',
      'Insects',
      'Aquatic Animals'
    ]),
    marker: PdfOrderedMarker(
        style: PdfNumberStyle.numeric,
        font: PdfStandardFont(PdfFontFamily.helvetica, 12)),
    markerHierarchy: true,
    format: PdfStringFormat(lineSpacing: 10),
    textIndent: 10);
// Create a un ordered list and add it as a sublist.
orderedList.items[0].subList = PdfUnorderedList(
    marker: PdfUnorderedMarker(
        font: PdfStandardFont(PdfFontFamily.helvetica, 10),
        style: PdfUnorderedMarkerStyle.disk),
    items: PdfListItemCollection(<String>[
      'body covered by hair or fur',
      'warm-blooded',
      'have a backbone',
      'produce milk',
      'Examples'
    ]),
    textIndent: 10,
    indent: 20);
// Draw the list to the PDF page.
orderedList.draw(
    page: page,
    bounds: Rect.fromLTWH(
        0, 0, page.getClientSize().width, page.getClientSize().height));
// Save the document.
File('BulletandList.pdf').writeAsBytes(await document.save());
// Dispose the document.
document.dispose();
```

### Add tables

Add the following code to create a PDF table.

```dart
// Create a new PDF document.
final PdfDocument document = PdfDocument();
// Add a new page to the document.
final PdfPage page = document.pages.add();
// Create a PDF grid class to add tables.
final PdfGrid grid = PdfGrid();
// Specify the grid column count.
grid.columns.add(count: 3);
// Add a grid header row.
final PdfGridRow headerRow = grid.headers.add(1)[0];
headerRow.cells[0].value = 'Customer ID';
headerRow.cells[1].value = 'Contact Name';
headerRow.cells[2].value = 'Country';
// Set header font.
headerRow.style.font =
    PdfStandardFont(PdfFontFamily.helvetica, 10, style: PdfFontStyle.bold);
// Add rows to the grid.
PdfGridRow row = grid.rows.add();
row.cells[0].value = 'ALFKI';
row.cells[1].value = 'Maria Anders';
row.cells[2].value = 'Germany';
// Add next row.
row = grid.rows.add();
row.cells[0].value = 'ANATR';
row.cells[1].value = 'Ana Trujillo';
row.cells[2].value = 'Mexico';
// Add next row.
row = grid.rows.add();
row.cells[0].value = 'ANTON';
row.cells[1].value = 'Antonio Mereno';
row.cells[2].value = 'Mexico';
// Set grid format.
grid.style.cellPadding = PdfPaddings(left: 5, top: 5);
// Draw table in the PDF page.
grid.draw(
    page: page,
    bounds: Rect.fromLTWH(
        0, 0, page.getClientSize().width, page.getClientSize().height));
// Save the document.
File('PDFTable.pdf').writeAsBytes(await document.save());
// Dispose the document.
document.dispose();
```

### Add headers and footers

Use the following code to add headers and footers to a PDF document.

```dart
//Create a new PDF document.
final PdfDocument document = PdfDocument();
//Create a PDF page template and add header content.
final PdfPageTemplateElement headerTemplate =
    PdfPageTemplateElement(const Rect.fromLTWH(0, 0, 515, 50));
//Draw text in the header.
headerTemplate.graphics.drawString(
    'This is page header', PdfStandardFont(PdfFontFamily.helvetica, 12),
    bounds: const Rect.fromLTWH(0, 15, 200, 20));
//Add the header element to the document.
document.template.top = headerTemplate;
//Create a PDF page template and add footer content.
final PdfPageTemplateElement footerTemplate =
    PdfPageTemplateElement(const Rect.fromLTWH(0, 0, 515, 50));
//Draw text in the footer.
footerTemplate.graphics.drawString(
    'This is page footer', PdfStandardFont(PdfFontFamily.helvetica, 12),
    bounds: const Rect.fromLTWH(0, 15, 200, 20));
//Set footer in the document.
document.template.bottom = footerTemplate;
//Now create pages.
document.pages.add();
document.pages.add();
// Save the document.
File('HeaderandFooter.pdf').writeAsBytes(await document.save());
// Dispose the document.
document.dispose();
```

### Load and modify an existing PDF document

Add the following code to load and modify the existing PDF document.

```dart
//Load the existing PDF document.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());
//Get the existing PDF page.
final PdfPage page = document.pages[0];
//Draw text in the PDF page.
page.graphics.drawString(
    'Hello World!', PdfStandardFont(PdfFontFamily.helvetica, 12),
    brush: PdfSolidBrush(PdfColor(0, 0, 0)),
    bounds: const Rect.fromLTWH(0, 0, 150, 20));
//Save the document.
File('output.pdf').writeAsBytes(await document.save());
//Dispose the document.
document.dispose();
```

Add the following code to add or remove a page from the existing PDF document.

```dart
//Load the existing PDF document.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());
//Remove the page from the document.
document.pages.removeAt(0);
//Add new page and draw text.
document.pages.add().graphics.drawString(
    'Hello World!', PdfStandardFont(PdfFontFamily.helvetica, 12),
    brush: PdfSolidBrush(PdfColor(0, 0, 0)),
    bounds: const Rect.fromLTWH(0, 0, 150, 20));
//Save the document.
File('output.pdf').writeAsBytes(await document.save());
//Dispose the document.
document.dispose();
```

### Create and load annotations

Using this package, we can create and load annotations in a new or existing PDF document.

Add the following code to create a new annotation in a PDF document.

```dart
//Load the existing PDF document.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());
//Create a new rectangle annotation and add to the PDF page.
document.pages[0].annotations.add(PdfRectangleAnnotation(
      Rect.fromLTWH(0, 0, 150, 100), 'Rectangle',
      color: PdfColor(255, 0, 0), setAppearance: true));
//Save the document.
File('annotations.pdf').writeAsBytes(await document.save());
//Dispose the document.
document.dispose();
```

Add the following code to load the annotation and modify it.

```dart
//Load and modify the existing annotation.
final PdfRectangleAnnotation rectangleAnnotation =
    document.pages[0].annotations[0] as PdfRectangleAnnotation;
//Change the annotation text.
rectangleAnnotation.text = 'Changed';
```



### Add bookmarks

Add the following code to create bookmarks in a PDF document.

```dart
//Load the existing PDF document.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());
//Create a document bookmark.
final PdfBookmark bookmark = document.bookmarks.add('Page 1');
//Set the destination page and location.
bookmark.destination = PdfDestination(document.pages[1], Offset(20, 20));
//Set the bookmark color.
bookmark.color = PdfColor(255, 0, 0);
//Save the document.
File('bookmark.pdf').writeAsBytes(await document.save());
//Dispose the document.
document.dispose();
```



### Extract text

Using this package, we can extract text from an existing PDF document along with its bounds.

Add the following code to extract text from a PDF document.

```dart
//Load an existing PDF document.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());
//Extract the text from all the pages.
String text = PdfTextExtractor(document).extractText();
//Dispose the document.
document.dispose();
```

The following code sample explains how to extract text from a specific page.

```dart
//Load an existing PDF document.
PdfDocument document =
   PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());
//Extract the text from page 1.
String text = PdfTextExtractor(document).extractText(startPageIndex: 0);
//Dispose the document.
document.dispose();
```



### Find text

Using this package, we can find text in an existing PDF document along with its bounds and page index.

Add the following code to find text in a PDF document.

```dart
//Load an existing PDF document.
PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());
//Find the text and get matched items.
List<MatchedItem> textCollection =
    PdfTextExtractor(document).findText(['text1', 'text2']); 
//Get the matched item in the collection using index.
MatchedItem matchedText = textCollection[0];
//Get the text bounds.
Rect textBounds = matchedText.bounds;  
//Get the page index.
int pageIndex = matchedText.pageIndex; 
//Get the text.
String text = matchedText.text;
//Dispose the document.
document.dispose();
```



### Encryption and decryption

Encrypt new or existing PDF documents with encryption standards like 40-bit RC4, 128-bit RC4, 128-bit AES, and 256-bit AES, and the advanced encryption standard 256-bit AES Revision 6 (PDF 2.0) to protect documents against unauthorized access. Using this package, you can also decrypt existing encrypted documents.

Add the following code to encrypt an existing PDF document.

```dart
//Load the existing PDF document.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());

//Add security to the document.
final PdfSecurity security = document.security;

//Set password.
security.userPassword = 'userpassword@123';
security.ownerPassword = 'ownerpassword@123';

//Set the encryption algorithm.
security.algorithm = PdfEncryptionAlgorithm.aesx256Bit;

//Save the document.
File('secured.pdf').writeAsBytes(await document.save());

//Dispose the document.
document.dispose();
```



### PDF conformance

Using this package, we can create PDF conformance documents, such as:

* PDF/A-1B
* PDF/A-2B
* PDF/A-3B

Add the following code to create a PDF conformance document.

```dart
//Create a PDF conformance document.
final PdfDocument document = PdfDocument(conformanceLevel: PdfConformanceLevel.a1b)
  ..pages.add().graphics.drawString('Hello World',
      PdfTrueTypeFont(File('Roboto-Regular.ttf').readAsBytesSync(), 12),
      bounds: Rect.fromLTWH(20, 20, 200, 50), brush: PdfBrushes.black);
//Save and dispose the document.
File('conformance.pdf').writeAsBytesSync(await document.save());
document.dispose();
```



### PDF form

PDF forms provide the best way to collect information from users. Using this package, we can create, modify, fill, and flatten PDF forms.

Add the following code to create PDF form.

```dart
//Create a new PDF document.
PdfDocument document = PdfDocument();

//Create a new page to add form fields.
PdfPage page = document.pages.add();

//Create text box field and add to the forms collection.
document.form.fields.add(PdfTextBoxField(
    page, 'firstname', Rect.fromLTWH(0, 0, 100, 20),
    text: 'John'));

//Create check box field and add to the form.
document.form.fields.add(PdfCheckBoxField(
    page, 'checkbox', Rect.fromLTWH(150, 0, 30, 30),
    isChecked: true));

//Save and dispose the document.
File('form.pdf').writeAsBytesSync(await document.save());
document.dispose();
```

Add the following code to fill the existing PDF form.

```dart
//Load the existing PDF document.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());

//Get the form.
PdfForm form = document.form;

//Get text box and fill value.
PdfTextBoxField name = document.form.fields[0] as PdfTextBoxField;
name.text = 'John';

//Get the radio button and select.
PdfRadioButtonListField gender = form.fields[1] as PdfRadioButtonListField;
gender.selectedIndex = 1;

//Save and dispose the document.
File('output.pdf').writeAsBytesSync(await document.save());
document.dispose();
```

Add the following code to flatten the existing form.

```dart
//Load the existing PDF document.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());

//Get the form.
PdfForm form = document.form;

//Flatten all the form fields.
form.flattenAllFields();

//Save and dispose the document.
File('output.pdf').writeAsBytesSync(await document.save());
document.dispose();
```



### Digital signature

PDF digital signature is the best way to protect your PDF files from being forged. Using this package, we can digitally sign a PDF document using X509 certificates (.pfx file with private key).

Add the following code to sign the PDF document.

```dart
//Create a new PDF document.
PdfDocument document = PdfDocument();

//Add a new PDF page.
PdfPage page = document.pages.add();

//Create signature field.
PdfSignatureField signatureField = PdfSignatureField(page, 'Signature',
    bounds: Rect.fromLTWH(0, 0, 200, 50),
    signature: PdfSignature(
       certificate:
          PdfCertificate(File('certificate.pfx').readAsBytesSync(), 'password@123')
    ));
  
//Add the signature field to the document.
document.form.fields.add(signatureField);

//Save and dispose the PDF document
File('signed.pdf').writeAsBytes(await document.save());
document.dispose();
```
Add the following code to sign the existing PDF document.

```dart
//Load the existing PDF document.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());

//Get the signature field.
PdfSignatureField signatureField =
    document.form.fields[0] as PdfSignatureField;

//Get signature field and sign.
signatureField.signature = PdfSignature(
  certificate:
      PdfCertificate(File('certificate.pfx').readAsBytesSync(), 'password@123'),
);

//Save and dispose the document.
File('output.pdf').writeAsBytesSync(await document.save());
document.dispose();
```

## Gov.br external signature (server-side)

This library now supports a robust external signing flow compatible with the Gov.br API.
The flow has two phases: prepare the PDF and compute the ByteRange hash, then inject the
PKCS#7 returned by the signing service.

### 1) Prepare PDF and hash (server-side)

Use `PdfExternalSigning.preparePdf` to add the signature field, reserve space, and compute
the Base64 hash to send to Gov.br. You can provide a custom visual appearance using
`drawAppearance`.

```dart
final prepared = await PdfExternalSigning.preparePdf(
  inputBytes: pdfBytes,
  pageNumber: 1,
  bounds: Rect.fromLTWH(100, 120, 220, 60),
  fieldName: 'GovBr_Signature',
  signature: PdfSignature()
    ..documentPermissions = [PdfCertificationFlags.allowFormFill]
    ..contactInfo = 'Gov.br - Assinatura Digital'
    ..reason = 'Assinatura eletrônica via Gov.br'
    ..digestAlgorithm = DigestAlgorithm.sha256,
  drawAppearance: (graphics, bounds) {
    graphics.drawString(
      'Assinado via Gov.br',
      PdfStandardFont(PdfFontFamily.helvetica, 9),
      bounds: bounds,
    );
  },
);

final String hashBase64 = prepared.hashBase64;
final Uint8List preparedPdfBytes = prepared.preparedPdfBytes;
```

### 2) Call Gov.br and inject the PKCS#7

Use `GovBrSignatureApi` to fetch the certificate and to sign the hash, then embed the
PKCS#7 bytes into the prepared PDF.

```dart
final api = GovBrSignatureApi();
final certPem = await api.getPublicCertificatePem(accessToken);

final pkcs7 = await api.signHashPkcs7(
  accessToken: accessToken,
  hashBase64: hashBase64,
);

final signedPdf = PdfExternalSigning.embedSignature(
  preparedPdfBytes: preparedPdfBytes,
  pkcs7Bytes: pkcs7,
);
```

### 3) OAuth (Gov.br login)

`GovBrOAuthClient` provides helpers to build the authorization URL and exchange the token
using the Gov.br CAS endpoints. Use it in your backend controller to drive the OAuth flow.

```dart
final oauth = GovBrOAuthClient();
final authorizeUri = oauth.buildAuthorizationUri({
  'client_id': clientId,
  'redirect_uri': redirectUri,
  'response_type': 'code',
  'scope': 'sign',
  'code_challenge': codeChallenge,
  'code_challenge_method': 'S256',
  'state': state,
});

final token = await oauth.exchangeToken(body: {
  'grant_type': 'authorization_code',
  'client_id': clientId,
  'redirect_uri': redirectUri,
  'code': code,
  'code_verifier': codeVerifier,
});
```

### Integration with your current controller

Map your current flow to the new helpers:

- `start`: call `PdfExternalSigning.preparePdf` and send `hashBase64` to Gov.br.
- `assinar`: receive `pkcs7` bytes from Gov.br and call `PdfExternalSigning.embedSignature`.
- Keep your existing DocMDP and visual layout logic; you can replace your custom placeholder
  logic with `drawAppearance` if desired.

### Demo script

This repo includes a demo that generates a certificate chain, signs a PDF with OpenSSL,
installs the certs in Windows, and opens the PDF in Foxit:

```bash
dart run scripts/govbr_pdf_sign_demo.dart
```

You can set `FOXIT_PATH` to point to a custom Foxit location.

### Internal parser flags

When you need to avoid regex scanning, enable the internal parser flags:

```dart
PdfExternalSigning.useInternalByteRangeParser = true;
PdfExternalSigning.useInternalContentsParser = true;
```

## External signature without helpers (low-level)

If you prefer not to use `PdfExternalSigning`, you can implement the same flow with
low-level APIs. The steps are:

1) Load the PDF and add a `PdfSignatureField`.
2) Attach a `PdfSignature` with `addExternalSigner` (placeholder).
3) Save the PDF to create `/ByteRange` and `/Contents`.
4) Extract the ByteRange, compute the Base64 SHA-256 hash, send to Gov.br.
5) Inject the returned PKCS#7 into `/Contents`.

Minimal example:

```dart
class _PlaceholderSigner extends IPdfExternalSigner {
  @override
  Future<SignerResult?> sign(List<int> message) async {
    return SignerResult(Uint8List(0));
  }
}

Future<Uint8List> preparePdfLowLevel(
  Uint8List inputBytes,
  Rect bounds,
) async {
  final doc = PdfDocument(inputBytes: inputBytes);
  final page = doc.pages[0];

  final sig = PdfSignature()
    ..documentPermissions = [PdfCertificationFlags.allowFormFill]
    ..contactInfo = 'Gov.br - Assinatura Digital'
    ..reason = 'Assinatura eletronica via Gov.br'
    ..digestAlgorithm = DigestAlgorithm.sha256;

  sig.addExternalSigner(_PlaceholderSigner(), <List<int>>[]);

  final field = PdfSignatureField(
    page,
    'GovBr_Signature',
    bounds: bounds,
    borderWidth: 0,
    borderStyle: PdfBorderStyle.solid,
    signature: sig,
  );
  doc.form.fields.add(field);

  final bytes = Uint8List.fromList(await doc.save());
  doc.dispose();
  return bytes;
}

List<int> extractByteRangeLowLevel(Uint8List pdfBytes) {
  final s = latin1.decode(pdfBytes, allowInvalid: true);
  final m = RegExp(
    r'/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]',
  ).allMatches(s);
  if (m.isEmpty) throw Exception('ByteRange not found');
  final match = m.last;
  return [
    int.parse(match.group(1)!),
    int.parse(match.group(2)!),
    int.parse(match.group(3)!),
    int.parse(match.group(4)!),
  ];
}

Uint8List embedPkcs7LowLevel(Uint8List pdfBytes, List<int> pkcs7Bytes) {
  final s = latin1.decode(pdfBytes, allowInvalid: true);
  final sigPos = s.lastIndexOf('/Type /Sig');
  if (sigPos == -1) throw Exception('No /Type /Sig');
  final dictStart = s.lastIndexOf('<<', sigPos);
  final dictEnd = s.indexOf('>>', sigPos);
  if (dictStart == -1 || dictEnd == -1) {
    throw Exception('Signature dict bounds not found');
  }
  final contentsPos = s.indexOf('/Contents', dictStart);
  if (contentsPos == -1 || contentsPos > dictEnd) {
    throw Exception('No /Contents in signature dict');
  }
  final lt = s.indexOf('<', contentsPos);
  final gt = s.indexOf('>', lt + 1);
  if (lt == -1 || gt == -1 || gt <= lt) {
    throw Exception('Contents hex not found');
  }
  final start = lt + 1;
  final end = gt;
  final available = end - start;
  String hex = pkcs7Bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  hex = hex.toUpperCase();
  if (hex.length.isOdd) hex = '0$hex';
  if (hex.length > available) {
    throw Exception('PKCS#7 larger than placeholder');
  }
  final out = Uint8List.fromList(pdfBytes);
  final sigBytes = ascii.encode(hex);
  out.setRange(start, start + sigBytes.length, sigBytes);
  for (int i = start + sigBytes.length; i < end; i++) {
    out[i] = 0x30;
  }
  return out;
}
```

This low-level flow mirrors the helper behavior but keeps full control in your app.



