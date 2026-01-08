# Biblioteca PDF

Biblioteca de PDF (sem UI), rica em recursos e de alta performance, escrita nativamente em Dart. Permite adicionar funcionalidades robustas de PDF a aplicações Flutter.


## Visão geral

O pacote PDF é uma biblioteca Flutter reutilizável (sem UI) para criar relatórios PDF programaticamente com texto formatado, imagens, formas, tabelas, links, listas, cabeçalhos, rodapés e mais. A biblioteca pode ser usada para criar, ler, editar e proteger PDFs em Flutter (mobile e web) sem dependência do Adobe Acrobat. A criação de PDFs segue a especificação PDF 1.7 (ISO 32000-1) e a PDF 2.0 (ISO 32000-2).


## Sumário
- [Principais recursos](#key-features)
- [Primeiros passos](#getting-started)
  - [Criar um PDF a partir de texto simples](#create-a-pdf-document-from-simple-text)
  - [Adicionar texto usando fontes TrueType](#add-text-using-truetype-fonts)
  - [Adicionar imagens em um PDF](#add-images-to-a-pdf-document)
  - [PDF com layout fluido (flow)](#pdf-document-with-flow-layout)
  - [Adicionar bullets e listas](#add-bullets-and-lists)
  - [Adicionar tabelas](#add-tables)
  - [Adicionar cabeçalhos e rodapés](#add-headers-and-footers)
  - [Carregar e modificar um PDF existente](#load-and-modify-an-existing-pdf-document)
  - [Criar e carregar anotações](#create-and-load-annotations)
  - [Adicionar bookmarks](#add-bookmarks)
  - [Extrair texto](#extract-text)
  - [Buscar texto](#find-text)
  - [Criptografia e descriptografia](#encryption-and-decryption)
  - [Conformidade PDF](#pdf-conformance)
  - [Formulários PDF](#pdf-form)
  - [Assinatura digital](#assinatura-digital)
- [Validação de assinaturas (PAdES / server-side)](#validação-de-assinaturas-pades--server-side)
- [Assinatura externa Gov.br (server-side)](#assinatura-externa-govbr-server-side)
- [Suporte e feedback](#support-and-feedback)
- [Sobre a Insinfo<sup>&reg;</sup>](#about-insinfo)

<a id="key-features"></a>

## Principais recursos

Principais recursos do Insinfo<sup>&reg;</sup> Flutter PDF:

* Criar PDFs multipágina do zero.
* Adicionar texto Unicode e RTL.
* Inserir imagens JPEG e PNG no documento.
* Gerar tabelas em PDFs com estilos e formatos diferentes.
* Adicionar cabeçalhos e rodapés.
* Adicionar diferentes formas no PDF.
* Adicionar parágrafos, bullets e listas.
* Abrir, modificar e salvar PDFs existentes.
* Criptografar e descriptografar PDFs com padrões avançados.
* Adicionar, modificar e remover elementos interativos como bookmarks, anotações, hyperlinks e anexos.
* Criar conformidades PDF/A-1B, PDF/A-2B, PDF/A-3B.
* Assinar digitalmente documentos PDF.
* Usar em plataformas mobile e web.


<a id="getting-started"></a>

## Primeiros passos

Importe o pacote abaixo no seu projeto para criar um PDF do zero.

```dart
import 'package:dart_pdf/pdf.dart';
```

### Create a PDF document from simple text

Add the following code to create a simple PDF document.

```dart

final PdfDocument document = PdfDocument();

document.pages.add().graphics.drawString(
    'Hello World!', PdfStandardFont(PdfFontFamily.helvetica, 12),
    brush: PdfSolidBrush(PdfColor(0, 0, 0)),
    bounds: const Rect.fromLTWH(0, 0, 150, 20));

File('HelloWorld.pdf').writeAsBytes(await document.save());

document.dispose();
```

### Add text using TrueType fonts

Use the following code to add a Unicode text to the PDF document.

```dart

final PdfDocument document = PdfDocument();

final Uint8List fontData = File('arial.ttf').readAsBytesSync();

final PdfFont font = PdfTrueTypeFont(fontData, 12);

document.pages.add().graphics.drawString('Hello World!!!', font,
    bounds: const Rect.fromLTWH(0, 0, 200, 50));

File('TrueType.pdf').writeAsBytes(await document.save());

document.dispose();
```

### Add images to a PDF document

The PdfBitmap class is used to draw images in a PDF document. Insinfo<sup>&reg;</sup> Flutter PDF supports PNG and JPEG images. Refer to the following code to draw images in a PDF document. 

```dart

final PdfDocument document = PdfDocument();

final Uint8List imageData = File('input.png').readAsBytesSync();

final PdfBitmap image = PdfBitmap(imageData);

document.pages
    .add()
    .graphics
    .drawImage(image, const Rect.fromLTWH(0, 0, 500, 200));

File('ImageToPDF.pdf').writeAsBytes(await document.save());

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



### Assinatura digital

A assinatura digital em PDF é uma forma robusta de proteger seus documentos contra adulteração. Com este pacote, é possível assinar um PDF usando certificados X.509 (arquivo .pfx contendo a chave privada).

Use o exemplo abaixo para assinar um PDF novo.

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
Use o exemplo abaixo para assinar um PDF existente.

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

## Validação de assinaturas (PAdES / server-side)

Este repositório inclui um helper de validação server-side que consegue inspecionar **todas** as assinaturas de um PDF e reportar:

- Validade da assinatura CMS
- Conferência do digest do ByteRange
- Integridade do documento (`documentIntact`)
- Confiança de cadeia (quando roots confiáveis são fornecidas)
- Status de revogação (best-effort ou estrito)
- Status de policy (quando `SignaturePolicyId` está presente e `Lpa` foi fornecido)
- Status de timestamp (RFC 3161, quando presente)
- Issues agregadas (warnings/errors) em `PdfSignatureValidationItem.issues`

Nota sobre severidade de timestamp (ICP-Brasil / Gov.br):

- Se o OID de policy indicar ICP-Brasil/Gov.br (`2.16.76.1.7.1.*`) e **não** houver token de timestamp RFC3161, isso é reportado como issue **warning** (`timestamp_missing`) por padrão.
- Se você fornecer o XML da policy via `policyXmlByOid` e esse XML exigir `SignatureTimeStamp`, então a ausência de RFC3161 é reportada como issue **error** (`timestamp_missing`).
- Se existir token de timestamp, mas ele for deterministicamente inválido (ex.: assinatura CMS do token inválida ou message imprint não confere), isso é reportado como issue **error** (`timestamp_invalid`).

### Scripts de teste (ICP-Brasil / policy exige timestamp)

Para evitar dependências de pastas removíveis (ex.: `test/assets/12`) e ter um caso de teste determinístico, este repositório inclui um gerador de PDF assinado que:

- Cria uma cadeia de certificados (Root → Intermediate → Leaf) via OpenSSL.
- Assina um PDF com CMS detached.
- Embute `SignaturePolicyId` (OID ICP-Brasil/Gov.br) nos signed attributes.
- **Não** embute RFC3161 (PAdES-T ausente de propósito), para exercitar `timestamp_missing`.

Gerar/atualizar o PDF de teste:

```bash
dart run scripts/generate_policy_mandated_timestamp_missing_pdf.dart
```

Arquivo gerado (deve ser versionado no repo para CI):

- `test/assets/generated_policy_mandated_timestamp_missing.pdf`

Rodar o teste de integração que valida o “flip” warning→error ao fornecer `policyXmlByOid`:

```bash
dart test test/policy_timestamp_integration_test.dart
```

### Scripts auxiliares (debug)

- Inspecionar rapidamente uma assinatura (policy OID + timestamp status):

```bash
dart run scripts/inspect_pdf_signature_brief.dart test/assets/generated_policy_mandated_timestamp_missing.pdf
```

- Extrair o PKCS#7 (/Contents) para DER e inspecionar com OpenSSL:

```bash
dart run scripts/extract_pdf_pkcs7.dart test/assets/generated_policy_mandated_timestamp_missing.pdf .dart_tool/generated_sig.der
openssl cms -inform DER -in .dart_tool/generated_sig.der -cmsout -print -noout
```

### Curadoria de PDFs de teste (opcional)

Se você tiver uma pasta com muitos PDFs e quiser copiar exemplos “bons” para `test/assets`, use:

```bash
dart run scripts/curate_policy_timestamp_test_pdfs.dart --source test/assets/12 --target test/assets policy-oid 3 1
```

Modos suportados: `policy-mandated-ts-missing`, `policy-oid`, `signed-any`, `multi-sig`.

### O que é validado (visão geral)

Este caminho de validação foi desenhado para ser robusto em fluxos PAdES/CMS no estilo ICP-Brasil.

- O parsing do PDF usa o parser interno (sem varredura por regex) para extrair `/ByteRange` e `/Contents`.
- O CMS/PKCS#7 é validado e atributos comuns são checados (compatibilidade de algoritmo, `signingTime` quando presente, coerência SKI/issuer/serial, etc.).
- A confiança de cadeia pode ser avaliada usando roots embutidas e/ou trust stores customizadas.
- A revogação pode rodar em modo best-effort ou estrito (assinatura + janela de tempo em evidências OCSP/CRL).
- LTV (DSS/VRI) é auditado com self-check best-effort para estimar se validação offline pode ser possível.

Entradas de código relevantes:

- Extração do PDF: `pdf_signature_utils.dart`
- Validação CMS: `pdf_signature_validation.dart`
- Orquestração/relatório: `pdf_signature_validator.dart`

### Validar todas as assinaturas

```dart
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';

Future<void> main() async {
  final Uint8List pdfBytes = File('input.pdf').readAsBytesSync();

  final PdfSignatureValidationReport report = await PdfSignatureValidator().validateAllSignatures(
    pdfBytes,
    // Adiciona roots embutidas (ICP-Brasil / ITI / SERPRO) como trust anchors.
    useEmbeddedIcpBrasil: true,

    // Baixa OCSP/CRL via URLs dos certificados (mais lento).
    fetchCrls: false,

    // Quando true, só retorna revogação "good" se a evidência for validada
    // (assinatura + janela de tempo).
    strictRevocation: false,

    // Quando true, exige o digest de SignaturePolicyId quando policyOid está presente.
    strictPolicyDigest: false,
  );

  print('PDF íntegro: ${report.allDocumentsIntact}');
  for (final s in report.signatures) {
    print('${s.fieldName}: cms=${s.validation.cmsSignatureValid} digest=${s.validation.byteRangeDigestOk} intact=${s.validation.documentIntact}');
  }
}
```

### Validar um único campo de assinatura

Se você já sabe o nome do campo e quer apenas o resultado daquela assinatura:

```dart
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';

Future<void> main() async {
  final Uint8List pdfBytes = File('input.pdf').readAsBytesSync();

  final PdfSignatureValidationItem? item = await PdfSignatureValidator().validateSignature(
    pdfBytes,
    fieldName: 'Signature1',
    useEmbeddedIcpBrasil: true,
    strictRevocation: true,
  );

  if (item == null) {
    print('Campo de assinatura não encontrado');
    return;
  }

  print('Cadeia confiável: ${item.validation.chainTrusted}');
  print('Revogação: ${item.validation.revocationStatus}');
}
```

Observação: `validateSignature(...)` é um atalho e expõe um subconjunto das opções. Se você precisar de `strictPolicyDigest`, `policyXmlByOid` ou `trustedRootsProviders`, use `validateAllSignatures(...)` e filtre pelo `fieldName`.

### Trust stores (ICP-Brasil / ITI / Serpro / Gov.br)

O validador consegue avaliar `chainTrusted` quando você fornece trust anchors.

- ICP-Brasil / ITI / Serpro: habilite `useEmbeddedIcpBrasil: true`
- Gov.br: use o provider embutido `GovBrProvider()`

Exemplo:

```dart
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';

Future<void> main() async {
  final Uint8List pdfBytes = File('input.pdf').readAsBytesSync();

  final report = await PdfSignatureValidator().validateAllSignatures(
    pdfBytes,
    useEmbeddedIcpBrasil: true,
    trustedRootsProviders: [GovBrProvider()],
  );

  for (final s in report.signatures) {
    print('${s.fieldName}: trusted=${s.validation.chainTrusted}');
  }
}
```

#### Atualizando trust stores embutidas

As trust stores são embutidas para suportar AOT/Wasm e são geradas a partir de `assets/truststore/**`.
Para regenerar:

```bash
dart run scripts/embed_certificates.dart
```

Isso atualiza os arquivos gerados em `lib/src/security/chain/generated/`.

### Helper de CLI

Para validar rapidamente via linha de comando:

```bash
dart run scripts/validate_pdf_signatures.dart input.pdf
```

Por padrão, a CLI habilita auto-trust (roots ICP-Brasil embutidas + roots Gov.br), então ela consegue imprimir `Cadeia confiável: SIM/NÃO`.

Flags úteis:

- `--no-auto-trust`: desabilita carregamento automático de trust roots
- `--embedded-icpbrasil`: habilita explicitamente roots ICP-Brasil (útil com `--no-auto-trust`)
- `--embedded-govbr`: habilita explicitamente roots Gov.br (útil com `--no-auto-trust`)
- `--fetch-crls`: habilita busca via rede de OCSP/CRL por URLs (mais lento)
- `--strict-revocation`: exige evidência validada (assinatura + janela de tempo)
- `--strict-policy-digest`: exige match do digest de SignaturePolicyId quando policy está presente

O script imprime integridade do PDF, validade por assinatura e um rótulo de provedor best-effort (serpro/gov.br/certisign).

### Status ICP-Brasil / PAdES (implementado vs lacunas)

Implementado (estado atual):

- Extração baseada em parser de `/ByteRange` e `/Contents` (evita regex)
- Validação CMS/PKCS#7, incluindo sanity checks de signed attributes
- Trust stores embutidas: ICP-Brasil / ITI / Serpro, + provider Gov.br (`GovBrProvider`)
- Construção de cadeia + avaliação de trust (`chainTrusted`) via providers/trust stores
- Revogação: busca OCSP/CRL + opção de validação estrita (assinatura + janela de tempo)
- Policy engine: validação determinística quando LPA e digest de SignaturePolicyId estão disponíveis
- LTV: scaffolding de DSS/VRI + auditoria best-effort de "self-check"
- APIs públicas de validação: validar todas as assinaturas ou um campo de assinatura

Lacunas que ainda podem impactar robustez (dependendo do seu nível de compliance):

- A injeção de assinatura externa ainda usa regex em um caminho (veja o TODO em `external_pdf_signature.dart`); o ideal é ser totalmente parser-based
- A validação de policy pode cair em heurísticas quando LPA/policy completos não estão disponíveis
- A validação de timestamp é reportada via `timestampStatus` e `issues`, mas você pode querer regras locais mais estritas dependendo do seu alvo (ex.: exigir PAdES-T/LTV como requisito duro)
- Prova offline-LTV completa (verificação estrita de que DSS/VRI contém *todas* as evidências exigidas em todos os cenários) é best-effort e pode exigir regras mais estritas no seu caso

## Assinatura externa Gov.br (server-side)

Esta biblioteca suporta um fluxo robusto de assinatura externa compatível com a API do Gov.br.
O fluxo tem duas fases: preparar o PDF e computar o hash do ByteRange; depois, injetar o PKCS#7 retornado pelo serviço de assinatura.

### 1) Preparar o PDF e calcular o hash (server-side)

Use `PdfExternalSigning.preparePdf` para adicionar o campo de assinatura, reservar espaço e calcular o hash Base64 para enviar ao Gov.br. Você pode customizar a aparência visual usando `drawAppearance`.

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

### 2) Chamar o Gov.br e injetar o PKCS#7

Use `GovBrSignatureApi` para obter o certificado e assinar o hash; depois, embuta os bytes PKCS#7 no PDF preparado.

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

### 3) OAuth (login Gov.br)

`GovBrOAuthClient` oferece helpers para montar a URL de autorização e trocar o token usando os endpoints CAS do Gov.br. Use-o no seu controller backend para conduzir o fluxo OAuth.

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

### Integração com seu controller atual

Mapeie seu fluxo atual para os helpers:

- `start`: chame `PdfExternalSigning.preparePdf` e envie `hashBase64` ao Gov.br.
- `assinar`: receba os bytes `pkcs7` do Gov.br e chame `PdfExternalSigning.embedSignature`.
- Mantenha sua lógica atual de DocMDP e layout visual; se quiser, substitua sua lógica customizada de placeholder por `drawAppearance`.

### Script de demo

Este repo inclui uma demo que gera uma cadeia de certificados, assina um PDF com OpenSSL, instala os certs no Windows e abre o PDF no Foxit:

```bash
dart run scripts/govbr_pdf_sign_demo.dart
```

Você pode definir `FOXIT_PATH` para apontar para uma instalação customizada do Foxit.

### Flags do parser interno

Quando você precisar evitar varredura por regex, habilite as flags do parser interno:

```dart
PdfExternalSigning.useInternalByteRangeParser = true;
PdfExternalSigning.useInternalContentsParser = true;
```

## Assinatura externa sem helpers (baixo nível)

Se você preferir não usar `PdfExternalSigning`, é possível implementar o mesmo fluxo com APIs de baixo nível. Os passos são:

1) Carregar o PDF e adicionar um `PdfSignatureField`.
2) Anexar um `PdfSignature` com `addExternalSigner` (placeholder).
3) Salvar o PDF para criar `/ByteRange` e `/Contents`.
4) Extrair o ByteRange, calcular o hash SHA-256 em Base64 e enviar ao Gov.br.
5) Injetar o PKCS#7 retornado dentro de `/Contents`.

Exemplo mínimo:

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

Esse fluxo de baixo nível espelha o comportamento dos helpers, mas mantém controle total na sua aplicação.



