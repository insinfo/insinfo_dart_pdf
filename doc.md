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

<a id="create-a-pdf-document-from-simple-text"></a>

### Criar um documento PDF com texto simples

Adicione o código abaixo para criar um documento PDF simples.

```dart

final PdfDocument document = PdfDocument();

document.pages.add().graphics.drawString(
    'Hello World!', PdfStandardFont(PdfFontFamily.helvetica, 12),
    brush: PdfSolidBrush(PdfColor(0, 0, 0)),
    bounds: const Rect.fromLTWH(0, 0, 150, 20));

File('HelloWorld.pdf').writeAsBytes(await document.save());

document.dispose();
```

<a id="add-text-using-truetype-fonts"></a>

### Adicionar texto usando fontes TrueType

Use o código abaixo para adicionar texto Unicode ao documento PDF.

```dart

final PdfDocument document = PdfDocument();

final Uint8List fontData = File('arial.ttf').readAsBytesSync();

final PdfFont font = PdfTrueTypeFont(fontData, 12);

document.pages.add().graphics.drawString('Hello World!!!', font,
    bounds: const Rect.fromLTWH(0, 0, 200, 50));

File('TrueType.pdf').writeAsBytes(await document.save());

document.dispose();
```

<a id="add-images-to-a-pdf-document"></a>

### Adicionar imagens a um documento PDF

A classe `PdfBitmap` é usada para desenhar imagens em um documento PDF. O Insinfo<sup>&reg;</sup> Flutter PDF suporta imagens PNG e JPEG. Veja o código abaixo para desenhar imagens em um PDF.

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

<a id="pdf-document-with-flow-layout"></a>

### Documento PDF com layout fluido (flow)

Adicione o código abaixo para criar um documento PDF com layout fluido (flow).

```dart
const String paragraphText =
  'O Portable Document Format (PDF) é um padrão de fato para a representação precisa, '
  'confiável e independente de plataforma de documentos paginados. Ele é um dos formatos '
  'mais aceitos para layouts fiéis ao pixel. Além disso, o PDF oferece suporte a interação '
  'do usuário e fluxos colaborativos que não são possíveis em documentos impressos.';

// Cria um novo documento PDF.
final PdfDocument document = PdfDocument();
// Adiciona uma nova página ao documento.
final PdfPage page = document.pages.add();
// Cria um elemento de texto PDF e desenha o texto em layout fluido.
final PdfLayoutResult layoutResult = PdfTextElement(
        text: paragraphText,
        font: PdfStandardFont(PdfFontFamily.helvetica, 12),
        brush: PdfSolidBrush(PdfColor(0, 0, 0)))
    .draw(
        page: page,
        bounds: Rect.fromLTWH(
            0, 0, page.getClientSize().width, page.getClientSize().height),
        format: PdfLayoutFormat(layoutType: PdfLayoutType.paginate))!;
// Desenha o próximo parágrafo/conteúdo.
page.graphics.drawLine(
    PdfPen(PdfColor(255, 0, 0)),
    Offset(0, layoutResult.bounds.bottom + 10),
    Offset(page.getClientSize().width, layoutResult.bounds.bottom + 10));
// Salva o documento.
File('TextFlow.pdf').writeAsBytes(await document.save());
// Libera o documento.
document.dispose();
```

<a id="add-bullets-and-lists"></a>

### Adicionar bullets e listas

Adicione o código abaixo para criar bullets e listas em um documento PDF.

```dart
// Cria um novo documento PDF.
final PdfDocument document = PdfDocument();
// Adiciona uma nova página ao documento.
final PdfPage page = document.pages.add();
// Cria uma lista ordenada.
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
// Cria uma lista não ordenada e adiciona como sublista.
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
// Desenha a lista na página PDF.
orderedList.draw(
    page: page,
    bounds: Rect.fromLTWH(
        0, 0, page.getClientSize().width, page.getClientSize().height));
// Salva o documento.
File('BulletandList.pdf').writeAsBytes(await document.save());
// Libera o documento.
document.dispose();
```

<a id="add-tables"></a>

### Adicionar tabelas

Adicione o código abaixo para criar uma tabela em PDF.

```dart
// Cria um novo documento PDF.
final PdfDocument document = PdfDocument();
// Adiciona uma nova página ao documento.
final PdfPage page = document.pages.add();
// Cria um grid PDF para adicionar tabelas.
final PdfGrid grid = PdfGrid();
// Define o número de colunas do grid.
grid.columns.add(count: 3);
// Adiciona uma linha de cabeçalho.
final PdfGridRow headerRow = grid.headers.add(1)[0];
headerRow.cells[0].value = 'Customer ID';
headerRow.cells[1].value = 'Contact Name';
headerRow.cells[2].value = 'Country';
// Define a fonte do cabeçalho.
headerRow.style.font =
    PdfStandardFont(PdfFontFamily.helvetica, 10, style: PdfFontStyle.bold);
// Adiciona linhas ao grid.
PdfGridRow row = grid.rows.add();
row.cells[0].value = 'ALFKI';
row.cells[1].value = 'Maria Anders';
row.cells[2].value = 'Germany';
// Adiciona a próxima linha.
row = grid.rows.add();
row.cells[0].value = 'ANATR';
row.cells[1].value = 'Ana Trujillo';
row.cells[2].value = 'Mexico';
// Adiciona a próxima linha.
row = grid.rows.add();
row.cells[0].value = 'ANTON';
row.cells[1].value = 'Antonio Mereno';
row.cells[2].value = 'Mexico';
// Ajusta o formato do grid.
grid.style.cellPadding = PdfPaddings(left: 5, top: 5);
// Desenha a tabela na página PDF.
grid.draw(
    page: page,
    bounds: Rect.fromLTWH(
        0, 0, page.getClientSize().width, page.getClientSize().height));
// Salva o documento.
File('PDFTable.pdf').writeAsBytes(await document.save());
// Libera o documento.
document.dispose();
```

<a id="add-headers-and-footers"></a>

### Adicionar cabeçalhos e rodapés

Use o código abaixo para adicionar cabeçalho e rodapé a um documento PDF.

```dart
// Cria um novo documento PDF.
final PdfDocument document = PdfDocument();
// Cria um template de página e adiciona o conteúdo do cabeçalho.
final PdfPageTemplateElement headerTemplate =
    PdfPageTemplateElement(const Rect.fromLTWH(0, 0, 515, 50));
// Desenha texto no cabeçalho.
headerTemplate.graphics.drawString(
  'Este é o cabeçalho da página', PdfStandardFont(PdfFontFamily.helvetica, 12),
    bounds: const Rect.fromLTWH(0, 15, 200, 20));
// Adiciona o elemento de cabeçalho ao documento.
document.template.top = headerTemplate;
// Cria um template de página e adiciona o conteúdo do rodapé.
final PdfPageTemplateElement footerTemplate =
    PdfPageTemplateElement(const Rect.fromLTWH(0, 0, 515, 50));
// Desenha texto no rodapé.
footerTemplate.graphics.drawString(
  'Este é o rodapé da página', PdfStandardFont(PdfFontFamily.helvetica, 12),
    bounds: const Rect.fromLTWH(0, 15, 200, 20));
// Define o rodapé no documento.
document.template.bottom = footerTemplate;
// Agora cria páginas.
document.pages.add();
document.pages.add();
// Salva o documento.
File('HeaderandFooter.pdf').writeAsBytes(await document.save());
// Libera o documento.
document.dispose();
```

<a id="load-and-modify-an-existing-pdf-document"></a>

### Carregar e modificar um documento PDF existente

Adicione o código abaixo para carregar e modificar um documento PDF existente.

```dart
// Carrega o documento PDF existente.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());
// Obtém a página existente.
final PdfPage page = document.pages[0];
// Desenha texto na página do PDF.
page.graphics.drawString(
    'Hello World!', PdfStandardFont(PdfFontFamily.helvetica, 12),
    brush: PdfSolidBrush(PdfColor(0, 0, 0)),
    bounds: const Rect.fromLTWH(0, 0, 150, 20));
// Salva o documento.
File('output.pdf').writeAsBytes(await document.save());
// Libera o documento.
document.dispose();
```

Adicione o código abaixo para adicionar ou remover uma página de um documento PDF existente.

```dart
// Carrega o documento PDF existente.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());
// Remove a página do documento.
document.pages.removeAt(0);
// Adiciona uma nova página e desenha texto.
document.pages.add().graphics.drawString(
    'Hello World!', PdfStandardFont(PdfFontFamily.helvetica, 12),
    brush: PdfSolidBrush(PdfColor(0, 0, 0)),
    bounds: const Rect.fromLTWH(0, 0, 150, 20));
// Salva o documento.
File('output.pdf').writeAsBytes(await document.save());
// Libera o documento.
document.dispose();
```

<a id="create-and-load-annotations"></a>

### Criar e carregar anotações

Com este pacote, é possível criar e carregar anotações em um documento PDF novo ou existente.

Adicione o código abaixo para criar uma nova anotação em um PDF.

```dart
// Carrega o documento PDF existente.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());
// Cria uma anotação retangular e adiciona à página do PDF.
document.pages[0].annotations.add(PdfRectangleAnnotation(
      Rect.fromLTWH(0, 0, 150, 100), 'Rectangle',
      color: PdfColor(255, 0, 0), setAppearance: true));
// Salva o documento.
File('annotations.pdf').writeAsBytes(await document.save());
// Libera o documento.
document.dispose();
```

Adicione o código abaixo para carregar a anotação e modificá-la.

```dart
// Carrega e modifica a anotação existente.
final PdfRectangleAnnotation rectangleAnnotation =
    document.pages[0].annotations[0] as PdfRectangleAnnotation;
// Altera o texto da anotação.
rectangleAnnotation.text = 'Changed';
```



<a id="add-bookmarks"></a>

### Adicionar bookmarks

Adicione o código abaixo para criar bookmarks em um documento PDF.

```dart
// Carrega o documento PDF existente.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());
// Cria um bookmark no documento.
final PdfBookmark bookmark = document.bookmarks.add('Página 1');
// Define a página de destino e a posição.
bookmark.destination = PdfDestination(document.pages[1], Offset(20, 20));
// Define a cor do bookmark.
bookmark.color = PdfColor(255, 0, 0);
// Salva o documento.
File('bookmark.pdf').writeAsBytes(await document.save());
// Libera o documento.
document.dispose();
```



<a id="extract-text"></a>

### Extrair texto

Com este pacote, é possível extrair texto de um documento PDF existente, junto com suas coordenadas (bounds).

Adicione o código abaixo para extrair texto de um documento PDF.

```dart
// Carrega um documento PDF existente.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());
// Extrai texto de todas as páginas.
String text = PdfTextExtractor(document).extractText();
// Libera o documento.
document.dispose();
```

O exemplo abaixo mostra como extrair texto de uma página específica.

```dart
// Carrega um documento PDF existente.
PdfDocument document =
   PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());
// Extrai o texto da página 1.
String text = PdfTextExtractor(document).extractText(startPageIndex: 0);
// Libera o documento.
document.dispose();
```



<a id="find-text"></a>

### Buscar texto

Com este pacote, é possível buscar texto em um documento PDF existente, junto com coordenadas (bounds) e índice da página.

Adicione o código abaixo para buscar texto em um documento PDF.

```dart
// Carrega um documento PDF existente.
PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());
// Busca o texto e obtém os itens correspondentes.
List<MatchedItem> textCollection =
    PdfTextExtractor(document).findText(['text1', 'text2']); 
// Obtém o item correspondente na coleção usando o índice.
MatchedItem matchedText = textCollection[0];
// Obtém as coordenadas (bounds) do texto.
Rect textBounds = matchedText.bounds;  
// Obtém o índice da página.
int pageIndex = matchedText.pageIndex; 
// Obtém o texto.
String text = matchedText.text;
// Libera o documento.
document.dispose();
```



<a id="encryption-and-decryption"></a>

### Criptografia e descriptografia

Criptografe documentos PDF novos ou existentes com padrões como RC4 40-bit, RC4 128-bit, AES 128-bit e AES 256-bit, incluindo AES 256-bit Revision 6 (PDF 2.0), para proteger documentos contra acesso não autorizado. Com este pacote, você também pode descriptografar documentos já criptografados.

Adicione o código abaixo para criptografar um documento PDF existente.

```dart
// Carrega o documento PDF existente.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());

// Adiciona segurança ao documento.
final PdfSecurity security = document.security;

// Define senhas.
security.userPassword = 'userpassword@123';
security.ownerPassword = 'ownerpassword@123';

// Define o algoritmo de criptografia.
security.algorithm = PdfEncryptionAlgorithm.aesx256Bit;

// Salva o documento.
File('secured.pdf').writeAsBytes(await document.save());

// Libera o documento.
document.dispose();
```



<a id="pdf-conformance"></a>

### Conformidade PDF

Com este pacote, é possível criar documentos PDF em conformidade com padrões como:

* PDF/A-1B
* PDF/A-2B
* PDF/A-3B

Adicione o código abaixo para criar um documento PDF em conformidade.

```dart
// Cria um documento PDF em conformidade.
final PdfDocument document = PdfDocument(conformanceLevel: PdfConformanceLevel.a1b)
  ..pages.add().graphics.drawString('Hello World',
      PdfTrueTypeFont(File('Roboto-Regular.ttf').readAsBytesSync(), 12),
      bounds: Rect.fromLTWH(20, 20, 200, 50), brush: PdfBrushes.black);
// Salva e libera o documento.
File('conformance.pdf').writeAsBytesSync(await document.save());
document.dispose();
```



<a id="pdf-form"></a>

### Formulários PDF

Formulários PDF são uma forma prática de coletar informações de usuários. Com este pacote, é possível criar, modificar, preencher e “achatar” (flatten) formulários PDF.

Adicione o código abaixo para criar um formulário PDF.

```dart
// Cria um novo documento PDF.
PdfDocument document = PdfDocument();

// Cria uma nova página para adicionar campos.
PdfPage page = document.pages.add();

// Cria um campo de texto e adiciona ao formulário.
document.form.fields.add(PdfTextBoxField(
    page, 'firstname', Rect.fromLTWH(0, 0, 100, 20),
    text: 'John'));

// Cria um checkbox e adiciona ao formulário.
document.form.fields.add(PdfCheckBoxField(
    page, 'checkbox', Rect.fromLTWH(150, 0, 30, 30),
    isChecked: true));

// Salva e libera o documento.
File('form.pdf').writeAsBytesSync(await document.save());
document.dispose();
```

Adicione o código abaixo para preencher um formulário PDF existente.

```dart
// Carrega o documento PDF existente.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());

// Obtém o formulário.
PdfForm form = document.form;

// Obtém o campo de texto e preenche o valor.
PdfTextBoxField name = document.form.fields[0] as PdfTextBoxField;
name.text = 'John';

// Obtém o radio button e seleciona.
PdfRadioButtonListField gender = form.fields[1] as PdfRadioButtonListField;
gender.selectedIndex = 1;

// Salva e libera o documento.
File('output.pdf').writeAsBytesSync(await document.save());
document.dispose();
```

Adicione o código abaixo para achatar (flatten) um formulário existente.

```dart
// Carrega o documento PDF existente.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());

// Obtém o formulário.
PdfForm form = document.form;

// Achata todos os campos do formulário.
form.flattenAllFields();

// Salva e libera o documento.
File('output.pdf').writeAsBytesSync(await document.save());
document.dispose();
```



### Assinatura digital

A assinatura digital em PDF é uma forma robusta de proteger seus documentos contra adulteração. Com este pacote, é possível assinar um PDF usando certificados X.509 (arquivo .pfx contendo a chave privada).

Use o exemplo abaixo para assinar um PDF novo.

```dart
// Cria um novo documento PDF.
PdfDocument document = PdfDocument();

// Adiciona uma nova página PDF.
PdfPage page = document.pages.add();

// Cria o campo de assinatura.
PdfSignatureField signatureField = PdfSignatureField(page, 'Signature',
    bounds: Rect.fromLTWH(0, 0, 200, 50),
    signature: PdfSignature(
       certificate:
          PdfCertificate(File('certificate.pfx').readAsBytesSync(), 'password@123')
    ));
  
// Adiciona o campo de assinatura ao documento.
document.form.fields.add(signatureField);

// Salva e libera o documento PDF
File('signed.pdf').writeAsBytes(await document.save());
document.dispose();
```
Use o exemplo abaixo para assinar um PDF existente.

```dart
// Carrega o documento PDF existente.
final PdfDocument document =
    PdfDocument(inputBytes: File('input.pdf').readAsBytesSync());

// Obtém o campo de assinatura.
PdfSignatureField signatureField =
    document.form.fields[0] as PdfSignatureField;

// Configura a assinatura no campo e assina.
signatureField.signature = PdfSignature(
  certificate:
      PdfCertificate(File('certificate.pfx').readAsBytesSync(), 'password@123'),
);

// Salva e libera o documento.
File('output.pdf').writeAsBytesSync(await document.save());
document.dispose();
```

## Novas APIs de Assinatura e PKI

### Parsing de Certificados (X509Utils)

Para manipular certificados PEM sem depender de bibliotecas externas:

```dart
import 'package:dart_pdf/pdf.dart';

// Parsing
final cert = X509Utils.parsePemCertificate(pemString);
print(cert.subject); // "CN=..., O=..."
```

### Geração de Chaves e CSR (X509GeneratorUtils)

Utilitários para geração de chaves RSA e solicitações de assinatura de certificado (CSR):

```dart
// Generation
final pair = X509GeneratorUtils.generateRsaKeyPair();
final csr = X509GeneratorUtils.generateRsaCsrPem(
  {'CN': 'My User', 'O': 'My Org'}, 
  pair.privateKey, 
  pair.publicKey
);
```

### Assinatura com PdfSigningSession

A classe `PdfSigningSession` simplifica o fluxo de assinatura ("Prepare" -> "Digest" -> "Sign" -> "Embed"), eliminando boilerplate.

Exemplo usando `PdfLocalSigner` (chaves locais PEM):

```dart
final signer = PdfLocalSigner(
  privateKeyPem: myPrivateKeyPem,
  certificatePem: myCertificatePem,
);

final signedBytes = await PdfSigningSession.signPdf(
  pdfBytes: myPdfBytes,
  signer: signer,
  pageNumber: 1,
  bounds: Rect.fromLTWH(50, 50, 200, 50),
  fieldName: 'Signature1',
  signature: PdfSignature(reason: 'Teste', locationInfo: 'BR'),
);
```

Para assinaturas externas (Gov.br, HSM), basta implementar `IPdfSigner`:

```dart
class MyRemoteSigner implements IPdfSigner {
  @override
  Future<Uint8List> signDigest(Uint8List digest) async {
    // Chame sua API remota aqui enviando o digest
    // Retorne a assinatura PKCS#7 (DER)
    return myRemoteApi.sign(digest);
  }
}
```

### Utilitário ByteRange

Para fluxos manuais de baixo nível, o cálculo do hash do ByteRange agora é exposto:

```dart
final hashBytes = PdfExternalSigning.computeByteRangeDigest(pdfBytes, byteRange);
```

## Validação de assinaturas (PAdES / server-side)

### Testes com Certificados de Desenvolvimento

Para testar assinaturas digitais em ambiente de desenvolvimento, a biblioteca inclui ferramentas para gerar uma cadeia de certificados de teste completa (4 níveis) no estilo ICP-Brasil:

```
Root CA (Autoridade Certificadora Raiz)
 └── AC Intermediária
      └── AC Final
           └── Certificado do Usuário (Assinante)
```

#### Gerando a cadeia de certificados de teste

Execute o teste para gerar os certificados:

```bash
dart test test/pki_simulation/expanded_scenarios_test.dart --name "Scenario 1"
```

Isso gera os seguintes arquivos em `test/tmp/`:

| Arquivo | Descrição |
|---------|-----------|
| `Cadeia_Test-der.p7b` | Cadeia completa em formato PKCS#7 |
| `AC_Raiz_Test.pem` / `.cer` | Certificado Root CA |
| `AC_Intermediaria_Test.pem` | Certificado AC Intermediária |
| `AC_Final_Test.pem` | Certificado AC Final |
| `Cert_Usuario_Isaque.pem` | Certificado do usuário (assinante) |
| `out_scenario1_govbr_chain.pdf` | PDF assinado com a cadeia de 4 níveis |

#### Instalando certificados de teste no Windows

**⚠️ IMPORTANTE:** Sempre remova certificados de teste antigos antes de instalar novos! Certificados com o mesmo DN (Distinguished Name) mas chaves diferentes causam erros de validação como "Este certificado tem uma assinatura digital inválida".

```powershell
# Instalar certificados (remove automaticamente versões antigas)
.\scripts\install_test_chain_windows.ps1

# Instalar no store da máquina (requer admin)
.\scripts\install_test_chain_windows.ps1 -Machine

# Remover certificados de teste manualmente
.\scripts\install_test_chain_windows.ps1 -Remove

# Instalar sem limpar antigos (NÃO RECOMENDADO)
.\scripts\install_test_chain_windows.ps1 -SkipCleanup
```

O script:
1. **Remove automaticamente** certificados de teste antigos do Windows Certificate Store
2. Instala o Root CA em "Autoridades de Certificação Raiz Confiáveis"
3. Instala certificados intermediários em "Autoridades de Certificação Intermediárias"

#### Configurando o Foxit Reader / Adobe Reader

Após instalar os certificados no Windows, configure o visualizador:

**Foxit Reader:**
1. Vá em **Arquivo** → **Preferências** → **Trust Manager**
2. Habilite **"Usar certificados confiáveis do Windows"**
3. Ou importe manualmente `AC_Raiz_Test.cer` em **Proteger** → **Identidades Confiáveis**

**Adobe Reader:**
1. Vá em **Editar** → **Preferências** → **Assinaturas**
2. Em **Identidades e Certificados Confiáveis** → **Mais...**
3. Importe `AC_Raiz_Test.cer` como certificado confiável

#### Estrutura dos certificados gerados

Os certificados incluem as extensões necessárias para validação correta:

- **Subject Key Identifier (SKI)**: Identifica a chave pública do certificado
- **Authority Key Identifier (AKI)**: Aponta para o SKI do emissor (exceto Root CA)
- **Basic Constraints**: `CA:TRUE` para CAs, `CA:FALSE` para usuários
- **Key Usage**: `Certificate Sign, CRL Sign` para CAs

**RFC 5280 Compliance:** O Root CA (auto-assinado) **não** inclui AKI, conforme especificação.

#### Verificação com OpenSSL

```bash
# Verificar cadeia completa
openssl verify -CAfile test/tmp/AC_Raiz_Test.pem \
  -untrusted test/tmp/AC_Intermediaria_Test.pem \
  -untrusted test/tmp/AC_Final_Test.pem \
  test/tmp/Cert_Usuario_Isaque.pem

# Ver detalhes de um certificado
openssl x509 -in test/tmp/Cert_Usuario_Isaque.pem -text -noout

# Verificar extensões SKI/AKI
openssl x509 -in test/tmp/Cert_Usuario_Isaque.pem -noout -text | grep -A1 "Key Identifier"
```

---

Este repositório inclui um helper de validação server-side que consegue inspecionar **todas** as assinaturas de um PDF e reportar:

- Validade da assinatura CMS
- Conferência do digest do ByteRange
- Integridade do documento (`documentIntact`)
- Confiança de cadeia (quando roots confiáveis são fornecidas)
- Status de revogação (best-effort ou estrito)
- Status de policy (quando `SignaturePolicyId` está presente e `Lpa` foi fornecido)
- Status de timestamp (RFC 3161, quando presente)
- Issues agregadas (warnings/errors) em `PdfSignatureValidationItem.issues`

### Novidades de API (assinatura/validação)

Foram expostos na API pública campos que antes só estavam nos tipos internos de validação. Isso facilita gerar relatórios consistentes com Acrobat/Validar.gov.br:

- **Data/hora da assinatura** em `PdfSignatureValidationResult.signingTime`.
  - Fonte principal: `CMS signedAttributes / id-signingTime`.
  - Fallback: campo `/M` do dicionário de assinatura quando o CMS não traz `signingTime`.
- **Validade do certificado do signatário** em `PdfSignerInfo.certNotBefore` e `PdfSignerInfo.certNotAfter`.
- **Informações do certificado** em `PdfSignerInfo` (subject, issuer, serial hex/dec, `commonName`, `issuerCommonName`).
- **Resultado de policy**:
  - `PdfSignatureValidationResult.policyPresent`
  - `PdfSignatureValidationResult.policyDigestOk` (quando há LPA/SignaturePolicyId)
  - `PdfSignatureValidationResult.policyOid`
- **Integridade/autenticidade do PDF** (já público): `cmsSignatureValid`, `byteRangeDigestOk`, `documentIntact`.
- **Cadeia validada por assinatura** (já público): `PdfSignatureValidationItem.chainTrusted`.

#### Script utilitário de extração

O script [scripts/extract_pdf_signature_info.dart](scripts/extract_pdf_signature_info.dart) foi atualizado para imprimir:

- `signing_time`
- validade do certificado (`certificate_not_before`, `certificate_not_after`)
- `policy_present` e `policy_digest_ok`
- `subject`, `issuer`, `certificate_serial_hex`/`certificate_serial_decimal`

Execute:

```bash
dart run scripts/extract_pdf_signature_info.dart test/assets/2\ ass\ leonardo\ e\ mauricio.pdf
```

Nota sobre severidade de timestamp (ICP-Brasil / Gov.br):

- Se o OID de policy indicar ICP-Brasil/Gov.br (`2.16.76.1.7.1.*`) e **não** houver token de timestamp RFC3161, isso é reportado como issue **warning** (`timestamp_missing`) por padrão.
- Se você fornecer o XML da policy via `policyXmlByOid` e esse XML exigir `SignatureTimeStamp`, então a ausência de RFC3161 é reportada como issue **error** (`timestamp_missing`).
- Se existir token de timestamp, mas ele for deterministicamente inválido (ex.: assinatura CMS do token inválida ou message imprint não confere), isso é reportado como issue **error** (`timestamp_invalid`).

### Scripts de teste (ICP-Brasil / policy exige timestamp)

Para evitar dependências de pastas removíveis (ex.: uma pasta local grande de PDFs) e ter um caso de teste determinístico, este repositório inclui um gerador de PDF assinado que:

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

#### Sanitizar comentários `%` (header)

Alguns PDFs podem conter comentários `%...` no início do arquivo com informações de debug/"verbose" do gerador (ex.: `% Verbose ...`, `% Producer ...`). Comentários são permitidos pela sintaxe do PDF, mas você pode querer removê-los para reduzir ruído.

Este repositório expõe um utilitário de baixo nível que **sanitiza somente os comentários `%` do cabeçalho** (antes do primeiro `N N obj`), preservando o tamanho do arquivo e os separadores de linha:

```dart
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';

Uint8List sanitize(Uint8List pdfBytes) {
  final result = sanitizePdfLeadingPercentComments(pdfBytes);
  return result.bytes;
}
```

**Riscos / limitações**

- Se o PDF estiver assinado, qualquer alteração de byte invalida a assinatura (mesmo que seja só comentário).
- O utilitário não remove `%` “estranhos” que aparecem no meio do arquivo (ex.: dentro de streams comprimidos), porque mexer nisso pode corromper o PDF.

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

Se você tiver uma pasta com muitos PDFs e quiser copiar exemplos “bons” para `test/assets`, use (ajuste `--source` para sua pasta local):

```bash
dart run scripts/curate_policy_timestamp_test_pdfs.dart --source test/assets --target test/assets policy-oid 3 1
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

### Metadados do assinante (PdfSignatureInspector)

O helper `PdfSignatureInspector` encapsula a validação e também extrai metadados
do certificado do assinante, retornando `PdfSignerInfo` dentro de cada
`PdfSignatureSummary`.

**Extração ICP-Brasil (SAN / otherName)**

- PF (e-CPF): o OID `2.16.76.1.3.1` carrega um bloco que **começa** com
  **DDMMAAAA + CPF**.
- PJ: o OID `2.16.76.1.3.4` carrega **DDMMAAAA + CPF** do responsável.
- **Importante:** `2.16.76.1.3.5` é **Título de Eleitor**, não data de nascimento.

O mapa `otherNames` guarda os valores crus dos `otherName` encontrados, e o
parser tenta “desembrulhar” `OCTET STRING` e ASN.1 interno quando aplicável.

Uso típico:

```dart
final report = await PdfSignatureInspector().inspect(
  pdfBytes,
  useEmbeddedIcpBrasil: true,
);

for (final s in report.signatures) {
  final signer = s.signer;
  print('CPF: ${signer?.cpf}');
  print('DOB: ${signer?.dateOfBirth}');
}
```

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

- Extração híbrida e otimizada de `/ByteRange` e `/Contents` (FastBytes xref-independente, com fallback para StringSearch e, por último, parser interno)
- Validação CMS/PKCS#7, incluindo sanity checks de signed attributes
- Trust stores embutidas: ICP-Brasil / ITI / Serpro, + provider Gov.br (`GovBrProvider`)
- Construção de cadeia + avaliação de trust (`chainTrusted`) via providers/trust stores
- Revogação: busca OCSP/CRL + opção de validação estrita (assinatura + janela de tempo)
- Policy engine: validação determinística quando LPA e digest de SignaturePolicyId estão disponíveis
- LTV: scaffolding de DSS/VRI + auditoria best-effort de "self-check"
- APIs públicas de validação: validar todas as assinaturas ou um campo de assinatura

Lacunas que ainda podem impactar robustez (dependendo do seu nível de compliance):

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

#### Parser otimizado (recomendado)

Por padrão, a extração de `/ByteRange` e `/Contents` usa uma estratégia **híbrida, correction-first**:

1) **FastBytes**: varredura em nível de bytes (xref-independente; não faz `latin1.decode` do PDF inteiro)
2) **StringSearch**: varredura `latin1 + RegExp` (compatibilidade)
3) **InternalDoc**: parse completo via `PdfDocument` (mais robusto semanticamente, porém bem mais lento)

Você pode controlar isso com as flags estáticas em `PdfExternalSigning`:

```dart
// Recomendado (default): rápido e robusto contra xref quebrado.
PdfExternalSigning.useFastByteRangeParser = true;
PdfExternalSigning.useFastContentsParser = true;
PdfExternalSigning.useInternalByteRangeParser = false;
PdfExternalSigning.useInternalContentsParser = false;

// (Opcional) Forçar o parser interno (InternalDoc) — use só quando necessário.
PdfExternalSigning.useInternalByteRangeParser = true;
PdfExternalSigning.useInternalContentsParser = true;

// (Opcional) Desabilitar FastBytes e usar apenas StringSearch (debug/compatibilidade).
PdfExternalSigning.useInternalByteRangeParser = false;
PdfExternalSigning.useInternalContentsParser = false;
PdfExternalSigning.useFastByteRangeParser = false;
PdfExternalSigning.useFastContentsParser = false;
```

#### Validações (anti falso-positivo)

O modo híbrido valida o resultado antes de aceitar:

- **ByteRange**: checagem de bounds/ordem (`start/len` dentro do arquivo e segunda faixa após a primeira)
- **Contents**: checagem de plausibilidade de hex (`[0-9A-Fa-f]` + whitespace, número par de dígitos e mínimo de tamanho)

Se o FastBytes encontrar algo inconsistente, ele cai automaticamente para StringSearch e só então para InternalDoc.

#### Teste de integração (assets)

Existe um teste que percorre todos os PDFs em `test/assets/**` e valida o comportamento dos parsers (com e sem `/ByteRange`).

```bash
dart test test/security/external_signing_assets_integration_test.dart
```

Esse teste força a estratégia híbrida (FastBytes → StringSearch → InternalDoc) e garante que:

- PDFs com `/ByteRange` sejam parseados sem exceção
- PDFs sem `/ByteRange` lancem `StateError('ByteRange not found')` (erro claro, sem “travamentos”)

#### Benchmark (comparativo)

Para comparar performance entre Regex/String, FastBytes e InternalDoc:

```bash
dart test benchmarks/external_signing_benchmark.dart
```

Em geral, **FastBytes** deve ser ordens de grandeza mais rápido que **InternalDoc**, especialmente em PDFs maiores.

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


## Geração de CRL e OCSP (PKI Low-Level)

A biblioteca oferece utilitários para geração de artefatos PKI (Public Key Infrastructure) inteiramente em Dart, removendo dependências externas como OpenSSL.

### Geração de CRL (Certificate Revocation List)

Gera uma CRL X.509 v2 assinada.

```dart
final crlDer = PkiBuilder.createCRL(
  issuerKeyPair: caKeyPair, // Utils.generateRsaKeyPair() ou carregar PEM
  issuerDn: 'CN=Minha CA, O=Minha Org, C=BR',
  revokedCertificates: [
    RevokedCertificate(
      serialNumber: BigInt.parse('12345'),
      revocationDate: DateTime.now().subtract(Duration(days: 1)),
      reasonCode: 0, // 0=unspecified, 1=keyCompromise, etc.
    ),
  ],
  thisUpdate: DateTime.now(),
  nextUpdate: DateTime.now().add(Duration(days: 7)),
  crlNumber: 1,
);

File('ca.crl').writeAsBytesSync(crlDer);
```

### Geração de Resposta OCSP

Gera uma resposta OCSP assinada (RFC 6960) a partir de um request (DER). Útil para implementar responders OCSP customizados.

```dart
final responseDer = PkiBuilder.createOCSPResponse(
  responderKeyPair: responderKeyPair, // Geralmente a mesma da CA
  issuerKeyPair: caKeyPair,
  requestBytes: requestBytes, // Bytes do OCSP Request recebido
  checkStatus: (serial) {
    // Callback para verificar status do certificado no banco de dados
    if (isRevoked(serial)) {
       return OcspEntryStatus(
         status: 1, // 1=revoked
         revocationTime: getRevocationDate(serial),
         revocationReason: 0,
       );
    }
    return OcspEntryStatus(status: 0); // 0=good
  },
);

// Enviar responseDer de volta ao cliente
```

Essas funções permitem criar Autoridades Certificadoras (CA) e Responders OCSP completos em Dart puro.



