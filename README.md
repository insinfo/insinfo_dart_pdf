# dart_pdf

Biblioteca escrita nativamente em Dart para criar, ler, editar estruturalmente
e proteger arquivos PDF. Não depende de Flutter nem de binários externos.

## Instalação

```yaml
dependencies:
  dart_pdf:
    git:
      url: https://github.com/insinfo/insinfo_dart_pdf
```

Um único import dá acesso a toda a API pública:

```dart
import 'package:dart_pdf/pdf.dart';
```

## Uso rápido

Criar um documento:

```dart
final PdfDocument document = PdfDocument();
document.pages.add().graphics.drawString(
  'Olá, mundo',
  PdfStandardFont(PdfFontFamily.helvetica, 24),
  brush: PdfBrushes.black,
  bounds: const Rect.fromLTWH(40, 40, 400, 40),
);
final List<int> bytes = document.saveSync();
document.dispose();
```

Extrair texto de um documento existente:

```dart
final PdfDocument document = PdfDocument(inputBytes: bytes);
final String texto = PdfTextExtractor(document).extractText();
document.dispose();
```

Mesclar documentos:

```dart
final List<int> merged = PdfDocument.mergeSync(<List<int>>[a, b, c]);
```

Carimbar uma página já existente sem reescrever o conteúdo dela:

```dart
final PdfDocument document = PdfDocument(inputBytes: bytes);
document.pages[0].appendGraphics().drawString(
  'CONFIDENCIAL',
  PdfStandardFont(PdfFontFamily.helvetica, 32),
  brush: PdfBrushes.red,
  bounds: const Rect.fromLTWH(100, 200, 300, 50),
);
final List<int> saida = document.saveSync();
document.dispose();
```

## Edição de PDFs existentes

A biblioteca abre um PDF, altera a estrutura dele e salva uma revisão nova.
O que ela ainda **não** faz é editar o conteúdo que já está desenhado nos
streams das páginas: substituir um trecho de texto, trocar uma imagem já
posicionada ou fazer redação segura. Cobrir algo com um retângulo esconde,
não remove.

A matriz abaixo é o estado atual, operação por operação.

| Operação | Situação atual | Observação |
|---|---|---|
| Abrir, modificar e salvar PDF existente | Suportada | O salvamento incremental já existe para documentos carregados. |
| Adicionar conteúdo sobre uma página | Suportada | `PdfPage.appendGraphics()` desenha em um stream próprio, isolado do estado gráfico que a página deixou aberto; `PdfPage.graphics` e as layers continuam disponíveis. |
| Inserir e remover páginas | Suportada | `PdfPageCollection.insert`, `remove` e `removeAt`. |
| Rotacionar página existente | Suportada | `PdfPage.rotation`. |
| Mesclar/importar páginas | Suportada | Há modo preservado e achatado, com tratamento de recursos, formulários e anotações. |
| Editar formulários | Suportada | Texto, checkbox, lista, combo e rádio expõem setters, e o valor sobrevive ao round-trip. |
| Adicionar/remover/achatar anotações | Suportada | A coleção expõe `add`, `remove` e `flattenAllAnnotations`. |
| Alterar metadados | Suportada | Título, autor, assunto, palavras-chave, criador e produtor têm setters. |
| Localizar/extrair texto | Suportada | Há texto, linhas, palavras, glifos, limites e `findText`. |
| Substituir texto existente | Não suportada | Não existe vínculo público entre o texto extraído e os tokens/bytes do stream. |
| Remover texto existente | Não suportada | Cobrir com um retângulo só oculta visualmente e não remove os dados. |
| Trocar/remover imagem existente | Não suportada | Falta inventário editável de `Do`, imagens inline, máscaras e XObjects aninhados. |
| Editar paths/vetores existentes | Não suportada | O parser reconhece operadores, mas não há modelo público mutável nem serializador lossless. |
| Redação segura | Não suportada | Exige remover dados e revisões antigas; não pode usar salvamento incremental. |
| Refluxo de parágrafos como em Word | Fora do modelo atual | PDF é uma lista de operações gráficas, não um formato semântico de parágrafos. |

Cada operação marcada como suportada tem teste que salva, reabre e verifica o
resultado, usando somente `package:dart_pdf/pdf.dart`: veja
`test/pdf_document/loaded_document_round_trip_test.dart`.

### Efeito sobre assinaturas existentes

Uma assinatura digital cobre um intervalo de bytes do arquivo. Qualquer coisa
que a biblioteca faça em um documento já assinado se enquadra em um destes
casos:

- **Salvamento incremental** — o padrão para documentos carregados, e o modo
  forçado quando o documento tem assinaturas. A revisão assinada continua no
  arquivo, byte a byte, e a assinatura permanece criptograficamente válida
  **para aquela revisão**. O leitor mostra o documento como assinado e
  alterado depois da assinatura, e cabe à política do leitor e ao `DocMDP`
  dizer se a alteração era permitida. Preencher formulário e anotar costumam
  ser permitidos; montar páginas e alterar conteúdo, não.

- **Regravação completa** (`document.fileStructure.incrementalUpdate = false`,
  e também o reparo de um arquivo danificado) — o histórico é descartado e as
  assinaturas anteriores deixam de existir ou deixam de validar. Não há como
  remover dados de um PDF assinado preservando a assinatura: as duas coisas
  são incompatíveis por construção.

Achatar anotações ou campos de formulário reescreve o conteúdo da página e
tem o mesmo efeito de uma alteração de conteúdo, mesmo quando salvo de forma
incremental.

Se a intenção é assinar, assine por último: monte, carimbe e preencha o
documento antes, e deixe a assinatura como a última revisão gravada.
