# Roteiro de Implementação — Merge (Mesclagem) de PDFs

> Alvo: `dart_pdf` (`c:\MyDartProjects\insinfo_dart_pdf`)
> **Status: implementado na v31.2.0**, branch `nova`. Ver §9 para o que ficou
> de fora e §10 para o mapa entre o plano e o código entregue.

---

## 0. Resumo executivo

> **Nota de leitura.** As seções 1 a 8 são o plano original, escrito quando a
> biblioteca ainda não tinha merge; ficam aqui porque documentam *por que* cada
> decisão foi tomada. As seções 9 em diante descrevem o que efetivamente foi
> entregue, onde o plano mudou e o que ficou de fora.

Quando este roteiro foi escrito, a biblioteca **não expunha** nenhuma API de
merge (`importPage`, `mergeDocuments`, `appendDocument` — nenhuma existia).

Porém, **a maior parte da infraestrutura necessária já estava no repositório**:
um motor completo de clonagem profunda de objetos PDF entre cross-tables
(`IPdfPrimitive.cloneObject(PdfCrossTable)`), com resolução de referências
circulares e cache de objetos clonados. Ele era usado para importar *recursos*
de páginas carregadas (`PdfTemplate`) e *campos de formulário*
(`PdfFormFieldCollection`), mas estava **deliberadamente bloqueado** para
objetos de página.

Duas entregas:

| Nível | O que é | Fidelidade |
|---|---|---|
| **Nível 1 — `flatten`** | Merge via `PdfTemplate` (achatamento visual) | Só conteúdo gráfico |
| **Nível 2 — `objectImport`** | Import real do grafo de objetos da página | Anotações, links, formulários, bookmarks, camadas, page labels |

**Ambos estão implementados**, com `objectImport` como padrão. A suíte tem 286
testes de merge, incluindo varredura dos 54 PDFs de `test/assets` e comparação
ponta a ponta contra a saída do SEI (§11).

---

## 1. Estado atual da base de código

### 1.1 O que já existe e será reaproveitado

| Recurso | Local | Papel no merge |
|---|---|---|
| `PdfPage.createTemplate()` | [pdf_page.dart:373](../lib/src/pdf/implementation/pages/pdf_page.dart#L373) | Gera XObject Form a partir de página carregada |
| `PdfPageHelper._getContent()` | [pdf_page.dart:1047](../lib/src/pdf/implementation/pages/pdf_page.dart#L1047) | Combina camadas + `/Resources` da página |
| `PdfTemplateHelper.cloneResources()` | [pdf_template.dart:327](../lib/src/pdf/implementation/graphics/figures/pdf_template.dart#L327) | **Já faz import cross-document de recursos** |
| `PdfGraphics._drawTemplate()` | [pdf_graphics.dart:922-966](../lib/src/pdf/implementation/graphics/pdf_graphics.dart#L922-L966) | Detecta template de página carregada e dispara o clone |
| `PdfReferenceHolder.cloneObject()` | [pdf_reference_holder.dart:178](../lib/src/pdf/implementation/primitives/pdf_reference_holder.dart#L178) | Clone profundo + resolução de ciclos |
| `PdfDictionary.cloneObject()` | [pdf_dictionary.dart:591](../lib/src/pdf/implementation/primitives/pdf_dictionary.dart#L591) | Clone de dicionários, com cache por cross-table |
| `PdfStream.cloneObject()` | [pdf_stream.dart:534](../lib/src/pdf/implementation/primitives/pdf_stream.dart#L534) | Clone de streams preservando `dataStream` e `compress` |
| `PdfArray.cloneObject()` | [pdf_array.dart:244](../lib/src/pdf/implementation/primitives/pdf_array.dart#L244) | Clone de arrays |
| `PdfCrossTable.getReference()` | [pdf_cross_table.dart:593](../lib/src/pdf/implementation/io/pdf_cross_table.dart#L593) | Aloca número de objeto no destino |
| `PdfCrossTable.prevReference` | [pdf_cross_table.dart:185](../lib/src/pdf/implementation/io/pdf_cross_table.dart#L185) | Pilha anti-recursão do clone |
| `PdfMainObjectCollection.add()` | [pdf_main_object_collection.dart:59](../lib/src/pdf/implementation/io/pdf_main_object_collection.dart#L59) | Registro global de objetos do documento |
| `PdfPageCollection.insert()` | [pdf_page_collection.dart:144](../lib/src/pdf/implementation/pages/pdf_page_collection.dart#L144) | **Modelo de como enxertar página na árvore `/Pages`** |
| `PdfPageHelper.fromDictionary()` | [pdf_page.dart:504](../lib/src/pdf/implementation/pages/pdf_page.dart#L504) | Constrói `PdfPage` a partir de dicionário existente |
| Import de campos cross-doc | [pdf_form_field_collection.dart:289-300](../lib/src/pdf/implementation/forms/pdf_form_field_collection.dart#L289-L300) | **Precedente exato** do padrão: clonar → religar `/P` → remover `/Parent` |
| `PdfDocumentHelper.getNamedDestination()` | [pdf_document.dart:1577](../lib/src/pdf/implementation/pdf_document/pdf_document.dart#L1577) | Resolve destinos nomeados |

### 1.2 Os bloqueios concretos

**Bloqueio #1 — clone de página é proibido por design.**
Em [pdf_reference_holder.dart:186-196](../lib/src/pdf/implementation/primitives/pdf_reference_holder.dart#L186-L196):

```dart
if (object is PdfDictionary) {
  // Meaning the referenced page is not available for import.
  final PdfName type = PdfName(PdfDictionaryProperties.type);
  final PdfDictionary dict = object! as PdfDictionary;
  if (dict.containsKey(type)) {
    final PdfName? pageName = dict[type] as PdfName?;
    if (pageName != null) {
      if (pageName.name == 'Page') {
        return PdfNull();   // <-- aqui
      }
    }
  }
}
```

Qualquer referência a `/Type /Page` vira `PdfNull` durante o clone. Isso mata:

- o próprio dicionário da página que queremos importar;
- o `/P` (back-reference) das anotações;
- o array de destino `[pageRef /XYZ x y z]` de links internos e bookmarks.

**Bloqueio #2 — chaves nulas são silenciosamente descartadas.**
Em [pdf_dictionary.dart:606](../lib/src/pdf/implementation/primitives/pdf_dictionary.dart#L606):

```dart
if (newObj is! PdfNull) {
  newDict[name] = newObj;
}
```

Combinado com o bloqueio #1, clonar uma anotação de link produz um dicionário
**sem** `/Dest` — o link some sem erro. É necessário um mecanismo de
*pendências* para reinjetar essas chaves ao final do merge.

**Bloqueio #3 — o cache de clone é global por primitivo.**
`clonedObject` / `_clonedObject` são campos de instância chaveados pela
cross-table de destino ([pdf_dictionary.dart:592-598](../lib/src/pdf/implementation/primitives/pdf_dictionary.dart#L592-L598),
[pdf_stream.dart:535](../lib/src/pdf/implementation/primitives/pdf_stream.dart#L535),
[pdf_array.dart:245](../lib/src/pdf/implementation/primitives/pdf_array.dart#L245)).
É bom para deduplicação dentro de um merge, mas exige invalidação explícita
entre sessões de merge para o mesmo par origem/destino.

**Bloqueio #4 — atributos herdados.**
`/Resources`, `/MediaBox`, `/CropBox` e `/Rotate` podem estar em nós ancestrais
`/Pages` na origem. Ao desenxertar a página da árvore original, esses valores
precisam ser **materializados** no dicionário clonado, senão a página importada
perde tamanho/fontes.

**Bloqueio #5 — não há mapeamento origem→destino.**
`crossTable.prevReference` é uma lista linear usada só para cortar recursão;
não é um mapa `refOrigem → objDestino`. Para remapear links e bookmarks é
preciso um contexto de importação explícito.

---

## 2. Estratégia: dois níveis

### 2.1 Nível 1 — `PdfMergeMode.flatten` (funciona hoje)

Protótipo validável imediatamente, sem tocar na lib:

```dart
List<int> mergeFlatten(List<List<int>> inputs) {
  final PdfDocument out = PdfDocument();
  for (final List<int> bytes in inputs) {
    final PdfDocument src = PdfDocument(inputBytes: bytes);
    for (int i = 0; i < src.pages.count; i++) {
      final PdfPage sp = src.pages[i];
      final PdfPage dp = out.pages.insert(
        out.pages.count,
        sp.size,
        PdfMargins()..all = 0,
      );
      dp.graphics.drawPdfTemplate(sp.createTemplate(), Offset.zero, sp.size);
    }
    src.dispose();
  }
  final List<int> result = out.saveSync();
  out.dispose();
  return result;
}
```

Funciona porque `_drawTemplate` já chama `cloneResources(crossTable)` quando
`isLoadedPageTemplate == true`
([pdf_graphics.dart:963-965](../lib/src/pdf/implementation/graphics/pdf_graphics.dart#L963-L965)).

**Perde:** anotações, links, campos de formulário, bookmarks, camadas (OCG),
marcação estrutural, `/PageLabels`, anexos.
**Preserva:** todo o conteúdo gráfico, fontes e imagens.

Vale como modo oficial suportado (rápido, robusto, previsível) e como fallback
quando o import de objetos falhar.

### 2.2 Nível 2 — `PdfMergeMode.objectImport`

Clonar o grafo de objetos da página para a cross-table de destino e enxertar o
dicionário resultante na árvore `/Pages`. É o caminho que preserva estrutura.

---

## 3. API pública

> Entregue como descrito abaixo, com uma diferença: a política de
> assinaturas virou três booleanos independentes em vez de um enum (§8, F8).

Diretório: `lib/src/pdf/implementation/merging/`

```dart
// pdf_merge_options.dart

/// Estratégia de mesclagem.
enum PdfMergeMode {
  /// Importa o grafo de objetos: preserva anotações, links, campos e bookmarks.
  objectImport,

  /// Achata cada página de origem em um XObject Form. Rápido e previsível,
  /// mas descarta tudo que não for conteúdo gráfico.
  flatten,
}

/// Política aplicada quando dois documentos têm campos de formulário homônimos.
enum PdfFieldNameConflictPolicy { renameSuffix, keepFirst, throwError }

// Assinaturas: três booleanos independentes, todos `false` por padrão —
// `rejectSignedSources`, `keepInvalidSignatures`, `removeSignatureAppearance`.
// Ver F8 para a semântica e a precedência.

class PdfMergeOptions {
  PdfMergeOptions({
    this.mode = PdfMergeMode.objectImport,
    this.importAnnotations = true,
    this.importFormFields = true,
    this.fieldNameConflict = PdfFieldNameConflictPolicy.renameSuffix,
    this.importBookmarks = true,
    this.importNamedDestinations = true,
    this.importLayers = true,
    this.importPageLabels = true,
    this.importAttachments = false,
    this.dropStructureTree = true,
    this.copyDocumentInfoFromFirst = false,
    this.rejectSignedSources = false,
    this.keepInvalidSignatures = false,
    this.removeSignatureAppearance = false,
    this.deduplicateResources = true,
  });
  // ... campos
}

class PdfMergeException implements Exception { /* ... */ }
```

```dart
// pdf_document_merger.dart

/// Mescla documentos PDF em um documento de destino.
class PdfDocumentMerger {
  PdfDocumentMerger(PdfDocument destination, {PdfMergeOptions? options});

  /// Importa uma única página.
  PdfPage importPage(PdfDocument source, int pageIndex);

  /// Importa um intervalo `[start, end]` (inclusive).
  List<PdfPage> importPageRange(PdfDocument source, int start, int end);

  /// Importa todas as páginas de [source].
  List<PdfPage> append(PdfDocument source);

  /// Resolve pendências (destinos de links, bookmarks, AcroForm).
  /// Chamado automaticamente por `PdfDocument.save*`, mas exposto para
  /// quem quiser inspecionar o resultado antes de salvar.
  void finish();

  /// Avisos não fatais acumulados (ex.: link removido por apontar para
  /// página não importada).
  List<String> get warnings;
}
```

Atalhos em `PdfDocument` (`pdf_document.dart`), seguindo o padrão
síncrono/assíncrono já existente em `save()`/`saveSync()`:

```dart
PdfPage importPage(PdfDocument source, int pageIndex, {PdfMergeOptions? options});
List<PdfPage> importPageRange(PdfDocument source, int start, int end, {PdfMergeOptions? options});
List<PdfPage> appendDocument(PdfDocument source, {PdfMergeOptions? options});

static List<int> mergeSync(List<List<int>> documents,
    {PdfMergeOptions? options, List<String?>? passwords});
static Future<List<int>> merge(List<List<int>> documents,
    {PdfMergeOptions? options, List<String?>? passwords});
```

---

## 4. Arquitetura interna

```
lib/src/pdf/implementation/merging/
  pdf_merge_options.dart       # enums + PdfMergeOptions + PdfMergeException
  pdf_import_context.dart      # estado de uma sessão de merge
  pdf_object_importer.dart     # clone do grafo com bypass do guard de /Type /Page
  pdf_page_importer.dart       # importação da página (F3)
  pdf_annotation_importer.dart # anotações e links (F4)
  pdf_form_importer.dart       # AcroForm (F5)
  pdf_outline_importer.dart    # bookmarks + destinos nomeados (F6)
  pdf_catalog_merger.dart      # OCProperties, PageLabels, Info, XMP (F7)
  pdf_document_merger.dart     # fachada pública
```

### `PdfImportContext`

```dart
class PdfImportContext {
  PdfImportContext(this.destination, this.options);

  final PdfDocument destination;
  final PdfMergeOptions options;

  PdfCrossTable get destinationCrossTable =>
      PdfDocumentHelper.getHelper(destination).crossTable;

  /// Documento de origem da importação em andamento.
  PdfDocument? source;

  /// Dicionário de página na ORIGEM -> página criada no DESTINO.
  final Map<PdfDictionary, PdfPage> pageMap = <PdfDictionary, PdfPage>{};

  /// Chaves que viraram PdfNull durante o clone e precisam ser reinjetadas.
  final List<PendingReference> pending = <PendingReference>[];

  /// Renomeações de campos de formulário: nome original -> nome final.
  final Map<String, String> renamedFields = <String, String>{};

  /// Renomeações de destinos nomeados.
  final Map<String, String> renamedDestinations = <String, String>{};

  /// Habilita o bypass do guard de /Type /Page em PdfReferenceHolder.
  bool allowPageClone = false;

  final List<String> warnings = <String>[];
}

class PendingReference {
  PendingReference(
    this.owner,
    this.key,
    this.sourcePageDictionary, {
    this.destinationArrayTail,
  });

  /// Dicionário já criado no DESTINO que perdeu a chave.
  final PdfDictionary owner;

  /// Nome da chave perdida: 'Dest', 'P', 'D', ...
  final String key;

  /// Página na ORIGEM para a qual a chave apontava.
  final PdfDictionary sourcePageDictionary;

  /// Restante do array de destino (`/XYZ x y z`), já clonado.
  final List<IPdfPrimitive>? destinationArrayTail;
}
```

### Ponto de extensão em `PdfCrossTable`

Adicionar campo interno:

```dart
/// internal field — não nulo apenas durante uma sessão de merge.
PdfImportContext? importContext;
```

E alterar
[pdf_reference_holder.dart:186-196](../lib/src/pdf/implementation/primitives/pdf_reference_holder.dart#L186-L196):

```dart
if (object is PdfDictionary) {
  final PdfDictionary dict = object! as PdfDictionary;
  final PdfName? pageName =
      dict[PdfName(PdfDictionaryProperties.type)] as PdfName?;
  if (pageName != null && pageName.name == 'Page') {
    final PdfImportContext? ctx = crossTable.importContext;
    if (ctx == null || !ctx.allowPageClone) {
      return PdfNull();                    // comportamento atual preservado
    }
    final PdfPage? mapped = ctx.pageMap[dict];
    if (mapped != null) {
      return PdfReferenceHolder(
        PdfPageHelper.getHelper(mapped).dictionary,
      );
    }
    ctx.registerForwardPageReference(dict); // resolvido em finish()
    return PdfNull();
  }
}
```

> **Compatibilidade:** com `importContext == null` — ou seja, para todo o código
> existente — o comportamento é idêntico ao de hoje. Isso é obrigatório: esse
> método é usado por `PdfTemplate`, `PdfFormFieldCollection` e `json_document`.

---

## 5. Fases de implementação

### F0 — Fundação de testes e fixtures — *0,5 dia*

- Criar `test/merging/` e `test/assets/merge/`.
- Gerar fixtures **com a própria lib** (determinísticas, versionáveis):
  - `simples_2p.pdf` — texto com fonte padrão;
  - `ttf_embutida.pdf` — `PdfTrueTypeFont`;
  - `com_imagem.pdf` — JPEG + PNG;
  - `links.pdf` — link interno (pág. 1 → pág. 3) + link URI;
  - `formulario.pdf` — text box, checkbox, combo;
  - `bookmarks.pdf` — outline com 2 níveis;
  - `rotacionado.pdf` — `/Rotate 90` + `CropBox != MediaBox`;
  - `camadas.pdf` — 2 `PdfLayer`.
- Fixtures externas (não geráveis): PDF 1.5 com xref stream + object streams;
  PDF criptografado; PDF assinado (reusar os já existentes em `test/assets/`).
- Helpers: `reopen(List<int>)`, `pageTextOf(doc, i)` (via `PdfTextExtractor`),
  `annotCountOf(doc, i)`.

**Critério de aceite:** `dart test test/merging` roda verde com um teste
trivial de contagem de páginas.

---

### F1 — Modo `flatten` — *1 dia*

- Implementar `PdfMergeOptions`, `PdfMergeException` e `PdfDocumentMerger`
  com apenas `PdfMergeMode.flatten`.
- Para cada página de origem:
  1. `out.pages.insert(out.pages.count, srcPage.size, PdfMargins()..all = 0)` —
     **não** usar `pages.add()`, que aplica `document.pageSettings` e a margem
     padrão de 40pt
     ([pdf_document.dart:1445](../lib/src/pdf/implementation/pdf_document/pdf_document.dart#L1445));
  2. usar `PdfPageHelper.getHelper(srcPage).mediaBox` para o tamanho real
     ([pdf_page.dart:616](../lib/src/pdf/implementation/pages/pdf_page.dart#L616));
  3. propagar `/Rotate` da origem (ver decisão pendente #2);
  4. `dp.graphics.drawPdfTemplate(srcPage.createTemplate(), Offset.zero, size)`.
- Cuidado com `CropBox` de origem deslocada: `PdfTemplate._` já trata
  `page.cropBox.left/top > 0`
  ([pdf_template.dart:98-104](../lib/src/pdf/implementation/graphics/figures/pdf_template.dart#L98-L104)) —
  cobrir com teste.

**Critério de aceite:** merge de 3 fixtures gráficas; contagem de páginas,
tamanho de cada página e texto extraído conferem; nenhuma exceção com
`rotacionado.pdf`.

---

### F2 — Motor de importação de objetos — *2–3 dias*

- Criar `PdfImportContext` e `PdfObjectImporter`.
- Adicionar `PdfCrossTable.importContext` e o bypass em
  `PdfReferenceHolder.cloneObject` (§4).
- Implementar `resolvePending()`: percorre `ctx.pending` e reinjeta as chaves
  descartadas pelo filtro de `PdfNull`
  ([pdf_dictionary.dart:606](../lib/src/pdf/implementation/primitives/pdf_dictionary.dart#L606)).
- Implementar `resetCloneCache(IPdfPrimitive root)` — zera `clonedObject` /
  `_clonedObject` recursivamente ao final de cada sessão, evitando vazamento de
  estado entre merges consecutivos.
- Forçar materialização (`crossTable.getObject(ref)`) de tudo que vier de object
  stream antes de clonar — relevante para PDF 1.5+.
- Descriptografia: se a origem é criptografada, os streams precisam estar
  descriptografados antes do clone
  ([pdf_stream.dart:557](../lib/src/pdf/implementation/primitives/pdf_stream.dart#L557)),
  porque `PdfStream.cloneObject` copia `dataStream` cru
  ([pdf_stream.dart:541](../lib/src/pdf/implementation/primitives/pdf_stream.dart#L541)).

**Critério de aceite (teste unitário, ainda sem página):** clonar um subgrafo
com ciclo (`A → B → A`) entre duas cross-tables produz exatamente 2 objetos no
destino, e o ciclo é preservado.

---

### F3 — Importação da página — *1–2 dias*

`PdfPageImporter.import(PdfPage srcPage) → PdfPage`:

1. **Materializar herdados** subindo a cadeia `/Parent` na origem:
   `/Resources`, `/MediaBox`, `/CropBox`, `/Rotate`. A lib já resolve isso em
   `PdfPageHelper.getResources()`,
   `.cropBox` ([pdf_page.dart:595](../lib/src/pdf/implementation/pages/pdf_page.dart#L595)),
   `.mediaBox` ([:616](../lib/src/pdf/implementation/pages/pdf_page.dart#L616)) e
   `_obtainRotation()` ([:425](../lib/src/pdf/implementation/pages/pdf_page.dart#L425)).
2. Clonar o dicionário da página **excluindo** `/Parent`, `/Annots` (F4),
   `/StructParents` e `/B` (F7).
3. Criar a página de destino com `pages.insert(...)` e substituir as chaves:
   `/Contents`, `/Resources`, `/MediaBox`, `/CropBox`, `/BleedBox`, `/TrimBox`,
   `/ArtBox`, `/Rotate`, `/Group`, `/UserUnit`.
4. Religar `/Parent` ao nó `/Pages` do destino — seguir exatamente o padrão de
   [pdf_page_collection.dart:189-192](../lib/src/pdf/implementation/pages/pdf_page_collection.dart#L189-L192)
   (`dic[parent] = PdfReferenceHolder(parent)`, `kids.insert(...)`,
   `_updateCount(parent)`).
5. Registrar em `ctx.pageMap[srcDict] = dstPage` e no `_pageCache` da coleção.

> **Alternativa a avaliar no início da fase:** em vez de criar página vazia e
> sobrescrever, enxertar o dicionário clonado direto na árvore `/Pages` e
> envolvê-lo com `PdfPageHelper.fromDictionary()`
> ([pdf_page.dart:504](../lib/src/pdf/implementation/pages/pdf_page.dart#L504)).
> Gera menos lixo, mas exige entender como `PdfSection` participa da
> serialização. Fazer um spike de 2h antes de escolher.

**Critério de aceite:** content stream da página importada é byte-idêntico ao da
origem; fontes e imagens presentes no PDF de saída; tamanho e rotação
preservados; `PdfTextExtractor` retorna o mesmo texto.

---

### F4 — Anotações e links — *1–2 dias*

- Clonar `/Annots` item a item, pulando `/Subtype /Widget` (fica para F5).
- Para cada anotação clonada: `/P` ← referência da página de destino; remover
  `/Parent` órfão. **Precedente pronto** em
  [pdf_form_field_collection.dart:289-300](../lib/src/pdf/implementation/forms/pdf_form_field_collection.dart#L289-L300).
- Remapear destinos:
  - `/Dest` como array `[pageRef /XYZ …]` → substituir `pageRef` via `pageMap`;
  - `/Dest` como nome/string → resolver no `/Names /Dests` da origem
    (`PdfDocumentHelper.getNamedDestination`,
    [pdf_document.dart:1577](../lib/src/pdf/implementation/pdf_document/pdf_document.dart#L1577))
    e reemitir no destino (F6);
  - `/A << /S /GoTo /D … >>` → mesmo tratamento;
  - `/A << /S /URI >>`, `/Launch`, `/GoToR` → clonar sem alteração.
- Se o destino apontar para página **não importada**: registrar `warning` e
  remover o link (evolução futura: converter em `/GoToR` para o arquivo
  original).
- `/Popup` e `/IRT`: remapear referências cruzadas entre anotações da mesma
  página.

**Critério de aceite:** `links.pdf` mesclado duas vezes; ambos os links internos
apontam para as páginas corretas *dentro de cada cópia*; link URI intacto;
contagem de anotações preservada.

---

### F5 — AcroForm — *2 dias*

- Mesclar `/AcroForm` do destino com o da origem:
  - `/Fields` — concatenar, resolvendo colisões de `/T` conforme
    `fieldNameConflict` (padrão `renameSuffix` → `nome`, `nome_2`, …),
    registrando em `ctx.renamedFields`;
  - `/DR` — merge de `/Font`, `/XObject`, `/ExtGState`… com renomeação de chaves
    em conflito **e reescrita das `/DA`** que as referenciam;
  - `/DA`, `/Q` — herdar do destino, materializar na origem quando divergir;
  - `/NeedAppearances` — `OR` lógico;
  - `/SigFlags` — ver F8.
- Widgets: clonar como anotações, religar `/P` e a hierarquia `/Parent`
  campo↔widget.
- Após o merge, os campos importados devem aparecer em
  `destination.form.fields`.

**Critério de aceite:** dois `formulario.pdf` mesclados; 2× o número de campos;
nomes desambiguados; valores preservados após reabrir o PDF de saída.

---

### F6 — Bookmarks e destinos nomeados — *1–2 dias*

- Clonar a árvore `/Outlines` da origem e anexá-la à raiz do destino
  (`PdfBookmarkBase`,
  `lib/src/pdf/implementation/pdf_document/outlines/pdf_outline.dart`).
  Opção `groupBookmarksPerDocument` para criar um nó-pai por documento.
- Remapear `/Dest` e `/A` de cada item via `pageMap` (mesma rotina de F4).
- Recalcular `/Count`, `/First`, `/Last`, `/Prev`, `/Next` da árvore combinada.
- `/Names /Dests`: merge com renomeação em conflito; propagar as renomeações
  para links (F4) e outlines — por isso `ctx.renamedDestinations` só é resolvido
  em `finish()`, depois de todas as páginas importadas.

**Critério de aceite:** `bookmarks.pdf` + `simples_2p.pdf` mesclados; todos os
bookmarks navegam para a página certa; nenhum destino nomeado duplicado.

---

### F7 — Recursos de nível de documento — *1–2 dias*

| Chave do catálogo | Tratamento |
|---|---|
| `/OCProperties` | Merge de `/OCGs`, `/D /Order`, `/ON`, `/OFF`. A lib já mantém esse estado em `PdfDocumentHelper.order/on/off/printLayer` ([pdf_document.dart:1481-1495](../lib/src/pdf/implementation/pdf_document/pdf_document.dart#L1481-L1495)) |
| `/PageLabels` | Concatenar faixas aplicando offset do índice inicial |
| `/StructTreeRoot`, `/MarkInfo` | **v1: descartar** — remover `/StructParents` das páginas e emitir warning. Merge real da árvore de marcação fica como trabalho futuro |
| `/Metadata` (XMP) | Manter o do destino; opcionalmente registrar `dc:source` das origens |
| `/Info` | `copyDocumentInfoFromFirst` |
| `/ViewerPreferences`, `/PageMode`, `/PageLayout`, `/OpenAction` | Do destino; opção para herdar do primeiro documento |
| `/Names /EmbeddedFiles` | `importAttachments` (padrão `false`) |
| `/Extensions`, `/Lang` | Copiar se ausente no destino |
| Versão do PDF | `max(versões)` — `PdfDocument._setFileVersion` ([pdf_document.dart:1097](../lib/src/pdf/implementation/pdf_document/pdf_document.dart#L1097)) |

---

### F8 — Casos especiais e políticas — *1–2 dias*

**Documentos assinados — crítico para esta biblioteca.**
Mesclar invalida *toda* assinatura digital existente: a assinatura cobre os
bytes exatos do documento em que foi aplicada, e o merge reescreve o arquivo
inteiro. Não há como contornar.

Pesquisa de mercado (PDF24, iLovePDF, PDFsam, PDF Architect, Adobe Acrobat,
PDFBox, iText): **nenhuma ferramenta recusa** documentos assinados — todas
mesclam e a assinatura some ou fica inválida. Recusar seria comportamento
divergente, então o padrão desta lib também é mesclar.

Comportamento implementado — três chaves independentes em `PdfMergeOptions`:

| Opção | Padrão | Efeito |
|---|---|---|
| `rejectSignedSources` | `false` | `true` lança `PdfMergeException` ao encontrar origem assinada |
| `keepInvalidSignatures` | `false` | `true` mantém os campos `/FT /Sig` com o CMS e os certificados; `/SigFlags` é propagado. O visualizador vai reportar assinatura inválida |
| `removeSignatureAppearance` | `false` | `true` remove também o carimbo visual |

Padrão (todas `false`): os campos de assinatura são removidos, mas o
**carimbo visual é preservado** como anotação `/Subtype /Stamp` somente-leitura
(flag `/F` com bit 64). A página continua *parecendo* assinada — o que se
espera de um relatório ou documento judicial — e nenhum visualizador reclama de
assinatura quebrada, porque não há mais assinatura para conferir.

Precedência: `rejectSignedSources` > `keepInvalidSignatures` >
`removeSignatureAppearance`.

Em todos os casos a perda é registrada em `PdfDocumentMerger.warnings`, e
`fileStructure.incrementalUpdate` **nunca** é habilitado durante um merge.

**Documentos criptografados.** Exigir senha na carga
(`PdfDocument(inputBytes:, password:)`). Verificar que `PdfCrossTable.encryptor`
([pdf_cross_table.dart:110](../lib/src/pdf/implementation/io/pdf_cross_table.dart#L110))
descriptografou todos os streams antes do clone. Teste: origem criptografada →
destino sem criptografia.

**Object streams / xref stream (PDF ≥ 1.5).** Garantir materialização de todos
os objetos comprimidos antes do clone.

**PDF/A.** Se o destino tem `conformanceLevel` A1b/A2b/A3b, validar que as
fontes importadas estão embutidas — a lib já lança nesse caso em
[pdf_graphics.dart:900-920](../lib/src/pdf/implementation/graphics/pdf_graphics.dart#L900-L920);
replicar a checagem no importador.

**Geometria atípica.** `MediaBox` com origem ≠ (0,0); `CropBox` invertido;
`/UserUnit` ≠ 1; `/Rotate` não múltiplo de 90.

---

### F9 — API pública, exports e documentação — *0,5 dia*

- Exportar em `lib/pdf.dart` (e `lib/pdf_server.dart` se aplicável):
  `PdfDocumentMerger`, `PdfMergeOptions`, `PdfMergeMode`,
  `PdfFieldNameConflictPolicy`, `PdfMergeException`.
- Doc comments no padrão da lib (com exemplo `///` executável).
- Atualizar `doc/doc.md`, `doc.md` (raiz) e `CHANGELOG.md`; bump de versão.
- Exemplo em `example1/bin/merge_example.dart`.

---

### F10 — Desempenho — *1 dia*

- **Deduplicação de recursos** (`deduplicateResources`): hash SHA-1 do
  `dataStream` + dicionário normalizado dos streams importados; reusar o objeto
  já clonado quando idêntico. Ganho grande ao mesclar N documentos gerados pelo
  mesmo template (fontes e logos repetidos).
- Variante assíncrona `appendDocumentAsync` / `PdfDocument.merge`, seguindo o
  padrão de `_saveDocumentAsync`
  ([pdf_document.dart:776](../lib/src/pdf/implementation/pdf_document/pdf_document.dart#L776)).
- Benchmark em `benchmarks/`: 50 PDFs × 10 páginas. Métricas: tempo total, pico
  de memória, tamanho de saída vs. soma dos originais (esperado: menor, graças à
  dedup).

---

## 6. Plano de testes

| Suíte | Arquivo | Cobre |
|---|---|---|
| Básico | `test/merging/merge_basic_test.dart` | contagem/ordem de páginas, tamanho, rotação, ambos os modos |
| Conteúdo | `test/merging/merge_content_test.dart` | content stream idêntico, texto extraído, fontes TTF, imagens |
| Anotações | `test/merging/merge_annotations_test.dart` | links internos/URI, popups, contagem |
| Formulários | `test/merging/merge_forms_test.dart` | colisão de nomes, `/DR`, valores após reabrir |
| Outlines | `test/merging/merge_outlines_test.dart` | árvore combinada, destinos nomeados |
| Camadas | `test/merging/merge_layers_test.dart` | OCGs preservados e independentes |
| Robustez e assinaturas | `test/merging/merge_edge_cases_test.dart` | PDFs reais, rotação, MediaBox herdado, e as três chaves de assinatura com sua precedência |
| Round-trip | `test/merging/merge_roundtrip_test.dart` | merge → salvar → recarregar → merge de novo |
| Corpus | `test/merging/merge_corpus_test.dart` | varredura dos 54 PDFs de `test/assets`: estrutura, geometria, texto, assinaturas, corpus inteiro em um documento |
| Documentos reais | `test/merging/merge_real_documents_test.dart` | outline de `paginador.pdf`, formulário de 63 campos de `sample3.pdf`, anotações de `termo.pdf`, arquivos com 5–12 assinaturas, modo flatten |
| Compatibilidade SEI | `test/merging/merge_sei_compatibility_test.dart` | comparação ponta a ponta contra a saída do SEI: mesmas entradas (conferidas por SHA-256 contra o ZIP do processo), assinaturas mantidas com `/ByteRange` verbatim, campo órfão, renomeação em colisão |
| Perf | `benchmarks/merge_benchmark.dart` | 50×10 páginas |

**Invariante geral de todos os testes:** o PDF de saída deve ser recarregável
por `PdfDocument(inputBytes: out)` sem exceção, e `document.pages.count` deve
bater com a soma esperada.

---

## 7. Riscos e decisões em aberto

| # | Risco | Mitigação |
|---|---|---|
| # | Risco | Desfecho |
|---|---|---|
| R1 | Alterar `PdfReferenceHolder.cloneObject` quebra `PdfTemplate` / `PdfFormFieldCollection` / `json_document` | **Controlado.** Bypass só ativo com `importContext != null`; os 199 testes pré-existentes continuam verdes |
| R2 | Cache `clonedObject` vazando entre sessões de merge | **Não se materializou.** O cache é chaveado pela cross-table de destino, então invalida sozinho ao trocar de destino. `resetCloneCache()` não foi necessário |
| R3 | `PdfDictionary.cloneObject` descarta chaves nulas silenciosamente | **Resolvido de outra forma.** Duas passagens em vez de `PendingReference`; o que sobra é detectado em `_dropBrokenDestinations` |
| R4 | Árvore de marcação estrutural (tagged PDF) | **Descartada**, como planejado (§9) |
| R5 | Explosão de tamanho ao mesclar muitos documentos similares | **Resolvido.** Memo explícito no contexto; teste verifica que 5 cópias saem menores que a soma |
| R6 | Usuário mesclar documento assinado sem perceber | **Repensado.** Recusar divergia do mercado; hoje mescla por padrão e registra em `warnings` (F8) |

**Decisões que estavam pendentes:**

1. Enxerto direto do dicionário clonado *vs.* criar página vazia e sobrescrever.
   → **Sobrescrever.** `PdfPageCollection.insert` só funciona em documento
   carregado, e para documento novo o modelo de seções já dá o tamanho por
   página. Enxertar direto exigiria mexer em `PdfSection`.
2. `flatten` normaliza `/Rotate` ou propaga? → **Propaga**, como recomendado.
   Teste: `merge_edge_cases_test.dart`, "page rotation is carried over".
3. Bookmarks agrupados por documento de origem? → **Desligado por padrão**,
   com `groupBookmarksPerDocument` para ligar.

---

## 8. Ordem de execução — checklist

```
[x] F0  Fixtures + helpers de teste                      test/merging/merge_fixtures.dart
[x] F1  Modo flatten                                     PdfMergeMode.flatten
[x] F2  PdfImportContext + bypass do guard de página     pdf_import_context.dart
[x] F3  Importação da página + atributos herdados        pdf_page_importer.dart
[x] F4  Anotações e links                                pdf_annotation_importer.dart
[x] F5  AcroForm                                         pdf_form_importer.dart
[x] F6  Bookmarks                                        pdf_outline_importer.dart
[x] F7  Catálogo (OCG, PageLabels, Info)                 pdf_catalog_merger.dart
[x] F8  Assinaturas, xref stream, geometria atípica      política + testes
[x] F9  API pública, exports, docs, CHANGELOG            PdfDocument.merge*, lib/pdf.dart
[~] F10 Dedup (feito), async (feito), benchmarks (não)
```

---

## 9. O que ficou fora desta entrega

| Item | Situação | Motivo |
|---|---|---|
| Árvore de marcação estrutural (`/StructTreeRoot`, tagged PDF) | Descartada; `/StructParent` é removido das páginas importadas (`dropStructureTree`, padrão `true`) | Mesclar árvores de marcação exige remapear todo o `/ParentTree`; fora do escopo da v1 |
| `/Names /Dests` no destino | Não é reconstruído | Destinos nomeados são resolvidos para arrays explícitos no momento do import, então o resultado navega sem precisar da árvore de nomes |
| `/DR` do AcroForm com nomes em conflito | O recurso do destino vence; a colisão vira warning | Renomear exigiria reescrever todas as strings `/DA` que citam o recurso |
| Anexos (`/Names /EmbeddedFiles`) | `importAttachments` existe nas opções mas ainda não é honrado | Não implementado |
| XMP (`/Metadata`) | O do destino é mantido | Mesclar metadados XMP de N documentos não tem semântica óbvia |
| Documentos criptografados na origem | Funcionam quando a senha é passada na carga (`PdfDocument(inputBytes:, password:)`); sem teste automatizado | Falta fixture criptografada no repositório |
| Benchmarks | Não escritos | — |
| Conformidade PDF/A do destino | Não é validada durante o import | A checagem de fontes embutidas existe só no caminho `PdfGraphics` |
| `PdfExternalSigning` sobre PDF já mesclado | `findContentsRange` lança `Contents range found but inconsistent` | Comportamento correto: o `/ByteRange` mantido por `keepInvalidSignatures` não descreve o arquivo novo. Assinar um documento mesclado exige decidir antes o que fazer com as assinaturas anteriores |

**Limitação conhecida:** se o documento de destino receber camadas via
`document.layers.add()` *depois* de um merge, `PdfLayerCollection` substitui
`/OCProperties` inteiro e descarta os OCGs importados. Adicione as camadas
próprias antes de mesclar.

---

## 10. Mapa plano → código

| Fase | Arquivo entregue |
|---|---|
| F2 | [pdf_import_context.dart](../lib/src/pdf/implementation/merging/pdf_import_context.dart), campo `PdfCrossTable.importContext`, bypass em [pdf_reference_holder.dart](../lib/src/pdf/implementation/primitives/pdf_reference_holder.dart) |
| F3 | [pdf_page_importer.dart](../lib/src/pdf/implementation/merging/pdf_page_importer.dart) |
| F4 | [pdf_annotation_importer.dart](../lib/src/pdf/implementation/merging/pdf_annotation_importer.dart) |
| F5 | [pdf_form_importer.dart](../lib/src/pdf/implementation/merging/pdf_form_importer.dart) |
| F6 | [pdf_outline_importer.dart](../lib/src/pdf/implementation/merging/pdf_outline_importer.dart) |
| F7 | [pdf_catalog_merger.dart](../lib/src/pdf/implementation/merging/pdf_catalog_merger.dart) |
| F5 (extensão) | Campos sem widget: `PdfFormImporter.importOrphanFields` |
| F1/F8/F9 | [pdf_document_merger.dart](../lib/src/pdf/implementation/merging/pdf_document_merger.dart), [pdf_merge_options.dart](../lib/src/pdf/implementation/merging/pdf_merge_options.dart), `PdfDocument.mergeSync`/`merge`/`appendDocument`/`importPage`/`importPageRange` |
| Testes | [test/merging/](../test/merging/) — 286 testes em 11 arquivos, incluindo varredura dos 54 PDFs de `test/assets` e a comparação contra o SEI (§11) |
| Exemplo | [example1/bin/merge_documents.dart](../example1/bin/merge_documents.dart) |

### Desvios em relação ao plano

1. **Sem mecanismo de pendências (`PendingReference`).** O plano previa
   reinjetar chaves descartadas pelo filtro de `PdfNull`. Na implementação o
   import roda em **duas passagens** — todas as páginas do intervalo primeiro,
   anotações e bookmarks depois —, então o `pageMap` já está completo quando
   uma referência de página é resolvida. Referências para fora do intervalo
   continuam virando `PdfNull`, e são detectadas e removidas explicitamente em
   `_dropBrokenDestinations`.

2. **Memo de clone explícito no contexto.** Além do bypass do guard de página,
   `PdfReferenceHolder.cloneObject` passou a consultar
   `PdfImportContext.clonedObjects` **antes** do guard de ciclo
   (`prevReference`). Sem isso, o segundo encontro com um objeto compartilhado
   (uma fonte usada por duas páginas) caía no ramo "circular" e **adotava o
   objeto de origem** dentro do documento de destino. O memo faz o clone ser
   reaproveitado — é o que garante a deduplicação verificada em
   `merge_content_test.dart`.

3. **Bookmarks reconstruídos pelo modelo público, não clonados.**
   `PdfBookmarkBase` é dono de `/First`, `/Last`, `/Prev`, `/Next` e `/Count` e
   os reescreve ao salvar, então uma árvore enxertada à mão seria sobrescrita.
   O importador percorre a árvore de origem e recria cada nó com
   `PdfBookmarkBase.add`. Isso expôs um bug: `add` aceitava `destination`,
   `color`, `textStyle` e `isExpanded` mas nunca os repassava ao construtor —
   corrigido nesta entrega.

4. **Hierarquia de campos achatada.** Em vez de preservar a árvore de campos,
   cada campo terminal é recriado no topo de `/AcroForm /Fields` com o nome
   totalmente qualificado em `/T`. Campos com vários widgets (grupos de rádio,
   campos que atravessam páginas) continuam agrupados sob um único campo via
   `/Kids`.

5. **Campos de formulário sem widget são varridos à parte.** O plano assumia
   que todo campo é alcançável pelo widget que o mostra numa página. Não é:
   `/AcroForm /Fields` pode conter campo sem widget nenhum — um campo de dados
   oculto, ou uma assinatura invisível. A comparação com o SEI (§11) expôs isso
   custando uma de duas assinaturas. `PdfFormImporter.importOrphanFields` varre
   os campos terminais ao fim de cada documento de origem e traz os que nenhum
   widget alcançou.

6. **Bookmarks reconstruídos toleram destino ilegível.** Resolver o destino de
   um bookmark percorre a árvore de nomes do documento de origem, que pode
   estar malformada de formas que o leitor não sobrevive. A leitura é isolada:
   o bookmark entra sem destino e a falha vira warning, em vez de derrubar a
   mesclagem inteira.

7. **Destino carregado usa `pages.insert`; destino novo usa seções.**
   `PdfPageCollection.insert` só funciona em documento carregado (depende de
   `_crossTable`). Para um `PdfDocument()` novo, cada página importada ganha
   uma `PdfSection` própria com as dimensões da origem — é o que permite
   preservar tamanho por página.

---

## 11. Referência de campo: como o SEI mescla

O SEI (Sistema Eletrônico de Informações, do TRF4, usado em boa parte da
administração pública brasileira) tem a função "Gerar Arquivo PDF do Processo",
que mescla os documentos de um processo. Como é o sistema de referência para
quem usa esta biblioteca, a saída dele foi analisada e virou fixture.

### Qual engine o SEI usa

Perícia em `test/merging/assets/sei_merged_reference.pdf`. Duas ferramentas
atuam no pipeline, e confundi-las é fácil: **wkhtmltopdf**
converte o documento HTML do processo em PDF, e **PDFBox** mescla os PDFs.

#### Evidência direta

| Evidência | O que indica |
|---|---|
| Campo `dummyFieldName1` no consolidado, **ausente nos três PDFs de origem** | Foi *gerado na mesclagem*. É string literal em `PDFMergerUtility.acroFormLegacyMode`, usada ao renomear campo em colisão. Presente no PDFBox desde o 1.8 |
| Comentário binário do header `%öäüß` (`F6 E4 FC DF`) | Constante `COSWriter.GARBAGE` do PDFBox, byte a byte |
| Header `%PDF-1.4` com `/Version /1.7` no catálogo | `new PDDocument()` nasce em 1.4 e `setVersion` grava no **catálogo** quando a versão é ≥ 1.4. Um reserializador comum poria a versão real no header |
| Xref clássica, sem object streams | **Não é PDFBox 3.x**, que comprime por padrão desde o 3.0 → ramo 2.x |
| `/ID` com as duas entradas idênticas | Primeira gravação de um `PDDocument` novo |
| Cópia objeto a objeto: 43 dos 87 streams do relatório idênticos byte a byte no consolidado, incluindo os dois programas de fonte | `PDFCloneUtility`, o mecanismo do `PDFMergerUtility`. Renderização não reproduz isso |

**Conclusão: Apache PDFBox 2.x, `PDFMergerUtility` em `PDFBOX_LEGACY_MODE`.**
Corroborado de forma independente pela documentação de operação do SEI, que
cita o `pdfboxmerge.jar`, um cache em `/opt/sei/temp/.pdfbox.cache` e a
exigência de JDK 1.8.

#### Duas armadilhas nesta perícia

**1. A ausência do nome da biblioteca em `/Producer` não é evidência contra.**
O raciocínio "toda biblioteca se carimba em `/Producer`, aqui está `Qt 4.8.7`,
logo não é PDFBox" vale para iText, TCPDF, ReportLab e afins — **mas não para o
PDFBox**, que nunca se carimba. Confirmado no código: nem `COSWriter` nem
`PDDocument` escrevem `/Producer`, `PDDocumentInformation.getProducer()`
devolve `null` quando ausente, e `PDFMergerUtility` não sobrescreve
`/Producer` nem `/Creator`. O `/Info` do consolidado
(`Creator = wkhtmltopdf 0.12.6`, `Producer = Qt 4.8.7`, `Title` posto pelo SEI)
veio do despacho HTML renderizado — nenhum dos três PDFs de origem tem `/Info`.

**2. `E2 E3 CF D3` não é exclusivo do iText, e não é o que está aqui.**
O `PDF_MAGIC` do **PoDoFo** é `"âãÏÓ
"` — o mesmo do iText. O
arquivo do SEI traz `F6 E4 FC DF`, que é do PDFBox. Isso **elimina o PoDoFo**,
hipótese plausível à primeira vista por ser a biblioteca contra a qual o
wkhtmltopdf 0.12.x é ligado: a impressão digital em que a suspeita se apoiaria
aponta para o outro lado. Some-se que PoDoFo, Qt e wkhtmltopdf não têm lógica
de merge de AcroForm — nenhum deles produziria `dummyFieldName1`.

### O que o SEI faz com as assinaturas

Mantém os campos `/FT /Sig` com o `/ByteRange` original. No arquivo de
referência são duas assinaturas com ranges somando 20 643 e 29 711 bytes dentro
de um PDF de 238 KB — o ITI reporta "assinaturas desconhecidas" e o Chaindoc,
"Invalid". É o comportamento de `keepInvalidSignatures: true`.

### O processo analisado

| Documento | Páginas | Assinatura |
|---|---|---|
| `[1]-0009609_Despacho.pdf` | 39 | — |
| `[2]-0009610_Recurso.pdf` | 1 | `Signature1` **sem widget** e com `/Rect [0 0 0 0]` (invisível) |
| `[3]-0009611_Apartado.pdf` | 1 | `Signature1` com widget |
| `[4]-0009612_Despacho.html` | 1 | HTML renderizado pelo SEI na hora da mesclagem |

Os três PDFs estão em `test/merging/assets/`, conferidos por SHA-256 contra as
entradas do ZIP exportado pelo processo. O quarto é HTML — renderizar HTML não
é função de uma biblioteca PDF, então a comparação é de 41 contra 42 páginas e
verifica a estrutura das assinaturas, não a contagem.

### Onde esta biblioteca coincide e onde difere

| Aspecto | SEI (PDFBox) | Esta biblioteca |
|---|---|---|
| Assinaturas | Mantidas, inválidas | `keepInvalidSignatures: true` faz o mesmo; **por padrão** vira carimbo somente-leitura |
| `/ByteRange` | Verbatim | Verbatim |
| Colisão de nome de campo | Renomeia para `dummyFieldName<N>` | Renomeia para `<nome>_<N>`, preservando o nome original |
| Campo sem widget | Preservado, continua órfão | Preservado (`importOrphanFields`) |
| `/Info` | Do documento HTML renderizado | Do destino; `copyDocumentInfoFromFirst` para herdar do primeiro |

A diferença que importa é o padrão: o SEI entrega um arquivo que todo validador
marca como inválido, enquanto o padrão daqui entrega um que nenhum validador
reclama — porque não sobrou assinatura para conferir — mantendo o carimbo
visual. Quem precisa da saída no formato do SEI liga `keepInvalidSignatures`.
