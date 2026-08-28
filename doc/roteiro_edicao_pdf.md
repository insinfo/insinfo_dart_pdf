# Roteiro para edição de PDFs existentes

> **Status em 27/08/2026: suporte parcial.** A biblioteca já altera PDFs
> carregados, mas ainda não oferece edição geral e segura do conteúdo que já
> existe nos streams das páginas.

## 1. Resposta curta

A biblioteca já suporta estas formas de edição:

- abrir um PDF com `PdfDocument(inputBytes: bytes)` e salvar uma nova revisão;
- adicionar, inserir, remover e rotacionar páginas;
- importar e mesclar páginas de outros documentos;
- desenhar conteúdo novo, carimbos e marcas d'água sobre páginas;
- adicionar, remover e achatar anotações;
- ler e alterar valores de campos de formulário;
- alterar metadados, anexos, marcadores, segurança e assinaturas dentro das
  APIs existentes.

Ela **não é, por enquanto, um editor completo de conteúdo existente**. Não há
API pública para selecionar um trecho do stream da página e substituir ou
remover texto, trocar/remover uma imagem já desenhada, editar vetores
existentes ou fazer redação segura. `PdfTextExtractor.findText` localiza texto,
mas o resultado não identifica quais operandos `Tj`/`TJ` produziram cada glifo
e não pode ser usado para reescrever o conteúdo com fidelidade.

Portanto, a descrição do `pubspec.yaml` — “creating, reading, editing, and
securing” — é verdadeira no sentido estrutural e incremental, mas ampla demais
se “editing” for entendido como a edição de texto e objetos já presentes na
página.

## 2. Matriz atual de capacidades

| Operação | Situação atual | Observação |
|---|---|---|
| Abrir, modificar e salvar PDF existente | Suportada | O salvamento incremental já existe para documentos carregados. |
| Adicionar conteúdo sobre uma página | Suportada | `PdfPage.graphics`/layers permitem texto, imagem e desenho novos. Convém expor uma API explicitamente segura para páginas carregadas, semelhante a `PdfImportedPage.appendGraphics()`. |
| Inserir e remover páginas | Suportada | `PdfPageCollection.insert`, `remove` e `removeAt`. |
| Rotacionar página existente | Suportada | `PdfPage.rotation`. |
| Mesclar/importar páginas | Suportada | Há modo preservado e achatado, com tratamento de recursos, formulários e anotações. |
| Editar formulários | Suportada | Há teste de round-trip alterando `PdfTextBoxField.text`; checkboxes, listas, combos e rádios também expõem setters. |
| Adicionar/remover/achatar anotações | Suportada | A coleção expõe `add`, `remove` e `flattenAllAnnotations`. |
| Alterar metadados | Suportada | Título, autor, assunto, palavras-chave, criador e produtor têm setters. |
| Localizar/extrair texto | Suportada | Há texto, linhas, palavras, glifos, limites e `findText`. |
| Substituir texto existente | Não suportada | Não existe vínculo público entre o texto extraído e os tokens/bytes do stream. |
| Remover texto existente | Não suportada | Cobrir com um retângulo só oculta visualmente e não remove os dados. |
| Trocar/remover imagem existente | Não suportada | Falta inventário editável de `Do`, imagens inline, máscaras e XObjects aninhados. |
| Editar paths/vetores existentes | Não suportada | O parser reconhece operadores, mas não há modelo público mutável nem serializador lossless. |
| Redação segura | Não suportada | Exige remover dados e revisões antigas; não pode usar salvamento incremental. |
| Refluxo de parágrafos como em Word | Fora do modelo atual | PDF é uma lista de operações gráficas, não um formato semântico de parágrafos. |

## 3. Objetivo do projeto

Entregar uma API pública que permita inspecionar e editar conteúdo existente
sem corromper o PDF, preservando por padrão tudo o que não foi alterado.

O projeto deve oferecer dois níveis deliberadamente distintos:

1. **Edição visual**, adequada para carimbos, sobreposição e substituição
   aparente. É simples, preserva o conteúdo original e pode ser incremental.
2. **Edição destrutiva**, que reescreve/remova operadores e recursos. É
   necessária para remover conteúdo e para redação segura, tem mais restrições
   e deve produzir uma regravação completa.

Não prometer, na primeira versão, refluxo automático de página ou edição de
qualquer PDF arbitrário. Fontes customizadas, ligaduras, escrita vertical,
Type3, transparências, patterns, conteúdo marcado e XObjects aninhados exigem
tratamento explícito e diagnóstico de não suporte quando não forem seguros.

## 4. Princípios e invariantes

- Preservar byte a byte streams não alterados sempre que o modo de salvamento
  permitir.
- Nunca chamar uma cobertura visual de “remoção” ou “redação”.
- Nunca salvar uma redação segura de forma incremental, pois revisões antigas
  continuam no arquivo e permitem recuperar o conteúdo.
- Não editar silenciosamente todas as ocorrências de um XObject compartilhado.
  Clonar antes de modificar quando apenas um uso foi selecionado.
- Manter balanceados `q/Q`, `BT/ET`, marked content e clipping paths.
- Preservar operadores desconhecidos e extensões de terceiros no modo lossless.
- Respeitar criptografia, permissões e `DocMDP`; informar ao chamador quando a
  operação invalida uma assinatura ou viola a política de certificação.
- Toda edição deve ser transacional: falha de validação não pode deixar o
  `PdfDocument` parcialmente alterado.
- Coordenadas públicas seguem a convenção atual da biblioteca; a camada interna
  deve registrar as matrizes necessárias para voltar ao espaço do stream.

## 5. API pública proposta

Os nomes são uma proposta inicial e devem passar por uma revisão curta de API
antes da implementação.

```dart
final PdfDocument document = PdfDocument(inputBytes: input);
final PdfPageEditor editor = document.pages[0].editor;

// Conteúdo novo, sem tocar no stream original.
editor.overlay.drawString(
  'CONFIDENCIAL',
  PdfStandardFont(PdfFontFamily.helvetica, 32),
  bounds: const Rect.fromLTWH(100, 200, 300, 50),
);

// Pesquisa ligada às operações que produziram o texto.
final List<PdfTextMatch> matches = editor.findText('Nome antigo');

// Substituição visual: conserva o conteúdo antigo nos bytes.
editor.replaceText(
  matches.first,
  'Nome novo',
  mode: PdfTextReplacementMode.overlay,
);

// Redação real: remove o conteúdo e obriga full rewrite.
editor.redact(matches.first, replacementText: 'REMOVIDO');

final List<int> output = document.saveSync(
  mode: PdfSaveMode.fullRewrite,
);
```

Tipos mínimos:

- `PdfPageEditor`: fachada transacional para a página;
- `PdfContentElement`: base imutável para texto, imagem, path, estado gráfico,
  XObject e conteúdo desconhecido;
- `PdfTextRun` e `PdfTextMatch`: texto, glifos, bounds, fonte, matrizes, stream,
  índice do operador e intervalo dos operandos;
- `PdfImageElement`: nome do recurso, bounds transformado, stream e cadeia de
  XObjects que levou ao elemento;
- `PdfEditOperation` e `PdfEditResult`: mudança pedida, avisos, conteúdo afetado
  e necessidade de full rewrite;
- `PdfEditException` com códigos estáveis, por exemplo
  `unsupportedFontEncoding`, `sharedXObject`, `signaturePermissionDenied` e
  `losslessSerializationUnavailable`;
- `PdfSaveMode.incremental` e `PdfSaveMode.fullRewrite` para documentos
  saudáveis, sem confundir essa decisão geral com `PdfRepairedSaveMode`.

Também deve existir uma operação conveniente e inequivocamente visual:

```dart
PdfGraphics PdfPage.appendGraphics();
```

Ela deve usar o mesmo isolamento já documentado por
`PdfImportedPage.appendGraphics()`: envolver o conteúdo anterior com `q/Q` e
acrescentar um stream novo em estado gráfico limpo.

## 6. Arquitetura

### 6.1 Parser lossless de conteúdo

O `ContentParser` atual pode servir de ponto de partida, mas `PdfRecord` guarda
apenas `operatorName`, operandos convertidos em `String` e, em um caso, bytes de
imagem inline. Para editar com segurança, introduzir uma representação que
também preserve:

- stream e intervalo original de bytes de cada token e operador;
- tipo lexical, grafia, comentários e whitespace;
- strings literais/hexadecimais sem perda;
- arrays aninhados de `TJ`, dicionários e imagens inline;
- operadores desconhecidos;
- estado gráfico e estado de texto antes/depois do operador;
- origem do recurso e pilha de XObjects/Form XObjects.

O serializador deve poder copiar intervalos intactos e gerar novamente somente
os nós alterados. Antes de editar, parsear todos os streams em `/Contents`, na
ordem, incluindo arrays e streams comprimidos. Filtros suportados devem ser
decodificados e recodificados; filtro não suportado deve gerar diagnóstico, não
uma alteração parcial.

### 6.2 Índice de conteúdo

Separar a extração para exibição do vínculo necessário à edição. O índice deve
mapear cada glifo a:

- operador `Tj`, `TJ`, `'` ou `"` e posição no operando;
- código original e Unicode resultante;
- fonte, tamanho, espaçamentos e modo de renderização;
- matriz de texto, CTM, clipping e bounds no espaço da página;
- stream direto ou Form XObject e cadeia de invocações `Do`.

Reaproveitar cálculos do `PdfTextExtractor`, `ImageRenderer`,
`PageResourceLoader` e `TextGlyph`, mas evitar duas implementações divergentes
do interpretador de operadores. O destino é um interpretador interno único,
consumido tanto pela extração quanto pela edição.

### 6.3 Planejador transacional

Uma chamada de edição primeiro produz um plano, valida todas as pré-condições e
só então modifica primitives/resources. O plano deve registrar objetos clonados,
streams reescritos, recursos adicionados/removidos e modo mínimo de salvamento.
Se qualquer etapa falhar, nada é aplicado.

### 6.4 Recursos compartilhados

Antes de editar Form XObject, imagem, fonte ou ExtGState, contar referências.
Se o objeto é compartilhado e a seleção cobre apenas um uso, clonar o objeto e
alterar o `/Resources` do contexto selecionado. Se o usuário pedir alteração
global, permitir a edição do recurso compartilhado explicitamente.

## 7. Fases de implementação

### Fase 0 — consolidar e documentar o que já funciona

1. Criar testes públicos de round-trip para documento carregado:
   adicionar overlay, inserir/remover/rotacionar página, alterar formulário,
   anotação e metadado.
2. Adicionar `PdfPage.appendGraphics()` e fazer `PdfImportedPage` delegar a ela.
3. Documentar no README a matriz da seção 2 e os efeitos sobre assinaturas.
4. Ajustar a descrição do pacote para “creating, reading, structurally editing
   and securing” até a edição de conteúdo estar pronta.

**Aceite:** cada capacidade anunciada tem exemplo somente com `package:dart_pdf/pdf.dart`
e teste que salva, reabre e verifica estrutura e aparência/texto.

### Fase 1 — parser e serializador lossless

1. Extrair o parser de conteúdo do diretório de `pdf_text_extractor` para um
   módulo interno compartilhado.
2. Implementar tokens com offsets e árvore de operandos.
3. Cobrir todos os operadores PDF conhecidos, preservando desconhecidos.
4. Implementar serialização idêntica quando não há edição e localizada quando
   apenas um nó muda.
5. Suportar arrays de `/Contents`, Flate e imagens inline; retornar erro
   estruturado para filtros ainda não suportados.

**Aceite:** corpus de PDFs reais faz parse/serialize sem mudança visual nem
semântica; streams sem edição são idênticos e streams normalizados passam por
qpdf/veraPDF e pelos leitores de referência adotados pelo projeto.

### Fase 2 — inventário e seleção editável

1. Criar o interpretador comum de estado gráfico/texto.
2. Expor inventário read-only de texto e imagens.
3. Fazer `findText` opcionalmente retornar `PdfTextMatch` com proveniência.
4. Tratar rotação, crop box, CTM, texto rotacionado, `TJ`, Type0/CID e
   `ToUnicode`.
5. Detectar elementos em Form XObjects e recursos herdados.

**Aceite:** cada match aponta para os bytes/operandos corretos e seus bounds
batem com renderização de referência dentro de uma tolerância definida.

### Fase 3 — edição visual suportada

1. Implementar overlay, cobertura e substituição aparente.
2. Permitir política de ajuste do novo texto: `fit`, `shrink`, `clip` e
   `overflow`, sem alegar refluxo do restante da página.
3. Preservar a fonte quando ela for reutilizável; caso contrário exigir ou
   escolher explicitamente uma fonte substituta.
4. Acrescentar novo stream isolado e recursos sem tocar no conteúdo original.

**Aceite:** funciona por salvamento incremental, não altera streams antigos e
a API/resultado informa `originalContentRetained: true`.

### Fase 4 — substituição destrutiva de texto

1. Começar pelo subconjunto seguro: um único `Tj`/item textual de `TJ`, fonte
   com codificação reversível e sem compartilhamento ambíguo.
2. Codificar o novo texto na fonte existente ou incorporar fonte substituta.
3. Recalcular deslocamentos em `TJ` para preservar posicionamento quando
   possível.
4. Evoluir para matches que atravessam itens e operadores, mantendo estado e
   posicionamento.
5. Para casos fora do subconjunto, falhar com diagnóstico ou oferecer
   explicitamente o modo overlay.

**Aceite:** o texto antigo não aparece na extração nem nos streams atuais; o
novo texto tem bounds previsíveis e o restante da página não se desloca.

### Fase 5 — imagens e vetores

1. Inventariar `Do` de image/Form XObject e imagens inline.
2. Implementar substituição de imagem preservando bounds/transformação.
3. Implementar remoção com clonagem de XObject compartilhado quando necessária.
4. Só depois expor edição de paths; começar por remoção/transformação de um
   grupo selecionado, sem tentar reconstruir formas semânticas.
5. Remover recursos órfãos apenas no full rewrite, após análise de alcance.

**Aceite:** alterar uma ocorrência não muda outras ocorrências compartilhadas;
máscaras, alpha e color spaces permanecem válidos.

### Fase 6 — redação segura

1. Redigir texto, imagem e vetor que intersectem a região escolhida, inclusive
   dentro de Form XObjects após clonagem.
2. Remover conteúdo de appearance streams, anotações, campos, metadados,
   conteúdo marcado e estruturas associadas quando intersectarem a seleção.
3. Fazer garbage collection de objetos e recursos inalcançáveis.
4. Exigir `fullRewrite`, descartar revisões incrementais anteriores e impedir
   que bytes antigos sejam copiados ao arquivo novo.
5. Oferecer auditoria pós-save que procure texto/bytes redigidos e reporte os
   locais que não puderam ser comprovadamente limpos.
6. Separar “sanitização completa” (anexos, JavaScript, embedded files, XMP etc.)
   como opção adicional; redação de página não deve prometer isso implicitamente.

**Aceite:** o conteúdo não é recuperável por extração, busca nos streams,
inspeção de objetos órfãos ou histórico incremental; testes negativos tentam
deliberadamente recuperá-lo.

### Fase 7 — compatibilidade, desempenho e estabilização

1. Rodar corpus com PDFs 1.4–2.0, xref table/stream, object streams,
   criptografia, páginas rotacionadas, formulários, layers e arquivos reparados.
2. Validar visualmente por renderização pixel a pixel e estruturalmente com ao
   menos dois leitores independentes.
3. Medir tempo e memória em arquivos grandes; indexar páginas sob demanda e
   liberar AST/índices que não estejam em uso.
4. Fazer fuzzing do lexer/parser/serializador e testes de propriedade para
   parse/serialize.
5. Congelar a API somente depois dos resultados do corpus.

**Aceite:** nenhum crash/corrupção no corpus; limites de tempo e memória ficam
documentados; casos não suportados retornam diagnósticos determinísticos.

## 8. Estratégia de testes

Cada operação deve ter quatro níveis:

1. **Unitário:** lexer, offsets, matrizes, codificação e serialização.
2. **Round-trip:** criar fixture, abrir, editar, salvar, reabrir e inspecionar.
3. **Visual:** renderizar antes/depois e comparar regiões esperadas, com golden.
4. **Interoperabilidade:** abrir o resultado em validadores/renderizadores
   independentes e registrar warnings.

Casos obrigatórios incluem:

- `Tj`, `TJ`, aspas simples/duplas, várias strings no mesmo match e kerning;
- WinAnsi, MacRoman, Type0/CID com/sem `ToUnicode`, ligaturas e Type3;
- conteúdo em arrays de streams, Form XObjects aninhados e recursos herdados;
- o mesmo XObject usado em páginas/posições diferentes;
- rotação 0/90/180/270, CropBox diferente de MediaBox e matrizes negativas;
- clipping, transparência, blend modes, layers e marked content;
- imagens JPEG/Flate, máscara, SMask e imagens inline;
- PDFs criptografados, assinados/certificados, reparados e linearizados;
- entradas malformadas em modo estrito e leniente;
- redação seguida de busca textual, busca binária e inspeção de objetos/revisões.

Fixtures pequenas devem ser geradas no próprio teste quando isso deixa a causa
clara. PDFs reais licenciados para teste ficam em `test/assets` acompanhados de
origem e expectativa. Não usar apenas `PdfTextExtractor` como oráculo, pois o
editor e o extrator compartilharão parte da implementação.

## 9. Assinaturas, permissões e salvamento

Editar um PDF assinado requer tratamento explícito:

- antes da operação, consultar `DocMDP` e permissões do documento;
- classificar a mudança (formulário, anotação, montagem, conteúdo etc.);
- por padrão, rejeitar alteração proibida por certificação;
- oferecer diagnóstico de quais assinaturas continuam criptograficamente
  válidas para suas revisões e quais viewers podem marcar a revisão nova como
  alteração não permitida;
- qualquer redação segura/full rewrite elimina o histórico assinado e não deve
  preservar a aparência de validade sem aviso explícito.

O modo incremental é apropriado para overlays e várias edições estruturais,
mas não para apagar informação. O full rewrite precisa de garbage collection e
não deve copiar `_data`/revisões antigas para o novo writer.

## 10. Documentação e entrega

Antes de declarar “edição de conteúdo” pronta:

- publicar tabela de operações e limitações por tipo de fonte/conteúdo;
- fornecer exemplos de overlay, alteração de formulário, substituição
  destrutiva e redação segura;
- explicar que substituição não implica refluxo de layout;
- explicar a diferença entre ocultar, achatar e remover;
- documentar impacto em assinaturas e tamanho do arquivo;
- adicionar seção de migração para usuários que hoje desenham diretamente em
  `PdfPage.graphics`.

## 11. Ordem recomendada e marcos

1. **Marco A — edição existente bem definida:** Fase 0.
2. **Marco B — núcleo lossless e seleção:** Fases 1 e 2.
3. **Marco C — editor visual público:** Fase 3.
4. **Marco D — texto realmente substituível:** Fase 4.
5. **Marco E — objetos gráficos:** Fase 5.
6. **Marco F — redação segura:** Fase 6.
7. **Marco G — API estável:** Fase 7 e documentação final.

As fases 0–3 formam o primeiro incremento de baixo risco e já tornam o suporte
de edição honesto e fácil de usar. A afirmação “edita texto existente” só deve
ser feita após o Marco D; “remove dados/redige com segurança”, somente após o
Marco F e sua auditoria negativa.
