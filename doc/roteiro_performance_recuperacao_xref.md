# Roteiro — Performance da recuperação de xref danificada

> Alvo: `dart_pdf` (`c:\MyDartProjects\insinfo_dart_pdf`), branch `nova`.
> Escrito em 27/08/2026, depois de `PdfStrictnessLevel` tornar a recuperação
> opcional.
> **Status: implementado no mesmo dia.** As seções 0 a 6 são o diagnóstico e o
> plano, preservados porque documentam *por que* cada decisão foi tomada; a §8
> registra o que foi entregue e o que os números viraram.

---

## 0. Resumo executivo

A biblioteca sabe reconstruir a tabela de referência cruzada varrendo o arquivo
atrás de cabeçalhos de objeto — é o que `PdfStrictnessLevel.lenient` liga. O
resultado está correto. O custo é que **a varredura leva cerca de meio segundo
por megabyte**, o que a torna inutilizável exatamente nos arquivos em que ela
mais importa.

| Entrada | Recuperação |
|---|---|
| 8 MB | 4,3 s |
| 16 MB | 8,5 s |
| 32 MB | 16,8 s |
| 64 MB | 35,1 s |
| 250 MB | ~2 min (extrapolado) |
| 2,1 GB | ~19 min (estourou timeout de 590 s) |
| 3,0 GB | ~27 min (extrapolado) |

Linear, ~0,54 s/MB. Para comparação, no mesmo `Vol 5.pdf` de 3,0 GB:

| Ferramenta | Tempo |
|---|---|
| `mutool info` | quase instantâneo |
| `pdf_plus` (`tool/pdf_info.dart`) | 1,356 s de abertura/parse |
| `dart_pdf` hoje | ~27 min |

A diferença não é de constante, é de **modelo de execução**: a varredura desta
biblioteca trabalha sobre `String` de Dart. Ela monta cada linha do arquivo
concatenando caractere a caractere — o que é quadrático — e depois a fatia em
uma `String` por byte. Num PDF digitalizado, "linha" quer dizer o trecho de JPEG
entre dois `0x0A` acidentais, com centenas de kilobytes.

Quatro implementações de referência foram lidas — MuPDF, PDFBox, iText e o
`pdf_plus` — e as duas mais usadas do mundo foram **executadas sobre os mesmos
arquivos** (§1.2). O resultado separa dois problemas que eu tinha juntado:

> **Nenhuma referência aloca por byte.** É isso que separa esta biblioteca de
> PDFBox e iText — um fator de ~15×.
>
> **PDFBox e iText também varrem o arquivo inteiro** e levam de 56 s a 129 s
> nesses arquivos. O que separa *elas* do MuPDF — outro fator de ~60× — é pular
> o corpo dos streams, que num arquivo grande significa **nem sequer ler** a
> maior parte dos bytes.

Portanto são dois consertos, com ganhos multiplicativos e riscos bem diferentes:

| | Ganho | Alvo | Risco |
|---|---|---|---|
| Tirar a `String` do laço | ~19 min → ~1 min | PDFBox, iText | baixo |
| Pular corpo de stream | ~1 min → ~1-2 s | MuPDF, `pdf_plus` | depende do `/Length` |

O primeiro é trabalho localizado: uma função em
[pdf_parser.dart](../lib/src/pdf/implementation/io/pdf_parser.dart) e duas em
[cross_table.dart](../lib/src/pdf/implementation/io/cross_table.dart).

---

## 1. Como reproduzir a medição

O corpus usado foi `Z:\desenvolvimento\DIGITALIZADOS_SEMFAZ` — doze volumes de
processo digitalizado, de 251 MB a 2,99 GB, 14,9 GB no total. Dano de xref ali é
real e não é raro:

| Arquivo | Tamanho | Modo conservador |
|---|---|---|
| `Vol 7`, `Vol. 4_Fls. 2649 à 2891` | 251 MB | carrega, 262 páginas, 2 s |
| `Vol 3` | 409 MB | carrega, 489 páginas, 3 s |
| `Vol 1` | 437 MB | carrega, 457 páginas, 4 s |
| `Vol 4` | 464 MB | carrega, 472 páginas, 4 s |
| `Vol 2` | 505 MB | carrega, 467 páginas, 4 s |
| `Apenso …` | 619 MB | carrega, 557 páginas, 6 s |
| `Vol 1_Fls. 02 à 1667` | 1,8 GB | carrega, 1885 páginas, 17 s |
| **`Vol 6`** | **2,1 GB** | **`PdfFormatException`, 19 s** |
| `Vol 5`, `Vol. 2_Fls. …`, `Vol. 3_Fls. …` | 2,1–3,0 GB | não medidos |

O `Vol 5` também está danificado: rodado à mão, o `mutool info` reporta
`cannot find startxref` / `trying to repair broken xref` e ainda assim entrega
as 528 páginas. Os tempos acima são dominados por ler o arquivo do
compartilhamento de rede, não por parse — `Vol 6` gasta 19 s para chegar à
recusa, e praticamente todos eles são leitura.

Para medir a escala sem esperar meia hora, fatie um arquivo saudável e quebre o
`startxref` (apagá-lo com espaços basta, e evita materializar o arquivo como
`String`):

```dart
// Fatia o arquivo em N MB, apaga o ultimo `startxref` e cronometra a carga.
for (final int mb in <int>[8, 16, 32, 64]) {
  final Uint8List slice = breakStartxref(Uint8List.sublistView(full, 0, mb << 20));
  final Stopwatch sw = Stopwatch()..start();
  PdfDocument(inputBytes: slice, strictness: PdfStrictnessLevel.lenient).dispose();
  print('${mb}MB -> ${sw.elapsedMilliseconds}ms');
}
```

O ponto importante: **fatiar um PDF digitalizado é uma boa aproximação** porque
o custo é proporcional ao total de bytes varridos, não ao número de objetos. É
imagem que domina o arquivo, e é imagem que a varredura atual lê caractere a
caractere.

### 1.2 As implementações de referência, nos mesmos arquivos

PDFBox e iText foram executados sobre os dois volumes danificados, medindo a
mesma coisa que o teste de Dart mede: abrir o documento e contar as páginas.
O relógio é interno ao processo, então não inclui partida da JVM nem do .NET.

| | `Vol 6` — 2,1 GB, **disco local** | `Vol 5` — 3,0 GB, rede |
|---|---|---|
| iText 9.7.0 (.NET) | **56,5 s** — 463 páginas | **89,4 s** — 528 páginas |
| PDFBox 3.0.3 (Java) | **77,4 s** — 463 páginas | **129,2 s** — 528 páginas |
| MuPDF (`mutool info`) | — | ~1 s, 528 páginas ¹ |
| `pdf_plus` | — | 1,356 s de abertura/parse ¹ |
| `dart_pdf` conservador | recusa | recusa |
| `dart_pdf` lenient | ~19 min ² | ~27 min ² |

¹ Não cronometrado por mim: observação do operador e número que a própria
ferramenta reporta. Ambas leem o arquivo pela rede, como as demais.
² Extrapolado de 0,54 s/MB; a medição direta estourou o timeout de 590 s.

Três coisas que essa tabela estabelece:

**Os arquivos estão de fato danificados, e a varredura de força bruta rodou.**
O iText expõe isso na API, e nos dois arquivos respondeu `rebuiltXref=True`,
`fixedXref=False`. Não é suposição.

**A reconstrução concorda.** As três implementações independentes chegam a 463 e
528 páginas nos mesmos arquivos, e o 528 bate com o `mutool`. Isso vira o
gabarito do critério de aceite (§5.3).

**PDFBox e iText não são "rápidos" em termos absolutos** — um minuto ou dois num
arquivo desses. São ~15× mais rápidos que esta biblioteca, não 500×. Os 500×
são do MuPDF, e vêm de outro lugar: ele usa `fz_seek` para pular o corpo do
stream, e num arquivo de 3 GB pela rede isso significa **não transferir** a
maior parte dos bytes. iText e PDFBox leem os 3 GB inteiros; o MuPDF lê os
cabeçalhos. O `pdf_plus` prova que dá para fazer isso em Dart.

Os arreios usados estão descritos em §5.4 — são vinte linhas cada um.

---

## 2. Onde o tempo vai

Cinco causas, em ordem de peso. As três primeiras estão no mesmo laço.

### 2.1 `readLine()` concatena `String` byte a byte — quadrático por linha

[pdf_reader.dart:135](../lib/src/pdf/implementation/io/pdf_reader.dart#L135):

```dart
String readLine() {
  String line = '';
  int character = _read();
  while (character != -1 && !_isEol(String.fromCharCode(character))) {
    line += String.fromCharCode(character);   // <-- realoca a linha inteira
    character = _read();
  }
  ...
}
```

`line += c` cria uma `String` nova a cada byte: uma linha de comprimento *L*
custa O(*L*²) em cópia. Em texto isso é irrelevante — linhas de PDF têm dezenas
de bytes. Em dados DCT comprimidos, o byte `0x0A` aparece por acaso, e entre
duas ocorrências pode haver centenas de kilobytes. Cada uma dessas "linhas" é
paga ao quadrado.

Some-se a isso **duas `String` de um caractere alocadas por byte lido**: uma no
`String.fromCharCode` do `+=` e outra no `_isEol(String.fromCharCode(...))`.

### 2.2 `split('')` — uma `String` por byte da linha

[pdf_parser.dart:395](../lib/src/pdf/implementation/io/pdf_parser.dart#L395):

```dart
final List<String> tokens = str.split('');
```

Aloca uma lista com uma `String` de um caractere para **cada byte da linha**, e
usa exatamente dois elementos dela: `tokens[0]` e `tokens[1]`. Uma linha de
1 MB vira uma lista de um milhão de objetos para responder a duas perguntas que
se respondem com dois `int`.

Logo abaixo, `str.split(' ')` aloca outra lista para pegar três palavras.

### 2.3 O corpo do stream é varrido como texto

O laço de `rebuildXrefTable` não conhece `stream`/`endstream`. Ele encontra
`N G obj`, registra o offset e **continua lendo linha a linha** — inclusive os
megabytes de JPEG que vêm logo depois. Num volume digitalizado, mais de 99% dos
bytes do arquivo são corpo de stream, e portanto mais de 99% do trabalho é
desperdiçado.

Este item é real, mas **não é o que separa esta biblioteca de PDFBox e iText**:
elas também varrem tudo, e ainda assim levam ~1 min onde esta leva ~19. A
distância até elas é a `String` das §2.1 e §2.2.

O que este item vale está medido na §1.2: é a distância de PDFBox e iText até o
MuPDF, outro fator de ~60×. E num arquivo grande o ganho é maior do que "não
processar" — é **não ler**. `fz_seek` sobre o corpo do stream não transfere os
bytes; num arquivo de 3 GB pela rede, isso é a diferença entre mover 3 GB e
mover alguns megabytes.

### 2.4 `_recoverTrailer` varre para trás com uma `String` por posição

[cross_table.dart:401](../lib/src/pdf/implementation/io/cross_table.dart#L401)
usa `PdfReader.searchBack`, que em
[pdf_reader.dart:214](../lib/src/pdf/implementation/io/pdf_reader.dart#L214)
recua **um byte por vez** e, a cada passo, chama `_readBack`
([pdf_reader.dart:200](../lib/src/pdf/implementation/io/pdf_reader.dart#L200)),
que faz `String.fromCharCodes(readBytes(length))` e compara `String` com
`String`. Num arquivo cujo `trailer` foi truncado fora, isso é uma varredura
completa de trás para frente, com alocação por posição — e `_recoverTrailer`
repete a busca até oito vezes.

### 2.5 `_synthesizeTrailer` parseia objeto por objeto

[cross_table.dart:434](../lib/src/pdf/implementation/io/cross_table.dart#L434)
percorre os objetos reconstruídos do maior número para o menor chamando
`info.parser!.parseOffset(info.offset!)` em cada um, até achar um `/Type
/Catalog`. Em documento gerado por iText o catálogo costuma estar entre os
últimos objetos, então na prática para cedo — mas o pior caso é parsear todos.
Só entra em cena quando `_recoverTrailer` falha.

---

## 3. O que as referências fazem

### 3.1 MuPDF — `pdf_repair_xref_base`

`C:\MyDartProjects\pdf_plus\referencias\mupdf-master\source\pdf\pdf-repair.c`

O laço principal (linha ~490) não lê linhas: chama `pdf_lex_no_string` sobre o
arquivo e reage a *tokens*. Guarda os dois últimos inteiros vistos; quando o
token seguinte é `obj`, os dois inteiros anteriores eram o número e a geração do
objeto, e a posição do primeiro deles é o offset a registrar. O nome
`pdf_lex_no_string` é literal: no modo de reparo ele nem constrói o conteúdo das
strings do PDF, porque nada disso é necessário para achar cabeçalhos.

O salto de stream está em `pdf_repair_obj` (linha ~200):

```c
if (stm_len > 0)
{
    fz_seek(ctx, file, *stmofsp + stm_len, 0);   /* pula o corpo pelo /Length */
    tok = pdf_lex(ctx, file, buf);
    if (tok == PDF_TOK_ENDSTREAM)
        goto atobjend;                            /* confirmou: seguir em frente */
    fz_seek(ctx, file, *stmofsp, 0);              /* /Length mentiu: volta e varre */
}
/* fallback: janela deslizante de 9 bytes procurando "endstream" */
```

Duas coisas a copiar daqui:

1. **`/Length` é uma dica, não uma verdade.** Salta-se por ele e **verifica-se**
   se o token no destino é `endstream`. Só se a verificação falhar é que se
   varre.
2. **O fallback também é em bytes** — uma janela deslizante de 9 bytes com
   `memmove`, sem alocar nada.

### 3.2 pdf_plus — `_repairXrefByScan`

`C:\MyDartProjects\pdf_plus\lib\src\pdf\parsing\parser_xref.dart:922`

A mesma ideia, já em Dart, sobre `Uint8List`, o que a torna a referência mais
próxima de portar:

```dart
while (i < bytes.length) {
  i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
  if (PdfParserTokens.isDigit(bytes[i]) || bytes[i] == 0x2D || bytes[i] == 0x2B) {
    final num = PdfParserTokens.readInt(bytes, i, bytes.length);
    prevInt = lastInt; prevIntPos = lastIntPos;
    lastInt = num.value; lastIntPos = i;
    i = num.nextIndex;

    final j = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
    if (PdfParserTokens.matchToken(bytes, j, const <int>[0x6F, 0x62, 0x6A])) {  // 'obj'
      entries[prevInt] = XrefEntry(offset: prevIntPos, gen: lastInt, ...);
      final dictInfo = PdfParserScan.scanObjectDictAndSkipStream(bytes, j + 3);
      i = dictInfo.nextIndex;                    // <-- saltou o corpo do stream
      if (rootObj == null && dictInfo.isCatalog) rootObj = objId;
    }
    continue;
  }
  i++;
}
```

Nenhuma `String` é criada. E `scanObjectDictAndSkipStream`
(`parser_scan.dart:214`) faz duas coisas de uma vez: lê o dicionário
superficialmente — só o suficiente para extrair `/Length` e saber se o `/Type` é
`/Catalog`, limitado a uma janela de 4 KB — e salta o corpo. Ou seja, **o
catálogo é descoberto durante a varredura**, de graça, o que dispensa por
completo o `_synthesizeTrailer` da §2.5.

Vale notar também o `findRootFromTail`, chamado antes do laço: se o `/Root`
ainda estiver legível na cauda, o catálogo sai dali, e o resto da varredura só
precisa completar a tabela.

### 3.3 PDFBox — `BruteForceParser.bfSearchForObjects`

`referencias/pdfbox-trunk/pdfbox/src/main/java/org/apache/pdfbox/pdfparser/BruteForceParser.java:133`
(idêntico ao `COSParser` do 2.0.x, onde o método morava antes)

**PDFBox não pula corpo de stream** — e por isso leva 77 s no `Vol 6` (§1.2).
Ele varre o arquivo inteiro, byte a byte, do começo até o último `%%EOF`,
procurando a sequência `obj` precedida de espaço. Quando acha, anda para trás
sobre os dígitos para recuperar número e
geração. E mesmo assim é rápido, porque em nenhum momento constrói `String`:

```java
source.seek(currentOffset);
int nextChar = source.read();
currentOffset++;
if (BaseParser.isWhitespace(nextChar) && parser.isString(OBJ_MARKER))
```

`isString` (`COSParser.java:1527`) compara byte a byte contra um `char[]` e
volta o cursor — sem alocar nada. Os dois únicos arrays do método,
`"ndo".toCharArray()` e `"bj".toCharArray()`, são criados uma vez, fora do laço.

### 3.4 iText — `PdfReader.rebuildXref`

iText 5: `referencias/…/PdfReader.java:1838` · iText 7:
`referencias/itext-dotnet-develop/itext/itext.kernel/itext/kernel/pdf/PdfReader.cs:1428`
(o Java é linha por linha o mesmo)

Também varre o arquivo inteiro, também sem pular stream, também lendo "linhas".
A diferença com esta biblioteca está em **onde a linha é guardada**:

```csharp
ByteBuffer buffer = new ByteBuffer(24);      // uma vez, fora do laço
for (; ; ) {
    long pos = tokens.GetPosition();
    buffer.Reset();                          // reaproveita a capacidade
    if (!tokens.ReadLineSegment(buffer, true)) break;
    if (buffer.Get(0) == 't') { ... }        // comparação de byte
    else if (buffer.Get(0) >= '0' && buffer.Get(0) <= '9') {
        int[] obj = PdfTokenizer.CheckObjectStart(lineTokenizer);
```

E o detalhe que resolve o problema das linhas gigantes, em
`PdfTokenizer.ReadLineSegment`:

```csharp
// break loop? do it before we read() again
if (eol || buffer.Size() == buffer.Capacity()) {
    eol = true;
}
```

**O buffer é tampado na capacidade.** Cheio, ele para de guardar e drena o resto
da linha sem armazenar. Uma "linha" de 1 MB de JPEG custa 24 bytes guardados e
um laço de leitura crua. O iText 5 faz o mesmo com `byte line[] = new byte[64]`.

Ou seja: iText resolve exatamente o problema da §2.1 — e resolve por
construção, não por otimização. Um cabeçalho de objeto cabe em 24 bytes; o que
passa disso não interessa e não é guardado.

### 3.5 Comparação

| | `dart_pdf` hoje | MuPDF | pdf_plus | PDFBox | iText 5/7 |
|---|---|---|---|---|---|
| Unidade de trabalho | `String` por linha | token sobre bytes | índice em `Uint8List` | byte a byte | linha em buffer de bytes |
| Buffer de linha | `String` que cresce por concatenação | — | — | — | 64 B / 24 B, tampado |
| Alocação por byte | ≥ 3 objetos | zero | zero | zero | zero |
| Corpo de stream | varrido como texto | **saltado** por `/Length`, verificado | **saltado** por `/Length`, com fallback | varrido | varrido |
| Catálogo / trailer | parse posterior objeto a objeto | detectado na varredura | detectado na varredura | `rebuildTrailer` separado | `trailer` detectado na varredura |
| Se um objeto aparece duas vezes | vence o **primeiro** | vence o último | vence o de offset maior | vence o último | vence o de geração maior |
| Gerações ≠ 0 | **descartadas** | aceitas | aceitas | aceitas | aceitas |
| `Vol 6` (2,1 GB, local) | ~19 min | — | — | **77,4 s** | **56,5 s** |
| `Vol 5` (3,0 GB, rede) | ~27 min | ~1 s | 1,4 s | **129,2 s** | **89,4 s** |

Duas leituras da última linha, e as duas importam:

**Contra PDFBox e iText, a varredura completa não é o defeito — a `String` é.**
Elas varrem cada byte do arquivo, como esta, e são ~15× mais rápidas. A
diferença inteira está em não alocar.

**Contra o MuPDF, aí sim a varredura completa é o defeito.** Ele é ~60× mais
rápido que PDFBox e iText, e a única coisa que faz de diferente é pular o corpo
do stream. O `pdf_plus`, em Dart, chega ao mesmo lugar.

---

## 3.6 Uma divergência que não é de performance

As duas últimas linhas da tabela merecem atenção separada, porque são de
correção e as três referências concordam entre si e discordam desta biblioteca.

Em [pdf_parser.dart:395](../lib/src/pdf/implementation/io/pdf_parser.dart#L395):

```dart
if (marker == 0 && words[2] == PdfDictionaryProperties.obj) {   // so geracao 0
  ...
  if (!newObjects.containsKey(objNumber)) {                     // vence o primeiro
    newObjects[objNumber] = objectInfo;
  }
}
```

A varredura anda do início para o fim, então "vence o primeiro" quer dizer
**vence a revisão mais antiga**. Num PDF com atualização incremental — todo PDF
assinado é um — a definição válida de um objeto é a **última**. As referências:

| | Regra |
|---|---|
| iText 5 | `if (xr[num] == null \|\| gen >= xr[num][1])` → sobrescreve |
| iText 7 | `if (xref.Get(num) == null \|\| xref.Get(num).GetGenNumber() <= gen)` → sobrescreve |
| PDFBox | `bfSearchCOSObjectKeyOffsets.put(...)` num `HashMap` → o último vence |
| pdf_plus | `if (existing == null \|\| prevIntPos > existing.offset)` → offset maior vence |

E nenhuma delas descarta geração diferente de zero; o iText usa a geração
justamente como critério de desempate.

Consequência prática: um documento com histórico de revisões, recuperado por
varredura, é remontado com a versão **errada** de cada objeto que foi atualizado
— e sem nenhum dos objetos de geração não zero. Isso não aparece nos dez padrões
de dano do teste atual porque todos partem de um documento de revisão única.

Não é escopo deste roteiro, mas é a mesma função, e conserta-se junto com um
teste próprio: um documento com atualização incremental, danificado, cuja
recuperação tem que devolver o conteúdo da última revisão.

---

## 4. O plano

Quatro fases, independentes e cada uma entregável sozinha. **A fase 1 põe a
biblioteca no páreo com PDFBox e iText; a fase 4 a põe no páreo com o MuPDF.**
As duas do meio são correção e acabamento.

A ordem foi escolhida por risco, e a §3 é a razão: a fase 1 copia o que PDFBox e
iText fazem — varrer tudo, em bytes — que é o caminho comprovado e sem risco de
correção. Saltar corpo de stream é ganho extra, depende de confiar no `/Length`,
e por isso vem por último, depois de a suíte já estar verde sobre a base nova.

### Fase 1 — varredura sobre bytes, sem saltar nada

Reescrever `PdfParser.rebuildXrefTable`
([pdf_parser.dart:395](../lib/src/pdf/implementation/io/pdf_parser.dart#L395))
para operar sobre `Uint8List`. Duas formas equivalentes, ambas com referência:

- **Molde iText** (§3.4), o mais próximo do código atual: manter o laço de
  linhas, mas com buffer de bytes reutilizado e **tampado** — cheio, para de
  guardar e drena o resto da linha. É a menor mudança estrutural: o laço externo
  continua idêntico, só a origem da "linha" muda.
- **Molde pdf_plus/MuPDF** (§3.1, §3.2): abandonar linhas e andar por tokens,
  guardando os dois últimos inteiros e suas posições até topar com `obj`.
  Mais código, e prepara o terreno para a fase 4.

Recomendo o molde iText para a fase 1. O laço atual já está estruturado em
linhas, e trocar só o buffer mantém a mudança pequena o bastante para que os 65
testes de dano sejam prova suficiente.

O que sai, em qualquer dos dois: `PdfReader.readLine`, `str.split('')` e
`str.split(' ')`. O que entra: comparação de byte e leitura de inteiro sobre
índice.

**Não** mexer em `PdfReader.readLine`. Ele é usado em outros caminhos de parse
e trocá-lo é uma mudança de risco desproporcional a este roteiro; a fase 1 só
deixa de chamá-lo. Otimizá-lo continua valendo como trabalho separado — a
concatenação quadrática da §2.1 é um defeito onde quer que ela seja executada.

### Fase 2 — a divergência de semântica da §3.6

Passar a preferir a **última** ocorrência de cada número de objeto e a aceitar
gerações diferentes de zero, como fazem iText, PDFBox e pdf_plus. Precisa de
teste próprio: documento com atualização incremental, danificado, cuja
recuperação tem que devolver o conteúdo da última revisão. É correção, não
performance, e é independente da fase 1 — mas mexe na mesma função, então fazer
as duas na mesma passada economiza uma releitura.

### Fase 3 — trailer sem `String`

Trocar o `searchBack` de `_recoverTrailer`
([cross_table.dart:401](../lib/src/pdf/implementation/io/cross_table.dart#L401))
por uma busca de sequência de bytes de trás para frente. É a mesma técnica da
janela deslizante, e elimina a alocação por posição da §2.4.

Vale copiar daqui o que o iText faz de melhor: ele **encontra o `trailer`
durante a varredura** (`buffer.Get(0) == 't'` e `CheckTrailer`), em vez de
procurá-lo depois. Com a fase 1 no molde iText isso sai quase de graça.

### Fase 4 — saltar corpo de stream

Vem por último por causa do risco, não por ser pequena: é ela que separa MuPDF e
`pdf_plus` (~1 s) de PDFBox e iText (56 a 129 s) — outro fator de ~60× sobre o
que a fase 1 entrega. Se o alvo forem os volumes digitalizados do arquivo, a
fase 1 sozinha não basta: um minuto por arquivo ainda inviabiliza processar uma
pasta inteira.

O ganho não é só de CPU. `fz_seek` sobre o corpo do stream **não transfere os
bytes**; num arquivo de 3 GB numa pasta de rede, essa é a diferença entre mover
3 GB e mover alguns megabytes — e explica por que o MuPDF responde em ~1 s sobre
o mesmo `Z:` onde o iText leva 89 s.

Ler o dicionário superficialmente atrás de `/Length` e `/Type /Catalog` numa
janela limitada (4 KB no `pdf_plus`); ao ver `stream`, saltar `/Length` bytes e
**conferir** que o token de destino é `endstream`; se não for, voltar e varrer
com janela deslizante de 9 bytes. O catálogo detectado nesse passo alimenta
`_synthesizeTrailer`
([cross_table.dart:434](../lib/src/pdf/implementation/io/cross_table.dart#L434)),
que deixa de percorrer e parsear objetos (§2.5) — mantendo o laço atual como
fallback, e a preferência que hoje existe: entre dois catálogos vence o que tem
`/Pages`, porque um arquivo danificado pode carregar um catálogo vazio de uma
revisão anterior.

---

## 5. Critério de aceite

### 5.1 O que não pode mudar

Os 15 testes de [test/io/xref_repair_test.dart](../test/io/xref_repair_test.dart)
e os 50 de [test/merging/merge_damaged_input_test.dart](../test/merging/merge_damaged_input_test.dart)
passam sem alteração. Em especial os dez padrões de dano com verificação em três
frentes — carrega, mescla preservando o texto da página, e mescla ao lado de um
documento saudável — e as quatro entradas irrecuperáveis, que devem continuar
falhando com `PdfFormatException` sem travar.

`dart test` inteiro verde: 1107 testes.

### 5.2 O que precisa ser provado

Um teste de orçamento, com um PDF sintético grande o suficiente para que a
diferença seja inequívoca e pequeno o suficiente para rodar na suíte — algo como
16 MB de stream com `startxref` quebrado:

```dart
test('a recuperacao anda em bytes, nao em caracteres', () {
  final Stopwatch sw = Stopwatch()..start();
  PdfDocument(inputBytes: damaged16MB, strictness: PdfStrictnessLevel.lenient)
      .dispose();
  expect(sw.elapsedMilliseconds, lessThan(1000),
      reason: 'hoje custa ~8500ms; o alvo e ordem de grandeza, nao ajuste fino');
});
```

O limite generoso é proposital: o teste existe para pegar uma regressão de
modelo — alguém reintroduzir `String` no laço — não para medir a máquina de CI.
Na prática o teto ficou em 3000 ms, não em 1000: com 1000 ele falhou uma vez em
cada duas rodadas da suíte completa, por concorrência entre os processos de
teste. Um teste de relógio que falha por carga é ruído; o de agora ainda reprova
o modelo antigo (~11 s nessa entrada) com folga de quatro vezes.

### 5.4 Os arreios de comparação

Reproduzir os números da §1.2 leva alguns minutos. Nenhum dos dois passa de
vinte linhas, e ambos medem o mesmo que o teste de Dart: abrir e contar páginas,
com relógio interno ao processo.

**PDFBox** — basta o jar `pdfbox-app`, que já traz todas as dependências:

```bash
curl -o pdfbox-app.jar   https://repo1.maven.org/maven2/org/apache/pdfbox/pdfbox-app/3.0.3/pdfbox-app-3.0.3.jar
javac -cp pdfbox-app.jar -d . Bench.java     # JDK 25 em C:\Program Files\Java\jdk-25
java -Xmx8g -cp "pdfbox-app.jar;." Bench <arquivo.pdf>
```

```java
long t0 = System.nanoTime();
try (PDDocument doc = Loader.loadPDF(new File(args[0]))) {
  System.out.printf("load=%.2fs pages=%d%n",
      (System.nanoTime() - t0) / 1e9, doc.getNumberOfPages());
}
```

**iText** — projeto de console e o pacote `itext` do NuGet (9.7.0 na medição):

```bash
dotnet new console -o itbench && cd itbench && dotnet add package itext
dotnet run -c Release -- <arquivo.pdf>
```

```csharp
var sw = Stopwatch.StartNew();
var reader = new PdfReader(args[0]);
var doc = new PdfDocument(reader);
Console.WriteLine($"load={sw.Elapsed.TotalSeconds:F2}s pages={doc.GetNumberOfPages()} " +
                  $"rebuiltXref={reader.HasRebuiltXref()} fixedXref={reader.HasFixedXref()}");
```

O `HasRebuiltXref()` do iText é o que permite afirmar que a força bruta rodou,
em vez de supor. É exatamente o papel de `PdfDocument.wasRepaired` nesta
biblioteca.

### 5.3 A prova de verdade

`14_34074_Vol 6.pdf` (2,1 GB) e `14_34074_Vol 5.pdf` (3,0 GB) carregam com
`PdfStrictnessLevel.lenient` e devolvem **463 e 528 páginas** — os números em que
MuPDF, PDFBox e iText concordam (§1.2). O gabarito de tempo depende da fase: até
a fase 3, empatar com iText e PDFBox (~1 a 2 min) é o esperado; com a fase 4, o
alvo passa a ser a casa dos segundos. Isso não cabe na
suíte — é verificação manual, e o número do `mutool` é o gabarito.

---

## 6. Riscos

**Regressão silenciosa de correção.** A varredura é heurística: mudar a forma de
achar `N G obj` pode fazê-la achar coisas diferentes. O antídoto é a §5.1 — os
dez padrões de dano existem exatamente para isso, e cada um verifica conteúdo,
não só que carregou.

**`/Length` mentiroso — só a fase 4.** É comum, e é por isso que MuPDF verifica o
salto em vez de confiar nele. Pular esse passo troca lentidão por corrupção
silenciosa, que é pior. O fallback não é opcional. Vale lembrar que PDFBox e
iText evitam esse risco inteiro simplesmente não saltando — é o argumento para
a fase 4 ser a última, e opcional.

**`/Length` como referência indireta — só a fase 4.** `/Length 12 0 R` é legal e
aparece em arquivo gerado por iText. O `readDictLight` do pdf_plus já trata: se
depois do inteiro vier outro inteiro e um `R`, aquilo não é o comprimento. Sem
esse cuidado, salta-se para o lugar errado.

**O que está medido e o que não está.** PDFBox 3.0.3 e iText 9.7.0 foram lidos
*e executados* sobre os dois volumes danificados (§1.2, arreios em §5.4). Já os
números de MuPDF e `pdf_plus` são de terceiros — observação do operador e o
relógio da própria ferramenta — e servem de ordem de grandeza, não de medição
controlada. Os de `dart_pdf` acima de 64 MB são extrapolação de 0,54 s/MB.

**Arquivos acima de 2 GB.** Independente deste roteiro, o modelo de carregar o
documento inteiro em memória põe o RSS em cerca de duas vezes o tamanho do
arquivo — 2,6 GB para o `Vol 6`. A varredura em bytes não piora isso, mas também
não resolve; um leitor de acesso aleatório sobre arquivo, como o
`PdfRandomAccessReader` do pdf_plus, é outro roteiro.

---

## 7. Como escolher os modos

> Esta seção foi reescrita depois da implementação. A versão original mandava
> resolver arquivo grande com `mutool clean` fora do processo; não é mais
> necessário.

São dois eixos independentes, e a decisão de cada um é de natureza diferente.

**`PdfStrictnessLevel` é sobre integridade.** `conservative`, o padrão, é a
resposta certa para assinar: um documento cuja tabela de objetos a biblioteca
inventou é um documento que o próximo leitor pode ler de outro jeito. A recusa
é imediata — no `Vol 6` em disco local, a leitura dos 2,1 GB leva 1,03 s e a
recusa vem 0,02 s depois. Os 19 s da primeira medição eram a pasta de rede, não
a biblioteca. Use `lenient` onde a alternativa é perder o arquivo (merge,
extração, visualização), e cheque `wasRepaired` antes de tratar o resultado
como confiável.

**`PdfRepairScan` é sobre tempo.** `thorough`, o padrão, é a resposta que não
pode estar errada, e já é mais rápida que iText e PDFBox (§8.1). `skipStreams`
vale quando o volume manda: em documentos digitalizados de gigabytes a
diferença é de 15 s para 0,01 s por arquivo, e o que se abre mão é encontrar
cabeçalho de objeto escondido dentro do que o arquivo declara como stream.

A combinação padrão — `conservative` + `thorough` — é a que não surpreende
ninguém. Quem processa acervo quer `lenient` + `skipStreams` e um `wasRepaired`
registrado no log.

---

## 8. O que foi entregue

As quatro fases entraram de uma vez. `dart analyze` limpo, **1120 testes
verdes** (eram 1107; 14 novos em
[test/io/xref_repair_scan_test.dart](../test/io/xref_repair_scan_test.dart)).

### 8.1 Os números

Mesmo arreio da §1.2 — abrir e contar páginas, relógio interno ao processo:

| | `Vol 6` — 2,1 GB, disco local | `Vol 5` — 3,0 GB, rede |
|---|---|---|
| **antes** | **675,9 s, e falhava** | ~27 min (estimado) |
| iText 9.7.0 | 56,5 s | 89,4 s |
| PDFBox 3.0.3 | 77,4 s | 129,2 s |
| **agora, `thorough`** | **14,7 s** | **18,3 s** |
| **agora, `skipStreams`** | **0,01 s** | **0,01 s** |
| páginas | 463 — igual a iText e PDFBox | 528 — igual a `mutool` |

Duas coisas que a linha "antes" merece: os 675,9 s são medição direta em disco
local, não extrapolação, e o `FALHOU` no fim é literal — a varredura antiga
gastava onze minutos e ainda assim não remontava o documento. Não era só lenta.

O modo padrão ficou ~4× mais rápido que o iText e ~5× que o PDFBox, o que não
era o alvo: o alvo era empatar. A vantagem vem de a varredura já colher o
catálogo e os `trailer` de passagem (fase 3), poupando as passadas extras que
essas duas fazem depois.

### 8.2 O mapa entre o plano e o código

| Fase | O que entrou |
|---|---|
| 1 — bytes | [pdf_repair_scanner.dart](../lib/src/pdf/implementation/io/pdf_repair_scanner.dart), classe nova; `PdfParser.rebuildXrefTable` passou a delegar |
| 2 — semântica | vence a última ocorrência, e geração ≠ 0 é aceita — dentro do mesmo laço |
| 3 — trailer | `PdfRepairScanResult.trailerOffsets` e `.catalogNumber`, colhidos na passagem; `_recoverTrailer` e `_synthesizeTrailer` consomem |
| 4 — pular stream | `PdfRepairScan.skipStreams`, **desligado por padrão** |

O plano dizia para usar o molde iText na fase 1 (buffer tampado, laço de linhas
preservado). Acabou saindo o molde pdf_plus/MuPDF — índice sobre `Uint8List`,
sem linhas — porque a fase 4 precisava dele de qualquer forma, e manter duas
formas de varrer o mesmo arquivo seria pior do que escrever a definitiva uma
vez.

### 8.3 O que não estava no plano

**`PdfReader.searchBack` também alocava por posição.** A §2.4 tratava disso
como problema do `_recoverTrailer`, mas ele está no caminho principal: sem
`startxref`, `_initialize` varre o arquivo inteiro de trás para frente montando
uma `String` por posição, **antes** de a recuperação começar. Num arquivo de
16 MB isso sozinho custava ~3 s. Agora compara bytes.

**Apagar só o último `startxref` não força a recuperação.** Num arquivo com
atualização incremental, o leitor acha o `startxref` da revisão anterior, a
tabela dele ainda parseia, e o documento carrega — como a revisão antiga, em
silêncio, com `wasRepaired` em `false` porque de fato nada foi remendado. É
comportamento anterior a este roteiro e discutível, mas está registrado no
comentário do arreio de teste para quem for construir fixture de dano.

### 8.4 O que continua em aberto

A §6 segue valendo inteira. O teto de memória virou
[roteiro_teto_de_memoria.md](roteiro_teto_de_memoria.md), e medi-lo mudou o
diagnóstico que eu tinha deixado aqui: **ter o arquivo em memória custa 1×, não
2×, e não é o problema.** Abrir os 250 MB do `Vol 7` custa +251 MB de RSS e o
parse é preguiçoso — abrir e contar 262 páginas soma +4 MB. O que estoura são os
buffers: um `List<int>` growable no Dart gasta 8 bytes por elemento, e tanto o
buffer de saída de `saveSync` quanto a cópia que `readBytes` faz quando há lixo
depois do `%%EOF` são um desses. Oito bytes de lixo na cauda custam 2 GB.

A `skipStreams` continua sem resolver isso — ela evita *processar* os bytes, não
*ter* os bytes. O MuPDF responde em ~1 s sobre a pasta de rede porque também não
os **lê**, e alcançar isso segue exigindo leitor de acesso aleatório: é a fase 4
do roteiro novo.
