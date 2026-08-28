# Roteiro — Teto de memória: carregar e salvar sem duplicar o arquivo

> Alvo: `dart_pdf` (`c:\MyDartProjects\insinfo_dart_pdf`), branch `nova`.
> Escrito em 27/08/2026, depois de
> [roteiro_performance_recuperacao_xref.md](roteiro_performance_recuperacao_xref.md)
> fechar a recuperação de xref e deixar o teto de memória em aberto (§8.4).
> **Status: não implementado.** Este documento é o plano.

---

## 0. Resumo executivo

O roteiro anterior terminou dizendo que o teto de memória exigiria um leitor de
acesso aleatório sobre arquivo. Ao medir para escrever este, o diagnóstico ficou
diferente e melhor: **ter o arquivo em memória custa 1×, e não é o problema.**
São três andares, e os dois mais caros são baratos de consertar.

Medido sobre `14_34074_Vol 7.pdf`, 250 MB, 262 páginas:

| Etapa | RSS | Comentário |
|---|---|---|
| VM vazia | 490 MB | linha de base do Dart com a lib carregada |
| depois de ler o arquivo | 741 MB | **+251 MB — exatamente 1× o arquivo** |
| depois de abrir o documento | 745 MB | **+4 MB** — o parse é preguiçoso |
| depois de contar 262 páginas | 745 MB | +0 |
| depois de extrair 1 página | 786 MB | +41 MB |
| **depois de `saveSync()`** | **2818 MB** | **+2 GB**, pico de **3840 MB** |
| depois de `saveAsBytesSync()` | 1256 MB | +473 MB, pico de 1258 MB |

E, no mesmo arquivo, o efeito de **oito bytes de lixo depois do `%%EOF`**:

| Entrada | Tempo de carga | RSS adicional | Pico |
|---|---|---|---|
| limpo | **67 ms** | **+2 MB** | 744 MB |
| `GARBAGE\n` no fim | **3270 ms** | **+2010 MB** | 3006 MB |

Os três andares, em ordem de custo por esforço:

| # | Problema | Custo medido | Esforço |
|---|---|---|---|
| 1 | `readBytes` monta `List<int>` growable byte a byte | +2 GB e +3,2 s por 8 bytes de lixo | pequeno |
| 2 | `saveSync`/`save` acumulam a saída em `List<int>` growable | +1,5 GB sobre `saveAsBytesSync` | pequeno |
| 3 | Entrada e saída inteiras em RAM ao mesmo tempo | 1× cada | grande |

Os dois primeiros têm a mesma causa: **um `List<int>` growable no Dart de 64 bits
gasta 8 bytes por elemento.** Um PDF de 250 MB guardado num deles ocupa 2 GB. O
terceiro é o problema arquitetural que PDFBox, iText e MuPDF resolvem com um
leitor de acesso aleatório — e que o `pdf_plus` já resolveu em Dart.

---

## 1. Como reproduzir

Cada medição num processo separado; `ProcessInfo.currentRss` e `maxRss` dão RSS
atual e pico. Construir a entrada com spread (`<int>[...bytes, ...cauda]`)
**invalida a medição** — esse spread é ele próprio um `List<int>` growable, e
foi assim que a primeira tentativa acusou 6 GB de pico. Use `Uint8List` e
`setRange`.

```dart
final Uint8List clean = File(path).readAsBytesSync();
final Uint8List input = Uint8List(clean.length + 8)
  ..setRange(0, clean.length, clean)
  ..setRange(clean.length, clean.length + 8, 'GARBAGE\n'.codeUnits);
final int before = ProcessInfo.currentRss;
final PdfDocument d = PdfDocument(inputBytes: input);
print('rss +${(ProcessInfo.currentRss - before) ~/ 1048576}MB '
      'pico=${ProcessInfo.maxRss ~/ 1048576}MB paginas=${d.pages.count}');
```

---

## 2. Onde o custo está

### 2.1 Oito bytes de lixo custam 2 GB

Em [pdf_reader.dart](../lib/src/pdf/implementation/io/pdf_reader.dart):

```dart
List<int> readBytes(int length) {
  final List<int> bytes = List<int>.filled(length, 0, growable: true);
  for (int i = 0; i < length; i++) {
    bytes[i] = _read();          // byte a byte, por cima de um _read() com peek
  }
  return bytes;
}
```

`List<int>.filled(n, 0, growable: true)` é uma lista de objetos, não um buffer:
**8 bytes por elemento**. E o preenchimento é byte a byte, o que explica os
3,2 s.

O gatilho está em `CrossTable._initialize`
([cross_table.dart](../lib/src/pdf/implementation/io/cross_table.dart)): quando
existe qualquer coisa depois do último `%%EOF` que forme um token não vazio e
não comece com `0` ou NUL, o leitor decide reprocessar só o prefixo válido e
copia o arquivo inteiro:

```dart
reader.position = 0;
final List<int> buffer = reader.readBytes(endPosition + 5);   // <-- 8× o arquivo
reader = PdfReader(buffer);
```

Cauda com lixo é das coisas mais comuns em PDF do mundo real — anexo de
ferramenta que não limpou, download que grudou bytes, byte range copiado
errado. É a mesma família de dano que o roteiro anterior tratou; só que aqui não
falha, encarece.

`readBytes` tem 30 chamadas em 10 arquivos, então a troca precisa de uma
passada, mas o corpo do método é o mesmo em todas: alocar `Uint8List` e copiar
por faixa em vez de por byte.

### 2.2 O buffer de saída custa 8×, e o remédio já está no arquivo

[pdf_document.dart](../lib/src/pdf/implementation/pdf_document/pdf_document.dart):

```dart
List<int> saveSync() {
  final List<int> buffer = <int>[];        // growable: 8 bytes por byte de PDF
  final PdfWriter writer = PdfWriter(buffer);
  _saveDocument(writer);
  return writer.buffer!;
}

Uint8List saveAsBytesSync() {
  final PdfBytesBuilder buffer = PdfBytesBuilder();   // pedaços de Uint8List
  final PdfWriter writer = PdfWriter(null, buffer);
  _saveDocument(writer);
  return buffer.takeBytes();
}
```

`PdfWriter` já aceita as duas formas e `PdfBytesBuilder` já existe
([pdf_writer.dart](../lib/src/pdf/implementation/io/pdf_writer.dart)); é
`saveSync`/`save` que não usam. Quem chama `saveSync()` paga 2 GB onde
`saveAsBytesSync()` paga 473 MB, no mesmo documento.

Vale notar que mesmo o caminho bom guarda o documento duas vezes: os pedaços do
builder e o `Uint8List` final do `takeBytes()`. Daí os 473 MB para 250 MB de
saída — resolver isso é a fase 3.

### 2.3 A entrada, e a cópia que o save incremental faz dela

`_copyOldStream` escreve o documento original inteiro no writer antes de anexar
a revisão nova:

```dart
void _copyOldStream(PdfWriter writer) {
  writer.write(_data);
  _helper.isStreamCopied = true;
}
```

Correto por definição — é o que atualização incremental significa — mas quer
dizer que assinar um arquivo de 250 MB tem, no pico, o original em memória mais
a saída inteira em memória. É o caso de uso de produção do repositório, e é o
que a fase 3 elimina.

### 2.4 O que não custa

Abrir custou +4 MB e contar 262 páginas custou zero. O parse é preguiçoso e não
precisa mudar. Isso importa para o plano: **o teto não está na leitura de
objetos, está nos buffers.**

---

## 3. O que as referências fazem

Todas as quatro leem por acesso aleatório com uma janela pequena, e nenhuma
carrega o arquivo por padrão.

### 3.1 PDFBox — `RandomAccessRead`, páginas de 4 KB, LRU de 4 MB

`referencias/pdfbox-trunk/io/src/main/java/org/apache/pdfbox/io/`

A interface é mínima — cinco métodos, o suficiente para um parser:

```java
int read();
int read(byte[] b, int offset, int length);
long getPosition();
void seek(long position);
long length();
```

E vem com uma família de implementações: `RandomAccessReadBuffer` (memória),
`RandomAccessReadBufferedFile` (arquivo), `RandomAccessReadMemoryMappedFile`,
`RandomAccessReadView` (uma janela sobre outra) e `SequenceRandomAccessRead`.

`Loader.loadPDF(File)` usa `RandomAccessReadBufferedFile` — o arquivo **nunca**
é carregado inteiro. Ele pagina em 4 KB (`PAGE_SIZE_SHIFT = 12`) e mantém um
LRU de mil páginas (`MAX_CACHED_PAGES = 1000`), via `LinkedHashMap` com
`removeEldestEntry`. Teto: **4 MB**, independente do tamanho do arquivo.

PDFBox ainda expõe uma política explícita, `MemoryUsageSetting`, com
`setupMainMemoryOnly()`, `setupTempFileOnly()` e `setupMixed(maxMainMemoryBytes)`
— e um `ScratchFile` para guardar stream decodificado em disco em vez de RAM.

### 3.2 iText — `IRandomAccessSource`, e ler para memória é opt-in

`referencias/itext-dotnet-develop/itext/itext.io/itext/io/source/RandomAccessSourceFactory.cs:219`

```csharp
public IRandomAccessSource CreateBestSource(String filename) {
    ...
    if (forceRead) {
        return CreateByReadingToMemory(new FileStream(filename, ...));
    }
    return new RAFRandomAccessSource(new FileStream(filename, ...));
}
```

`forceRead` é `false` por padrão. Abrir um PDF por caminho não traz o arquivo
para a memória; é preciso pedir. A fábrica ainda compõe: `CreateRanged` monta
`WindowRandomAccessSource` sobre faixas e junta com `GroupedRandomAccessSource`
— exatamente o que uma validação de `/ByteRange` de assinatura quer.

### 3.3 MuPDF — `fz_stream` com 4 KB

`C:\MyDartProjects\pdf_plus\referencias\mupdf-master\source\fitz\stream-open.c:120`

```c
unsigned char buffer[4096];
```

Um buffer de 4 KB por stream aberto, e `fz_seek` sobre ele. É o que permite ao
`mutool` responder em ~1 s sobre um arquivo de 3 GB numa pasta de rede: os
bytes que ele não precisa **não são transferidos**.

### 3.4 pdf_plus — a mesma ideia, já em Dart

`C:\MyDartProjects\pdf_plus\lib\src\pdf\io\`

Três arquivos, e é o molde mais direto de portar porque já resolve as
peculiaridades do Dart:

```dart
abstract class PdfRandomAccessReader {
  int get length;
  Uint8List readRange(int offset, int length);
  Uint8List readAll();
  void close();
}
```

- `PdfMemoryRandomAccessReader` — sobre `Uint8List`, para web e arquivo pequeno;
- `PdfRandomAccessFileReader` — sobre `RandomAccessFile`, com `openSync`/`open`;
- `PdfCachedRandomAccessReader` — decorador com LRU por blocos de 256 KB,
  32 blocos, teto de **8 MB**.

### 3.5 Comparação

| | `dart_pdf` hoje | PDFBox | iText | MuPDF | pdf_plus |
|---|---|---|---|---|---|
| Abstração de entrada | nenhuma (`List<int>`) | `RandomAccessRead` | `IRandomAccessSource` | `fz_stream` | `PdfRandomAccessReader` |
| Padrão ao abrir arquivo | tudo em RAM | paginado | paginado | bufferizado | escolha do chamador |
| Janela | — | 4 KB × 1000 = 4 MB | por canal | 4 KB | 256 KB × 32 = 8 MB |
| Política explícita | — | `MemoryUsageSetting` | `SetForceRead` | — | — |
| Janela sobre faixa | — | `RandomAccessReadView` | `WindowRandomAccessSource` | — | — |

A última linha interessa mais do que parece aqui: validar `/ByteRange` de
assinatura é exatamente "leia estas duas faixas do arquivo", e hoje isso é feito
fatiando uma lista que está inteira em memória.

---

## 4. O plano

Quatro fases. As duas primeiras são independentes de tudo e entregam a maior
parte do ganho; as duas últimas são o trabalho arquitetural.

### Fase 1 — `readBytes` devolve `Uint8List` e copia por faixa

Em [pdf_reader.dart](../lib/src/pdf/implementation/io/pdf_reader.dart):

```dart
Uint8List readBytes(int length) {
  final Uint8List bytes = Uint8List(length);
  // copiar por faixa a partir de streamReader.data, respeitando o byte
  // já espiado (_bytePeeked), em vez de chamar _read() por byte
  ...
}
```

Trinta chamadas em dez arquivos; o tipo de retorno declarado (`List<int>`)
continua válido, porque `Uint8List` é um `List<int>`. O risco é chamador que
mutasse o resultado com `add`/`removeLast` — busca simples nos dez arquivos
resolve.

Ganho medido do gatilho que essa fase mata: de +2010 MB e 3270 ms para o mesmo
que o arquivo limpo, +2 MB e 67 ms.

### Fase 2 — `saveSync`/`save` usam `PdfBytesBuilder`

Trocar as quatro linhas de `saveSync()` e `save()` pelo que
`saveAsBytesSync()`/`saveAsBytes()` já fazem. Ganho: de 2818 MB para 1256 MB de
RSS, e de 3840 MB para 1258 MB de pico, num documento de 250 MB.

**Compatibilidade:** o retorno declarado continua `List<int>`, mas passa a ser
um `Uint8List` de tamanho fixo. Código que fizesse `saved.add(...)` quebraria.
É improvável — ninguém acrescenta bytes ao fim de um PDF salvo sem saber o que
está fazendo — mas é mudança de comportamento e merece uma linha no CHANGELOG.

Alternativa sem nenhum risco: deixar `saveSync` como está e documentar
`saveAsBytesSync` como o caminho recomendado. Não recomendo — significa manter
uma armadilha de 2 GB no método de nome mais óbvio.

### Fase 3 — salvar direto para um destino

`PdfDocument.saveToSink(IOSink)` / `saveToFile(String path)`, escrevendo os
pedaços conforme saem em vez de acumular. Elimina os 473 MB restantes da fase 2
e, junto com a fase 4, tira o pico de "original + saída" que assinar um arquivo
grande tem hoje (§2.3).

O `PdfWriter` já é uma interface (`IPdfWriter`) com `write`/`position`/`length`,
então o ponto de extensão existe. O obstáculo é `position` ser escrita durante o
save — um destino sequencial não permite voltar. Ver §6.

### Fase 4 — abstração de leitura

Introduzir a interface, no molde do `pdf_plus`, e fazer `PdfStreamReader` passar
a falar com ela em vez de com um `List<int>`:

```dart
abstract class PdfDataSource {
  int get length;
  int readByte(int offset);
  Uint8List readRange(int offset, int length);
}
```

Implementações: memória (embrulha o `inputBytes` de hoje, comportamento
inalterado), arquivo (`RandomAccessFile`) e cache LRU por blocos. Entrada nova:
`PdfDocument.fromFile(String path)`, com o cache ligado por padrão — é o
`Loader.loadPDF(File)` do PDFBox.

Quem toca `_data` diretamente e precisa passar pela abstração:
`PdfStreamReader.data`, `CrossTable._data`, `PdfCrossTable._data`,
`PdfDocument._data`, e o `PdfRepairScanner`, que hoje recebe o arquivo inteiro
como `Uint8List` — este último é o mais delicado, porque varrer por acesso
aleatório com janela é o que MuPDF faz e o que torna a recuperação de um arquivo
de 3 GB pela rede possível sem trazer os 3 GB.

---

## 5. Critério de aceite

**Nada muda de comportamento.** Os 1121 testes passam sem alteração depois das
fases 1 e 2. As fases 3 e 4 acrescentam API; o caminho de `inputBytes` continua
byte a byte idêntico.

**Testes de teto**, com documento sintético grande o bastante para a diferença
ser inequívoca e pequeno o bastante para a suíte — na linha do teste de tempo
que o roteiro anterior deixou em
[test/io/xref_repair_scan_test.dart](../test/io/xref_repair_scan_test.dart):

- carregar com lixo depois do `%%EOF` não pode custar mais RSS que carregar sem
  (fase 1);
- `saveSync` e `saveAsBytesSync` devem ficar dentro da mesma ordem de grandeza
  de RSS (fase 2);
- `PdfDocument.fromFile` sobre um arquivo de N MB deve terminar com RSS muito
  abaixo de N (fase 4).

Medir RSS em teste é ruidoso; valem os mesmos cuidados do teste de tempo — teto
folgado, e o número real no `reason` para quem for investigar. Onde der, prefira
asserção relativa (um caminho contra o outro no mesmo processo) a absoluta.

**A prova de verdade**, fora da suíte: abrir `14_34074_Vol 5.pdf` (3,0 GB) com
`fromFile` e contar as páginas com RSS na casa das dezenas de MB, e as 528
páginas que `mutool`, iText e PDFBox reportam.

---

## 6. Riscos

**`position` retroativa no writer.** O save escreve `writer.position` em mais de
um ponto — a tabela xref precisa de offsets que só se conhecem depois. Um
destino sequencial (fase 3) não permite voltar. Saídas: montar a xref em memória
e escrevê-la no fim (é o que ela já é, uma seção no fim do arquivo), ou manter
um buffer pequeno de reescrita. Investigar antes de prometer a fase 3.

**Assinatura digital depende de offsets absolutos.** `/ByteRange` cobre faixas
de bytes do arquivo final, e o cálculo assume poder ler e reler a saída. A fase
3 mexe justamente nisso. As três frentes de produção do repositório passam por
aqui, então a fase 3 pede a mesma verificação A/B por corpus que o roteiro de
recuperação usou.

**Custo de I/O por byte.** Trocar `List<int>` por leitor de arquivo troca acesso
de nanossegundos por chamada de sistema. É por isso que todas as referências têm
cache — sem ele, a fase 4 fica mais lenta que hoje. Os tamanhos de janela delas
(4 KB no PDFBox e MuPDF, 256 KB no `pdf_plus`) são o ponto de partida, não
chute.

**Web.** `dart:io` não existe no navegador. A abstração da fase 4 precisa deixar
a implementação de arquivo em um arquivo à parte, com importação condicional,
como o `pdf_plus` faz (`pdf_random_access_reader_io.dart`).

---

## 7. Ordem recomendada

As fases 1 e 2 valem por si e não dependem de nada: juntas tiram cerca de 4 GB
de pico de um fluxo que abre e salva um arquivo de 250 MB, e cabem numa tarde.
Faça-as primeiro, meça de novo, e só então decida se as fases 3 e 4 se pagam —
elas são semanas, não uma tarde, e o número que as justifica só fica claro
depois que as duas primeiras saírem da frente.
