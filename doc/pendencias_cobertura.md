# Pendências de cobertura de testes

> Alvo: `dart_pdf` (`c:\MyDartProjects\insinfo_dart_pdf`), branch `nova`.
> Escrito em 26/08/2026, depois da rodada que levou a cobertura de 39,5% para
> 53,2% e a suíte de 823 para 1080 testes.

Três frentes usadas em produção definem a prioridade: **extração de texto**,
**assinatura de PDF** e **merge**. O que está aqui é o que ficou de fora dessa
rodada, com o motivo — não é lista de desejos, é o que se sabe que falta e por
que ainda não foi feito.

Estado no fim da rodada:

| Frente | Cobertura | Observação |
|---|---|---|
| Merge | 93,5% | fechada em rodada anterior |
| Extração de texto | 79,2% | era 34,7% |
| Assinatura | 55,9% | era 45,4% |
| **Total da lib** | **53,2%** | era 39,5% |

O salto da extração não é só teste novo: `font_file2.dart` — a lista de glifos
da Adobe, 4.225 linhas — estava em 0% porque sua única chamada era
inalcançável — o `if` perguntava se uma chave estava ausente de um mapa que o
`if` de fora acabara de encontrar nela. Ligar esse caminho passou 4.218 linhas
de código morto a código exercitado, sozinho. Ver o commit `d803e5a` e
`test/exporting/font_encoding_test.dart`.

---

## 1. Vetores conhecidos para `MessageDigestFinder.getDigest`

**Onde:** `lib/src/pdf/implementation/security/digital_signature/cryptography/message_digest_utils.dart`
(1.303 linhas, 0% de cobertura).

**O que falta:** um teste de unidade chamando `getDigest` direto com vetores
conhecidos — SHA-1, SHA-256, SHA-384, SHA-512, MD5 e RIPEMD-160 contra os
valores publicados nos RFCs correspondentes.

**Por que importa:** as linhas 207 a 1303 — quase 1.100 das 1.303 — são uma
implementação de **RIPEMD-160 escrita à mão**, com as classes
`IMessageDigest`/`MessageDigest` existindo só para sustentá-la. Código
criptográfico escrito à mão e nunca exercitado é o tipo que erra em silêncio:
não estoura, devolve o hash errado.

**Por que ainda não foi feito:** é barato e vale, mas o retorno em cobertura
das três frentes é indireto — nenhum caminho de assinar ou validar passa por
ali (ver §2). Ficou atrás de trabalho com efeito mais direto.

**Cuidado ao fazer:** o único chamador da lib pede sempre SHA-1
(`CertificateIdentity.sha1`, o OID `1.3.14.3.2.26`), então de `getDigest` só a
primeira ramificação roda hoje. Um teste de vetores exercita as outras pela
primeira vez — se RIPEMD-160 estiver errado, é aí que aparece.

---

## 2. A cadeia OCSP

**Onde:** `lib/src/pdf/implementation/security/digital_signature/x509/ocsp_utils.dart`
(0% de cobertura) e os dois pontos em `pdf_pkcs_certificate.dart:3565` que são
os únicos consumidores de `message_digest_utils.dart`.

**A cadeia inteira, de cima para baixo:**

```
PdfSignature.createLongTermValidity()        ← única API pública que chega lá
  └─ PdfSignatureHelper.getDSSDetails(certs, type, ...)
       └─ Ocsp().getEncodedOcspResponse(cert, root)     ← só se type inclui OCSP
            └─ generateOcspRequest(issuer, serial)
                 └─ CertificateIdentity(sha1, issuer, serial)
                      └─ MessageDigestFinder().getDigest(...)
```

**Três consequências disso:**

1. **Não é exercitado ao assinar nem ao validar.** É só LTV — carimbar no
   documento a prova de que o certificado não estava revogado no momento da
   assinatura. Por isso `message_digest_utils.dart` continuou em 0% mesmo
   depois de o carregamento do PKCS#12 e a assinatura completa ganharem teste.
2. **Exige rede.** `getEncodedOcspResponse` faz POST para a URL de OCSP do
   certificado. Um teste que exercite isso de verdade sai para a internet.
3. **Não é injetável hoje.** `Ocsp` chama `fetchData` diretamente, sem
   passagem de transporte.

**O que fazer:** tornar o transporte injetável em `Ocsp` — um parâmetro
opcional com o `fetchData` atual como padrão — e então testar com um servidor
falso ou um duplo em memória. Sem isso, a única alternativa é um teste de
integração que depende de rede, o que quebra CI por motivos que não são da
biblioteca.

**Relacionado:** `revocation_signature_verifier.dart` também está em 0% e cai
na mesma categoria.

---

## 3. Capitular: o cursor de glifos ainda fica um à frente

**Onde:** `lib/src/pdf/implementation/exporting/pdf_text_extractor/pdf_text_extractor.dart`,
no método `_getTextLine` e nos auxiliares `_anchorGlyphs`/`_spellsWord`.

**Arquivos afetados** — nomeados em
`test/exporting/text_extraction_corpus_test.dart`, na constante
`_dropCapDocuments`, com o motivo escrito ao lado:

- `decisao-4874-assinada.pdf`
- `paginador (2).pdf`
- `paginador.pdf`

**O sintoma:** nesses três, um cabeçalho tem capitular — a primeira letra é um
elemento de texto próprio, num corpo maior (`P` em 13pt, `ÚBLICO` em 10,4pt).
Quando o elemento seguinte começa, o cursor de glifos já está uma posição à
frente, então a palavra `P` recebe o glifo `Ú`, a palavra `ÚBLICO` recebe
`BLICO `, e assim por diante. São **4 palavras** em todo o corpus de 54
arquivos. O texto das palavras e das linhas sai correto; o que fica errado é a
divisão por glifo do cabeçalho, e as bounds de glifo que saem do mesmo cursor.

**O que já foi tentado e por que não ficou:** a reancoragem do cursor busca só
para frente. Buscar também para trás recupera essas 4 palavras — mas parte
`PÚBLICO-GERAL` em três linhas (`ÚBLICO`, `-`, `GERAL`), que é a troca pior.
Medido contra a linha de base do corpus: para frente, 185 → 10 palavras com
glifos errados e uma única lista de linhas alterada, para melhor; para trás e
para frente, 185 → 4 mas com a regressão de agrupamento em um arquivo.

**Por onde atacar:** a causa não é a reancoragem, é o elemento *anterior*
consumir um glifo a mais quando há mudança de corpo no meio da linha. O
conserto certo é no avanço do cursor em `_getTextLine`, não na reancoragem.

**Cuidado ao fazer:** se este caso for consertado, os três nomes saem de
`_dropCapDocuments` e a asserção de glifo por palavra passa a valer para o
corpus inteiro. Se o conjunto precisar **crescer**, alguma coisa regrediu.

---

## Como verificar qualquer mexida no extrator

Antes de mudar qualquer coisa em `pdf_text_extractor/`, gravar uma linha de
base: para os 54 PDFs de `test/assets`, o `extractText` e a lista de textos de
`extractTextLines` das três primeiras páginas, em JSON. Depois da mudança,
gravar de novo e comparar.

O critério é `extractText` sair **byte a byte idêntico**; qualquer linha que
mude tem que ser inspecionada uma a uma e justificada como melhoria. Foi assim
que se descobriu a troca ruim da reancoragem para trás descrita em §3 — sem a
linha de base, teria passado como ganho.

A sonda precisa ser um `.dart` na raiz do repositório: fora dela o
`package:dart_pdf` não resolve.

---

## Áreas fora das três frentes

Descobertas e grandes, mas de prioridade menor justamente por estarem fora do
que se usa em produção. Ficam aqui só para não se perderem:

| Área | Cobertura | Linhas descobertas |
|---|---|---|
| `structured_elements` (grid) | 25,0% | 4.494 |
| `graphics` | 41,4% | 4.067 |
| `forms` | 43,0% | 4.030 |
| `annotations` | 39,7% | 3.956 |
| `pages` | 47,5% | 1.593 |
| `pdf_document` | 50,0% | 1.145 |

Dentro das frentes, o que ainda pesa por arquivo:

| Arquivo | Cobertura | Descobertas |
|---|---|---|
| `font_structure.dart` | 52,3% | 1.285 de 2.692 |
| `message_digest_utils.dart` | 0,0% | 739 de 739 (§1) |
| `asn1.dart` | 40,4% | 317 de 532 |
| `ocsp_utils.dart` | 0,0% | 299 de 299 (§2) |
