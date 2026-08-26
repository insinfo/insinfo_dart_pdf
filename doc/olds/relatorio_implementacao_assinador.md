# Relatório de Implementação: Reconstrução do Assinador Serpro em Flutter

Este documento detalha o mapeamento técnico e as APIs necessárias para reconstruir as funcionalidades do "Serpro Assinador" (Java) utilizando a biblioteca `insinfo_dart_pdf` no Flutter.

## 1. Visão Geral da Arquitetura

O sistema original (Java) funciona como um processador de comandos baseado em requisições JSON. A migração deve seguir três pilares principais:

1.  **Modelo de Dados (DTO):** Recebimento dos parâmetros de assinatura.
2.  **Controlador de Fluxo:** Decisão entre assinar PDF (PAdES) ou Arquivos Genéricos (CAdES).
3.  **Motor de Assinatura:** Uso da `insinfo_dart_pdf` para criptografia e manipulação de arquivos.

---

## 2. API de Entrada de Dados (SignRequest)

A classe Java `SignRequest` é o ponto de entrada. Deve ser criada uma classe Dart equivalente para parsear o JSON de entrada.

### Campos Obrigatórios a Implementar
| Campo Java | Tipo | Descrição | Implementação Dart Sugerida |
|------------|------|-----------|-----------------------------|
| `type` | String | Define a estratégia (`PDF`, `file`, `text`, `hash`) | Enum `SignatureType { pdf, file, text, hash }` |
| `inputData` | List | Dados em Base64 ou Caminhos de arquivo | `List<String> inputData` |
| `outputDataType` | String | Formato de saída (`file` ou `base64`) | `OutputFormat outputFormat` |
| `attached` | boolean | Se a assinatura inclui o conteúdo (Attached) ou não (Detached) | `bool isAttached` (Apenas para CAdES) |
| `pdfInvisibleSignature` | boolean | Se falso, deve desenhar a estampa visual no PDF | `bool invisibleSignature` |
| `pdfStampPage`, `posX`, `posY` | int | Coordenadas da estampa visual | `int page, x, y` |
| `algorithm` | String | Algoritmo de hash (ex: SHA256) | `String hashAlgorithm` |

---

## 3. Estratégias de Implementação de Assinatura

O controlador principal (`Sign.java`) divide o fluxo baseando-se no `type`. Abaixo, as APIs da `insinfo_dart_pdf` mapeadas para cada caso.

### 3.1. Assinatura de PDF (PAdES)
**Origem Java:** `SignerPDF.java` e `WebIntegratedSignature.java`.

A biblioteca `insinfo_dart_pdf` possui suporte nativo robusto para isso.

**APIs a Implementar:**

1.  **Carregamento do Documento:**
    *   *API Dart:* `PdfDocument(inputBytes: bytes)`
2.  **Configuração da Assinatura:**
    *   *API Dart:* `PdfSigningSession`
    *   Deve-se configurar `PdfSignatureOptions` definindo `PdfSignatureType.signed`.
3.  **Estampa Visual (Opcional):**
    *   Se `pdfInvisibleSignature == false`, o código Java desenha uma imagem.
    *   *API Dart:* Acessar a página via `pdfDoc.pages[index]` e usar `page.graphics.drawImage(...)` para desenhar o selo do Serpro nas coordenadas `posX`/`posY`.
4.  **Criptografia:**
    *   Para certificado em arquivo (A1): Usar `PdfPkcs7Signer`.
    *   Para token (A3): Usar `PdfExternalSigning` (veja seção 4).

### 3.2. Assinatura Genérica (CAdES/CMS)
**Origem Java:** `Sign.java` (linhas 464-467) chamando métodos `doAttachedSign` ou `doDetachedSign`.

Utilizado quando `type` é "file", "text" ou "base64". O resultado é um arquivo `.p7s`.

**APIs a Implementar:**

1.  **Classe Principal:**
    *   *API Dart:* `PdfCmsSigner` (Localizada em `lib/src/pdf/implementation/security/digital_signature/pdf_cms_signer.dart`).
2.  **Modo Detached (Assinatura Destacada):**
    *   Onde o arquivo `.p7s` contém apenas a assinatura, não o arquivo original.
    *   *Método:* `PdfCmsSigner.signDetached(...)`.
3.  **Modo Attached (Assinatura Envelopada):**
    *   Onde o arquivo original fica embutido dentro do `.p7s`.
    *   *Método:* `PdfCmsSigner.signAttached(...)` (Verificar disponibilidade ou implementar wrapper usando `signDetached` e encapsulamento CMS manual se necessário, mas a lib geralmente suporta via configuração).
4.  **Tratamento de Input:**
    *   Se `type == text`: Converter String para Uint8List usando `utf8.encode()`.
    *   Se `type == base64`: Decodificar usando `base64Decode()`.

---

## 4. Integração com Tokens Hardware (A3/Java PKCS11)

Esta é a parte mais crítica da migração. O Java usa `SunPKCS11`. O Dart/Flutter não acessa hardware nativo diretamente sem plugins.

**Estratégia de Implementação:**

1.  **Interface de Assinatura Externa:**
    *   A `insinfo_dart_pdf` suporta assinaturas onde a chave privada não está na memória via `PdfExternalSigning`.
2.  **Callback de Assinatura:**
    *   Você deve implementar um método que receba o `digest` (hash) do documento calculado pela `insinfo_dart_pdf`.
    *   Este hash deve ser enviado para um Plugin Flutter (que precisará ser desenvolvido ou utilizado um existente como `mypkcs11` ou ponte C++) que conversa com o Token USB/SmartCard.
    *   O Plugin retorna a assinatura RSA bruta.
    *   A `insinfo_dart_pdf` embuta essa assinatura no PDF/CMS final.

---

## 5. Tabela de Mapeamento Direto (Java -> Dart)

| Funcionalidade Java | Classe/Método Java | Equivalente `insinfo_dart_pdf` |
|---------------------|--------------------|--------------------------------|
| Decodificar Base64 | `Base64Utils.base64Decode` | `dart:convert` (`base64Decode`) |
| Ler PDF | `PDDocument.load()` | `PdfDocument(inputBytes: ...)` |
| Criar Hash SHA256 | `MessageDigest.getInstance("SHA-256")` | `package:crypto` (`sha256.convert`) |
| Assinar PDF (Lógica) | `SignerPDF.doSigner` | `PdfSigningSession.sign` |
| Assinar CMS (P7S) | `PAdESSigner.doDetachedSign` | `PdfCmsSigner.signDetached` |
| Desenhar Selo Visual | `PDFRenderer` / `Graphics2D` | `PdfGraphics.drawImage` |
| Política de Assinatura | `PolicyFactory` | `PdfSignatureValidationOptions` (Configuração manual de OIDs) |

## 6. Próximos Passos Recomendados

1.  **Criar a classe `AssinadorService`:** Esta classe será o "Controller", recebendo o JSON do `SignRequest` e despachando para `AssinadorPdf` ou `AssinadorCms`.
2.  **Mockar Assinatura Externa:** Implementar, inicialmente, o `PdfExternalSigning` apontando para um arquivo `.p12` local para simular um Token, facilitando o desenvolvimento da lógica de PDF/CMS antes de lidar com a complexidade do hardware.
3.  **Validar Outputs:** Gerar arquivos assinados com a nova implementação e validá-los no próprio verificador do ITI (https://verificador.iti.gov.br/) para garantir conformidade com ICP-Brasil.
