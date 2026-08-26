# Relatório de Implementação e Correções (Git Diff)

**Projeto:** `insinfo_dart_pdf`  
**Branch:** `31.1.21-fix`  
**Base de análise:** `git status` + `git diff` (alterações não staged e arquivos untracked)  
**Data:** 2026-02-26

---

## 1) Resumo executivo

Foi implementado um conjunto de melhorias focado em:

1. **Conformidade ICP-Brasil** (LPA XML/DER, mapeamento de OIDs e aliases CAdES/XAdES).  
2. **Robustez de parsing ASN.1/DER** (com correção de `GeneralizedTime`).  
3. **Evidência de revogação mais detalhada** (fonte OCSP/CRL/mista/none).  
4. **Validação de cadeia offline reutilizável** (utilitário novo na biblioteca).  
5. **Compatibilidade Web x Server na API pública** (split para `pdf.dart` web-safe e `pdf_server.dart` server-only).  
6. **Cobertura de testes de integração real** com `test/assets/documento assinado erro.pdf`.

**Estatística geral (arquivos modificados):** `18 files changed, 1028 insertions(+), 762 deletions(-)`.

---

## 2) Alterações na biblioteca (núcleo)

### 2.1 API pública e compatibilidade plataforma

#### `lib/pdf.dart` (modificado)
- Removidos exports server-only da API principal:
  - `external_pdf_signature.dart`
  - `govbr_signature_api.dart`
  - `govbr_oauth.dart`
- Adicionado export de utilitário novo:
  - `OfflineCertificateChainBuilder`
- Objetivo: manter `pdf.dart` **web-safe**.

#### `lib/pdf_server.dart` (novo)
- Novo entrypoint server-side:
  - Reexporta `pdf.dart`
  - Expõe APIs com dependência de `dart:io`:
    - `PdfExternalSigning`, `PdfExternalSigningResult`
    - `GovBrSignatureApi`
    - `GovBrOAuthClient`
- Objetivo: preservar casos de uso backend sem quebrar consumidores web.

---

### 2.2 ICP-Brasil: parsing/mapeamento/política

#### `lib/src/pdf/implementation/security/digital_signature/icp_brasil/policy_oid_map_builder.dart` (novo)
Implementado builder de mapa OID→nome de política com:
- leitura de artefatos **XML e DER** em `assets/policy/engine/artifacts`;
- prioridade para nome derivado de `PolicyURI` (`policyUri > fallback`);
- fallback por extração de `urn:oid:` quando necessário;
- aplicação automática de aliases ICP-Brasil (famílias `1..5` ↔ `6..10`).

#### `lib/src/pdf/implementation/security/digital_signature/icp_brasil/policy_engine.dart` (modificado)
- Busca de política passou a aceitar OID original **ou alias ICP-Brasil equivalente**.
- Heurística de algoritmo para AD-RB v2 expandida para cobrir as duas famílias:
  - `2.16.76.1.7.1.1.2.*`
  - `2.16.76.1.7.1.6.2.*`
- Adicionadas funções auxiliares:
  - `_isAdRbV2Family(...)`
  - `_getIcpBrasilAliasOid(...)`.

#### `lib/src/pdf/implementation/security/digital_signature/icp_brasil/lpa.dart` (modificado)
- Harden do parser ASN.1 para estruturas DER com variações de sequência/tag.
- Melhorias de conversão de tempo (`GeneralizedTime` e `DerUtcTime`) em parse de LPA.
- Reforço de parse em:
  - `Lpa.fromAsn1(...)`
  - `PolicyInfo.fromAsn1(...)`
  - `PolicyDigest.fromAsn1(...)`
  - `SigningPeriod.fromAsn1(...)`.
- Remoção de dependência de `x509_time.dart` nesse fluxo específico.

#### `lib/src/pdf/implementation/security/digital_signature/asn1/asn1.dart` (modificado)
- Corrigido `GeneralizedTime.toDateTime()` para aceitar formato DER compacto:
  - `YYYYMMDDHHMMSSZ`
  - frações de segundo opcionais
  - offsets `+/-HHMM`
- Impacto direto: parse correto de datas em LPA DER real (`LPA_CAdES.der`).

---

### 2.3 Validação de assinatura e revogação

#### `lib/src/pdf/implementation/security/digital_signature/pdf_signature_validator.dart` (modificado)
- Estrutura `PdfRevocationResult` ganhou novo campo:
  - `source` (`ocsp`, `crl`, `mixed`, `none`)
- Fluxo de revogação passou a rastrear evidência observada (OCSP/CRL) e propagar no resultado.
- `toMap()` atualizado para serializar `source`.
- Resultado `good/unknown/revoked` agora inclui origem de evidência de forma consistente.

---

### 2.4 Utilitário reutilizável de cadeia completa offline

#### `lib/src/security/chain/offline_certificate_chain_builder.dart` (novo)
- API reutilizável para:
  - carregar pool de certificados por diretórios;
  - montar cadeia completa offline a partir do certificado do assinante.
- Construção da cadeia usando `X509Utils.findIssuer(...)`, com proteção contra loop e limite de profundidade.

#### `lib/src/security/chain/offline_certificate_chain_loader_io.dart` (novo)
- Implementação com `dart:io`:
  - varredura recursiva de `.der/.cer/.crt/.pem`;
  - detecção de PEM por conteúdo (`BEGIN CERTIFICATE`) além da extensão;
  - parse robusto para PEM e DER.

#### `lib/src/security/chain/offline_certificate_chain_loader_stub.dart` (novo)
- Stub para plataformas sem `dart:io` (ex.: web), lançando `UnsupportedError`.

**Arquitetura aplicada:** import condicional (`if (dart.library.io)`) para manter compatibilidade multiplataforma sem expor IO no entrypoint web-safe.

---

## 3) Alterações em testes e validação

### 3.1 Novos testes de integração ICP-Brasil

#### `test/documento_assinado_erro_integration_test.dart` (novo)
- Cenário **estrito**:
  - exige parse explícito de `LPA_CAdES.der`;
  - valida comportamento de política com digest/LPA sem fallback.
- Cenário **completo**:
  - valida campos de relatório (policy/timestamp/revogação/docMDP);
  - valida cadeia completa offline montada com truststores locais;
  - valida período de validade dos certificados no `signingTime`.
- Usa `assets/policy-engine-config-default.properties` para resolver artefato LPA CAdES.

#### `test/icp_brasil_lpa_xml_test.dart` (modificado)
- Adicionada cobertura de:
  - mapa OID com artefatos XML+DER;
  - alias CAdES/XAdES;
  - regressão de parse `LPA_CAdES.der` com OID `2.16.76.1.7.1.1.2.3`.

### 3.2 Ajustes de teste para novo campo de revogação

#### `test/pki_simulation/pki_simulation_test.dart` (modificado)
- Incluída asserção de origem de revogação:
  - `sig.revocationStatus.source == 'ocsp'`.

### 3.3 Migração de imports para entrypoint server

Arquivos que usam `PdfExternalSigning`/Gov.br foram atualizados de `package:dart_pdf/pdf.dart` para `package:dart_pdf/pdf_server.dart`:

- `benchmarks/external_signing_benchmark.dart`
- `scripts/govbr_pdf_sign_demo.dart`
- `scripts/generate_policy_mandated_timestamp_missing_pdf.dart`
- `test/external_signature_test.dart`
- `test/govbr_integration_test.dart`
- `test/govbr_integration_no_openssl_test.dart`
- `test/ltv_integration_test.dart`
- `test/pdf_signature_contents_reserve_test.dart`
- `test/pdf_signature_validator_test.dart`
- `test/pki_simulation/expanded_scenarios_test.dart`
- `test/security/external_signing_assets_integration_test.dart`

Observação: parte relevante das mudanças em alguns desses arquivos é de **formatação automática** (reflow/indentação), além da troca de import.

---

## 4) Novos artefatos de configuração e truststores

### 4.1 Arquivos adicionados em `assets/`
- `assets/cadeiasicpbrasil.bks`
- `assets/chain-icpbrasil-config-default.properties`
- `assets/chain-icpbrasil-config-default_pt_BR.properties`
- `assets/icpbrasil.jks`
- `assets/lets-encrypt-x3.jks`
- `assets/policy-engine-config-default.properties`
- `assets/servertruststore.jks`
- `assets/timestamp-config-default.properties`
- `assets/truststore/gov.br/cadeia_govbr_unica.jks`
- `assets/truststore/keystore_icp_brasil/` (diretório + conteúdo)

### 4.2 Novo asset de teste
- `test/assets/documento assinado erro.pdf`

Esses artefatos suportam cenários reais de validação ICP-Brasil e testes de integração offline.

---

## 5) Impacto funcional consolidado

1. **Maior aderência ICP-Brasil** ao interpretar políticas entre XML/DER e aliases de família OID.  
2. **Menor fragilidade de parse DER** com tempo ASN.1 em formato real de produção.  
3. **Diagnóstico de revogação mais auditável** com origem de evidência (`source`).  
4. **Reuso da montagem de cadeia offline** fora de testes (agora como utilitário de biblioteca).  
5. **API pública mais segura para Web** com separação clara entre entrypoint web-safe e server-only.

---

## 6) Inventário final (estado atual reportado)

### Arquivos modificados
- `benchmarks/external_signing_benchmark.dart`
- `lib/pdf.dart`
- `lib/src/pdf/implementation/security/digital_signature/asn1/asn1.dart`
- `lib/src/pdf/implementation/security/digital_signature/icp_brasil/lpa.dart`
- `lib/src/pdf/implementation/security/digital_signature/icp_brasil/policy_engine.dart`
- `lib/src/pdf/implementation/security/digital_signature/pdf_signature_validator.dart`
- `scripts/generate_policy_mandated_timestamp_missing_pdf.dart`
- `scripts/govbr_pdf_sign_demo.dart`
- `test/external_signature_test.dart`
- `test/govbr_integration_no_openssl_test.dart`
- `test/govbr_integration_test.dart`
- `test/icp_brasil_lpa_xml_test.dart`
- `test/ltv_integration_test.dart`
- `test/pdf_signature_contents_reserve_test.dart`
- `test/pdf_signature_validator_test.dart`
- `test/pki_simulation/expanded_scenarios_test.dart`
- `test/pki_simulation/pki_simulation_test.dart`
- `test/security/external_signing_assets_integration_test.dart`

### Arquivos novos
- `lib/pdf_server.dart`
- `lib/src/pdf/implementation/security/digital_signature/icp_brasil/policy_oid_map_builder.dart`
- `lib/src/security/chain/offline_certificate_chain_builder.dart`
- `lib/src/security/chain/offline_certificate_chain_loader_io.dart`
- `lib/src/security/chain/offline_certificate_chain_loader_stub.dart`
- `test/documento_assinado_erro_integration_test.dart`
- `test/assets/documento assinado erro.pdf`
- (demais assets/truststores/configs listados na seção 4)

---

## 7) Conclusão

O conjunto de mudanças implementa melhorias estruturais e funcionais relevantes na biblioteca para validação de assinatura digital em cenários ICP-Brasil, com evolução de robustez técnica, clareza diagnóstica e compatibilidade multiplataforma.

Recomendação de continuidade:
- manter `pdf.dart` como entrypoint web-safe;
- documentar no README quando usar `pdf_server.dart`;
- considerar etapa futura de reconciliação semântica fina com verificadores externos (ITI/Demoiselle) para casos de divergência de política/digest.
