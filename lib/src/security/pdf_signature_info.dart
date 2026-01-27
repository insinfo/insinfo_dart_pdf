import 'dart:typed_data';

import '../pdf/implementation/security/digital_signature/icp_brasil/lpa.dart';
import '../pdf/implementation/security/digital_signature/pdf_signature_validator.dart';
import 'chain/trusted_roots_provider.dart';
import 'pdf_signer_info.dart';


/// Resumo de validação de uma assinatura com metadados do assinante.
class PdfSignatureSummary {
  PdfSignatureSummary({
    required this.fieldName,
    required this.cmsSignatureValid,
    required this.byteRangeDigestOk,
    required this.documentIntact,
    required this.chainTrusted,
    required this.signingTime,
    required this.policyOid,
    required this.policyPresent,
    required this.policyDigestOk,
    required this.signer,
    required this.docMdp,
  });

  final String fieldName;
  final bool cmsSignatureValid;
  final bool byteRangeDigestOk;
  final bool documentIntact;
  final bool? chainTrusted;
  final DateTime? signingTime;
  final String? policyOid;
  final bool policyPresent;
  final bool? policyDigestOk;
  final PdfSignerInfo? signer;
  final PdfDocMdpInfo? docMdp;

  Map<String, dynamic> toMap() => <String, dynamic>{
        'field_name': fieldName,
        'cms_signature_valid': cmsSignatureValid,
        'byte_range_digest_ok': byteRangeDigestOk,
        'document_intact': documentIntact,
        'chain_trusted': chainTrusted,
        'signing_time': signingTime?.toIso8601String(),
        'policy_oid': policyOid,
        'policy_present': policyPresent,
        'policy_digest_ok': policyDigestOk,
        'signer': signer?.toMap(),
        'doc_mdp': docMdp?.toMap(),
      };

  static PdfSignatureSummary fromValidationItem(
    PdfSignatureValidationItem item,
  ) {
    return PdfSignatureSummary(
      fieldName: item.fieldName,
      cmsSignatureValid: item.validation.cmsSignatureValid,
      byteRangeDigestOk: item.validation.byteRangeDigestOk,
      documentIntact: item.validation.documentIntact,
      chainTrusted: item.chainTrusted,
      signingTime: item.validation.signingTime,
      policyOid: item.validation.policyOid,
      policyPresent: item.validation.policyPresent,
      policyDigestOk: item.validation.policyDigestOk,
      signer: PdfSignerInfo.fromCertificatesPem(item.validation.certsPem),
      docMdp: item.docMdp,
    );
  }
}

/// Relatório final com resumo das assinaturas encontradas.
class PdfSignatureInspectionReport {
  PdfSignatureInspectionReport({
    required this.allDocumentsIntact,
    required this.signatures,
  });

  final bool allDocumentsIntact;
  final List<PdfSignatureSummary> signatures;

  Map<String, dynamic> toMap() => <String, dynamic>{
        'all_documents_intact': allDocumentsIntact,
        'signatures': signatures.map((s) => s.toMap()).toList(growable: false),
      };
}

/// Fachada para validar assinaturas e extrair metadados do certificado.
class PdfSignatureInspector {
  Future<PdfSignatureInspectionReport> inspect(
    Uint8List pdfBytes, {
    List<String>? trustedRootsPem,
    TrustedRootsProvider? trustedRootsProvider,
    List<TrustedRootsProvider>? trustedRootsProviders,
    List<Uint8List>? crlBytes,
    bool fetchCrls = false,
    bool useEmbeddedIcpBrasil = false,
    bool strictRevocation = false,
    bool strictPolicyDigest = false,
    Lpa? lpa,
    Map<String, String>? policyXmlByOid,
  }) async {
    final PdfSignatureValidationReport report =
        await PdfSignatureValidator().validateAllSignatures(
      pdfBytes,
      trustedRootsPem: trustedRootsPem,
      trustedRootsProvider: trustedRootsProvider,
      trustedRootsProviders: trustedRootsProviders,
      crlBytes: crlBytes,
      fetchCrls: fetchCrls,
      useEmbeddedIcpBrasil: useEmbeddedIcpBrasil,
      strictRevocation: strictRevocation,
      strictPolicyDigest: strictPolicyDigest,
      lpa: lpa,
      policyXmlByOid: policyXmlByOid,
    );

    final List<PdfSignatureSummary> summaries = report.signatures
        .map((s) => PdfSignatureSummary.fromValidationItem(s))
        .toList(growable: false);

    return PdfSignatureInspectionReport(
      allDocumentsIntact: report.allDocumentsIntact,
      signatures: summaries,
    );
  }
}
