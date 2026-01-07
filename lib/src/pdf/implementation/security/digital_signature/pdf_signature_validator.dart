import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../../forms/pdf_signature_field.dart';
import '../../io/pdf_constants.dart';
import '../../io/pdf_cross_table.dart';
import '../../pdf_document/pdf_document.dart';
import '../../primitives/pdf_array.dart';
import '../../primitives/pdf_dictionary.dart';
import '../../primitives/pdf_name.dart';
import '../../primitives/pdf_number.dart';
import '../../primitives/pdf_reference.dart';
import '../../primitives/pdf_reference_holder.dart';
import '../../primitives/pdf_stream.dart';
import '../../primitives/pdf_string.dart';
import 'kms/revocation_data_client.dart';
import 'pdf_signature_validation.dart';
import 'pdf_signature_utils.dart';
import 'asn1/asn1.dart';
import 'asn1/asn1_stream.dart';
import 'asn1/der.dart';
import '../../io/stream_reader.dart';
import 'x509/ocsp.dart';
import 'icp_brasil/lpa.dart';
import 'icp_brasil/policy_engine.dart';
import 'x509/x509_certificates.dart';
import 'x509/x509_crl.dart';
import 'x509/x509_utils.dart';
import '../../../../security/chain/icp_brasil_provider.dart';
import '../../../../security/chain/iti_provider.dart';
import '../../../../security/chain/serpro_provider.dart';
import '../../../../security/chain/trusted_roots_provider.dart';

class PdfLtvInfo {
  const PdfLtvInfo({
    required this.hasDss,
    required this.signatureHasVri,
    required this.dssCertsCount,
    required this.dssOcspsCount,
    required this.dssCrlsCount,
  });

  final bool hasDss;
  final bool signatureHasVri;
  final int dssCertsCount;
  final int dssOcspsCount;
  final int dssCrlsCount;

  Map<String, dynamic> toMap() => <String, dynamic>{
        'has_dss': hasDss,
        'signature_has_vri': signatureHasVri,
        'dss_certs_count': dssCertsCount,
        'dss_ocsps_count': dssOcspsCount,
        'dss_crls_count': dssCrlsCount,
      };
}

class PdfLtvSelfCheckResult {
  const PdfLtvSelfCheckResult({
    required this.offlineSufficient,
    required this.issues,
    required this.cmsCertsCount,
    required this.dssCertsMatchedCount,
    required this.vriHasCerts,
    required this.vriHasOcsp,
    required this.vriHasCrl,
  });

  final bool offlineSufficient;
  final List<String> issues;
  final int cmsCertsCount;
  final int dssCertsMatchedCount;
  final bool vriHasCerts;
  final bool vriHasOcsp;
  final bool vriHasCrl;

  Map<String, dynamic> toMap() => <String, dynamic>{
        'offline_sufficient': offlineSufficient,
        'issues': issues,
        'cms_certs_count': cmsCertsCount,
        'dss_certs_matched_count': dssCertsMatchedCount,
        'vri_has_certs': vriHasCerts,
        'vri_has_ocsp': vriHasOcsp,
        'vri_has_crl': vriHasCrl,
      };
}

class PdfDocMdpInfo {
  const PdfDocMdpInfo({
    required this.isCertificationSignature,
    required this.permissionP,
  });

  final bool isCertificationSignature;
  final int? permissionP;

  Map<String, dynamic> toMap() => <String, dynamic>{
        'is_certification_signature': isCertificationSignature,
        'permission_p': permissionP,
      };
}

/// Status of revocation check for a certificate chain.
class PdfRevocationResult {
  const PdfRevocationResult({
    required this.isRevoked,
    required this.status,
    this.details,
  });

  final bool isRevoked;

  /// 'good', 'revoked', 'unknown'
  final String status;
  final String? details;

  Map<String, dynamic> toMap() => <String, dynamic>{
        'is_revoked': isRevoked,
        'status': status,
        'details': details,
      };
}

class PdfPolicyStatus {
  const PdfPolicyStatus(
      {required this.valid, this.error, this.warning, this.policyOid});
  final bool valid;
  final String? error;
  final String? warning;
  final String? policyOid;

  Map<String, dynamic> toMap() =>
      {'valid': valid, 'error': error, 'warning': warning, 'oid': policyOid};
}

class PdfTimestampStatus {
  const PdfTimestampStatus({
    required this.present,
    required this.valid,
    this.genTime,
    this.messageImprintOk,
    this.tokenSignatureValid,
    this.policyOid,
    this.nonce,
    this.chainTrusted,
    this.chainErrors,
    this.revocationStatus,
    this.errors = const <String>[],
  });

  final bool present;
  final bool valid;
  final DateTime? genTime;
  final bool? messageImprintOk;
  final bool? tokenSignatureValid;
  final String? policyOid;
  final String? nonce;
  final bool? chainTrusted;
  final List<String>? chainErrors;
  final PdfRevocationResult? revocationStatus;
  final List<String> errors;

  Map<String, dynamic> toMap() => <String, dynamic>{
        'present': present,
        'valid': valid,
        'gen_time': genTime?.toUtc().toIso8601String(),
        'message_imprint_ok': messageImprintOk,
        'token_signature_valid': tokenSignatureValid,
        'policy_oid': policyOid,
        'nonce': nonce,
        'chain_trusted': chainTrusted,
        'chain_errors': chainErrors,
        'revocation_status': revocationStatus?.toMap(),
        'errors': errors,
      };
}

class PdfSignatureValidationItem {
  PdfSignatureValidationItem({
    required this.fieldName,
    required this.byteRange,
    required this.signedRevisionLength,
    required this.coversCurrentFile,
    required this.contentsStart,
    required this.contentsEnd,
    required this.validation,
    required this.chainTrusted,
    this.chainErrors,
    required this.docMdp,
    required this.ltv,
    this.ltvSelfCheck,
    required this.revocationStatus,
    this.policyStatus,
    this.timestampStatus,
  });

  final String fieldName;
  final List<int> byteRange;
  final int signedRevisionLength;
  final bool coversCurrentFile;

  /// Start index (inclusive) of the /Contents hex payload in the original PDF.
  ///
  /// This is best-effort and may be null if not found.
  final int? contentsStart;

  /// End index (exclusive) of the /Contents hex payload in the original PDF.
  final int? contentsEnd;

  final PdfSignatureValidationResult validation;

  /// True when the certificate chain validates up to one of [trustedRootsPem].
  /// Null when no trusted roots are provided.
  final bool? chainTrusted;

  /// When [chainTrusted] is false, this may contain error codes describing why.
  ///
  /// Null when chain trust was not evaluated.
  final List<String>? chainErrors;

  final PdfDocMdpInfo docMdp;
  final PdfLtvInfo ltv;

  /// Best-effort audit of whether DSS/VRI seems sufficient for offline validation.
  ///
  /// Null when the PDF has no DSS.
  final PdfLtvSelfCheckResult? ltvSelfCheck;

  final PdfRevocationResult revocationStatus;

  final PdfPolicyStatus? policyStatus;

  final PdfTimestampStatus? timestampStatus;

  Map<String, dynamic> toMap() => <String, dynamic>{
        'field_name': fieldName,
        'byte_range': byteRange,
        'signed_revision_length': signedRevisionLength,
        'covers_current_file': coversCurrentFile,
        'contents_start': contentsStart,
        'contents_end': contentsEnd,
        'cms_signature_valid': validation.cmsSignatureValid,
        'byte_range_digest_ok': validation.byteRangeDigestOk,
        'document_intact': validation.documentIntact,
        'certs_pem':
            validation.certsPem.length, // Avoid dumping all certs in map
        'policy_oid': validation.policyOid,
        'chain_trusted': chainTrusted,
        'chain_errors': chainErrors,
        'doc_mdp': docMdp.toMap(),
        'ltv': ltv.toMap(),
        'ltv_self_check': ltvSelfCheck?.toMap(),
        'revocation_status': revocationStatus.toMap(),
        'policy_status': policyStatus?.toMap(),
        'timestamp_status': timestampStatus?.toMap(),
      };
}

class PdfSignatureValidationReport {
  PdfSignatureValidationReport({required this.signatures});

  final List<PdfSignatureValidationItem> signatures;

  bool get allDocumentsIntact =>
      signatures.isNotEmpty &&
      signatures.every((s) => s.validation.documentIntact);

  Map<String, dynamic> toMap() => <String, dynamic>{
        'all_documents_intact': allDocumentsIntact,
        'signatures': signatures.map((s) => s.toMap()).toList(growable: false),
      };

  String toJson() => jsonEncode(toMap());
}

class PdfSignatureValidator {
  /// Validates all signatures in the PDF, performing integrity, trust, and revocation checks.
  ///
  /// [pdfBytes]: The PDF file content.
  /// [trustedRootsPem]: List of trusted CA certificates in PEM format.
  /// [crlBytes]: Optional list of CRLs (DER or PEM bytes) to use for revocation checking.
  /// [fetchCrls]: If true, tries to download CRLs from Distribution Points in certificates.
  /// [useEmbeddedIcpBrasil]: If true, adds the built-in ICP-Brasil trusted roots to the verification anchors.
  /// [strictRevocation]: If true, only returns revocation status 'good' when OCSP/CRL evidence is
  /// validated (signature + time window). When false, revocation checking is best-effort.
  Future<PdfSignatureValidationReport> validateAllSignatures(
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
  }) async {
    final PdfDocument doc = PdfDocument(inputBytes: pdfBytes);
    try {
      final _CatalogInfo catalogInfo = _readCatalogInfo(doc);
      final List<_ParsedSignature> sigs = _extractAllSignatures(doc);
      sigs.sort(
          (a, b) => a.signedRevisionLength.compareTo(b.signedRevisionLength));

      final PdfSignatureValidation cmsValidator = PdfSignatureValidation();
      final List<PdfSignatureValidationItem> out =
          <PdfSignatureValidationItem>[];

      final List<String> effectiveRoots = <String>[];
      final List<String> extraCandidatesPem = <String>[];
      if (trustedRootsPem != null) {
        effectiveRoots.addAll(trustedRootsPem);
      }

      bool isSelfSigned(X509Certificate cert) {
        final String? subject = cert.c?.subject?.toString();
        final String? issuer = cert.c?.issuer?.toString();
        if (subject == null || issuer == null || subject != issuer) {
          return false;
        }
        try {
          cert.verify(cert.getPublicKey());
          return true;
        } catch (_) {
          return false;
        }
      }

      Future<void> addRootsFromProvider(TrustedRootsProvider provider) async {
        final List<Uint8List> ders = await provider.getTrustedRootsDer();
        for (final Uint8List der in ders) {
          final String pem = X509Utils.derToPem(der);
          extraCandidatesPem.add(pem);
          try {
            final X509Certificate cert = X509Utils.parsePemCertificate(pem);
            if (isSelfSigned(cert)) {
              effectiveRoots.add(pem);
            }
          } catch (_) {
            // ignore invalid certs
          }
        }
      }

      if (trustedRootsProvider != null) {
        await addRootsFromProvider(trustedRootsProvider);
      }
      if (trustedRootsProviders != null && trustedRootsProviders.isNotEmpty) {
        for (final TrustedRootsProvider p in trustedRootsProviders) {
          await addRootsFromProvider(p);
        }
      }
      if (useEmbeddedIcpBrasil) {
        // Trust anchors embutidos (roots) para ICP-Brasil / ITI / Serpro.
        final IcpBrasilProvider icpProvider = IcpBrasilProvider();
        final ItiProvider itiProvider = ItiProvider();
        final SerproProvider serproProvider = SerproProvider();

        final List<Uint8List> icpRootsDer = await icpProvider.getTrustedRoots();
        final List<Uint8List> itiRootsDer = await itiProvider.getTrustedRoots();
        final List<Uint8List> serproRootsDer =
            await serproProvider.getTrustedRoots();

        for (final Uint8List der in <Uint8List>[
          ...icpRootsDer,
          ...itiRootsDer,
          ...serproRootsDer
        ]) {
          final String pem = X509Utils.derToPem(der);
          extraCandidatesPem.add(pem);
          try {
            final X509Certificate cert = X509Utils.parsePemCertificate(pem);
            if (isSelfSigned(cert)) {
              effectiveRoots.add(pem);
            }
          } catch (_) {
            // ignore invalid embedded certs
          }
        }
      }

      // Prepare CRLs
      final List<X509Crl> loadedCrls = <X509Crl>[];
      if (crlBytes != null) {
        for (final Uint8List bytes in crlBytes) {
          final X509Crl? parsed = X509Crl.fromBytes(bytes);
          if (parsed != null) loadedCrls.add(parsed);
        }
      }

      // Prepare Roots Objects
      final List<X509Certificate> roots = <X509Certificate>[];
      for (final String r in effectiveRoots) {
        try {
          roots.add(X509Utils.parsePemCertificate(r));
        } catch (_) {}
      }

      for (final _ParsedSignature sig in sigs) {
        final PdfSignatureValidationResult res =
            cmsValidator.validateDetachedSignature(
          pdfBytes,
          signatureName: sig.fieldName,
          byteRange: sig.byteRange,
          pkcs7DerBytes: sig.pkcs7Der,
        );

        bool? chainTrusted;
        List<String>? chainErrors;
        if (effectiveRoots.isNotEmpty) {
          final X509ChainValidationResult chainResult =
              X509Utils.verifyChainPem(
            chainPem: res.certsPem,
            trustedRootsPem: effectiveRoots,
            extraCandidatesPem: extraCandidatesPem,
            validationTime: res.signingTime,
          );
          chainTrusted = chainResult.trusted;
          chainErrors = chainResult.errors;

          // If chain validation fails and online fetching is allowed, try to augment
          // intermediates from AIA (CA Issuers) similar to PDFBox's CertInformationCollector.
          if (fetchCrls && chainTrusted == false && res.certsPem.isNotEmpty) {
            try {
              final X509Certificate leaf =
                  X509Utils.parsePemCertificate(res.certsPem.first);
              final List<String> fetchedPem =
                  await RevocationDataClient.fetchCaIssuersCertificatesPem(
                      leaf);
              if (fetchedPem.isNotEmpty) {
                extraCandidatesPem.addAll(fetchedPem);
                final X509ChainValidationResult retry =
                    X509Utils.verifyChainPem(
                  chainPem: res.certsPem,
                  trustedRootsPem: effectiveRoots,
                  extraCandidatesPem: extraCandidatesPem,
                  validationTime: res.signingTime,
                );
                chainTrusted = retry.trusted;
                chainErrors = retry.errors;
              }
            } catch (_) {
              // ignore
            }
          }
        }

        // Revocation Check
        final DateTime revocationTime =
            (res.signingTime ?? DateTime.now()).toUtc();
        final PdfRevocationResult revStatus = await _checkRevocation(
          res.certsPem,
          roots,
          loadedCrls,
          fetchCrls: fetchCrls,
          strict: strictRevocation,
          validationTime: revocationTime,
        );

        // Policy Check
        PdfPolicyStatus? policyStatus;
        if (res.policyOid != null) {
          final IcpBrasilPolicyEngine engine = IcpBrasilPolicyEngine(lpa);
          final DateTime checkTime = res.signingTime ?? DateTime.now();
          PolicyValidationResult polRes = engine.validatePolicyWithDigest(
            res.policyOid!,
            checkTime,
            policyHashAlgorithmOid: res.policyHashAlgorithmOid,
            policyHashValue: res.policyHashValue,
            strictDigest: strictPolicyDigest,
          );

          // Check algorithm constraints if policy is otherwise valid
          if (polRes.isValid && res.digestAlgorithmOid != null) {
            final PolicyValidationResult algoRes = engine.validateAlgorithm(
                res.policyOid!, res.digestAlgorithmOid!, checkTime);
            if (!algoRes.isValid) {
              // Algorithm invalid: override result
              polRes = algoRes;
            }
          }

          policyStatus = PdfPolicyStatus(
            valid: polRes.isValid,
            error: polRes.error,
            warning: polRes.warning,
            policyOid: res.policyOid,
          );
        }

        // RFC3161 Timestamp Check (PAdES-T unsigned attribute)
        final PdfTimestampStatus tsStatus = await _validateRfc3161Timestamp(
          signatureCmsDer: sig.pkcs7Der,
          trustedRootsPem: effectiveRoots,
          extraCandidatesPem: extraCandidatesPem,
          roots: roots,
          loadedCrls: loadedCrls,
          fetchCrls: fetchCrls,
          strictRevocation: strictRevocation,
        );

        // ByteRange/Contents positions
        final PdfSignatureOffsets? preciseOffsets = sig.signatureRef != null
            ? PdfSignatureUtils.resolveOffsets(
                doc: doc,
                pdfBytes: pdfBytes,
                signatureReference: sig.signatureRef!,
              )
            : null;

        int? cStart = preciseOffsets?.contentsOffsets[0];
        int? cEnd = preciseOffsets?.contentsOffsets[1];

        if (cStart == null) {
          final _ContentsRange? cr = _findContentsRangeInGap(
            pdfBytes,
            sig.byteRange,
          );
          cStart = cr?.start;
          cEnd = cr?.end;
        }

        final PdfDocMdpInfo docMdp = PdfDocMdpInfo(
          isCertificationSignature: catalogInfo.docMdpRef != null &&
              sig.signatureRef != null &&
              _sameReference(catalogInfo.docMdpRef!, sig.signatureRef!),
          permissionP: _extractDocMdpP(sig.signatureDict),
        );

        final PdfLtvInfo ltv = _computeLtvInfo(
          catalogInfo: catalogInfo,
          signaturePkcs7Der: sig.pkcs7Der,
        );

        final PdfLtvSelfCheckResult? ltvSelfCheck = _computeLtvSelfCheck(
          catalogInfo: catalogInfo,
          signaturePkcs7Der: sig.pkcs7Der,
          cmsCertsPem: res.certsPem,
        );

        out.add(
          PdfSignatureValidationItem(
            fieldName: sig.fieldName,
            byteRange: sig.byteRange,
            signedRevisionLength: sig.signedRevisionLength,
            coversCurrentFile: sig.byteRange.length == 4 &&
                sig.byteRange[0] == 0 &&
                (sig.byteRange[2] + sig.byteRange[3]) == pdfBytes.length,
            contentsStart: cStart,
            contentsEnd: cEnd,
            validation: res,
            chainTrusted: chainTrusted,
            chainErrors: chainErrors,
            docMdp: docMdp,
            ltv: ltv,
            ltvSelfCheck: ltvSelfCheck,
            revocationStatus: revStatus,
            policyStatus: policyStatus,
            timestampStatus: tsStatus,
          ),
        );
      }

      return PdfSignatureValidationReport(signatures: out);
    } finally {
      doc.dispose();
    }
  }

  static const String _oidIdAaTimeStampToken = '1.2.840.113549.1.9.16.2.14';
  static const String _oidSignedData = '1.2.840.113549.1.7.2';
  static const String _oidTstInfo = '1.2.840.113549.1.9.16.1.4';

  Future<PdfTimestampStatus> _validateRfc3161Timestamp({
    required Uint8List signatureCmsDer,
    required List<String> trustedRootsPem,
    required List<String> extraCandidatesPem,
    required List<X509Certificate> roots,
    required List<X509Crl> loadedCrls,
    required bool fetchCrls,
    required bool strictRevocation,
  }) async {
    final List<String> errors = <String>[];

    final Uint8List? tokenDer =
        _extractTimeStampTokenFromUnsignedAttrs(signatureCmsDer);
    if (tokenDer == null) {
      return const PdfTimestampStatus(present: false, valid: false);
    }

    final _TstInfo? tst = _parseTstInfoFromTimeStampToken(tokenDer);
    if (tst == null) {
      errors.add('tstinfo_parse_failed');
      return PdfTimestampStatus(
        present: true,
        valid: false,
        errors: errors,
      );
    }

    final DateTime? genTimeUtc = tst.genTime?.toUtc();
    if (genTimeUtc == null) {
      errors.add('tstinfo_missing_gentime');
    }

    // Validate token CMS signature
    final PdfSignatureValidation cmsValidator = PdfSignatureValidation();
    final CmsSignedDataValidationResult tokenSigRes =
        cmsValidator.validateCmsSignedData(tokenDer);
    final bool tokenSignatureValid = tokenSigRes.cmsSignatureValid;
    if (!tokenSignatureValid) {
      errors.add('timestamp_token_signature_invalid');
    }

    // Validate messageImprint against hash(signatureValue)
    bool? imprintOk;
    final Uint8List? signatureValue =
        _extractSignerSignatureValueFromCms(signatureCmsDer);
    if (signatureValue == null) {
      errors.add('pdf_cms_signature_value_missing');
      imprintOk = false;
    } else if (tst.messageImprintAlgOid == null || tst.messageImprint == null) {
      errors.add('tstinfo_missing_message_imprint');
      imprintOk = false;
    } else {
      final crypto.Hash? h = _hashFromDigestOid(tst.messageImprintAlgOid!);
      if (h == null) {
        errors.add(
            'tstinfo_unsupported_imprint_hash_oid=${tst.messageImprintAlgOid}');
        imprintOk = false;
      } else {
        final Uint8List expected =
            Uint8List.fromList(h.convert(signatureValue).bytes);
        imprintOk = _constantTimeEquals(expected, tst.messageImprint!);
        if (imprintOk == false) {
          errors.add('tstinfo_message_imprint_mismatch');
        }
      }
    }

    // Validate TSA chain trust at genTime
    bool? tsaChainTrusted;
    List<String>? tsaChainErrors;
    if (trustedRootsPem.isNotEmpty && genTimeUtc != null) {
      final X509ChainValidationResult chainResult = X509Utils.verifyChainPem(
        chainPem: tokenSigRes.certsPem,
        trustedRootsPem: trustedRootsPem,
        extraCandidatesPem: extraCandidatesPem,
        validationTime: genTimeUtc,
      );
      tsaChainTrusted = chainResult.trusted;
      tsaChainErrors = chainResult.errors;
      if (tsaChainTrusted == false) {
        errors.add('tsa_chain_untrusted');
      }
    }

    // Revocation check for TSA chain at genTime
    PdfRevocationResult? tsaRevocation;
    if (genTimeUtc != null) {
      tsaRevocation = await _checkRevocation(
        tokenSigRes.certsPem,
        roots,
        loadedCrls,
        fetchCrls: fetchCrls,
        strict: strictRevocation,
        validationTime: genTimeUtc,
      );
      if (strictRevocation && tsaRevocation.status != 'good') {
        errors.add('tsa_revocation_not_good');
      }
      if (tsaRevocation.status == 'revoked') {
        errors.add('tsa_revoked');
      }
    }

    final bool chainOk = tsaChainTrusted != false;
    final bool imprintOkFinal = imprintOk == true;
    final bool valid = tokenSignatureValid &&
        imprintOkFinal &&
        chainOk &&
        (!strictRevocation || (tsaRevocation?.status == 'good'));

    return PdfTimestampStatus(
      present: true,
      valid: valid,
      genTime: genTimeUtc,
      messageImprintOk: imprintOk,
      tokenSignatureValid: tokenSignatureValid,
      policyOid: tst.policyOid,
      nonce: tst.nonce,
      chainTrusted: tsaChainTrusted,
      chainErrors: tsaChainErrors,
      revocationStatus: tsaRevocation,
      errors: errors,
    );
  }

  crypto.Hash? _hashFromDigestOid(String oid) {
    switch (oid) {
      case '1.3.14.3.2.26':
        return crypto.sha1;
      case '2.16.840.1.101.3.4.2.4':
        return crypto.sha224;
      case '2.16.840.1.101.3.4.2.1':
        return crypto.sha256;
      case '2.16.840.1.101.3.4.2.2':
        return crypto.sha384;
      case '2.16.840.1.101.3.4.2.3':
        return crypto.sha512;
    }
    return null;
  }

  bool _constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.lengthInBytes != b.lengthInBytes) return false;
    int diff = 0;
    for (int i = 0; i < a.lengthInBytes; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  Uint8List? _extractSignerSignatureValueFromCms(Uint8List cmsBytes) {
    try {
      final Asn1Stream asn1 = Asn1Stream(PdfStreamReader(cmsBytes));
      final Asn1? contentInfoObj = asn1.readAsn1();
      if (contentInfoObj is! DerSequence) return null;
      final DerObjectID contentType =
          contentInfoObj[0]!.getAsn1()! as DerObjectID;
      if (contentType.id != _oidSignedData) return null;
      final Asn1Tag signedDataTag = contentInfoObj[1]!.getAsn1()! as Asn1Tag;
      final Asn1? signedDataObj = signedDataTag.getObject();
      if (signedDataObj is! DerSequence) return null;

      int idx = 0;
      idx++; // version
      idx++; // digestAlgorithms
      idx++; // encapContentInfo
      // optional certs [0]
      if (signedDataObj.count > idx) {
        final Asn1? maybeTag = signedDataObj[idx]?.getAsn1();
        if (maybeTag is Asn1Tag && maybeTag.tagNumber == 0) idx++;
      }
      // optional crls [1]
      if (signedDataObj.count > idx) {
        final Asn1? maybeTag = signedDataObj[idx]?.getAsn1();
        if (maybeTag is Asn1Tag && maybeTag.tagNumber == 1) idx++;
      }
      if (signedDataObj.count <= idx) return null;
      final Asn1? signerInfosObj = signedDataObj[idx]?.getAsn1();
      final Asn1Set? signerInfosSet =
          signerInfosObj is Asn1Set ? signerInfosObj : null;
      if (signerInfosSet == null || signerInfosSet.objects.isEmpty) return null;
      final Asn1? signerInfoObj = signerInfosSet[0]?.getAsn1();
      if (signerInfoObj is! DerSequence) return null;

      // signatureValue is the last OCTET STRING before optional unsignedAttrs.
      for (int i = signerInfoObj.count - 1; i >= 0; i--) {
        final Asn1? o = signerInfoObj[i]?.getAsn1();
        if (o is DerOctet) {
          final List<int>? bytes = o.getOctets();
          if (bytes != null) return Uint8List.fromList(bytes);
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  Uint8List? _extractTimeStampTokenFromUnsignedAttrs(Uint8List cmsBytes) {
    try {
      final Asn1Stream asn1 = Asn1Stream(PdfStreamReader(cmsBytes));
      final Asn1? contentInfoObj = asn1.readAsn1();
      if (contentInfoObj is! DerSequence) return null;
      final DerObjectID contentType =
          contentInfoObj[0]!.getAsn1()! as DerObjectID;
      if (contentType.id != _oidSignedData) return null;
      final Asn1Tag signedDataTag = contentInfoObj[1]!.getAsn1()! as Asn1Tag;
      final Asn1? signedDataObj = signedDataTag.getObject();
      if (signedDataObj is! DerSequence) return null;

      int idx = 0;
      idx++; // version
      idx++; // digestAlgorithms
      idx++; // encapContentInfo
      // optional certs [0]
      if (signedDataObj.count > idx) {
        final Asn1? maybeTag = signedDataObj[idx]?.getAsn1();
        if (maybeTag is Asn1Tag && maybeTag.tagNumber == 0) idx++;
      }
      // optional crls [1]
      if (signedDataObj.count > idx) {
        final Asn1? maybeTag = signedDataObj[idx]?.getAsn1();
        if (maybeTag is Asn1Tag && maybeTag.tagNumber == 1) idx++;
      }
      if (signedDataObj.count <= idx) return null;
      final Asn1? signerInfosObj = signedDataObj[idx]?.getAsn1();
      final Asn1Set? signerInfosSet =
          signerInfosObj is Asn1Set ? signerInfosObj : null;
      if (signerInfosSet == null || signerInfosSet.objects.isEmpty) return null;
      final Asn1? signerInfoObj = signerInfosSet[0]?.getAsn1();
      if (signerInfoObj is! DerSequence) return null;

      Asn1Tag? unsignedAttrs;
      for (int i = 0; i < signerInfoObj.count; i++) {
        final Asn1? o = signerInfoObj[i]?.getAsn1();
        if (o is Asn1Tag && o.tagNumber == 1) {
          unsignedAttrs = o;
          break;
        }
      }
      if (unsignedAttrs == null) return null;

      final Asn1? unsignedObj = unsignedAttrs.getObject();
      final Asn1Set? attrsSet = unsignedObj is Asn1Set ? unsignedObj : null;
      if (attrsSet == null) return null;

      for (int i = 0; i < attrsSet.objects.length; i++) {
        final Asn1? attrObj = attrsSet[i]?.getAsn1();
        if (attrObj is! DerSequence || attrObj.count < 2) continue;
        final Asn1? oidObj = attrObj[0]?.getAsn1();
        if (oidObj is! DerObjectID) continue;
        if (oidObj.id != _oidIdAaTimeStampToken) continue;

        final Asn1? valuesObj = attrObj[1]?.getAsn1();
        final Asn1Set? valuesSet = valuesObj is Asn1Set ? valuesObj : null;
        if (valuesSet == null || valuesSet.objects.isEmpty) return null;
        final Asn1? tokenSeq = valuesSet[0]?.getAsn1();
        if (tokenSeq == null) return null;
        final List<int>? der = tokenSeq.getDerEncoded();
        if (der == null || der.isEmpty) return null;
        return Uint8List.fromList(der);
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  _TstInfo? _parseTstInfoFromTimeStampToken(Uint8List tokenCmsDer) {
    final Asn1Stream asn1 = Asn1Stream(PdfStreamReader(tokenCmsDer));
    final Asn1? contentInfoObj = asn1.readAsn1();
    if (contentInfoObj is! DerSequence) return null;
    final DerObjectID contentType =
        contentInfoObj[0]!.getAsn1()! as DerObjectID;
    if (contentType.id != _oidSignedData) return null;
    final Asn1Tag signedDataTag = contentInfoObj[1]!.getAsn1()! as Asn1Tag;
    final Asn1? signedDataObj = signedDataTag.getObject();
    if (signedDataObj is! DerSequence) return null;

    final Asn1? encapObj = signedDataObj[2]?.getAsn1();
    if (encapObj is! DerSequence || encapObj.count < 2) return null;
    final Asn1? eContentTypeObj = encapObj[0]?.getAsn1();
    if (eContentTypeObj is! DerObjectID || eContentTypeObj.id != _oidTstInfo) {
      return null;
    }

    final Asn1? eContentTaggedObj = encapObj[1]?.getAsn1();
    if (eContentTaggedObj is! Asn1Tag || eContentTaggedObj.tagNumber != 0) {
      return null;
    }

    final Asn1? eContentObj = eContentTaggedObj.getObject();
    final Asn1Octet? eContentOct =
        Asn1Octet.getOctetStringFromObject(eContentObj);
    final List<int>? eContentBytes = eContentOct?.getOctets();
    if (eContentBytes == null || eContentBytes.isEmpty) return null;

    final Asn1? tstAsn1 = Asn1Stream(PdfStreamReader(eContentBytes)).readAsn1();
    if (tstAsn1 is! Asn1Sequence || tstAsn1.count < 5) return null;

    final Asn1? policyObj = tstAsn1[1]?.getAsn1();
    final String? policyOid = policyObj is DerObjectID ? policyObj.id : null;

    final Asn1? miObj = tstAsn1[2]?.getAsn1();
    String? miAlgOid;
    Uint8List? miHash;
    if (miObj is Asn1Sequence && miObj.count >= 2) {
      final Asn1? algIdObj = miObj[0]?.getAsn1();
      if (algIdObj is Asn1Sequence && algIdObj.count >= 1) {
        final Asn1? oid = algIdObj[0]?.getAsn1();
        if (oid is DerObjectID) miAlgOid = oid.id;
      }
      final Asn1Octet? hashOct =
          Asn1Octet.getOctetStringFromObject(miObj[1]?.getAsn1());
      final List<int>? hashBytes = hashOct?.getOctets();
      if (hashBytes != null) miHash = Uint8List.fromList(hashBytes);
    }

    final Asn1? genTimeObj = tstAsn1[4]?.getAsn1();
    DateTime? genTime;
    if (genTimeObj is GeneralizedTime) {
      genTime = genTimeObj.toDateTime();
    }

    BigInt? nonce;
    for (int i = 5; i < tstAsn1.count; i++) {
      final Asn1? o = tstAsn1[i]?.getAsn1();
      if (o is DerInteger) {
        nonce = o.value;
      }
    }

    return _TstInfo(
      policyOid: policyOid,
      messageImprintAlgOid: miAlgOid,
      messageImprint: miHash,
      genTime: genTime,
      nonce: nonce?.toString(),
    );
  }

  Future<PdfRevocationResult> _checkRevocation(
    List<String> chainPem,
    List<X509Certificate> trustedRoots,
    List<X509Crl> localCrls, {
    required bool fetchCrls,
    required DateTime validationTime,
    bool strict = false,
    Duration maxClockSkew = const Duration(minutes: 5),
  }) async {
    if (chainPem.isEmpty) {
      return const PdfRevocationResult(
          isRevoked: false,
          status: 'unknown',
          details: 'No certificates in signature');
    }

    // Parse chain
    final List<X509Certificate> chain = [];
    for (final s in chainPem) {
      try {
        chain.add(X509Utils.parsePemCertificate(s));
      } catch (_) {}
    }

    bool isSelfSigned(X509Certificate cert) {
      final String? subject = cert.c?.subject?.toString();
      final String? issuer = cert.c?.issuer?.toString();
      if (subject == null || issuer == null || subject != issuer) return false;
      try {
        cert.verify(cert.getPublicKey());
        return true;
      } catch (_) {
        return false;
      }
    }

    bool dnEqual(String? a, String? b) =>
        a != null && b != null && a.trim() == b.trim();

    bool crlTimeWindowOk(X509Crl crl) {
      final DateTime now = validationTime.toUtc();
      final DateTime? thisUp = crl.thisUpdate?.toUtc();
      final DateTime? nextUp = crl.nextUpdate?.toUtc();
      if (thisUp != null && now.isBefore(thisUp.subtract(maxClockSkew)))
        return false;
      if (nextUp != null && now.isAfter(nextUp.add(maxClockSkew))) return false;
      return true;
    }

    // Track missing evidence when strict.
    final List<String> missingEvidenceFor = <String>[];

    // 1. Iterate chain (leaf first)
    // Usually leaf matches issuer in next cert.
    for (int i = 0; i < chain.length; i++) {
      final X509Certificate cert = chain[i];

      // Skip revocation checks for a trust anchor / self-signed cert.
      if (isSelfSigned(cert)) {
        continue;
      }

      // Find Issuer (needed for OCSP and typically CRL check too)
      X509Certificate? issuer = X509Utils.findIssuer(cert, trustedRoots);
      if (issuer == null) {
        issuer = X509Utils.findIssuer(cert, chain);
      }

      bool hasValidatedGoodForCert = false;

      final BigInt? serial = cert.c?.serialNumber?.value;
      if (serial == null) {
        if (strict) {
          missingEvidenceFor
              .add(cert.c?.subject?.toString() ?? 'unknown-subject');
        }
        continue;
      }

      // 2. Try OCSP
      if (fetchCrls && issuer != null) {
        final List<int>? ocspBytes =
            await RevocationDataClient.fetchOcspResponseBytes(cert, issuer);
        if (ocspBytes != null && ocspBytes.isNotEmpty) {
          final OcspResponse? ocsp = strict
              ? OcspResponse.parseValidated(
                  ocspBytes,
                  cert: cert,
                  issuer: issuer,
                  validationTime: validationTime,
                  maxClockSkew: maxClockSkew,
                )
              : OcspResponse.parse(ocspBytes);

          if (ocsp != null) {
            if (ocsp.status == OcspCertificateStatus.revoked) {
              return PdfRevocationResult(
                isRevoked: true,
                status: 'revoked',
                details: 'OCSP: certificate revoked',
              );
            }
            if (ocsp.status == OcspCertificateStatus.good) {
              if (!strict || ocsp.signatureValid == true) {
                hasValidatedGoodForCert = true;
              }
            }
          }
        }
      }

      // 3. Fetch or find CRLs for this cert
      // We need an issuer to verify the CRL, usually chain[i+1]
      // But for revocation check via CRL, we assume the CRL is signed by a valid CA.
      // For simplicity: download CRLs from DP.

      List<X509Crl> candidateCrls = [...localCrls];

      if (fetchCrls) {
        final List<List<int>> fetched =
            await RevocationDataClient.fetchCrls(cert);
        for (final bytes in fetched) {
          final X509Crl? parsed = X509Crl.fromBytes(bytes);
          if (parsed != null) candidateCrls.add(parsed);
        }
      }

      if (candidateCrls.isEmpty) {
        if (strict && !hasValidatedGoodForCert) {
          missingEvidenceFor
              .add(cert.c?.subject?.toString() ?? 'unknown-subject');
        }
        continue;
      }

      for (final crl in candidateCrls) {
        if (strict) {
          if (issuer == null) {
            continue;
          }
          final String? crlIssuer = crl.issuer?.toString();
          final String? issuerSubject = issuer.c?.subject?.toString();
          final String? certIssuer = cert.c?.issuer?.toString();
          if (!dnEqual(crlIssuer, issuerSubject)) {
            continue;
          }
          if (!dnEqual(issuerSubject, certIssuer)) {
            continue;
          }
          if (!crlTimeWindowOk(crl)) {
            continue;
          }
          if (!crl.verifySignature(issuer)) {
            continue;
          }
        }

        if (crl.isRevoked(serial)) {
          return PdfRevocationResult(
            isRevoked: true,
            status: 'revoked',
            details: 'CRL: certificate revoked',
          );
        }

        if (strict) {
          // This CRL is relevant and validated; treat as positive evidence for "not revoked".
          hasValidatedGoodForCert = true;
        }
      }

      if (strict && !hasValidatedGoodForCert) {
        missingEvidenceFor
            .add(cert.c?.subject?.toString() ?? 'unknown-subject');
      }
    }

    if (strict && missingEvidenceFor.isNotEmpty) {
      final String msg =
          'Missing validated revocation evidence for ${missingEvidenceFor.length} cert(s)';
      return PdfRevocationResult(
          isRevoked: false, status: 'unknown', details: msg);
    }

    return const PdfRevocationResult(isRevoked: false, status: 'good');
  }

  /// Validates a single signature field by name.
  ///
  /// Returns null when the field is not found.
  Future<PdfSignatureValidationItem?> validateSignature(
    Uint8List pdfBytes, {
    required String fieldName,
    List<String>? trustedRootsPem,
    List<Uint8List>? crlBytes,
    bool fetchCrls = false,
    bool useEmbeddedIcpBrasil = false,
    bool strictRevocation = false,
    Lpa? lpa,
  }) async {
    final PdfSignatureValidationReport report = await validateAllSignatures(
      pdfBytes,
      trustedRootsPem: trustedRootsPem,
      crlBytes: crlBytes,
      fetchCrls: fetchCrls,
      useEmbeddedIcpBrasil: useEmbeddedIcpBrasil,
      strictRevocation: strictRevocation,
      lpa: lpa,
    );
    for (final PdfSignatureValidationItem item in report.signatures) {
      if (item.fieldName == fieldName) return item;
    }
    return null;
  }
}

class _TstInfo {
  const _TstInfo({
    required this.policyOid,
    required this.messageImprintAlgOid,
    required this.messageImprint,
    required this.genTime,
    required this.nonce,
  });

  final String? policyOid;
  final String? messageImprintAlgOid;
  final Uint8List? messageImprint;
  final DateTime? genTime;
  final String? nonce;
}

class _ParsedSignature {
  _ParsedSignature({
    required this.fieldName,
    required this.byteRange,
    required this.pkcs7Der,
    required this.signatureDict,
    required this.signatureRef,
  });

  final String fieldName;
  final List<int> byteRange;
  final Uint8List pkcs7Der;
  final PdfDictionary signatureDict;
  final PdfReference? signatureRef;

  int get signedRevisionLength =>
      byteRange.length == 4 ? byteRange[2] + byteRange[3] : -1;
}

class _CatalogInfo {
  _CatalogInfo({
    required this.docMdpRef,
    required this.dss,
  });

  final PdfReference? docMdpRef;
  final PdfDictionary? dss;
}

_CatalogInfo _readCatalogInfo(PdfDocument doc) {
  final dynamic catalog = PdfDocumentHelper.getHelper(doc).catalog;

  PdfReference? docMdpRef;
  try {
    final dynamic permsPrim = catalog[PdfDictionaryProperties.perms];
    final dynamic perms =
        permsPrim is PdfReferenceHolder ? permsPrim.object : permsPrim;
    if (perms is PdfDictionary) {
      final dynamic docMdpPrim = perms[PdfDictionaryProperties.docMDP];
      if (docMdpPrim is PdfReferenceHolder) {
        docMdpRef = docMdpPrim.reference;
      }
    }
  } catch (_) {
    docMdpRef = null;
  }

  PdfDictionary? dss;
  try {
    final dynamic dssPrim = catalog[PdfDictionaryProperties.dss];
    final dynamic dssObj =
        dssPrim is PdfReferenceHolder ? dssPrim.object : dssPrim;
    if (dssObj is PdfDictionary) {
      dss = dssObj;
    }
  } catch (_) {
    dss = null;
  }

  return _CatalogInfo(docMdpRef: docMdpRef, dss: dss);
}

List<_ParsedSignature> _extractAllSignatures(PdfDocument doc) {
  final List<_ParsedSignature> out = <_ParsedSignature>[];
  for (int idx = 0; idx < doc.form.fields.count; idx++) {
    final field = doc.form.fields[idx];
    if (field is! PdfSignatureField) continue;
    if (!field.isSigned) continue;

    final PdfSignatureFieldHelper helper =
        PdfSignatureFieldHelper.getHelper(field);
    final PdfDictionary fieldDict = helper.dictionary!;
    final PdfDictionary widget =
        helper.getWidgetAnnotation(fieldDict, helper.crossTable);
    final dynamic vHolder = widget[PdfDictionaryProperties.v] ??
        fieldDict[PdfDictionaryProperties.v];

    final PdfReferenceHolder? sigRefHolder =
        vHolder is PdfReferenceHolder ? vHolder : null;
    final dynamic sigObj = PdfCrossTable.dereference(vHolder);
    if (sigObj is! PdfDictionary) continue;

    final PdfDictionary sigDict = sigObj;

    final List<int>? byteRange = _readByteRange(sigDict);
    final Uint8List? pkcs7Der = _readContentsPkcs7(sigDict);
    if (byteRange == null || pkcs7Der == null) continue;

    out.add(
      _ParsedSignature(
        fieldName: field.name ?? '',
        byteRange: byteRange,
        pkcs7Der: pkcs7Der,
        signatureDict: sigDict,
        signatureRef: sigRefHolder?.reference,
      ),
    );
  }
  return out;
}

List<int>? _readByteRange(PdfDictionary sigDict) {
  if (!sigDict.containsKey(PdfDictionaryProperties.byteRange)) {
    return null;
  }
  final dynamic rangePrim =
      PdfCrossTable.dereference(sigDict[PdfDictionaryProperties.byteRange]);
  if (rangePrim is! PdfArray || rangePrim.count < 4) {
    return null;
  }
  final List<int> values = <int>[];
  for (int i = 0; i < 4; i++) {
    final PdfNumber? number =
        PdfCrossTable.dereference(rangePrim[i]) as PdfNumber?;
    if (number == null || number.value == null) {
      return null;
    }
    values.add(number.value!.toInt());
  }
  return values;
}

Uint8List? _readContentsPkcs7(PdfDictionary sigDict) {
  if (!sigDict.containsKey(PdfDictionaryProperties.contents)) {
    return null;
  }
  final dynamic contentsPrim =
      PdfCrossTable.dereference(sigDict[PdfDictionaryProperties.contents]);
  if (contentsPrim is! PdfString) {
    return null;
  }

  final List<int> data = contentsPrim.data ?? const <int>[];
  if (data.isNotEmpty && data[0] == 0x30) {
    return Uint8List.fromList(data);
  }

  // Some parser flows keep hex payload as ASCII. Decode it.
  final PdfString tmp = PdfString('');
  final String candidate = contentsPrim.value ?? String.fromCharCodes(data);
  final List<int> decoded = tmp.hexToBytes(candidate);
  if (decoded.isEmpty) {
    return null;
  }
  return Uint8List.fromList(decoded);
}

bool _sameReference(PdfReference a, PdfReference b) {
  return a.objNum == b.objNum && a.genNum == b.genNum;
}

int? _extractDocMdpP(PdfDictionary sigDict) {
  try {
    if (!sigDict.containsKey(PdfDictionaryProperties.reference)) {
      return null;
    }
    final dynamic refPrim =
        PdfCrossTable.dereference(sigDict[PdfDictionaryProperties.reference]);
    if (refPrim is! PdfArray || refPrim.count == 0) {
      return null;
    }

    final dynamic ref0Prim = PdfCrossTable.dereference(refPrim[0]);
    if (ref0Prim is! PdfDictionary) {
      return null;
    }

    final dynamic transformMethod = PdfCrossTable.dereference(
      ref0Prim[PdfDictionaryProperties.transformMethod],
    );
    if (transformMethod is PdfName) {
      if (transformMethod.name != 'DocMDP') {
        return null;
      }
    }

    final dynamic tpPrim =
        PdfCrossTable.dereference(ref0Prim['TransformParams']);
    final dynamic tp = tpPrim is PdfReferenceHolder ? tpPrim.object : tpPrim;
    if (tp is! PdfDictionary) {
      return null;
    }

    final dynamic pPrim =
        PdfCrossTable.dereference(tp[PdfDictionaryProperties.p]);
    if (pPrim is PdfNumber && pPrim.value != null) {
      return pPrim.value!.toInt();
    }
    return null;
  } catch (_) {
    return null;
  }
}

PdfLtvInfo _computeLtvInfo({
  required _CatalogInfo catalogInfo,
  required Uint8List signaturePkcs7Der,
}) {
  final PdfDictionary? dss = catalogInfo.dss;
  if (dss == null) {
    return const PdfLtvInfo(
      hasDss: false,
      signatureHasVri: false,
      dssCertsCount: 0,
      dssOcspsCount: 0,
      dssCrlsCount: 0,
    );
  }

  int certsCount = 0;
  int ocspsCount = 0;
  int crlsCount = 0;
  bool signatureHasVri = false;

  try {
    final dynamic certs =
        PdfCrossTable.dereference(dss[PdfDictionaryProperties.certs]);
    if (certs is PdfArray) certsCount = certs.count;
  } catch (_) {}

  try {
    final dynamic ocsps =
        PdfCrossTable.dereference(dss[PdfDictionaryProperties.ocsps]);
    if (ocsps is PdfArray) ocspsCount = ocsps.count;
  } catch (_) {}

  try {
    final dynamic crls =
        PdfCrossTable.dereference(dss[PdfDictionaryProperties.crls]);
    if (crls is PdfArray) crlsCount = crls.count;
  } catch (_) {}

  try {
    final dynamic vriPrim =
        PdfCrossTable.dereference(dss[PdfDictionaryProperties.vri]);
    final dynamic vri =
        vriPrim is PdfReferenceHolder ? vriPrim.object : vriPrim;
    if (vri is PdfDictionary) {
      final String vriName = _computeVriName(signaturePkcs7Der);
      signatureHasVri = vri.containsKey(vriName);
    }
  } catch (_) {
    signatureHasVri = false;
  }

  return PdfLtvInfo(
    hasDss: true,
    signatureHasVri: signatureHasVri,
    dssCertsCount: certsCount,
    dssOcspsCount: ocspsCount,
    dssCrlsCount: crlsCount,
  );
}

PdfLtvSelfCheckResult? _computeLtvSelfCheck({
  required _CatalogInfo catalogInfo,
  required Uint8List signaturePkcs7Der,
  required List<String> cmsCertsPem,
}) {
  final PdfDictionary? dss = catalogInfo.dss;
  if (dss == null) return null;

  final List<String> issues = <String>[];
  final String vriName = _computeVriName(signaturePkcs7Der);

  // Locate /DSS/VRI entry for this signature.
  PdfDictionary? vriDict;
  try {
    final dynamic vriPrim =
        PdfCrossTable.dereference(dss[PdfDictionaryProperties.vri]);
    final dynamic vri =
        vriPrim is PdfReferenceHolder ? vriPrim.object : vriPrim;
    if (vri is PdfDictionary) vriDict = vri;
  } catch (_) {
    vriDict = null;
  }
  if (vriDict == null) {
    issues.add('DSS/VRI missing');
  }

  PdfDictionary? vriEntry;
  if (vriDict != null) {
    try {
      dynamic entry = vriDict[vriName];
      entry ??= vriDict[PdfName(vriName)];
      entry = PdfCrossTable.dereference(entry);
      entry = entry is PdfReferenceHolder ? entry.object : entry;
      if (entry is PdfDictionary) vriEntry = entry;
    } catch (_) {
      vriEntry = null;
    }
  }
  if (vriDict != null && vriEntry == null) {
    issues.add('VRI entry missing for signature');
  }

  bool vriHasOcsp = false;
  bool vriHasCrl = false;
  bool vriHasCerts = false;

  if (vriEntry != null) {
    try {
      final dynamic ocsp =
          PdfCrossTable.dereference(vriEntry[PdfDictionaryProperties.ocsp]);
      if (ocsp is PdfArray && ocsp.count > 0) vriHasOcsp = true;
    } catch (_) {}

    try {
      final dynamic crl =
          PdfCrossTable.dereference(vriEntry[PdfDictionaryProperties.crl]);
      if (crl is PdfArray && crl.count > 0) vriHasCrl = true;
    } catch (_) {}

    try {
      final dynamic certs =
          PdfCrossTable.dereference(vriEntry['Cert'] ?? vriEntry['CERT']);
      if (certs is PdfArray && certs.count > 0) vriHasCerts = true;
    } catch (_) {}

    if (!vriHasOcsp && !vriHasCrl) {
      issues.add('VRI has no OCSP/CRL');
    }
    if (!vriHasCerts) {
      issues.add('VRI has no Cert array');
    }
  }

  // Check that DSS has certificates matching what CMS includes.
  int dssCertsMatchedCount = 0;
  final int cmsCertsCount = cmsCertsPem.length;

  try {
    final dynamic certsPrim =
        PdfCrossTable.dereference(dss[PdfDictionaryProperties.certs]);
    final PdfArray? dssCertsArr = certsPrim is PdfArray ? certsPrim : null;
    if (dssCertsArr == null) {
      if (cmsCertsCount > 0) issues.add('DSS/Certs missing');
    } else {
      final Set<String> dssCertHashes = <String>{};
      for (int i = 0; i < dssCertsArr.count; i++) {
        dynamic item = PdfCrossTable.dereference(dssCertsArr[i]);
        item = item is PdfReferenceHolder ? item.object : item;
        if (item is! PdfStream) continue;
        final List<int>? bytes =
            item.getDecompressedData(false) ?? item.dataStream;
        if (bytes == null || bytes.isEmpty) continue;
        final String h = crypto.sha256.convert(bytes).toString();
        dssCertHashes.add(h);
      }

      for (final String pem in cmsCertsPem) {
        try {
          final Uint8List der = X509Utils.pemToDer(pem);
          final String h = crypto.sha256.convert(der).toString();
          if (dssCertHashes.contains(h)) {
            dssCertsMatchedCount++;
          }
        } catch (_) {
          // ignore
        }
      }

      if (cmsCertsCount > 0 && dssCertsMatchedCount < cmsCertsCount) {
        issues.add('DSS certs do not cover CMS certs');
      }
    }
  } catch (_) {
    if (cmsCertsCount > 0) issues.add('Failed to read DSS/Certs');
  }

  final bool offlineSufficient = issues.isEmpty;
  return PdfLtvSelfCheckResult(
    offlineSufficient: offlineSufficient,
    issues: issues,
    cmsCertsCount: cmsCertsCount,
    dssCertsMatchedCount: dssCertsMatchedCount,
    vriHasCerts: vriHasCerts,
    vriHasOcsp: vriHasOcsp,
    vriHasCrl: vriHasCrl,
  );
}

String _computeVriName(Uint8List pkcs7Der) {
  // Same scheme used by PdfSignatureHelper.getVRIName(): sha1(signatureBytes) as hex.
  final dynamic output = crypto.sha1.convert(pkcs7Der);
  return PdfString.bytesToHex(output.bytes);
}

class _ContentsRange {
  _ContentsRange(this.start, this.end);
  final int start;
  final int end;
}

_ContentsRange? _findContentsRangeInGap(
    Uint8List pdfBytes, List<int> byteRange) {
  if (byteRange.length != 4) return null;
  final int gapStart = byteRange[0] + byteRange[1];
  final int gapEnd = byteRange[2];
  if (gapStart < 0 || gapEnd <= gapStart || gapEnd > pdfBytes.length) {
    return null;
  }

  const List<int> needle = <int>[
    0x2F, // /
    0x43, // C
    0x6F, // o
    0x6E, // n
    0x74, // t
    0x65, // e
    0x6E, // n
    0x74, // t
    0x73, // s
  ];

  final int labelPos = _indexOfBytes(pdfBytes, needle, gapStart, gapEnd);
  if (labelPos == -1) return null;

  int i = labelPos + needle.length;
  while (i < gapEnd) {
    final int b = pdfBytes[i];
    if (b == 0x3C) {
      // <
      final int lt = i;
      int j = lt + 1;
      while (j < gapEnd && pdfBytes[j] != 0x3E) {
        j++;
      }
      if (j < gapEnd) {
        return _ContentsRange(lt + 1, j);
      }
      return null;
    }
    // skip whitespace and delimiters
    i++;
  }

  return null;
}

int _indexOfBytes(Uint8List haystack, List<int> needle, int start, int end) {
  if (needle.isEmpty) return -1;
  final int max = end - needle.length;
  for (int i = start; i <= max; i++) {
    bool ok = true;
    for (int j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) {
        ok = false;
        break;
      }
    }
    if (ok) return i;
  }
  return -1;
}
