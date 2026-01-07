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
import '../../primitives/pdf_string.dart';
import 'kms/revocation_data_client.dart';
import 'pdf_signature_validation.dart';
import 'pdf_signature_utils.dart';
import 'x509/ocsp.dart';
import 'icp_brasil/lpa.dart';
import 'icp_brasil/policy_engine.dart';
import 'x509/x509_certificates.dart';
import 'x509/x509_crl.dart';
import 'x509/x509_utils.dart';

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
  const PdfPolicyStatus({required this.valid, this.error, this.warning, this.policyOid});
  final bool valid;
  final String? error;
  final String? warning;
  final String? policyOid;
  
  Map<String, dynamic> toMap() => {
    'valid': valid,
    'error': error,
    'warning': warning,
    'oid': policyOid
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
    required this.docMdp,
    required this.ltv,
    required this.revocationStatus,
    this.policyStatus,
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

  final PdfDocMdpInfo docMdp;
  final PdfLtvInfo ltv;
  
  final PdfRevocationResult revocationStatus;

  final PdfPolicyStatus? policyStatus;

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
        'certs_pem': validation.certsPem.length, // Avoid dumping all certs in map
        'policy_oid': validation.policyOid,
        'chain_trusted': chainTrusted,
        'doc_mdp': docMdp.toMap(),
        'ltv': ltv.toMap(),
        'revocation_status': revocationStatus.toMap(),
        'policy_status': policyStatus?.toMap(),
      };
}

class PdfSignatureValidationReport {
  PdfSignatureValidationReport({required this.signatures});

  final List<PdfSignatureValidationItem> signatures;

  bool get allDocumentsIntact =>
      signatures.isNotEmpty && signatures.every((s) => s.validation.documentIntact);

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
  Future<PdfSignatureValidationReport> validateAllSignatures(
    Uint8List pdfBytes, {
    List<String>? trustedRootsPem,
    List<Uint8List>? crlBytes,
    bool fetchCrls = false,
    Lpa? lpa,
  }) async {
    final PdfDocument doc = PdfDocument(inputBytes: pdfBytes);
    try {
      final _CatalogInfo catalogInfo = _readCatalogInfo(doc);
      final List<_ParsedSignature> sigs = _extractAllSignatures(doc);
      sigs.sort((a, b) => a.signedRevisionLength.compareTo(b.signedRevisionLength));

      final PdfSignatureValidation cmsValidator = PdfSignatureValidation();
      final List<PdfSignatureValidationItem> out = <PdfSignatureValidationItem>[];

      // Prepare CRLs
      final List<X509Crl> loadedCrls = <X509Crl>[];
      if (crlBytes != null) {
         for (final Uint8List bytes in crlBytes) {
           final X509Crl? parsed = X509Crl.fromBytes(bytes);
           if (parsed != null) loadedCrls.add(parsed);
         }
      }

      // Prepare Roots
      final List<X509Certificate> roots = <X509Certificate>[];
      if (trustedRootsPem != null) {
        for (final String r in trustedRootsPem) {
            try { roots.add(X509Utils.parsePemCertificate(r)); } catch (_) {}
        }
      }

      for (final _ParsedSignature sig in sigs) {
        final PdfSignatureValidationResult res = cmsValidator.validateDetachedSignature(
          pdfBytes,
          signatureName: sig.fieldName,
          byteRange: sig.byteRange,
          pkcs7DerBytes: sig.pkcs7Der,
        );

        bool? chainTrusted;
        if (trustedRootsPem != null && trustedRootsPem.isNotEmpty) {
          chainTrusted = X509Utils.verifyChainPem(
            chainPem: res.certsPem,
            trustedRootsPem: trustedRootsPem,
          ).trusted;
        }

        // Revocation Check
        final PdfRevocationResult revStatus = await _checkRevocation(
             res.certsPem, 
             roots,
             loadedCrls, 
             fetchCrls: fetchCrls
        );

        // Policy Check
        PdfPolicyStatus? policyStatus;
        if (res.policyOid != null) {
            final IcpBrasilPolicyEngine engine = IcpBrasilPolicyEngine(lpa);
            final DateTime checkTime = res.signingTime ?? DateTime.now();
            PolicyValidationResult polRes = engine.validatePolicy(res.policyOid!, checkTime);
            
            // Check algorithm constraints if policy is otherwise valid
            if (polRes.isValid && res.digestAlgorithmOid != null) {
                 final PolicyValidationResult algoRes = engine.validateAlgorithm(
                    res.policyOid!, 
                    res.digestAlgorithmOid!, 
                    checkTime
                 );
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
            docMdp: docMdp,
            ltv: ltv,
            revocationStatus: revStatus,
            policyStatus: policyStatus,
          ),
        );
      }

      return PdfSignatureValidationReport(signatures: out);
    } finally {
      doc.dispose();
    }
  }

  Future<PdfRevocationResult> _checkRevocation(
      List<String> chainPem,
      List<X509Certificate> trustedRoots,
      List<X509Crl> localCrls,
      {required bool fetchCrls}
  ) async {
     if (chainPem.isEmpty) {
        return const PdfRevocationResult(isRevoked: false, status: 'unknown', details: 'No certificates in signature');
     }

     // Parse chain
     final List<X509Certificate> chain = [];
     for(final s in chainPem) {
        try {
           chain.add(X509Utils.parsePemCertificate(s));
        } catch (_) {}
     }
     
     // 1. Iterate chain (leaf first)
     // Usually leaf matches issuer in next cert.
     for (int i=0; i<chain.length; i++) {
        final X509Certificate cert = chain[i];
        
        // Find Issuer (needed for OCSP and typically CRL check too)
        X509Certificate? issuer = X509Utils.findIssuer(cert, trustedRoots);
        if (issuer == null) {
             issuer = X509Utils.findIssuer(cert, chain);
        }

        // 2. Try OCSP
        if (fetchCrls && issuer != null) {
             final OcspResponse? ocsp = await RevocationDataClient.checkOcsp(cert, issuer);
             if (ocsp != null) {
                 if (ocsp.status == OcspCertificateStatus.revoked) {
                     return PdfRevocationResult(
                        isRevoked: true, 
                        status: 'revoked', 
                        details: 'OCSP: Certificate revoked',
                     );
                 }
                 if (ocsp.status == OcspCertificateStatus.good) {
                     // OCSP says good. Skip CRL check for this cert.
                     continue;
                 }
             }
        }
   
        // 3. Fetch or find CRLs for this cert
        // We need an issuer to verify the CRL, usually chain[i+1]
        // But for revocation check via CRL, we assume the CRL is signed by a valid CA.
        // For simplicity: download CRLs from DP.
        
        List<X509Crl> candidateCrls = [...localCrls];
        
        if (fetchCrls) {
           final List<List<int>> fetched = await RevocationDataClient.fetchCrls(cert);
           for(final bytes in fetched) {
              final X509Crl? parsed = X509Crl.fromBytes(bytes);
              if (parsed != null) candidateCrls.add(parsed);
           }
        }
        
        if (candidateCrls.isEmpty) {
           // Can't check
           continue; 
        }

        // 3. Check revocation
        final BigInt? serial = cert.c?.serialNumber?.value;
        if (serial == null) continue;
        
        for (final crl in candidateCrls) {
           // Ideally we check if CRL issuer matches cert issuer. 
           // Here we skip issuer check for MVP, just check serial presence.
           if (crl.isRevoked(serial)) {
              return PdfRevocationResult(
                 isRevoked: true,
                 status: 'revoked',
                 details: 'Certificate with serial $serial found in CRL',
              );
           }
        }
     }

     return const PdfRevocationResult(isRevoked: false, status: 'good');
  }
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

  int get signedRevisionLength => byteRange.length == 4 ? byteRange[2] + byteRange[3] : -1;
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
    final dynamic perms = permsPrim is PdfReferenceHolder ? permsPrim.object : permsPrim;
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
    final dynamic dssObj = dssPrim is PdfReferenceHolder ? dssPrim.object : dssPrim;
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

    final PdfSignatureFieldHelper helper = PdfSignatureFieldHelper.getHelper(field);
    final PdfDictionary fieldDict = helper.dictionary!;
    final PdfDictionary widget = helper.getWidgetAnnotation(fieldDict, helper.crossTable);
    final dynamic vHolder = widget[PdfDictionaryProperties.v] ?? fieldDict[PdfDictionaryProperties.v];

    final PdfReferenceHolder? sigRefHolder = vHolder is PdfReferenceHolder ? vHolder : null;
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
  final dynamic rangePrim = PdfCrossTable.dereference(sigDict[PdfDictionaryProperties.byteRange]);
  if (rangePrim is! PdfArray || rangePrim.count < 4) {
    return null;
  }
  final List<int> values = <int>[];
  for (int i = 0; i < 4; i++) {
    final PdfNumber? number = PdfCrossTable.dereference(rangePrim[i]) as PdfNumber?;
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
  final dynamic contentsPrim = PdfCrossTable.dereference(sigDict[PdfDictionaryProperties.contents]);
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
    final dynamic refPrim = PdfCrossTable.dereference(sigDict[PdfDictionaryProperties.reference]);
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

    final dynamic tpPrim = PdfCrossTable.dereference(ref0Prim['TransformParams']);
    final dynamic tp = tpPrim is PdfReferenceHolder ? tpPrim.object : tpPrim;
    if (tp is! PdfDictionary) {
      return null;
    }

    final dynamic pPrim = PdfCrossTable.dereference(tp[PdfDictionaryProperties.p]);
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
    final dynamic certs = PdfCrossTable.dereference(dss[PdfDictionaryProperties.certs]);
    if (certs is PdfArray) certsCount = certs.count;
  } catch (_) {}

  try {
    final dynamic ocsps = PdfCrossTable.dereference(dss[PdfDictionaryProperties.ocsps]);
    if (ocsps is PdfArray) ocspsCount = ocsps.count;
  } catch (_) {}

  try {
    final dynamic crls = PdfCrossTable.dereference(dss[PdfDictionaryProperties.crls]);
    if (crls is PdfArray) crlsCount = crls.count;
  } catch (_) {}

  try {
    final dynamic vriPrim = PdfCrossTable.dereference(dss[PdfDictionaryProperties.vri]);
    final dynamic vri = vriPrim is PdfReferenceHolder ? vriPrim.object : vriPrim;
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

_ContentsRange? _findContentsRangeInGap(Uint8List pdfBytes, List<int> byteRange) {
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
