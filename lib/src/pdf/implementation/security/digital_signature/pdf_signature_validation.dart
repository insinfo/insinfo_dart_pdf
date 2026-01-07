import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../../forms/pdf_signature_field.dart';
import '../../../interfaces/pdf_interface.dart';
import '../../io/pdf_constants.dart';
import '../../io/pdf_cross_table.dart';
import '../../pdf_document/pdf_document.dart';
import '../../primitives/pdf_array.dart';
import '../../primitives/pdf_dictionary.dart';
import '../../primitives/pdf_number.dart';
import '../../primitives/pdf_reference.dart';
import '../../primitives/pdf_reference_holder.dart';
import '../../primitives/pdf_string.dart';
import '../../io/stream_reader.dart';
import 'asn1/asn1.dart';
import 'asn1/asn1_stream.dart';
import 'asn1/der.dart';
import 'cryptography/cipher_block_chaining_mode.dart';
import 'cryptography/ipadding.dart';
import 'pdf_signature_dictionary.dart' show SignerUtilities;
import 'x509/x509_certificates.dart';
import 'x509/x509_time.dart';

/// Result of validating a detached CMS/PKCS#7 PDF signature.
class PdfSignatureValidationResult {
  /// The name of the signature field (e.g. "Signature1").
  final String? signatureName;

  /// `true` when the RSA signature over `signedAttrs` is valid.
  final bool cmsSignatureValid;

  /// `true` when the digest of the PDF ByteRange matches the `messageDigest`
  /// attribute found inside CMS `signedAttrs`.
  final bool byteRangeDigestOk;

  /// Convenience summary: `cmsSignatureValid && byteRangeDigestOk`.
  final bool documentIntact;

  /// `true` if this signature covers the entire file (no incremental updates after).
  final bool coversWholeDocument;

  /// Certificates extracted from CMS in PEM format.
  ///
  /// Order: `[signer, ...chain]` when the signer's certificate was found.
  final List<String> certsPem;

  /// The Signature Policy OID (e.g. "2.16.76.1.7.1.6") if present in signed attributes.
  final String? policyOid;

  /// Hash algorithm OID from SignaturePolicyId.sigPolicyHash (when present).
  final String? policyHashAlgorithmOid;

  /// Hash bytes from SignaturePolicyId.sigPolicyHash (when present).
  final Uint8List? policyHashValue;
  
  /// The signing time extracted from the signed attributes (id-signingTime), if present.
  final DateTime? signingTime;

  /// The digest algorithm OID (e.g. "2.16.840.1.101.3.4.2.1" for SHA-256).
  final String? digestAlgorithmOid;

  PdfSignatureValidationResult({
    this.signatureName,
    required this.cmsSignatureValid,
    required this.byteRangeDigestOk,
    required this.documentIntact,
    required this.coversWholeDocument,
    required this.certsPem,
    this.policyOid,
    this.policyHashAlgorithmOid,
    this.policyHashValue,
    this.signingTime,
    this.digestAlgorithmOid,
  });
}

class _PdfParsedSignature {
  _PdfParsedSignature({
    required this.fieldName,
    required this.byteRange,
    required this.pkcs7Der,
    required this.signatureRef,
  });

  final String fieldName;
  final List<int> byteRange;
  final Uint8List pkcs7Der;
  final PdfReference? signatureRef;

  int get signedRevisionLength => byteRange.length == 4 ? byteRange[2] + byteRange[3] : -1;
}

class _CmsParsed {
  _CmsParsed({
    this.messageDigest,
    this.signedAttrsDer,
    this.signedAttrsTaggedDer,
    this.signature,
    this.signatureAlgorithmOid,
    this.digestAlgorithmOid,
    this.signerPublicKey,
    required this.certs,
    this.signerSerial,
    this.signerIssuerDer,
    this.signerSki,
    this.policyOid,
    this.policyHashAlgorithmOid,
    this.policyHashValue,
    this.signingTime,
  });

  final Uint8List? messageDigest;
  final Uint8List? signedAttrsDer;
  final Uint8List? signedAttrsTaggedDer;
  final Uint8List? signature;
  final String? signatureAlgorithmOid;
  final String? digestAlgorithmOid;
  final CipherParameter? signerPublicKey;
  final List<_DerCertificate> certs;
  final BigInt? signerSerial;
  final Uint8List? signerIssuerDer;
  final Uint8List? signerSki;
  final String? policyOid;
  final String? policyHashAlgorithmOid;
  final Uint8List? policyHashValue;
  final DateTime? signingTime;
}

class _DerCertificate {
  _DerCertificate({required this.der, this.cert});
  final Uint8List der;
  final X509Certificate? cert;
}

class _DerTlv {
  _DerTlv({
    required this.tag,
    required this.headerLen,
    required this.length,
    required this.totalLen,
  });

  final int tag;
  final int headerLen;
  final int length;
  final int totalLen;
}

class _SignedAttrsRaw {
  _SignedAttrsRaw({
    required this.tagged,
    required this.setForVerify,
  });

  final Uint8List? tagged;
  final Uint8List? setForVerify;
}

/// Detached CMS/PKCS#7 validation utilities for PDF signatures.
///
/// This validates *integrity* (ByteRange digest) and the CMS signature (RSA).
/// It does **not** validate trust chains, revocation (OCSP/CRL), or LTV.
class PdfSignatureValidation {
  /// Validates the last signature dictionary in the PDF.
  ///
  /// If the CMS does not embed certificates, you may pass [userCertificatePem]
  /// (a PEM X.509 certificate) as a fallback to obtain the signer's public key.
  PdfSignatureValidationResult validatePdfSignature(
    Uint8List pdfBytes, {
    String? userCertificatePem,
  }) {
    final List<_PdfParsedSignature> sigs = _extractSignaturesUsingParser(pdfBytes);
    if (sigs.isEmpty) {
      return PdfSignatureValidationResult(
        cmsSignatureValid: false,
        byteRangeDigestOk: false,
        documentIntact: false,
        coversWholeDocument: false,
        certsPem: const <String>[],
      );
    }

    sigs.sort((a, b) => a.signedRevisionLength.compareTo(b.signedRevisionLength));
    final _PdfParsedSignature last = sigs.last;

    return validateDetachedSignature(
      pdfBytes,
      signatureName: last.fieldName,
      byteRange: last.byteRange,
      pkcs7DerBytes: last.pkcs7Der,
      userCertificatePem: userCertificatePem,
    );
  }

  /// Parses and validates **all** signatures found in the document.
  ///
  /// Returns a list of results corresponding to each signature field found,
  /// ordered by the size of the revision they sign (incremental updates).
  List<PdfSignatureValidationResult> validateAllSignatures(
    Uint8List pdfBytes, {
    String? userCertificatePem,
  }) {
    final List<_PdfParsedSignature> sigs = _extractSignaturesUsingParser(pdfBytes);
    if (sigs.isEmpty) {
      return <PdfSignatureValidationResult>[];
    }

    sigs.sort((a, b) => a.signedRevisionLength.compareTo(b.signedRevisionLength));

    final List<PdfSignatureValidationResult> results = <PdfSignatureValidationResult>[];
    for (final _PdfParsedSignature sig in sigs) {
      results.add(
        validateDetachedSignature(
          pdfBytes,
          signatureName: sig.fieldName,
          byteRange: sig.byteRange,
          pkcs7DerBytes: sig.pkcs7Der,
          userCertificatePem: userCertificatePem,
        ),
      );
    }
    return results;
  }

  /// Validates a detached CMS/PKCS#7 signature given its [byteRange] and raw
  /// [pkcs7DerBytes] extracted from `/Contents`.
  ///
  /// This is the core primitive used by higher-level validators that iterate
  /// through multiple signatures.
  PdfSignatureValidationResult validateDetachedSignature(
    Uint8List pdfBytes, {
    String? signatureName,
    required List<int> byteRange,
    required Uint8List pkcs7DerBytes,
    String? userCertificatePem,
  }) {
    // Check if the signature covers the entire file implies that the last
    // byte range extends to the end of the file.
    bool coversWholeDocument = false;
    if (byteRange.length >= 2) {
      final int lastOffset = byteRange[byteRange.length - 2];
      final int lastLen = byteRange[byteRange.length - 1];
      if (lastOffset + lastLen == pdfBytes.length) {
        coversWholeDocument = true;
      }
    }

    final Uint8List signedPortion;
    try {
      signedPortion = _collectSignedPortions(pdfBytes, byteRange);
    } catch (_) {
      return PdfSignatureValidationResult(
        signatureName: signatureName,
        cmsSignatureValid: false,
        byteRangeDigestOk: false,
        documentIntact: false,
        coversWholeDocument: false,
        certsPem: const <String>[],
      );
    }

    final Uint8List cmsBytes = _trimDerByLength(pkcs7DerBytes);

    final _CmsParsed cms;
    try {
      cms = _parseCmsDetachedSignedData(cmsBytes);
    } catch (_) {
      return PdfSignatureValidationResult(
        signatureName: signatureName,
        cmsSignatureValid: false,
        byteRangeDigestOk: false,
        documentIntact: false,
        coversWholeDocument: coversWholeDocument,
        certsPem: const <String>[],
      );
    }

    final crypto.Hash hash = _hashFromDigestAlgorithmOid(cms.digestAlgorithmOid);
    final Uint8List actualDigest = Uint8List.fromList(hash.convert(signedPortion).bytes);

    final bool digestMatches = _constantTimeEquals(
      actualDigest,
      cms.messageDigest ?? Uint8List(0),
    );

    bool sigValid = false;
    CipherParameter? publicKey = cms.signerPublicKey;
    _DerCertificate? matchedSignerCert;
    if (publicKey == null && userCertificatePem != null) {
      try {
        publicKey = _publicKeyFromPemCertificate(userCertificatePem);
      } catch (_) {
        publicKey = null;
      }
    }

    if (publicKey != null && cms.signature != null) {
      try {
        String? signMode =
            _signModeFromSignatureAlgorithmOid(cms.signatureAlgorithmOid);
        // Some CMS producers encode signatureAlgorithm as rsaEncryption and
        // specify the hash in digestAlgorithm.
        if (signMode == null && cms.signatureAlgorithmOid == '1.2.840.113549.1.1.1') {
          signMode = switch (cms.digestAlgorithmOid) {
            '1.3.14.3.2.26' => 'SHA-1withRSA',
            '2.16.840.1.101.3.4.2.2' => 'SHA-384withRSA',
            '2.16.840.1.101.3.4.2.3' => 'SHA-512withRSA',
            '2.16.840.1.101.3.4.2.1' || _ => 'SHA-256withRSA',
          };
        }
        signMode ??= 'SHA-256withRSA';
        final SignerUtilities util = SignerUtilities();

        final List<Uint8List> dataCandidates = <Uint8List>[];
        if (cms.signedAttrsDer != null) {
          dataCandidates.add(cms.signedAttrsDer!);
        } else if (cms.signedAttrsTaggedDer != null) {
          // If we couldn't extract raw DER clean, try the tagged version if available
          dataCandidates.add(cms.signedAttrsTaggedDer!);
        }
        
        if (cms.signedAttrsTaggedDer != null) {
          // For IMPLICIT tagging, OpenSSL commonly signs the bytes of the
          // tagged value after replacing the tag with SET (0x31).
          final Uint8List tagged = cms.signedAttrsTaggedDer!;
          if (tagged.isNotEmpty && tagged[0] == 0xA0) {
            final Uint8List swapped = Uint8List.fromList(tagged);
            swapped[0] = 0x31;
            dataCandidates.add(swapped);

            final int headerLen = _derHeaderLength(tagged);
            if (headerLen > 0 && headerLen < tagged.length && tagged[headerLen] == 0x31) {
              // EXPLICIT tagging: inner SET is present.
              dataCandidates.add(tagged.sublist(headerLen));
            }
          }
        }

        bool matched = false;
        for (int i = 0; i < dataCandidates.length; i++) {
          final Uint8List data = dataCandidates[i];
          if (data.isEmpty) continue;
          final ISigner signer = util.getSigner(signMode);
          signer.initialize(false, publicKey);
          signer.blockUpdate(data, 0, data.length);
          if (signer.validateSignature(cms.signature!)) {
            sigValid = true;
            matched = true;
            break;
          }
        }

        // If we couldn't validate with the SID-matched key (or we couldn't
        // identify the signer key at all), try all embedded certificates.
        // This is a safe fallback because only the true signer cert will
        // validate the signature bytes.
        if (!matched && cms.certs.isNotEmpty && cms.signature != null) {
          for (final _DerCertificate c in cms.certs) {
            final X509Certificate? x = c.cert;
            if (x == null) continue;

            CipherParameter candidateKey;
            try {
              candidateKey = x.getPublicKey();
            } catch (_) {
              continue;
            }

            for (int i = 0; i < dataCandidates.length; i++) {
              final Uint8List data = dataCandidates[i];
              if (data.isEmpty) continue;
              final ISigner signer = util.getSigner(signMode);
              signer.initialize(false, candidateKey);
              signer.blockUpdate(data, 0, data.length);
              if (signer.validateSignature(cms.signature!)) {
                sigValid = true;
                matchedSignerCert = c;
                matched = true;
                break;
              }
            }

            if (matched) {
              publicKey = candidateKey;
              break;
            }
          }
        }
        
        if (!matched) {
           final int certParsedCount = cms.certs.where((c) => c.cert != null).length;
           print(
             'CMS signature verification failed: signMode=$signMode '
             'sigAlgOid=${cms.signatureAlgorithmOid} '
             'digestAlgOid=${cms.digestAlgorithmOid} '
             'signedAttrsDer=${cms.signedAttrsDer?.length ?? 0} '
             'signedAttrsTagged=${cms.signedAttrsTaggedDer?.length ?? 0} '
             'dataCandidates=${dataCandidates.length} '
             'certs=${cms.certs.length} parsedCerts=$certParsedCount '
             'sidSerial=${cms.signerSerial != null}',
           );
        }
      } catch (e) {
        sigValid = false;
        print('CMS signature verification threw: $e');
      }
    }

    if (publicKey == null) {
      final int certParsedCount = cms.certs.where((c) => c.cert != null).length;
      print(
        'CMS signer public key missing: '
        'certs=${cms.certs.length} parsedCerts=$certParsedCount '
        'sidSerial=${cms.signerSerial != null} sidSki=${cms.signerSki != null}',
      );
    }

    final List<String> certsPem;
    if (matchedSignerCert != null) {
      final List<_DerCertificate> ordered = <_DerCertificate>[matchedSignerCert];
      for (final c in cms.certs) {
        if (!identical(c, matchedSignerCert)) ordered.add(c);
      }
      certsPem = ordered
          .map((c) => _derToPemCertificate(c.der))
          .toList(growable: false);
    } else {
      certsPem = _pemCertificatesOrdered(cms);
    }
    return PdfSignatureValidationResult(
      signatureName: signatureName,
      cmsSignatureValid: sigValid,
      byteRangeDigestOk: digestMatches,
      documentIntact: sigValid && digestMatches,
      coversWholeDocument: coversWholeDocument,
      certsPem: certsPem,
      policyOid: cms.policyOid,
      policyHashAlgorithmOid: cms.policyHashAlgorithmOid,
      policyHashValue: cms.policyHashValue,
      signingTime: cms.signingTime,
      digestAlgorithmOid: cms.digestAlgorithmOid,
    );
  }

  List<_PdfParsedSignature> _extractSignaturesUsingParser(Uint8List pdfBytes) {
    final PdfDocument doc = PdfDocument(inputBytes: pdfBytes);
    try {
      final List<_PdfParsedSignature> out = <_PdfParsedSignature>[];
      for (int idx = 0; idx < doc.form.fields.count; idx++) {
        final field = doc.form.fields[idx];
        if (field is! PdfSignatureField) continue;
        if (!field.isSigned) continue;

        final PdfSignatureFieldHelper helper = PdfSignatureFieldHelper.getHelper(field);
        final PdfDictionary fieldDict = helper.dictionary!;
        final PdfDictionary widget = helper.getWidgetAnnotation(fieldDict, helper.crossTable);
        final IPdfPrimitive? vHolder = widget[PdfDictionaryProperties.v] ?? fieldDict[PdfDictionaryProperties.v];
        final PdfReferenceHolder? sigRefHolder = vHolder is PdfReferenceHolder ? vHolder : null;
        final IPdfPrimitive? sigPrimitive = PdfCrossTable.dereference(vHolder);
        if (sigPrimitive is! PdfDictionary) continue;
        final PdfDictionary sigDict = sigPrimitive;

        final List<int>? byteRange = _readByteRange(sigDict);
        final Uint8List? pkcs7Der = _readContentsPkcs7(sigDict);
        if (byteRange == null || pkcs7Der == null) continue;

        out.add(
          _PdfParsedSignature(
            fieldName: field.name ?? '',
            byteRange: byteRange,
            pkcs7Der: pkcs7Der,
            signatureRef: sigRefHolder?.reference,
          ),
        );
      }
      return out;
    } finally {
      doc.dispose();
    }
  }

  List<int>? _readByteRange(PdfDictionary sigDict) {
    if (!sigDict.containsKey(PdfDictionaryProperties.byteRange)) {
      return null;
    }
    final IPdfPrimitive? rangePrim = PdfCrossTable.dereference(
      sigDict[PdfDictionaryProperties.byteRange],
    );
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
    final IPdfPrimitive? contentsPrim = PdfCrossTable.dereference(
      sigDict[PdfDictionaryProperties.contents],
    );
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

  Uint8List _collectSignedPortions(Uint8List pdf, List<int> br) {
    if (br.length != 4) {
      throw ArgumentError.value(br, 'br', 'Invalid ByteRange length');
    }
    final int a = br[0], b = br[1], c = br[2], d = br[3];
    if (a < 0 || b < 0 || c < 0 || d < 0) {
      throw ArgumentError.value(br, 'br', 'Negative ByteRange');
    }
    if (a + b > pdf.length || c + d > pdf.length) {
      throw ArgumentError.value(br, 'br', 'ByteRange out of bounds');
    }
    final BytesBuilder out = BytesBuilder();
    out.add(pdf.sublist(a, a + b));
    out.add(pdf.sublist(c, c + d));
    return out.toBytes();
  }

  Uint8List _trimDerByLength(Uint8List bytes) {
    if (bytes.length < 2) return bytes;
    if (bytes[0] != 0x30) return bytes; // not a SEQUENCE

    final int firstLen = bytes[1];
    
    // Handle Indefinite Length (BER)
    if (firstLen == 0x80) {
      return bytes;
    }

    int headerLen;
    int contentLen;
    if (firstLen <= 0x7f) {
      headerLen = 2;
      contentLen = firstLen;
    } else {
      final int numLenBytes = firstLen & 0x7f;
      if (bytes.length < 2 + numLenBytes) return bytes;
      headerLen = 2 + numLenBytes;
      contentLen = 0;
      for (int i = 0; i < numLenBytes; i++) {
        contentLen = (contentLen << 8) | bytes[2 + i];
      }
    }

    final int totalLen = headerLen + contentLen;
    if (totalLen <= 0 || totalLen > bytes.length) return bytes;
    return bytes.sublist(0, totalLen);
  }

  /// Returns the exact DER bytes that must be verified for CMS `signedAttrs`.
  ///
  /// CMS encodes `signedAttrs` as `[0] IMPLICIT SET OF Attribute`.
  /// For signature verification, the input is the DER encoding of the SET
  /// (tag 0x31) using the original bytes.
  Uint8List _signedAttrsDerFromTag(Asn1Tag tag) {
    final List<int>? tagged = tag.getDerEncoded();
    if (tagged == null || tagged.isEmpty) {
      return Uint8List(0);
    }

    if (tagged[0] == 0x31) {
      return Uint8List.fromList(tagged);
    }

    if (tagged[0] == 0xA0) {
      final int outerHeaderLen = _derHeaderLength(tagged);
      if (outerHeaderLen > 0 && outerHeaderLen < tagged.length) {
        if (tagged[outerHeaderLen] == 0x31) {
          // EXPLICIT tagging: A0 len 31 len ... => return inner SET as-is.
          return Uint8List.fromList(tagged.sublist(outerHeaderLen));
        }
      }

      // IMPLICIT tagging: swap tag byte to SET and keep original length/content.
      final Uint8List rebuilt = Uint8List.fromList(tagged);
      rebuilt[0] = 0x31;
      return rebuilt;
    }

    return Uint8List.fromList(tagged);
  }

  int _derHeaderLength(List<int> bytes) {
    if (bytes.length < 2) return -1;
    final int firstLen = bytes[1];
    if (firstLen <= 0x7f) {
      return 2;
    }
    final int numLenBytes = firstLen & 0x7f;
    if (bytes.length < 2 + numLenBytes) return -1;
    return 2 + numLenBytes;
  }

  _DerTlv _readDerTlv(Uint8List bytes, int offset) {
    if (offset < 0 || offset + 2 > bytes.length) {
      throw RangeError.range(offset, 0, bytes.length - 2);
    }
    final int tag = bytes[offset];
    final int firstLen = bytes[offset + 1];
    if (firstLen <= 0x7f) {
      const int headerLen = 2;
      final int len = firstLen;
      return _DerTlv(
        tag: tag,
        headerLen: headerLen,
        length: len,
        totalLen: headerLen + len,
      );
    }
    final int numLenBytes = firstLen & 0x7f;
    if (offset + 2 + numLenBytes > bytes.length) {
      throw RangeError.range(offset, 0, bytes.length - 1);
    }
    int len = 0;
    for (int i = 0; i < numLenBytes; i++) {
      len = (len << 8) | bytes[offset + 2 + i];
    }
    final int headerLen = 2 + numLenBytes;
    return _DerTlv(
      tag: tag,
      headerLen: headerLen,
      length: len,
      totalLen: headerLen + len,
    );
  }

  _SignedAttrsRaw _extractSignedAttrsRawFromCms(Uint8List cmsBytes) {
    try {
      int o = 0;

      // ContentInfo ::= SEQUENCE { contentType, [0] EXPLICIT signedData }
      final _DerTlv contentInfo = _readDerTlv(cmsBytes, o);
      if (contentInfo.tag != 0x30) {
        return _SignedAttrsRaw(tagged: null, setForVerify: null);
      }
      o += contentInfo.headerLen;

      // contentType OID
      final _DerTlv contentType = _readDerTlv(cmsBytes, o);
      o += contentType.totalLen;

      // [0] EXPLICIT signedData
      final _DerTlv signedDataExplicit = _readDerTlv(cmsBytes, o);
      if (signedDataExplicit.tag != 0xA0) {
        return _SignedAttrsRaw(tagged: null, setForVerify: null);
      }
      o += signedDataExplicit.headerLen;

      // SignedData SEQUENCE
      final _DerTlv signedDataSeq = _readDerTlv(cmsBytes, o);
      if (signedDataSeq.tag != 0x30) {
        return _SignedAttrsRaw(tagged: null, setForVerify: null);
      }
      o += signedDataSeq.headerLen;

      // version, digestAlgorithms, encapContentInfo
      o += _readDerTlv(cmsBytes, o).totalLen;
      o += _readDerTlv(cmsBytes, o).totalLen;
      o += _readDerTlv(cmsBytes, o).totalLen;

      // optional certs [0]
      if (o < cmsBytes.length && cmsBytes[o] == 0xA0) {
        o += _readDerTlv(cmsBytes, o).totalLen;
      }
      // optional crls [1]
      if (o < cmsBytes.length && cmsBytes[o] == 0xA1) {
        o += _readDerTlv(cmsBytes, o).totalLen;
      }

      // signerInfos SET
      final _DerTlv signerInfosSet = _readDerTlv(cmsBytes, o);
      if (signerInfosSet.tag != 0x31) {
        return _SignedAttrsRaw(tagged: null, setForVerify: null);
      }
      o += signerInfosSet.headerLen;

      // First SignerInfo SEQUENCE
      final _DerTlv signerInfoSeq = _readDerTlv(cmsBytes, o);
      if (signerInfoSeq.tag != 0x30) {
        return _SignedAttrsRaw(tagged: null, setForVerify: null);
      }
      int si = o + signerInfoSeq.headerLen;

      // version, sid, digestAlgorithm
      si += _readDerTlv(cmsBytes, si).totalLen;
      si += _readDerTlv(cmsBytes, si).totalLen;
      si += _readDerTlv(cmsBytes, si).totalLen;

      // signedAttrs [0]
      if (si >= cmsBytes.length || cmsBytes[si] != 0xA0) {
        return _SignedAttrsRaw(tagged: null, setForVerify: null);
      }
      final _DerTlv signedAttrsTagged = _readDerTlv(cmsBytes, si);
      final Uint8List taggedBytes = cmsBytes.sublist(
        si,
        si + signedAttrsTagged.totalLen,
      );

      final int contentStart = si + signedAttrsTagged.headerLen;
      Uint8List setForVerify;
      if (contentStart < cmsBytes.length && cmsBytes[contentStart] == 0x31) {
        final _DerTlv innerSet = _readDerTlv(cmsBytes, contentStart);
        setForVerify = cmsBytes.sublist(
          contentStart,
          contentStart + innerSet.totalLen,
        );
      } else {
        setForVerify = Uint8List.fromList(taggedBytes);
        setForVerify[0] = 0x31;
      }

      return _SignedAttrsRaw(tagged: taggedBytes, setForVerify: setForVerify);
    } catch (e, st) {
      print('Error extracting raw signedAttrs: $e\n$st');
      return _SignedAttrsRaw(tagged: null, setForVerify: null);
    }
  }

  List<_DerCertificate> _extractCertificatesRawFromCms(Uint8List cmsBytes) {
    try {
      int o = 0;

      // ContentInfo ::= SEQUENCE { contentType, [0] EXPLICIT signedData }
      final _DerTlv contentInfo = _readDerTlv(cmsBytes, o);
      if (contentInfo.tag != 0x30) return const <_DerCertificate>[];
      o += contentInfo.headerLen;

      // contentType OID
      o += _readDerTlv(cmsBytes, o).totalLen;

      // [0] EXPLICIT signedData
      final _DerTlv signedDataExplicit = _readDerTlv(cmsBytes, o);
      if (signedDataExplicit.tag != 0xA0) return const <_DerCertificate>[];
      o += signedDataExplicit.headerLen;

      // SignedData SEQUENCE
      final _DerTlv signedDataSeq = _readDerTlv(cmsBytes, o);
      if (signedDataSeq.tag != 0x30) return const <_DerCertificate>[];
      final int signedDataStart = o;
      final int signedDataContentStart = signedDataStart + signedDataSeq.headerLen;
      final int signedDataEnd = signedDataStart + signedDataSeq.totalLen;

      // Walk SignedData children
      int p = signedDataContentStart;
      p += _readDerTlv(cmsBytes, p).totalLen; // version
      p += _readDerTlv(cmsBytes, p).totalLen; // digestAlgorithms
      p += _readDerTlv(cmsBytes, p).totalLen; // encapContentInfo

      // optional certs [0] IMPLICIT
      if (p < signedDataEnd && cmsBytes[p] == 0xA0) {
        final _DerTlv certsTlv = _readDerTlv(cmsBytes, p);
        int certsContentStart = p + certsTlv.headerLen;
        int certsContentEnd = p + certsTlv.totalLen;

        // Some producers may encode this as EXPLICIT (content starts with SET 0x31).
        // CMS specifies IMPLICIT, so handle both defensively.
        if (certsContentStart < certsContentEnd && cmsBytes[certsContentStart] == 0x31) {
          final _DerTlv innerSet = _readDerTlv(cmsBytes, certsContentStart);
          certsContentStart = certsContentStart + innerSet.headerLen;
          certsContentEnd = (certsContentStart - innerSet.headerLen) + innerSet.totalLen;
        }

        final List<_DerCertificate> out = <_DerCertificate>[];
        int cpos = certsContentStart;
        while (cpos < certsContentEnd) {
          final _DerTlv tlv = _readDerTlv(cmsBytes, cpos);
          final int next = cpos + tlv.totalLen;
          if (next > certsContentEnd) break;

          // CertificateChoices.certificate is an X.509 Certificate SEQUENCE.
          if (tlv.tag == 0x30) {
            final Uint8List der = cmsBytes.sublist(cpos, next);
            X509Certificate? cert;
            try {
              final Asn1? parsed = Asn1Stream(PdfStreamReader(der)).readAsn1();
              if (parsed is Asn1Sequence) {
                final X509CertificateStructure? s =
                    X509CertificateStructure.getInstance(parsed);
                // For CMS signature validation we primarily need the signer's public key.
                // Some producers/parsers can yield structures missing outer wrapper fields
                // (signatureAlgorithm/signature). Keep certs when the public key is usable.
                if (s != null && s.subjectPublicKeyInfo != null) {
                  cert = X509Certificate(s);
                }
              }
            } catch (_) {
              cert = null;
            }

            // Always keep DER bytes; ordering/matching uses parsed fields when available.
            out.add(_DerCertificate(der: der, cert: cert));
          }

          cpos = next;
        }

        return out;
      }

      return const <_DerCertificate>[];
    } catch (_) {
      return const <_DerCertificate>[];
    }
  }

  _CmsParsed _parseCmsDetachedSignedData(Uint8List cmsBytes) {
    final Asn1Stream asn1 = Asn1Stream(PdfStreamReader(cmsBytes));
    final Asn1? contentInfoObj = asn1.readAsn1();
    if (contentInfoObj is! DerSequence) {
      throw StateError('CMS ContentInfo is not a SEQUENCE');
    }

    final DerObjectID contentType =
        contentInfoObj[0]!.getAsn1()! as DerObjectID;
    if (contentType.id != '1.2.840.113549.1.7.2') {
      throw StateError('CMS is not signedData');
    }

    final Asn1Tag signedDataTag = contentInfoObj[1]!.getAsn1()! as Asn1Tag;
    final Asn1? signedDataObj = signedDataTag.getObject();
    if (signedDataObj is! DerSequence) {
      throw StateError('SignedData is not a SEQUENCE');
    }

    // SignedData ::= SEQUENCE {
    //   version, digestAlgorithms, encapContentInfo, [0]certs?, [1]crls?, signerInfos
    // }
    int idx = 0;
    idx++; // version
    idx++; // digestAlgorithms
    idx++; // encapContentInfo

    // optional certs [0]
    Asn1Tag? certsTag;
    if (signedDataObj.count > idx) {
      final Asn1? maybeTag = signedDataObj[idx]?.getAsn1();
      if (maybeTag is Asn1Tag && maybeTag.tagNumber == 0) {
        certsTag = maybeTag;
        idx++;
      }
    }

    // skip optional crls [1]
    if (signedDataObj.count > idx) {
      final Asn1? maybeTag = signedDataObj[idx]?.getAsn1();
      if (maybeTag is Asn1Tag && maybeTag.tagNumber == 1) {
        idx++;
      }
    }

    final Asn1Set signerInfos = signedDataObj[idx]!.getAsn1()! as Asn1Set;
    final Asn1Sequence signerInfo = signerInfos[0]!.getAsn1()! as Asn1Sequence;

    // SignerInfo ::= SEQUENCE {
    //   version, sid, digestAlgorithm, [0]signedAttrs, signatureAlgorithm, signature, ...
    // }
    final Asn1 sid = signerInfo[1]!.getAsn1()!;
    final (BigInt? sidSerial, Uint8List? sidIssuerDer, Uint8List? sidSki) =
        _extractIssuerAndSerial(sid);

    int siIdx = 0;
    siIdx++; // version
    siIdx++; // sid

    final Asn1Sequence digestAlg =
        signerInfo[siIdx++]!.getAsn1()! as Asn1Sequence;
    final String? digestAlgorithmOid =
        (digestAlg[0]?.getAsn1() as DerObjectID?)?.id;

    Asn1Tag? signedAttrsTag;
    if (signerInfo.count > siIdx) {
      final Asn1? maybe = signerInfo[siIdx]?.getAsn1();
      if (maybe is Asn1Tag && maybe.tagNumber == 0) {
        signedAttrsTag = maybe;
        siIdx++;
      }
    }

    if (signedAttrsTag == null) {
       print('WARNING: signedAttrsTag [0] not found in SignerInfo!');
    }

    final Asn1Sequence sigAlg = signerInfo[siIdx++]!.getAsn1()! as Asn1Sequence;
    final DerOctet signatureOctet = signerInfo[siIdx++]!.getAsn1()! as DerOctet;

    final Uint8List signature = Uint8List.fromList(signatureOctet.getOctets()!);
    final String signatureAlgorithmOid =
        (sigAlg[0]!.getAsn1()! as DerObjectID).id!;

    Uint8List? signedAttrsDer;
    Uint8List? signedAttrsTaggedDer;
    Uint8List? messageDigest;
    String? policyOid;
    String? policyHashAlgorithmOid;
    Uint8List? policyHashValue;
    DateTime? signingTime;
    if (signedAttrsTag != null) {
      final _SignedAttrsRaw raw = _extractSignedAttrsRawFromCms(cmsBytes);
      signedAttrsDer = raw.setForVerify;
      signedAttrsTaggedDer = raw.tagged;

      if (signedAttrsDer != null && signedAttrsDer.isNotEmpty) {
        try {
          final Asn1? attrsParsed =
              Asn1Stream(PdfStreamReader(signedAttrsDer)).readAsn1();
          // print('RAW parsed type: ${attrsParsed.runtimeType}');
          if (attrsParsed is Asn1Set) {
            // print('Objects in set: ${attrsParsed.objects.length}');
            messageDigest = _extractMessageDigestFromSignedAttrs(attrsParsed);
            policyOid = _extractPolicyOidFromSignedAttrs(attrsParsed);
            final ({String? algorithmOid, Uint8List? value}) polHash =
              _extractPolicyHashFromSignedAttrs(attrsParsed);
            policyHashAlgorithmOid = polHash.algorithmOid;
            policyHashValue = polHash.value;
            signingTime = _extractSigningTimeFromSignedAttrs(attrsParsed);
            // print('EXTRACTED FROM RAW -> MD: ${messageDigest != null}, OID: $policyOid');
          } else {
             print('RAW content is not Asn1Set (is ${attrsParsed.runtimeType})');
             // invalid raw, force fallback?
             signedAttrsDer = null; 
          }
        } catch (e) {
          print('Error parsing RAW signed attributes: $e');
          signedAttrsDer = null; // Force fallback
        }
      }

      // Fallback (older behavior) if raw extraction fails.
      if (signedAttrsDer == null || signedAttrsDer.isEmpty) {
        final List<int>? tagged = signedAttrsTag.getDerEncoded();
        if (tagged != null && tagged.isNotEmpty) {
          signedAttrsTaggedDer = Uint8List.fromList(tagged);
        }

        final Uint8List candidate = _signedAttrsDerFromTag(signedAttrsTag);
        if (candidate.isNotEmpty) {
          signedAttrsDer = candidate;
          try {
            final Asn1? attrsParsed =
                Asn1Stream(PdfStreamReader(signedAttrsDer)).readAsn1();
            if (attrsParsed is Asn1Set) {
              messageDigest = _extractMessageDigestFromSignedAttrs(attrsParsed);
              policyOid = _extractPolicyOidFromSignedAttrs(attrsParsed);
              final ({String? algorithmOid, Uint8List? value}) polHash =
                  _extractPolicyHashFromSignedAttrs(attrsParsed);
              policyHashAlgorithmOid = polHash.algorithmOid;
              policyHashValue = polHash.value;
              signingTime = _extractSigningTimeFromSignedAttrs(attrsParsed);
            }
          } catch (_) {
            // ignore
          }
        }
      }
    }

    // Extract certificates.
    // Prefer raw slicing (preserves original bytes) when CMS is DER-like.
    // Fall back to ASN.1 object extraction for BER/indefinite-length encodings.
    List<_DerCertificate> certs = _extractCertificatesRawFromCms(cmsBytes);
    if (certs.isEmpty && certsTag != null) {
      certs = _extractCertificatesFromSignedDataTag(certsTag);
    }

    CipherParameter? signerKey;
    if (certs.isNotEmpty) {
      final _DerCertificate? signerCert = _findSignerCertificate(
        certs,
        sidSerial,
        sidIssuerDer,
        sidSki,
      );
      signerKey = signerCert?.cert?.getPublicKey();

      // Fallback: if we can't match signer identifier, but there is only 1 cert,
      // try using that one.
      if (signerKey == null && certs.length == 1 && certs.first.cert != null) {
        signerKey = certs.first.cert!.getPublicKey();
      }
    }

    return _CmsParsed(
      messageDigest: messageDigest,
      signedAttrsDer: signedAttrsDer,
      signedAttrsTaggedDer: signedAttrsTaggedDer,
      signature: signature,
      signatureAlgorithmOid: signatureAlgorithmOid,
      digestAlgorithmOid: digestAlgorithmOid,
      signerPublicKey: signerKey,
      certs: certs,
      signerSerial: sidSerial,
      signerIssuerDer: sidIssuerDer,
      signerSki: sidSki,
      policyOid: policyOid,
      policyHashAlgorithmOid: policyHashAlgorithmOid,
      policyHashValue: policyHashValue,
      signingTime: signingTime,
    );
  }

  List<_DerCertificate> _extractCertificatesFromSignedDataTag(Asn1Tag certsTag) {
    try {
      // SignedData.certificates is [0] IMPLICIT SET OF CertificateChoices.
      // Use Asn1Set.getAsn1Set(tag,false) to correctly handle IMPLICIT tagging
      // and BER/indefinite-length forms.
      final Asn1Set? certsSet = Asn1Set.getAsn1Set(certsTag, false);
      if (certsSet == null || certsSet.objects.isEmpty) {
        return const <_DerCertificate>[];
      }

      final List<_DerCertificate> out = <_DerCertificate>[];
      for (final Asn1Encode? enc in certsSet.objects) {
        final Asn1? item = enc?.getAsn1();
        if (item is! Asn1Sequence) continue;
        final List<int>? derList = item.getDerEncoded();
        if (derList == null || derList.isEmpty) continue;
        final Uint8List der = Uint8List.fromList(derList);

        X509Certificate? cert;
        try {
          final X509CertificateStructure? s =
              X509CertificateStructure.getInstance(item);
          if (s != null && s.subjectPublicKeyInfo != null) {
            cert = X509Certificate(s);
          }
        } catch (_) {
          cert = null;
        }

        out.add(_DerCertificate(der: der, cert: cert));
      }

      return out;
    } catch (_) {
      return const <_DerCertificate>[];
    }
  }

  (BigInt?, Uint8List?, Uint8List?) _extractIssuerAndSerial(Asn1 sid) {
    // issuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }
    if (sid is Asn1Sequence && sid.count >= 2) {
      final Asn1 issuer = sid[0]!.getAsn1()!;
      final DerInteger serial = sid[1]!.getAsn1()! as DerInteger;
      final Uint8List issuerDer = Uint8List.fromList(issuer.getDerEncoded()!);
      return (serial.positiveValue, issuerDer, null);
    }
    // subjectKeyIdentifier [0] IMPLICIT SubjectKeyIdentifier (OCTET STRING)
    if (sid is Asn1Tag && sid.tagNumber == 0) {
      final Asn1? obj = sid.getObject();
      print('DEBUG: Found SID Tag [0], obj=${obj.runtimeType}');
      // If implicit, the object inside should be treated as OctetString content directly?
      // Or Asn1Tag holds the OctetString.
      if (obj is DerOctet) {
        print('DEBUG: Extracted SKI: ${obj.getOctets()}');
        return (null, null, Uint8List.fromList(obj.getOctets() ?? []));
      }
      // If the parser wrapped it:
      // Some parsers might put an OctetString inside if it was constructed.
      // But SKI is usually primitive.
      // We might need to access the raw octets if Asn1Tag has them.
    }
    print('DEBUG: _extractIssuerAndSerial failed to extract. sid=${sid.runtimeType}');
    return (null, null, null);
  }

  Uint8List? _extractMessageDigestFromSignedAttrs(Asn1Set signedAttrs) {
    for (int i = 0; i < signedAttrs.objects.length; i++) {
      final Asn1Encode? itemEnc = signedAttrs[i];
      final Asn1? itemAsn1 = itemEnc?.getAsn1();
      if (itemAsn1 is! Asn1Sequence || itemAsn1.count < 2) continue;

      final DerObjectID? oidObj = itemAsn1[0]?.getAsn1() as DerObjectID?;
      if (oidObj == null) continue;
      if (oidObj.id != '1.2.840.113549.1.9.4') continue; // messageDigest

      final Asn1? valuesAsn1 = itemAsn1[1]?.getAsn1();
      final Asn1Set? values = valuesAsn1 is Asn1Set
          ? valuesAsn1
          : Asn1Set.getAsn1Set(valuesAsn1, false);
      if (values == null || values.objects.isEmpty) return null;

      final Asn1Encode? firstEnc = values[0];
      final Asn1? first = firstEnc?.getAsn1();
      if (first is DerOctet) {
        return Uint8List.fromList(first.getOctets()!);
      }
      return null;
    }
    return null;
  }

  String? _extractPolicyOidFromSignedAttrs(Asn1Set signedAttrs) {
    for (int i = 0; i < signedAttrs.objects.length; i++) {
      final Asn1Encode? itemEnc = signedAttrs[i];
      final Asn1? itemAsn1 = itemEnc?.getAsn1();
      if (itemAsn1 is! Asn1Sequence || itemAsn1.count < 2) continue;

      final DerObjectID? oidObj = itemAsn1[0]?.getAsn1() as DerObjectID?;
      if (oidObj == null) continue;
      // id-aa-ets-sigPolicyId
      if (oidObj.id != '1.2.840.113549.1.9.16.2.15') continue;

      final Asn1? valuesAsn1 = itemAsn1[1]?.getAsn1();
      final Asn1Set? values = valuesAsn1 is Asn1Set
          ? valuesAsn1
          : Asn1Set.getAsn1Set(valuesAsn1, false);
      if (values == null || values.objects.isEmpty) return null;

      final Asn1Encode? firstEnc = values[0];
      final Asn1? first = firstEnc?.getAsn1();

      // SignaturePolicyId ::= SEQUENCE {
      //    sigPolicyId SigPolicyId,
      //    sigPolicyHash SigPolicyHash OPTIONAL,
      //    sigPolicyQualifiers SEQUENCE SIZE (1..MAX) OF SigPolicyQualifier OPTIONAL }
      if (first is Asn1Sequence && first.count > 0) {
        final Asn1? policyId = first[0]?.getAsn1();
        if (policyId is DerObjectID) {
          return policyId.id;
        }
      }
      return null;
    }
    return null;
  }

  ({String? algorithmOid, Uint8List? value}) _extractPolicyHashFromSignedAttrs(
    Asn1Set signedAttrs,
  ) {
    for (int i = 0; i < signedAttrs.objects.length; i++) {
      final Asn1Encode? itemEnc = signedAttrs[i];
      final Asn1? itemAsn1 = itemEnc?.getAsn1();
      if (itemAsn1 is! Asn1Sequence || itemAsn1.count < 2) continue;

      final DerObjectID? oidObj = itemAsn1[0]?.getAsn1() as DerObjectID?;
      if (oidObj == null) continue;
      // id-aa-ets-sigPolicyId
      if (oidObj.id != '1.2.840.113549.1.9.16.2.15') continue;

      final Asn1? valuesAsn1 = itemAsn1[1]?.getAsn1();
      final Asn1Set? values = valuesAsn1 is Asn1Set
          ? valuesAsn1
          : Asn1Set.getAsn1Set(valuesAsn1, false);
      if (values == null || values.objects.isEmpty) {
        return (algorithmOid: null, value: null);
      }

      final Asn1Encode? firstEnc = values[0];
      final Asn1? first = firstEnc?.getAsn1();
      if (first is! Asn1Sequence) {
        return (algorithmOid: null, value: null);
      }

      // SignaturePolicyId ::= SEQUENCE {
      //    sigPolicyId SigPolicyId,
      //    sigPolicyHash SigPolicyHash OPTIONAL,
      //    sigPolicyQualifiers SEQUENCE SIZE (1..MAX) OF SigPolicyQualifier OPTIONAL }
      if (first.count < 2) {
        return (algorithmOid: null, value: null);
      }

      final Asn1? sigPolicyHashAsn1 = first[1]?.getAsn1();
      if (sigPolicyHashAsn1 is! Asn1Sequence || sigPolicyHashAsn1.count < 2) {
        return (algorithmOid: null, value: null);
      }

      // SigPolicyHash ::= OtherHashAlgAndValue
      // OtherHashAlgAndValue ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashValue OCTET STRING }
      final Asn1? algoSeq = sigPolicyHashAsn1[0]?.getAsn1();
      String? algorithmOid;
      if (algoSeq is Asn1Sequence && algoSeq.count >= 1) {
        final Asn1? algoOidAsn1 = algoSeq[0]?.getAsn1();
        if (algoOidAsn1 is DerObjectID) algorithmOid = algoOidAsn1.id;
      }

      final Asn1? valueAsn1 = sigPolicyHashAsn1[1]?.getAsn1();
      Uint8List? value;
      if (valueAsn1 is DerOctet && valueAsn1.getOctets() != null) {
        value = Uint8List.fromList(valueAsn1.getOctets()!);
      }

      return (algorithmOid: algorithmOid, value: value);
    }
    return (algorithmOid: null, value: null);
  }

  DateTime? _extractSigningTimeFromSignedAttrs(Asn1Set signedAttrs) {
     for (int i = 0; i < signedAttrs.objects.length; i++) {
        final Asn1Encode? itemEnc = signedAttrs[i];
        final Asn1? itemAsn1 = itemEnc?.getAsn1();
        if (itemAsn1 is! Asn1Sequence || itemAsn1.count < 2) continue;

        final DerObjectID? oidObj = itemAsn1[0]?.getAsn1() as DerObjectID?;
        if (oidObj?.id == '1.2.840.113549.1.9.5') { // id-signingTime
             final Asn1? valuesAsn1 = itemAsn1[1]?.getAsn1();
             final Asn1Set? values = valuesAsn1 is Asn1Set ? valuesAsn1 : Asn1Set.getAsn1Set(valuesAsn1, false);
             if (values != null && values.objects.isNotEmpty) {
                 final Asn1Encode? timeEnc = values[0];
                 final X509Time? time = X509Time.getTime(timeEnc);
                 return time?.toDateTime();
             }
        }
    }
    return null;
  }

  _DerCertificate? _findSignerCertificate(
    List<_DerCertificate> certs,
    BigInt? sidSerial,
    Uint8List? sidIssuerDer,
    Uint8List? sidSki,
  ) {
    if (sidSki != null) {
      // Find matches by Subject Key Identifier (extension: 2.5.29.14)
      for (final _DerCertificate c in certs) {
        final X509Certificate? x = c.cert;
        if (x == null) continue;

        final Asn1Octet? skiExt = x.getExtension(DerObjectID('2.5.29.14'));
        if (skiExt != null) {
          // Extension value is OCTET STRING wrapping the keyIdentifier (OCTET STRING).
          try {
            final Asn1? inner =
                Asn1Stream(PdfStreamReader(skiExt.getOctets())).readAsn1();
            if (inner is DerOctet) {
              final Uint8List keyId =
                  Uint8List.fromList(inner.getOctets() ?? []);
              if (_constantTimeEquals(keyId, sidSki)) return c;
            }
          } catch (_) {
            // ignore
          }
        }
      }
    }

    if (sidSerial == null) return null;
    for (final _DerCertificate c in certs) {
      final X509Certificate? x = c.cert;
      if (x == null) continue;
      final BigInt? serial = x.c?.serialNumber?.positiveValue;
      if (serial != sidSerial) {
        continue;
      }

      if (sidIssuerDer != null) {
        try {
          final Uint8List issuerDer = Uint8List.fromList(
            x.c!.issuer!.getDerEncoded()!,
          );
          if (!_constantTimeEquals(issuerDer, sidIssuerDer)) {
            continue;
          }
        } catch (_) {
          // if issuer comparison fails, fall back to serial-only match
        }
      }
      return c;
    }
    return null;
  }

  List<String> _pemCertificatesOrdered(_CmsParsed cms) {
    if (cms.certs.isEmpty) return const <String>[];

    final _DerCertificate? signer = _findSignerCertificate(
      cms.certs,
      cms.signerSerial,
      cms.signerIssuerDer,
      cms.signerSki,
    );

    final List<_DerCertificate> ordered = <_DerCertificate>[];
    if (signer != null) {
      ordered.add(signer);
      for (final c in cms.certs) {
        if (!identical(c, signer)) ordered.add(c);
      }
    } else {
      ordered.addAll(cms.certs);
    }

    return ordered
        .map((c) => _derToPemCertificate(c.der))
        .toList(growable: false);
  }

  crypto.Hash _hashFromDigestAlgorithmOid(String? oid) {
    // OIDs:
    // - sha1:   1.3.14.3.2.26
    // - sha256: 2.16.840.1.101.3.4.2.1
    // - sha384: 2.16.840.1.101.3.4.2.2
    // - sha512: 2.16.840.1.101.3.4.2.3
    switch (oid) {
      case '1.3.14.3.2.26':
        return crypto.sha1;
      case '2.16.840.1.101.3.4.2.2':
        return crypto.sha384;
      case '2.16.840.1.101.3.4.2.3':
        return crypto.sha512;
      case '2.16.840.1.101.3.4.2.1':
      default:
        return crypto.sha256;
    }
  }

  String? _signModeFromSignatureAlgorithmOid(String? oid) {
    switch (oid) {
      case '1.2.840.113549.1.1.5':
        return 'SHA-1withRSA';
      case '1.2.840.113549.1.1.11':
        return 'SHA-256withRSA';
      case '1.2.840.113549.1.1.12':
        return 'SHA-384withRSA';
      case '1.2.840.113549.1.1.13':
        return 'SHA-512withRSA';
      default:
        return null;
    }
  }

  CipherParameter _publicKeyFromPemCertificate(String pem) {
    final Uint8List der = _pemToDer(pem);
    final Asn1? parsed = Asn1Stream(PdfStreamReader(der)).readAsn1();
    if (parsed is! Asn1Sequence) {
      throw StateError('Invalid certificate DER');
    }
    final X509CertificateStructure? s =
        X509CertificateStructure.getInstance(parsed);
    if (s == null) {
      throw StateError('Could not parse certificate');
    }
    final X509Certificate cert = X509Certificate(s);
    return cert.getPublicKey();
  }

  Uint8List _pemToDer(String pem) {
    final String normalized = pem
        .replaceAll('-----BEGIN CERTIFICATE-----', '')
        .replaceAll('-----END CERTIFICATE-----', '')
        .replaceAll(RegExp(r'\s+'), '');
    return Uint8List.fromList(base64Decode(normalized));
  }

  String _derToPemCertificate(Uint8List der) {
    final String b64 = base64Encode(der);
    final StringBuffer out = StringBuffer();
    out.writeln('-----BEGIN CERTIFICATE-----');
    for (int i = 0; i < b64.length; i += 64) {
      out.writeln(b64.substring(i, i + 64 > b64.length ? b64.length : i + 64));
    }
    out.writeln('-----END CERTIFICATE-----');
    return out.toString();
  }

  bool _constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    int r = 0;
    for (int i = 0; i < a.length; i++) {
      r |= a[i] ^ b[i];
    }
    return r == 0;
  }
}
