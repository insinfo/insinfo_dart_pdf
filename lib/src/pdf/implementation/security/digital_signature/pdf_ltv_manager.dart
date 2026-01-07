import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../../../interfaces/pdf_interface.dart';
import '../../io/pdf_constants.dart';
import '../../io/pdf_cross_table.dart';
import '../../pdf_document/pdf_document.dart';
import '../../primitives/pdf_array.dart';
import '../../primitives/pdf_dictionary.dart';
import '../../primitives/pdf_name.dart';
import '../../primitives/pdf_reference_holder.dart';
import '../../primitives/pdf_stream.dart';
import '../../primitives/pdf_string.dart';
import 'kms/revocation_data_client.dart';
import 'pdf_signature_validator.dart';
import 'x509/x509_certificates.dart';
import 'x509/x509_utils.dart';

/// Manages Long Term Validation (LTV) features for PDF Documents.
///
/// Enables adding DSS (Document Security Store) and VRI (Validation Related Information)
/// to ensure signatures remain valid even if certificates expire or revocation servers go offline.
class PdfLtvManager {
  PdfLtvManager(this.document);

  final PdfDocument document;

  /// Adds LTV information (DSS/VRI) for all signatures in the document.
  ///
  /// [pdfBytes]: The raw bytes of the PDF document (required to parse existing signatures).
  /// [trustedRoots]: List of trusted root certificates to validate chains.
  /// [addVri]: Whether to add VRI dictionaries for each signature (recommended for PAdES-LTV).
  Future<void> enableLtv(
    Uint8List pdfBytes, {
    List<X509Certificate>? trustedRoots,
    bool addVri = true,
  }) async {
      // LTV precisa ser aplicado via atualização incremental (append-only)
      // quando o documento já está assinado.
      if (PdfDocumentHelper.getHelper(document).isLoadedDocument &&
            document.hasSignatures) {
         document.fileStructure.incrementalUpdate = true;
      }

    final PdfSignatureValidator validator = PdfSignatureValidator();
    // We use the validator to extract signatures and their certificates
    final PdfSignatureValidationReport report = await validator.validateAllSignatures(
      pdfBytes,
      fetchCrls: false, // We will fetch carefully below
    ); // No roots passed here, manual chain processing

    final List<List<int>> allCrls = [];
    final List<List<int>> allOcsps = [];
    final List<List<int>> allCerts = [];

    final PdfDictionary catalog = PdfDocumentHelper.getHelper(document).catalog;
    
    // Preparation: Get Repositories
    // We'll update the DSS at the end.

    for (final PdfSignatureValidationItem sig in report.signatures) {
      if (!sig.validation.cmsSignatureValid) continue;

      // Chain building
      final List<X509Certificate> chain = [];
      // Also keep raw bytes for DSS even if parsing fails
      final List<Uint8List> chainBytes = [];

      for (final String pem in sig.validation.certsPem) {
        try {
          final Uint8List der = X509Utils.pemToDer(pem);
          chainBytes.add(der);
          chain.add(X509Utils.parsePemCertificate(pem));
        } catch (_) {
          // If parsing fails, we still have the bytes for DSS, 
          // but chain logic (revocation) might be incomplete.
        }
      }
      
      // Collect certificates for DSS
      for(final bytes in chainBytes) {
         allCerts.add(bytes);
      }

      // Fetch Revocation Info
      final List<List<int>> sigCrls = [];
      final List<List<int>> sigOcsps = [];

      for (int i = 0; i < chain.length; i++) {
        final X509Certificate cert = chain[i];
        
        // Find Issuer
        X509Certificate? issuer;
        if (trustedRoots != null) {
           issuer = X509Utils.findIssuer(cert, trustedRoots);
        }
        if (issuer == null && i + 1 < chain.length) {
          // Assuming the next in chain is issuer (typical, but findIssuer is safer)
           issuer = X509Utils.findIssuer(cert, chain);
        }
        
        // 1. Try OCSP
        if (issuer != null) {
          final List<int>? ocspBytes = await RevocationDataClient.fetchOcspResponseBytes(cert, issuer);
          if (ocspBytes != null) {
            sigOcsps.add(ocspBytes);
            allOcsps.add(ocspBytes);
          }
        }

        // 2. Try CRL
        final List<List<int>> fetchedCrls = await RevocationDataClient.fetchCrls(cert);
        for(final crl in fetchedCrls) {
           sigCrls.add(crl);
           allCrls.add(crl);
        }
      }

      // Add VRI for this signature
      if (addVri) {
        _addVri(catalog, sig, sigCrls, sigOcsps, chain);
      }
    }

    // Update Global DSS
    _updateDss(catalog, allCrls, allOcsps, allCerts);

      // Garanta que o catálogo seja persistido no save incremental.
      catalog.modify();
  }
  
  void _addVri(
      PdfDictionary catalog,
      PdfSignatureValidationItem sig,
      List<List<int>> crls,
      List<List<int>> ocsps,
      List<X509Certificate> chain) {
          
    // Ensure DSS dictionary exists or will be created by _updateDss
    // However, VRI is inside DSS, so we need to coordinate.
    // We will assume _updateDss handles the main structure, but we need to create the VRI entries.
    
    // 1. Compute VRI Key: SHA1 of signature contents
    // sig.validation doesn't have contents, but sig.byteRange can help or we need the raw bytes.
    // The Validator doesn't return the signature bytes explicitly in Item.
    // But we have PdfSignatureValidationResult. 
    // And we have the signature name.
    
    // We need to find the signature object in the PdfDocument to get the /Contents
    final PdfDocumentHelper helper = PdfDocumentHelper.getHelper(document);
    final PdfDictionary? sigDict = _findSignatureDictionary(helper, sig.fieldName);
    
    if (sigDict != null) {
       final IPdfPrimitive? contentsObj = sigDict[PdfDictionaryProperties.contents];
       List<int>? signatureBytes;
       if (contentsObj is PdfString) {
          signatureBytes = contentsObj.data;
       }
       
       if (signatureBytes != null) {
          final String vriKey = sha1.convert(signatureBytes).toString().toUpperCase();
          
          final PdfDictionary vriDict = PdfDictionary();
          
          if (crls.isNotEmpty) {
             final PdfArray crlArr = PdfArray();
             for(final c in crls) _addToArrayAsStream(crlArr, c);
             vriDict[PdfDictionaryProperties.crl] = crlArr;
          }
          if (ocsps.isNotEmpty) {
             final PdfArray ocspArr = PdfArray();
             for(final o in ocsps) _addToArrayAsStream(ocspArr, o);
             vriDict[PdfDictionaryProperties.ocsp] = ocspArr;
          }
          if (chain.isNotEmpty) {
             final PdfArray certArr = PdfArray();
             for(final c in chain) {
                 if (c.c?.getDerEncoded() != null) {
                    _addToArrayAsStream(certArr, c.c!.getDerEncoded()!);
                 }
             }
             vriDict['Cert'] = certArr;
          }
          
          // Add to /DSS/VRI
          // We need to fetch/create DSS/VRI
          _addToDssVri(catalog, vriKey, vriDict);
       }
    }
  }

  PdfDictionary? _findSignatureDictionary(PdfDocumentHelper helper, String fieldName) {
     // Simple linear search or usage of helper maps if available.
     // For now, let's scan AcroForm fields.
     final PdfDictionary? root = helper.catalog;
     if (root == null) return null;
     
     if (root.containsKey(PdfDictionaryProperties.acroForm)) {
       // Traverse fields... implementation omitted for brevity, 
       // but typically we can use the field name map if it was built.
       // Since we don't have easy access to the form field map here without parsing,
       // we might rely on the fact that PdfSignatureValidator parses it.
       // But we are in a writing context.
       
       // Optimization: Rely on PdfStructure or specific lookup?
       // Let's iterate fields.
       final IPdfPrimitive? form = PdfCrossTable.dereference(root[PdfDictionaryProperties.acroForm]);
       if (form is PdfDictionary && form.containsKey(PdfDictionaryProperties.fields)) {
           final IPdfPrimitive? fields = PdfCrossTable.dereference(form[PdfDictionaryProperties.fields]);
           if (fields is PdfArray) {
              return _findSigInArray(fields, fieldName);
           }
       }
     }
     return null;
  }
  
  PdfDictionary? _findSigInArray(PdfArray fields, String name) {
      for(int i=0; i<fields.count; i++) {
          final IPdfPrimitive? field = PdfCrossTable.dereference(fields[i]);
          if (field is PdfDictionary) {
               // Check name
               String? fName;
               if (field.containsKey(PdfDictionaryProperties.t)) {
                   final IPdfPrimitive? t = PdfCrossTable.dereference(field[PdfDictionaryProperties.t]);
                   if (t is PdfString) fName = t.value;
               }
               
               if (fName == name) {
                   if (field.containsKey(PdfDictionaryProperties.v)) {
                      final IPdfPrimitive? v = PdfCrossTable.dereference(field[PdfDictionaryProperties.v]);
                      if (v is PdfDictionary) return v;
                   }
                   return field; // Or maybe the dict itself is the sig field, but /V holds value
               }
               
               // Kids
               if (field.containsKey(PdfDictionaryProperties.kids)) {
                    final IPdfPrimitive? kids = PdfCrossTable.dereference(field[PdfDictionaryProperties.kids]);
                    if (kids is PdfArray) {
                         final PdfDictionary? found = _findSigInArray(kids, name);
                         if (found != null) return found;
                    }
               }
          }
      }
      return null;
  }

  void _updateDss(PdfDictionary catalog, List<List<int>> crls, List<List<int>> ocsps, List<List<int>> certs) {
    PdfDictionary? dss;
    if (catalog.containsKey(PdfDictionaryProperties.dss)) {
       final IPdfPrimitive? existing = PdfCrossTable.dereference(catalog[PdfDictionaryProperties.dss]);
       if (existing is PdfDictionary) dss = existing;
    }
    
    if (dss == null) {
       dss = PdfDictionary();
       catalog[PdfDictionaryProperties.dss] = PdfReferenceHolder(dss);
    }
    
    // Certs
    if (certs.isNotEmpty) {
       _mergeArray(dss, PdfDictionaryProperties.certs, certs);
    }
    // CRLs
    if (crls.isNotEmpty) {
       _mergeArray(dss, PdfDictionaryProperties.crls, crls);
    }
    // OCSPs
    if (ocsps.isNotEmpty) {
       _mergeArray(dss, PdfDictionaryProperties.ocsps, ocsps);
    }

    dss.modify();
  }

  void _addToDssVri(PdfDictionary catalog, String key, PdfDictionary vriDict) {
       // Ensure DSS
       _updateDss(catalog, [], [], []); 
       final IPdfPrimitive? dssObj = PdfCrossTable.dereference(catalog[PdfDictionaryProperties.dss]);
       if (dssObj is! PdfDictionary) return;
       final PdfDictionary dss = dssObj;
       
       PdfDictionary? vri;
       if (dss.containsKey(PdfDictionaryProperties.vri)) {
           final IPdfPrimitive? existingVri = PdfCrossTable.dereference(dss[PdfDictionaryProperties.vri]);
           if (existingVri is PdfDictionary) vri = existingVri;
       }
       if (vri == null) {
           vri = PdfDictionary();
           dss[PdfDictionaryProperties.vri] = PdfReferenceHolder(vri);
       }
       
       vri[PdfName(key)] = PdfReferenceHolder(vriDict);

         vriDict.modify();
         vri.modify();
         dss.modify();
  }

  void _mergeArray(PdfDictionary dict, String key, List<List<int>> newItems) {
      PdfArray? arr;
      if (dict.containsKey(key)) {
          final IPdfPrimitive? existing = PdfCrossTable.dereference(dict[key]);
          if (existing is PdfArray) arr = existing;
      }
      if (arr == null) {
          arr = PdfArray();
          dict[key] = PdfReferenceHolder(arr);
      }
      
      // We should check for duplicates to optimize, but pure append is valid.
      // Optimizing: Check if bytes already exist? 
      // Comparing streams is expensive. We'll append.
      // Ideally implementation should check hashes or similar.
      for(final item in newItems) {
         _addToArrayAsStream(arr, item);
      }

      arr.changed = true;
      dict.modify();
  }

  void _addToArrayAsStream(PdfArray arr, List<int> bytes) {
      // Check if we can find this stream? Hard without reading all.
      // Just add.
      final PdfDictionary streamDict = PdfDictionary();
      final PdfStream stream = PdfStream(streamDict, bytes);
      // stream.compress = true; // Use default
      arr.add(PdfReferenceHolder(stream));
  }
}
