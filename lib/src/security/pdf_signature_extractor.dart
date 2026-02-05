import 'dart:typed_data';

import '../vector/ui.dart';
import '../pdf/implementation/forms/pdf_signature_field.dart';
import '../pdf/implementation/io/pdf_constants.dart';
import '../pdf/implementation/io/pdf_cross_table.dart';
import '../pdf/implementation/pages/pdf_page.dart';
import '../pdf/implementation/pdf_document/pdf_document.dart';
import '../pdf/implementation/primitives/pdf_array.dart';
import '../pdf/implementation/primitives/pdf_dictionary.dart';
import '../pdf/implementation/primitives/pdf_name.dart';
import '../pdf/implementation/primitives/pdf_number.dart';
import '../pdf/implementation/primitives/pdf_reference.dart';
import '../pdf/implementation/primitives/pdf_reference_holder.dart';
import '../pdf/implementation/primitives/pdf_string.dart';
import '../pdf/implementation/security/digital_signature/pdf_signature_utils.dart';

/// Simple reference to a PDF page object.
class PdfPageRef {
  const PdfPageRef({required this.objNum, required this.genNum});

  final int objNum;
  final int genNum;

  Map<String, dynamic> toMap() => <String, dynamic>{
        'obj_num': objNum,
        'gen_num': genNum,
      };
}

/// Field mapping for a signature, useful for anchoring in UI.
class PdfSignatureFieldMapping {
  const PdfSignatureFieldMapping({
    required this.fieldName,
    required this.rect,
    required this.pageIndex,
    required this.pageNumber,
    required this.pageRef,
  });

  final String fieldName;
  final Rect? rect;
  final int? pageIndex;
  final int? pageNumber;
  final PdfPageRef? pageRef;

  Map<String, dynamic> toMap() => <String, dynamic>{
        'field_name': fieldName,
        'rect': rect == null
            ? null
            : <String, dynamic>{
                'left': rect!.left,
                'top': rect!.top,
                'width': rect!.width,
                'height': rect!.height,
              },
        'page_index': pageIndex,
        'page_number': pageNumber,
        'page_ref': pageRef?.toMap(),
      };
}

/// Extracted signature data without cryptographic validation.
class PdfSignatureExtraction {
  PdfSignatureExtraction({
    required this.field,
    required this.byteRange,
    required this.pkcs7Der,
    required this.contentsStart,
    required this.contentsEnd,
    required this.signingTime,
    required this.reason,
    required this.location,
    required this.contactInfo,
    required this.name,
    required this.filter,
    required this.subFilter,
  });

  final PdfSignatureFieldMapping field;
  final List<int> byteRange;
  final Uint8List pkcs7Der;
  final int? contentsStart;
  final int? contentsEnd;
  final DateTime? signingTime;
  final String? reason;
  final String? location;
  final String? contactInfo;
  final String? name;
  final String? filter;
  final String? subFilter;

  int get signedRevisionLength =>
      byteRange.length == 4 ? byteRange[2] + byteRange[3] : -1;

  Map<String, dynamic> toMap() => <String, dynamic>{
        'field': field.toMap(),
        'byte_range': byteRange,
        'contents_start': contentsStart,
        'contents_end': contentsEnd,
        'signed_revision_length': signedRevisionLength,
        'signing_time': signingTime?.toIso8601String(),
        'reason': reason,
        'location': location,
        'contact_info': contactInfo,
        'name': name,
        'filter': filter,
        'sub_filter': subFilter,
        'pkcs7_length': pkcs7Der.length,
      };
}

/// Extracted signature list.
class PdfSignatureExtractionReport {
  PdfSignatureExtractionReport({required this.signatures});

  final List<PdfSignatureExtraction> signatures;

  Map<String, dynamic> toMap() => <String, dynamic>{
        'signatures': signatures.map((s) => s.toMap()).toList(growable: false),
      };
}

/// Extracts signature data from a PDF without validation.
class PdfSignatureExtractor {
  PdfSignatureExtractionReport extract(Uint8List pdfBytes) {
    final PdfDocument doc = PdfDocument(inputBytes: pdfBytes);
    try {
      final List<PdfSignatureExtraction> out = <PdfSignatureExtraction>[];
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

        final _ContentsRange? cr = sigRefHolder?.reference != null
            ? _resolveContentsRange(
                doc: doc,
                pdfBytes: pdfBytes,
                signatureReference: sigRefHolder!.reference!,
                byteRange: byteRange,
              )
            : _findContentsRangeInGap(pdfBytes, byteRange);

        final PdfSignatureFieldMapping fieldMapping =
          _buildFieldMapping(doc, field, widget: widget);

        out.add(
          PdfSignatureExtraction(
            field: fieldMapping,
            byteRange: byteRange,
            pkcs7Der: pkcs7Der,
            contentsStart: cr?.start,
            contentsEnd: cr?.end,
            signingTime: _extractSigningTime(sigDict),
            reason: _readStringProperty(sigDict, PdfDictionaryProperties.reason),
            location:
                _readStringProperty(sigDict, PdfDictionaryProperties.location),
            contactInfo: _readStringProperty(
              sigDict,
              PdfDictionaryProperties.contactInfo,
            ),
            name: _readStringProperty(sigDict, PdfDictionaryProperties.name),
            filter: _readNameProperty(sigDict, PdfDictionaryProperties.filter),
            subFilter:
                _readNameProperty(sigDict, PdfDictionaryProperties.subFilter),
          ),
        );
      }

      out.sort(
        (a, b) => a.signedRevisionLength.compareTo(b.signedRevisionLength),
      );

      return PdfSignatureExtractionReport(signatures: out);
    } finally {
      doc.dispose();
    }
  }
}

/// Extracts the CMS/PKCS#7 contents (DER) for all signatures.
List<Uint8List> extractAllSignatureContents(Uint8List pdfBytes) {
  final PdfSignatureExtractionReport report =
      PdfSignatureExtractor().extract(pdfBytes);
  return report.signatures
      .map((s) => Uint8List.fromList(s.pkcs7Der))
      .toList(growable: false);
}

/// Extracts the CMS/PKCS#7 contents (DER) for the signature at [index].
Uint8List extractSignatureContentsAt(Uint8List pdfBytes, int index) {
  final List<Uint8List> all = extractAllSignatureContents(pdfBytes);
  if (index < 0 || index >= all.length) {
    throw RangeError.index(index, all, 'index');
  }
  return all[index];
}

PdfSignatureFieldMapping _buildFieldMapping(
  PdfDocument doc,
  PdfSignatureField field, {
  PdfDictionary? widget,
}) {
  final PdfPage? page = field.page;
  int? pageIndex;
  int? pageNumber;
  Rect? rect;
  PdfPageRef? pageRef;

  if (page != null) {
    pageIndex = doc.pages.indexOf(page);
    if (pageIndex >= 0) {
      pageNumber = pageIndex + 1;
    } else {
      pageIndex = null;
    }
    rect = field.bounds;

    final PdfDictionary? pageDict = PdfPageHelper.getHelper(page).dictionary;
    if (pageDict != null) {
      final PdfReference ref =
          PdfDocumentHelper.getHelper(doc).crossTable.getReference(pageDict);
      if (ref.objNum != null && ref.genNum != null) {
        pageRef = PdfPageRef(objNum: ref.objNum!, genNum: ref.genNum!);
      }
    }
  } else if (widget != null) {
    rect = field.bounds;
    final PdfDictionary? pageDict =
        PdfCrossTable.dereference(widget[PdfDictionaryProperties.p])
            as PdfDictionary?;
    if (pageDict != null) {
      final PdfReference ref =
          PdfDocumentHelper.getHelper(doc).crossTable.getReference(pageDict);
      if (ref.objNum != null && ref.genNum != null) {
        pageRef = PdfPageRef(objNum: ref.objNum!, genNum: ref.genNum!);
        for (int i = 0; i < doc.pages.count; i++) {
          final PdfPage p = doc.pages[i];
          final PdfDictionary? pDict = PdfPageHelper.getHelper(p).dictionary;
          if (pDict == null) continue;
          final PdfReference pRef =
              PdfDocumentHelper.getHelper(doc).crossTable.getReference(pDict);
          if (pRef.objNum == ref.objNum && pRef.genNum == ref.genNum) {
            pageIndex = i;
            pageNumber = i + 1;
            break;
          }
        }
      }
    }
    if (pageIndex == null) {
      final PdfReference widgetRef =
          PdfDocumentHelper.getHelper(doc).crossTable.getReference(widget);
      final bool widgetHasRef =
          widgetRef.objNum != null && widgetRef.genNum != null;
      bool found = false;
      for (int i = 0; i < doc.pages.count && !found; i++) {
        final PdfPage p = doc.pages[i];
        final PdfArray? annots = PdfPageHelper.getHelper(p).obtainAnnotations();
        if (annots == null) continue;
        for (int j = 0; j < annots.count; j++) {
          final dynamic annot = annots[j];
          final PdfDictionary? annotDict =
              PdfCrossTable.dereference(annot) as PdfDictionary?;
          PdfReference? annotRef;
          if (annot is PdfReferenceHolder) {
            annotRef = annot.reference;
          } else if (annot is PdfReference) {
            annotRef = annot;
          } else if (annotDict != null) {
            annotRef =
                PdfDocumentHelper.getHelper(doc).crossTable.getReference(
                      annotDict,
                    );
          }

          final bool matchByRef = widgetHasRef &&
              annotRef != null &&
              annotRef.objNum == widgetRef.objNum &&
              annotRef.genNum == widgetRef.genNum;
          final bool matchByDict =
              annotDict != null && identical(annotDict, widget);

          if (matchByRef || matchByDict) {
            pageIndex = i;
            pageNumber = i + 1;
            final PdfDictionary? pDict = PdfPageHelper.getHelper(p).dictionary;
            if (pageRef == null && pDict != null) {
              final PdfReference pRef =
                  PdfDocumentHelper.getHelper(doc).crossTable.getReference(
                        pDict,
                      );
              if (pRef.objNum != null && pRef.genNum != null) {
                pageRef = PdfPageRef(objNum: pRef.objNum!, genNum: pRef.genNum!);
              }
            }
            found = true;
            break;
          }
        }
      }
    }
    if (pageIndex == null) {
      final PdfSignatureFieldHelper helper =
          PdfSignatureFieldHelper.getHelper(field);
      final PdfDictionary? fieldDict = helper.dictionary;
      if (fieldDict != null) {
        final PdfReference fieldRef =
            PdfDocumentHelper.getHelper(doc).crossTable.getReference(fieldDict);
        final bool fieldHasRef =
            fieldRef.objNum != null && fieldRef.genNum != null;
        bool found = false;
        for (int i = 0; i < doc.pages.count && !found; i++) {
          final PdfPage p = doc.pages[i];
          final PdfArray? annots =
              PdfPageHelper.getHelper(p).obtainAnnotations();
          if (annots == null) continue;
          for (int j = 0; j < annots.count; j++) {
            final dynamic annot = annots[j];
            final PdfDictionary? annotDict =
                PdfCrossTable.dereference(annot) as PdfDictionary?;
            if (annotDict == null) continue;
            final dynamic parent = annotDict[PdfDictionaryProperties.parent];
            PdfReference? parentRef;
            if (parent is PdfReferenceHolder) {
              parentRef = parent.reference;
            } else if (parent is PdfReference) {
              parentRef = parent;
            } else if (parent is PdfDictionary) {
              parentRef =
                  PdfDocumentHelper.getHelper(doc).crossTable.getReference(parent);
            }

            final bool matchByRef = fieldHasRef &&
                parentRef != null &&
                parentRef.objNum == fieldRef.objNum &&
                parentRef.genNum == fieldRef.genNum;
            final bool matchByDict =
                parent is PdfDictionary && identical(parent, fieldDict);

            if (matchByRef || matchByDict) {
              pageIndex = i;
              pageNumber = i + 1;
              final PdfDictionary? pDict =
                  PdfPageHelper.getHelper(p).dictionary;
              if (pageRef == null && pDict != null) {
                final PdfReference pRef =
                    PdfDocumentHelper.getHelper(doc).crossTable.getReference(
                          pDict,
                        );
                if (pRef.objNum != null && pRef.genNum != null) {
                  pageRef =
                      PdfPageRef(objNum: pRef.objNum!, genNum: pRef.genNum!);
                }
              }
              found = true;
              break;
            }
          }
        }
      }
    }
  }

  return PdfSignatureFieldMapping(
    fieldName: field.name ?? '',
    rect: rect,
    pageIndex: pageIndex,
    pageNumber: pageNumber,
    pageRef: pageRef,
  );
}

_ContentsRange? _resolveContentsRange({
  required PdfDocument doc,
  required Uint8List pdfBytes,
  required PdfReference signatureReference,
  required List<int> byteRange,
}) {
  final PdfSignatureOffsets? preciseOffsets = PdfSignatureUtils.resolveOffsets(
    doc: doc,
    pdfBytes: pdfBytes,
    signatureReference: signatureReference,
  );
  if (preciseOffsets != null) {
    return _ContentsRange(
      preciseOffsets.contentsOffsets[0],
      preciseOffsets.contentsOffsets[1],
    );
  }
  return _findContentsRangeInGap(pdfBytes, byteRange);
}

class _ContentsRange {
  _ContentsRange(this.start, this.end);
  final int start;
  final int end;
}

_ContentsRange? _findContentsRangeInGap(
  Uint8List pdfBytes,
  List<int> byteRange,
) {
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
  if (labelPos == -1) {
    final int lt = _scanForwardByte(pdfBytes, gapStart, gapEnd, 0x3C); // '<'
    final int gt = _scanBackwardByte(pdfBytes, gapEnd - 1, gapStart, 0x3E); // '>'
    if (lt != -1 && gt != -1 && gt > lt) {
      return _ContentsRange(lt + 1, gt);
    }
    return null;
  }

  int i = labelPos + needle.length;
  while (i < gapEnd) {
    final int b = pdfBytes[i];
    if (b == 0x3C) {
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

int _scanForwardByte(Uint8List bytes, int start, int end, int target) {
  for (int i = start; i < end; i++) {
    if (bytes[i] == target) return i;
  }
  return -1;
}

int _scanBackwardByte(Uint8List bytes, int start, int end, int target) {
  for (int i = start; i >= end; i--) {
    if (bytes[i] == target) return i;
  }
  return -1;
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

  final PdfString tmp = PdfString('');
  final String candidate = contentsPrim.value ?? String.fromCharCodes(data);
  final List<int> decoded = tmp.hexToBytes(candidate);
  if (decoded.isEmpty) {
    return null;
  }
  return Uint8List.fromList(decoded);
}

DateTime? _extractSigningTime(PdfDictionary sigDict) {
  if (!sigDict.containsKey(PdfDictionaryProperties.m)) return null;
  final dynamic mPrim =
      PdfCrossTable.dereference(sigDict[PdfDictionaryProperties.m]);
  if (mPrim is! PdfString) return null;
  final String? raw = mPrim.value;
  if (raw == null || raw.trim().isEmpty) return null;
  try {
    return sigDict.getDateTime(mPrim);
  } catch (_) {
    return null;
  }
}

String? _readStringProperty(PdfDictionary sigDict, String key) {
  if (!sigDict.containsKey(key)) return null;
  final dynamic prim = PdfCrossTable.dereference(sigDict[key]);
  if (prim is PdfString) return prim.value;
  return null;
}

String? _readNameProperty(PdfDictionary sigDict, String key) {
  if (!sigDict.containsKey(key)) return null;
  final dynamic prim = PdfCrossTable.dereference(sigDict[key]);
  if (prim is PdfName) return prim.name;
  return null;
}
