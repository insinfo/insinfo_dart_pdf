import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import '../pdf/implementation/io/pdf_constants.dart';
import '../pdf/implementation/io/pdf_cross_table.dart';
import '../pdf/implementation/pdf_document/pdf_document.dart';
import '../pdf/implementation/primitives/pdf_array.dart';
import '../pdf/implementation/primitives/pdf_dictionary.dart';
import '../pdf/implementation/primitives/pdf_name.dart';
import '../pdf/implementation/primitives/pdf_number.dart';
import '../pdf/implementation/primitives/pdf_reference_holder.dart';

/// Informações rápidas do PDF (versão + DocMDP).
///
/// Esta classe faz leituras leves e não valida assinaturas.
///
/// - Versão: lida no header `%PDF-x.y` (primeiros bytes).
/// - DocMDP: lido do catálogo (`/Perms/DocMDP`) para extrair o `P`.
///
/// Use [PdfQuickInfo.fromBytes] para criar a instância com os bytes
/// apenas uma vez.
class PdfQuickInfo {
  const PdfQuickInfo._({
    required this.versionMajor,
    required this.versionMinor,
    required this.versionOffset,
    required this.versionRawHeader,
    required this.docMdpPermissionP,
  });

  /// Parte maior da versão (ex.: 1 em "1.7"), ou `null` se ausente.
  ///
  /// Extraída do header `%PDF-x.y`.
  final int? versionMajor;

  /// Parte menor da versão (ex.: 7 em "1.7"), ou `null` se ausente.
  ///
  /// Extraída do header `%PDF-x.y`.
  final int? versionMinor;

  /// Offset (em bytes) do token "%PDF-", ou `null` se ausente.
  final int? versionOffset;

  /// Linha de cabeçalho crua (Latin-1), ou `null` se ausente.
  final String? versionRawHeader;

  /// Valor P do DocMDP (ex.: 2), ou `null` se não houver DocMDP.
  ///
  /// DocMDP é por documento (catálogo), não por assinatura individual.
  final int? docMdpPermissionP;

  /// True quando há DocMDP.
  bool get hasDocMdp => docMdpPermissionP != null;

  /// Versão no formato "major.minor", ou `null` se ausente.
  String? get versionString => (versionMajor != null && versionMinor != null)
      ? '${versionMajor!}.${versionMinor!}'
      : null;

  /// Lê as informações rápidas (versão + DocMDP) do PDF em uma única passada.
  ///
  /// [maxVersionScanBytes] limita a busca do header.
  /// [readMDPInfo] pode ser desativado para evitar abrir o PDF.
  static PdfQuickInfo fromBytes(
    Uint8List pdfBytes, {
    int maxVersionScanBytes = 1024,
    bool readMDPInfo = true,
  }) {
    final _ParsedVersion version = _readPdfVersion(
      pdfBytes,
      maxScanBytes: maxVersionScanBytes,
    );
    final int? docMdpPermissionP =
        readMDPInfo ? _readDocMdpPermission(pdfBytes) : null;
    return PdfQuickInfo._(
      versionMajor: version.major,
      versionMinor: version.minor,
      versionOffset: version.offset,
      versionRawHeader: version.rawHeader,
      docMdpPermissionP: docMdpPermissionP,
    );
  }
}

class _ParsedVersion {
  const _ParsedVersion({
    required this.major,
    required this.minor,
    required this.offset,
    required this.rawHeader,
  });

  final int? major;
  final int? minor;
  final int? offset;
  final String? rawHeader;
}

_ParsedVersion _readPdfVersion(
  Uint8List pdfBytes, {
  int maxScanBytes = 1024,
}) {
  if (pdfBytes.isEmpty || maxScanBytes <= 0) {
    return const _ParsedVersion(
      major: null,
      minor: null,
      offset: null,
      rawHeader: null,
    );
  }

  final int scanLength = min(pdfBytes.length, maxScanBytes);
  const List<int> marker = <int>[0x25, 0x50, 0x44, 0x46, 0x2D]; // %PDF-

  for (int i = 0; i <= scanLength - marker.length; i++) {
    bool match = true;
    for (int j = 0; j < marker.length; j++) {
      if (pdfBytes[i + j] != marker[j]) {
        match = false;
        break;
      }
    }
    if (!match) continue;

    final int start = i + marker.length;
    int idx = start;

    // Parse major digits.
    int major = 0;
    int majorDigits = 0;
    while (idx < scanLength) {
      final int b = pdfBytes[idx];
      if (b < 0x30 || b > 0x39) break;
      major = major * 10 + (b - 0x30);
      majorDigits++;
      idx++;
    }
    if (majorDigits == 0 || idx >= scanLength || pdfBytes[idx] != 0x2E) {
      continue;
    }
    idx++; // skip '.'

    // Parse minor digits.
    int minor = 0;
    int minorDigits = 0;
    while (idx < scanLength) {
      final int b = pdfBytes[idx];
      if (b < 0x30 || b > 0x39) break;
      minor = minor * 10 + (b - 0x30);
      minorDigits++;
      idx++;
    }
    if (minorDigits == 0) continue;

    // Capture raw header line (until CR/LF or end of scan).
    int lineEnd = i;
    while (lineEnd < scanLength &&
        pdfBytes[lineEnd] != 0x0A &&
        pdfBytes[lineEnd] != 0x0D) {
      lineEnd++;
    }
    final String rawHeader = latin1.decode(
      pdfBytes.sublist(i, lineEnd),
      allowInvalid: true,
    );

    return _ParsedVersion(
      major: major,
      minor: minor,
      offset: i,
      rawHeader: rawHeader,
    );
  }

  return const _ParsedVersion(
    major: null,
    minor: null,
    offset: null,
    rawHeader: null,
  );
}

int? _readDocMdpPermission(Uint8List pdfBytes) {
  final PdfDocument doc = PdfDocument(inputBytes: pdfBytes);
  try {
    final dynamic catalog = PdfDocumentHelper.getHelper(doc).catalog;
    final dynamic permsPrim = catalog[PdfDictionaryProperties.perms];
    final dynamic perms =
        permsPrim is PdfReferenceHolder ? permsPrim.object : permsPrim;
    if (perms is! PdfDictionary) return null;

    final dynamic docMdpPrim = perms[PdfDictionaryProperties.docMDP];
    if (docMdpPrim == null) return null;

    final dynamic docMdpObj = PdfCrossTable.dereference(docMdpPrim);
    final PdfDictionary? sigDict = docMdpObj is PdfDictionary
        ? docMdpObj
        : (docMdpPrim is PdfReferenceHolder &&
                docMdpPrim.object is PdfDictionary)
            ? docMdpPrim.object as PdfDictionary
            : null;

    return sigDict != null ? _extractDocMdpP(sigDict) : null;
  } catch (_) {
    return null;
  } finally {
    doc.dispose();
  }
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
    if (transformMethod is PdfName && transformMethod.name != 'DocMDP') {
      return null;
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
