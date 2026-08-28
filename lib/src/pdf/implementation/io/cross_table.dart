import '../../interfaces/pdf_interface.dart';
import '../io/pdf_constants.dart';
import '../primitives/pdf_array.dart';
import '../primitives/pdf_dictionary.dart';
import '../primitives/pdf_name.dart';
import '../primitives/pdf_null.dart';
import '../primitives/pdf_number.dart';
import '../primitives/pdf_reference.dart';
import '../primitives/pdf_reference_holder.dart';
import '../primitives/pdf_stream.dart';
import '../primitives/pdf_string.dart';
import '../security/pdf_encryptor.dart';
import 'enums.dart';
import 'pdf_cross_table.dart';
import 'pdf_data_source.dart';
import 'pdf_format_exception.dart';
import 'pdf_parser.dart';
import 'pdf_repair_options.dart';
import 'pdf_repair_scanner.dart';
import 'pdf_reader.dart';

const bool _debugXref =
    bool.fromEnvironment('PDF_DEBUG_XREF', defaultValue: false);

void _debugXrefLog(String message) {
  if (_debugXref) {
    // ignore: avoid_print
    print('[pdf][xref] $message');
  }
}

/// internal class
class CrossTable {
  //Constructor
  /// internal constructor
  CrossTable(
    PdfDataSource? data,
    PdfCrossTable crossTable, [
    this.strictness = PdfStrictnessLevel.conservative,
    this.repairScan = PdfRepairScan.thorough,
  ]) {
    if (data == null || data.length == 0) {
      throw PdfFormatException('The PDF data is empty.');
    }
    _source = data;
    _crossTable = crossTable;
    _initialize();
  }

  /// internal constructor
  CrossTable.fromFdf(List<int> docStream, PdfCrossTable crossTable) {
    _source = PdfMemoryDataSource(docStream);
    _crossTable = crossTable;
    objects = <int, ObjectInformation>{};
  }

  //Fields
  late PdfDataSource _source;
  late PdfCrossTable _crossTable;
  PdfReader? _reader;
  PdfParser? _parser;

  /// internal field
  late Map<int, ObjectInformation> objects;
  late Map<PdfStream, PdfParser> _readersTable;
  late Map<int, PdfStream> _archives;

  /// internal field
  int startCrossReference = 0;

  /// internal field
  ///
  /// How much damage the reader is allowed to work around. See
  /// [PdfStrictnessLevel].
  PdfStrictnessLevel strictness = PdfStrictnessLevel.conservative;

  /// internal field
  ///
  /// How much of the file the recovery scan reads. See [PdfRepairScan].
  PdfRepairScan repairScan = PdfRepairScan.thorough;

  /// internal field
  ///
  /// Whether the object table came from scanning the file rather than from a
  /// cross-reference table the file itself supplied.
  bool isRepaired = false;

  /// internal field
  bool validateSyntax = false;

  /// internal field
  PdfDictionary? trailer;
  bool _isStructureAltered = false;
  int _whiteSpace = 0;

  /// internal field
  int initialNumberOfSubsection = 0;

  /// internal field
  int initialSubsectionCount = 0;

  /// internal field
  int totalNumberOfSubsection = 0;
  int? _generationNumber;
  late Map<int, List<ObjectInformation>> _allTables;
  PdfReferenceHolder? _documentCatalog;
  PdfEncryptor? _encryptor;

  //Properties
  /// internal property
  ObjectInformation? operator [](int? key) => _returnValue(key);

  /// internal property
  PdfReader get reader {
    _reader ??= PdfReader.fromSource(_source);
    return _reader!;
  }

  /// internal property
  PdfParser get parser {
    _parser ??= PdfParser(this, reader, _crossTable);
    return _parser!;
  }

  /// internal property
  PdfReferenceHolder? get documentCatalog {
    if (_documentCatalog == null) {
      final PdfDictionary trailerObj = trailer!;
      final IPdfPrimitive? obj = trailerObj[PdfDictionaryProperties.root];
      if (obj is PdfReferenceHolder) {
        _documentCatalog = obj;
      } else {
        throw PdfFormatException(
          'The trailer does not point at a document catalog (/Root).',
        );
      }
    }
    return _documentCatalog;
  }

  /// internal property
  PdfEncryptor? get encryptor {
    return _encryptor;
  }

  set encryptor(PdfEncryptor? value) {
    if (value != null) {
      _encryptor = value;
    }
  }

  //Implementation
  void _initialize() {
    _generationNumber = 65535;
    _archives = <int, PdfStream>{};
    _readersTable = <PdfStream, PdfParser>{};
    _allTables = <int, List<ObjectInformation>>{};
    final int startingOffset = _checkJunk();
    _debugXrefLog('startingOffset=$startingOffset dataLen=${_source.length}');
    if (startingOffset < 0) {
      throw PdfFormatException(
        'The data does not start with a PDF header (%PDF-).',
      );
    }
    objects = <int, ObjectInformation>{};
    PdfReader reader = this.reader;
    PdfParser parser = this.parser;
    reader.position = startingOffset;
    reader.skipWhiteSpace();
    _whiteSpace = reader.position;
    int position = reader.seekEnd()!;
    checkStartXRef();
    reader.position = position;
    final int endPosition = reader.searchBack(PdfOperators.endOfFileMarker);
    if (endPosition != -1) {
      if (position != endPosition + 5) {
        reader.position = endPosition + 5;
        final String token = reader.getNextToken()!;
        if (token.isNotEmpty && token.codeUnitAt(0) != 0 && token[0] != '0') {
          reader.position = 0;
          final List<int> buffer = reader.readBytes(endPosition + 5);
          reader = PdfReader(buffer);
          reader.position = buffer.length;
          parser = PdfParser(this, reader, _crossTable);
          _reader = reader;
          _parser = parser;
        }
      }
    } else {
      reader.position = position;
    }
    position = reader.searchBack(PdfOperators.startCrossReference);
    bool isForwardSearch = false;
    _debugXrefLog('startxref searchBack position=$position');
    if (position >= 0) {
      parser.setOffset(position);
      position = parser.startCrossReference();
      _debugXrefLog('startxref value=$position');
      startCrossReference = position;
      if (position < 0 || position > reader.length!) {
        // `startxref` names an offset past the end of the file — the usual
        // sign of a truncated download or of a tool that appended without
        // fixing the pointer.
        _debugXrefLog('startxref $position out of range, rebuilding');
        _rebuildByScanning(parser);
        return;
      }
      _parser!.setOffset(position);
      if (_whiteSpace != 0) {
        final int crossReferencePosition = reader.searchForward(
          PdfOperators.crossReference,
        );
        if (crossReferencePosition == -1) {
          isForwardSearch = false;
          position += _whiteSpace;
          reader.position = position;
        } else {
          position = crossReferencePosition;
          parser.setOffset(position);
          isForwardSearch = true;
        }
        _debugXrefLog(
          'xref forwardSearch=$isForwardSearch position=$position whiteSpace=$_whiteSpace',
        );
      }
    }
    String tempString = reader.readLine();
    if (!tempString.contains(PdfOperators.crossReference) &&
        !tempString.contains(PdfOperators.obj) &&
        !isForwardSearch) {
      final int rposition = reader.position;
      final String tempS = reader.readLine();
      if (tempS.contains(PdfOperators.crossReference)) {
        tempString = tempS;
        position = rposition;
      } else {
        reader.position = rposition;
      }
    }
    if (!tempString.contains(PdfOperators.crossReference) &&
        !tempString.contains(PdfOperators.obj) &&
        !isForwardSearch) {
      if (position > reader.length!) {
        position = reader.length!;
        reader.position = position;
        position = reader.searchBack(PdfOperators.startCrossReference);
      }
      final int tempOffset = reader.searchBack(PdfOperators.crossReference);
      if (tempOffset != -1) {
        position = tempOffset;
      }
      if (position < 0 || position > reader.length!) {
        // No `startxref`, no `xref` — nothing left to point at a table.
        _debugXrefLog('no cross reference table found, rebuilding');
        _rebuildByScanning(parser);
        return;
      }
      parser.setOffset(position);
    }
    if (position < 0 || position > reader.length!) {
      // Nothing in the file pointed at a usable cross-reference table: the
      // offset is out of range, or `startxref` is missing because the tail was
      // truncated. Browsers recover by scanning; so do we.
      _debugXrefLog('cross reference offset $position unusable, rebuilding');
      _rebuildByScanning(parser);
      return;
    }
    reader.position = position;
    try {
      _debugXrefLog('parseCrossReferenceTable offset=$position');
      final Map<String, dynamic> tempResult = parser.parseCrossReferenceTable(
        objects,
        this,
      );
      trailer = tempResult['object'] as PdfDictionary?;
      objects = tempResult['objects'] as Map<int, ObjectInformation>;
    } catch (e) {
      _debugXrefLog('parseCrossReferenceTable failed ($e), rebuilding');
      _rebuildByScanning(parser);
      return;
    }
    if (trailer == null || !_hasUsableRoot(trailer!)) {
      _debugXrefLog('trailer without a usable /Root, rebuilding');
      _rebuildByScanning(parser);
      return;
    }
    PdfDictionary trailerObj = trailer!;
    _debugXrefLog('trailer keys=${trailerObj.items?.keys.length ?? 0}');
    final Set<int> visitedPrevOffsets = <int>{};
    while (trailerObj.containsKey(PdfDictionaryProperties.prev)) {
      if (_whiteSpace != 0) {
        final PdfNumber number =
            trailerObj[PdfDictionaryProperties.prev]! as PdfNumber;
        number.value = number.value! + _whiteSpace;
        _isStructureAltered = true;
      }
      position =
          (trailerObj[PdfDictionaryProperties.prev]! as PdfNumber).value!
              .toInt();
      _debugXrefLog('prev=$position');
      if (position <= 0 || position >= _reader!.length!) {
        _debugXrefLog('prev out of range, breaking');
        break;
      }
      if (!visitedPrevOffsets.add(position)) {
        _debugXrefLog('prev loop detected at $position, breaking');
        break;
      }
      final PdfReader tokenReader = PdfReader(_reader!.streamReader.data);
      tokenReader.position = position;
      String? token = tokenReader.getNextToken();
      while (token == '%') {
        tokenReader.readLine();
        token = tokenReader.getNextToken();
      }
      if (token != PdfDictionaryProperties.crossReference) {
        token = tokenReader.getNextToken();
        //check the coditon for valid object number
        final int? number = int.tryParse(token!);
        if (number != null && number >= 0) {
          token = tokenReader.getNextToken();
          if (token == PdfDictionaryProperties.obj) {
            parser.setOffset(position);
            final Map<String, dynamic> tempResults = parser
                .parseCrossReferenceTable(objects, this);
            trailerObj = tempResults['object'] as PdfDictionary;
            objects = tempResults['objects'] as Map<int, ObjectInformation>;
            parser.setOffset(position);
            continue;
          }
        }
        parser.rebuildXrefTable(objects, this);
        break;
      } else {
        parser.setOffset(position);
        final Map<String, dynamic> tempResults = parser
            .parseCrossReferenceTable(objects, this);
        trailerObj = tempResults['object'] as PdfDictionary;
        objects = tempResults['objects'] as Map<int, ObjectInformation>;
        if (trailerObj.containsKey(PdfDictionaryProperties.size) &&
            trailer!.containsKey(PdfDictionaryProperties.size)) {
          if ((trailerObj[PdfDictionaryProperties.size]! as PdfNumber).value! >
              (trailer![PdfDictionaryProperties.size]! as PdfNumber).value!) {
            (trailer![PdfDictionaryProperties.size]! as PdfNumber).value =
                (trailerObj[PdfDictionaryProperties.size]! as PdfNumber).value;
          }
        }
      }
    }
    if (_whiteSpace != 0 && isForwardSearch) {
      List<int> objKey = List<int>.filled(objects.length, 0);
      objKey = objects.keys.toList();
      for (int i = 0; i < objKey.length; i++) {
        final int key = objKey[i];
        final ObjectInformation info = objects[key]!;
        objects[key] = ObjectInformation(
          info._offset! + _whiteSpace,
          null,
          this,
        );
      }
      _isStructureAltered = true;
    } else if (_whiteSpace != 0 && _whiteSpace > 0 && !_isStructureAltered) {
      if (!trailerObj.containsKey(PdfDictionaryProperties.prev)) {
        _isStructureAltered = true;
      }
    }
  }

  /// Rebuilds the object table by scanning the file for object headers, the
  /// way a viewer does when the cross-reference table it was handed cannot be
  /// used.
  ///
  /// The scan finds objects but no trailer, so the trailer is recovered too:
  /// first from a `trailer` dictionary still present in the file, and failing
  /// that by synthesizing one around whichever rebuilt object is the document
  /// catalog. A file a browser can render should merge, and the
  /// cross-reference table is the part most often damaged — by a truncated
  /// download, a byte range copied wrong, or a tool that appended without
  /// fixing the offsets.
  void _rebuildByScanning(PdfParser parser) {
    if (strictness == PdfStrictnessLevel.conservative) {
      // Recovery is opt-in: reconstructing the object table guesses at what
      // the file meant, and a caller that is about to sign — or to trust — the
      // result has to be the one deciding that a guess will do.
      throw PdfFormatException(
        'The cross-reference table is missing, out of range or unreadable. '
        'Pass strictness: PdfStrictnessLevel.lenient to recover the document '
        'by scanning the file for objects, the way a viewer does.',
      );
    }
    final PdfRepairScanResult scanned = parser.rebuildXrefTable(
      objects,
      this,
      scan: repairScan,
    );
    _debugXrefLog(
      'rebuilt ${objects.length} object(s) by scanning, '
      '${scanned.trailerOffsets.length} trailer(s), '
      'catalog=${scanned.catalogNumber}',
    );
    trailer = _recoverTrailer(scanned) ?? _synthesizeTrailer(scanned);
    if (trailer == null) {
      throw PdfFormatException(
        'The cross-reference table is unusable and scanning the file found no '
        'document catalog. The data is not a recoverable PDF.',
      );
    }
    // The offset `startxref` named is the damaged one. Keeping it would send
    // an incremental save's `/Prev` back to nothing.
    startCrossReference = 0;
    isRepaired = true;
    _isStructureAltered = true;
  }

  /// Looks for a `trailer` dictionary that still parses and names a `/Root`.
  ///
  /// The positions come from the scan, which noted every `trailer` keyword on
  /// its way through — the same thing iText does in `rebuildXref`. Searching
  /// for them again afterwards would mean a second pass over the file.
  PdfDictionary? _recoverTrailer(PdfRepairScanResult scanned) {
    final List<int> offsets = scanned.trailerOffsets;
    // Walk the trailers backwards: the last one that resolves wins, but an
    // incremental update may have left a damaged one at the very end.
    int attempts = 0;
    for (int i = offsets.length - 1; i >= 0 && attempts < 8; i--, attempts++) {
      final int position = offsets[i];
      try {
        final PdfParser trailerParser = PdfParser(
          this,
          PdfReader.fromSource(_source),
          _crossTable,
        );
        trailerParser.setOffset(position);
        final IPdfPrimitive? candidate = trailerParser.trailer();
        if (candidate is PdfDictionary && _hasUsableRoot(candidate)) {
          _debugXrefLog('recovered trailer at $position');
          return candidate;
        }
      } catch (_) {
        // Try the one before it.
      }
    }
    return null;
  }

  /// Builds a minimal trailer around the catalog found among the rebuilt
  /// objects.
  PdfDictionary? _synthesizeTrailer(PdfRepairScanResult scanned) {
    final List<int> numbers = objects.keys.toList()..sort();
    int? catalogNumber = scanned.catalogNumber;
    // The scan reads the head of every object dictionary it passes, so it
    // normally already knows which one is the catalog. Parsing objects back to
    // front is the fallback for when it did not see one.
    for (int i = numbers.length - 1; i >= 0 && catalogNumber == null; i--) {
      final int number = numbers[i];
      final ObjectInformation? info = objects[number];
      if (info == null) {
        continue;
      }
      IPdfPrimitive? object;
      try {
        object = info.parser!.parseOffset(info.offset!);
      } catch (_) {
        continue;
      }
      if (object is! PdfDictionary) {
        continue;
      }
      final IPdfPrimitive? type = object[PdfDictionaryProperties.type];
      if (type is PdfName && type.name == 'Catalog') {
        // Prefer a catalog that actually leads to pages; a damaged file can
        // carry an older, emptied one from a previous revision.
        catalogNumber = number;
        if (object.containsKey(PdfDictionaryProperties.pages)) {
          break;
        }
      }
    }
    if (catalogNumber == null) {
      return null;
    }
    _debugXrefLog('synthesized trailer pointing at object $catalogNumber');
    final PdfDictionary recovered = PdfDictionary();
    recovered[PdfDictionaryProperties.root] = PdfReferenceHolder.fromReference(
      PdfReference(catalogNumber, 0),
      _crossTable,
    );
    recovered[PdfDictionaryProperties.size] = PdfNumber(
      numbers.isEmpty ? 1 : numbers.last + 1,
    );
    return recovered;
  }

  bool _hasUsableRoot(PdfDictionary candidate) {
    final IPdfPrimitive? root = candidate[PdfDictionaryProperties.root];
    return root is PdfReferenceHolder || root is PdfDictionary;
  }

  ObjectInformation? _returnValue(int? key) {
    return objects.containsKey(key) ? objects[key!] : null;
  }

  /// internal method
  IPdfPrimitive? getObject(IPdfPrimitive? pointer) {
    if (pointer == null) {
      throw ArgumentError.value(pointer, 'pointer');
    }
    if (pointer is PdfReference) {
      IPdfPrimitive? obj;
      final PdfReference reference = pointer;
      final ObjectInformation? oi = this[reference.objNum];
      if (oi == null) {
        return PdfNull();
      }
      final PdfParser? parser = oi.parser;
      final int? position = oi.offset;
      if (oi.obj != null) {
        obj = oi.obj;
      } else if (oi._archive == null) {
        obj = parser!.parseOffset(position!);
      } else {
        obj = _getObjectFromPosition(parser!, position!);
        if (encryptor != null) {
          if (obj is PdfDictionary) {
            obj.decrypted = true;
            for (final dynamic element in obj.items!.values) {
              if (element is PdfString) {
                element.isParentDecrypted = true;
              }
            }
          }
        }
      }
      oi.obj = obj;
      return obj;
    } else {
      return pointer;
    }
  }

  IPdfPrimitive? _getObjectFromPosition(PdfParser parser, int position) {
    parser.startFrom(position);
    return parser.simple();
  }

  /// internal method
  Map<int, ObjectInformation>? parseNewTable(
    PdfStream? stream,
    Map<int, ObjectInformation>? objects,
  ) {
    if (stream == null) {
      throw PdfFormatException('Invalid format', source: stream);
    }
    stream.decompress();
    final List<_SubSection> subSections = _getSections(stream);
    int? ssIndex = 0;
    for (int i = 0; i < subSections.length; i++) {
      final _SubSection ss = subSections[i];
      final Map<String, dynamic> result = _parseWithHashTable(
        stream,
        ss,
        objects,
        ssIndex,
      );
      ssIndex = result['index'] as int?;
      objects = result['objects'] as Map<int, ObjectInformation>?;
    }
    return objects;
  }

  Map<String, dynamic> _parseWithHashTable(
    PdfStream stream,
    _SubSection subsection,
    Map<int, ObjectInformation>? table,
    int? startIndex,
  ) {
    int? index = startIndex;
    final IPdfPrimitive? entry = getObject(stream[PdfDictionaryProperties.w]);
    if (entry is PdfArray) {
      final int fields = entry.count;
      final List<int> format = List<int>.filled(fields, 0, growable: true);
      for (int i = 0; i < fields; ++i) {
        final PdfNumber formatNumber = entry[i]! as PdfNumber;
        format[i] = formatNumber.value!.toInt();
      }
      final List<int> reference = List<int>.filled(fields, 0, growable: true);
      final List<int>? buf = stream.dataStream;
      for (int i = 0; i < subsection.count; ++i) {
        for (int j = 0; j < fields; ++j) {
          int field = 0;
          if (j == 0) {
            if (format[j] > 0) {
              field = 0;
            } else {
              field = 1;
            }
          }
          for (int k = 0; k < format[j]; ++k) {
            field <<= 8;
            field = field + buf![index!];
            index += 1;
          }
          reference[j] = field;
        }
        int offset = 0;
        ArchiveInformation? ai;
        if (reference[0] == PdfObjectType.normal.index) {
          if (_whiteSpace != 0) {
            offset = reference[1] + _whiteSpace;
          } else {
            offset = reference[1];
          }
        } else if (reference[0] == PdfObjectType.packed.index) {
          ai = ArchiveInformation(reference[1], reference[2], _retrieveArchive);
        }
        ObjectInformation? oi;
        // NOTE: do not store removed objects.
        if (reference[0] != PdfObjectType.free.index) {
          oi = ObjectInformation(offset, ai, this);
        }
        if (oi != null) {
          final int objectOffset = subsection.startNumber + i;
          if (!table!.containsKey(objectOffset)) {
            table[objectOffset] = oi;
          }
          _addTables(objectOffset, oi);
        }
      }
    }
    return <String, dynamic>{'index': index, 'objects': table};
  }

  PdfStream _retrieveArchive(int archiveNumber) {
    PdfStream? archive;
    if (_archives.containsKey(archiveNumber)) {
      archive = _archives[archiveNumber];
    }
    if (archive == null) {
      final ObjectInformation oi = this[archiveNumber]!;
      final PdfParser parser = oi.parser!;
      archive = parser.parseOffset(oi._offset!) as PdfStream?;
      if (encryptor != null && !encryptor!.encryptAttachmentOnly!) {
        archive!.decrypt(encryptor!, archiveNumber);
      }
      archive!.decompress();
      _archives[archiveNumber] = archive;
    }
    return archive;
  }

  List<_SubSection> _getSections(PdfStream stream) {
    final List<_SubSection> subSections = <_SubSection>[];
    int count = 0;
    if (stream.containsKey(PdfDictionaryProperties.size)) {
      final IPdfPrimitive? primitive = stream[PdfDictionaryProperties.size];
      if (primitive is PdfNumber) {
        count = primitive.value!.toInt();
      }
    }
    if (count == 0) {
      throw PdfFormatException('Invalid Format', source: count);
    }
    final IPdfPrimitive? obj = stream[PdfDictionaryProperties.index];
    if (obj == null) {
      subSections.add(_SubSection(count));
    } else {
      final IPdfPrimitive? primitive = getObject(obj);
      if (primitive != null && primitive is PdfArray) {
        final PdfArray indices = primitive;
        if ((indices.count & 1) != 0) {
          throw PdfFormatException('Invalid Format', source: count);
        }
        for (int i = 0; i < indices.count; ++i) {
          int n = 0, c = 0;
          n = (indices[i]! as PdfNumber).value!.toInt();
          ++i;
          c = (indices[i]! as PdfNumber).value!.toInt();
          subSections.add(_SubSection(c, n));
        }
      }
    }
    return subSections;
  }

  /// internal method
  void parseSubsection(PdfParser parser, Map<int, ObjectInformation>? table) {
    // Read the initial number of the subsection.
    PdfNumber integer = parser.simple()! as PdfNumber;

    initialNumberOfSubsection = integer.value!.toInt();
    // Read the total number of subsection.
    integer = parser.simple()! as PdfNumber;

    totalNumberOfSubsection = integer.value!.toInt();
    initialSubsectionCount = initialNumberOfSubsection;
    for (int i = 0; i < totalNumberOfSubsection; ++i) {
      integer = parser.simple()! as PdfNumber;
      final int offset = integer.value!.toInt();
      integer = parser.simple()! as PdfNumber;
      final int genNum = integer.value!.toInt();
      final String flag = parser.getObjectFlag();
      if (flag == 'n') {
        final ObjectInformation oi = ObjectInformation(offset, null, this);
        int objectOffset = 0;
        if (initialSubsectionCount == initialNumberOfSubsection) {
          objectOffset = initialNumberOfSubsection + i;
        } else {
          objectOffset = initialSubsectionCount + i;
        }
        if (!table!.containsKey(objectOffset)) {
          table[objectOffset] = oi;
        }
        _addTables(objectOffset, oi);
      } else {
        if (initialNumberOfSubsection != 0 &&
            offset == 0 &&
            genNum == _generationNumber) {
          initialNumberOfSubsection = initialNumberOfSubsection - 1;
          if (i == 0) {
            initialSubsectionCount = initialNumberOfSubsection;
          }
        }
      }
    }
  }

  void _addTables(int objectOffset, ObjectInformation oi) {
    if (_allTables.containsKey(objectOffset)) {
      _allTables[objectOffset]!.add(oi);
    } else {
      _allTables[objectOffset] = <ObjectInformation>[oi];
    }
  }

  int _checkJunk() {
    // Busca byte-a-byte para evitar problemas de encoding e de fronteira de chunk.
    // Sequência ASCII: %PDF-
    const int b0 = 0x25; // %
    const int b1 = 0x50; // P
    const int b2 = 0x44; // D
    const int b3 = 0x46; // F
    const int b4 = 0x2D; // -

    if (_source.length < 5) {
      return -1;
    }
    for (int i = 0; i <= _source.length - 5; i++) {
      if (_source.byteAt(i) == b0 &&
          _source.byteAt(i + 1) == b1 &&
          _source.byteAt(i + 2) == b2 &&
          _source.byteAt(i + 3) == b3 &&
          _source.byteAt(i + 4) == b4) {
        return i;
      }
    }
    return -1;
  }

  /// internal method
  void checkStartXRef() {
    const int maxSize = 1024;
    int pos = reader.length! - maxSize;
    if (pos < 1) {
      pos = 1;
    }
    List<int>? data = List<int>.filled(maxSize, 0);
    while (pos > 0) {
      reader.position = pos;
      final Map<String, dynamic> result = reader.copyBytes(data, 0, maxSize);
      data = result['buffer'] as List<int>?;
      final String start = String.fromCharCodes(data!);
      final int index = start.lastIndexOf('startxref');
      if (index >= 0) {
        reader.position = index;
        break;
      }
      pos = pos - maxSize + 9;
    }
  }

  /// internal method
  PdfParser? retrieveParser(ArchiveInformation? archive) {
    if (archive == null) {
      return _parser;
    } else {
      final PdfStream stream = archive.archive;
      PdfParser? parser;
      if (_readersTable.containsKey(stream)) {
        parser = _readersTable[stream];
      }
      if (parser == null) {
        final PdfReader reader = PdfReader(stream.dataStream);
        parser = PdfParser(this, reader, _crossTable);
        _readersTable[stream] = parser;
      }
      return parser;
    }
  }
}

/// internal class
class ObjectInformation {
  //Constructor
  /// internal constructor
  ObjectInformation(
    int offset,
    ArchiveInformation? arciveInfo,
    CrossTable? crossTable,
  ) {
    _offset = offset;
    _archive = arciveInfo;
    _crossTable = crossTable;
  }
  //Fields
  ArchiveInformation? _archive;
  PdfParser? _parser;
  int? _offset;
  CrossTable? _crossTable;

  /// internal Fields
  IPdfPrimitive? obj;

  //Properties
  /// internal property
  PdfParser? get parser {
    _parser ??= _crossTable!.retrieveParser(_archive);
    return _parser;
  }

  /// internal property
  int? get offset {
    if (_offset == 0) {
      final PdfParser parser = this.parser!;
      parser.startFrom(0);
      int pairs = 0;
      // Read indices.
      if (_archive != null) {
        final PdfNumber? archieveNumber =
            _archive!.archive[PdfDictionaryProperties.n] as PdfNumber?;
        if (archieveNumber != null) {
          pairs = archieveNumber.value!.toInt();
        }
        final List<int> indices = List<int>.filled(
          pairs * 2,
          0,
          growable: true,
        );
        for (int i = 0; i < pairs; ++i) {
          PdfNumber? obj = parser.simple() as PdfNumber?;
          if (obj != null) {
            indices[i * 2] = obj.value!.toInt();
          }
          obj = parser.simple() as PdfNumber?;
          if (obj != null) {
            indices[i * 2 + 1] = obj.value!.toInt();
          }
        }
        final int index = _archive!._index;
        if (index * 2 >= indices.length) {
          throw PdfFormatException('Missing indexes in archive', source: _archive!._archiveNumber);
        }
        _offset = indices[index * 2 + 1];
        final int first =
            (_archive!.archive[PdfDictionaryProperties.first]! as PdfNumber)
                .value!
                .toInt();
        _offset = _offset! + first;
      }
    }
    return _offset;
  }
}

class ArchiveInformation {
  //Constructor
  ArchiveInformation(int archiveNumber, int index, GetArchive getArchive) {
    _archiveNumber = archiveNumber;
    _index = index;
    _getArchive = getArchive;
  }

  //Fields
  late int _archiveNumber;
  late int _index;
  PdfStream? _archive;
  late GetArchive _getArchive;

  //Properties
  PdfStream get archive {
    _archive ??= _getArchive(_archiveNumber);
    return _archive!;
  }
}

typedef GetArchive = PdfStream Function(int archiveNumber);

class _SubSection {
  //constructor
  _SubSection(this.count, [int? start]) {
    startNumber = start ?? 0;
  }

  late int startNumber;
  late int count;
}
