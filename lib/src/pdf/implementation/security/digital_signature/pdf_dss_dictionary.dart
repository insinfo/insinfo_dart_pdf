import '../../primitives/pdf_dictionary.dart';
import '../../primitives/pdf_array.dart';
import '../../primitives/pdf_stream.dart';

/// Represents the DSS dictionary (Document Security Store) - implementation of PAdES LTV
class PdfDssDictionary extends PdfDictionary {
  /// Initialize a new instance of [PdfDssDictionary]
  PdfDssDictionary([PdfDictionary? dictionary]) : super(dictionary);

  /// Adds a CRL stream to the DSS
  void addCrl(List<int> crlBytes) {
      _addToArray('CRLs', crlBytes);
  }
  
  /// Adds an OCSP stream to the DSS
  void addOcsp(List<int> ocspBytes) {
      _addToArray('OCSPs', ocspBytes);
  }
  
  /// Adds a Certificate stream to the DSS
  void addCert(List<int> certBytes) {
      _addToArray('Certs', certBytes);
  }
  
  void _addToArray(String key, List<int> data) {
      PdfArray? arr = this[key] as PdfArray?;
      if (arr == null) {
          arr = PdfArray();
          this[key] = arr;
      }
      final PdfStream stream = PdfStream(null, data);
      arr.add(stream);
  }
}
