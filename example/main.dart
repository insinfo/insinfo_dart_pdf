import 'dart:io';
import 'package:dart_pdf/pdf.dart';
import 'package:dart_pdf/src/pdf/implementation/general/pdf_collection.dart';

void main(List<String> args) async {
  final inputBytes =
      await File('gov_assinado.pdf')
          .readAsBytes();

  print('${DateTime.now()}  inputBytes');
  //Loads PDF file.
  final document = PdfDocument(inputBytes: inputBytes);

  print('${DateTime.now()} loads PDF file');

  final signFields = PdfObjectCollectionHelper.getHelper(document.form.fields)
      .list
      .where((field) => field is PdfSignatureField)
      .map((e) => e as PdfSignatureField)
      .toList();

  print('${DateTime.now()} Loads signFields ${signFields.length}');

  if (signFields.isNotEmpty) {
    for (final signField in signFields) {
      final signItem = signField;
      // Check if field is signed.
      print('${DateTime.now()}  has signature ${signItem.isSigned}');
      print('${DateTime.now()}  signature ${signItem.signature != null}');
      print('${DateTime.now()}  signedName ${signItem.signature?.signedName}');
      print(
          '${DateTime.now()}  contactInfo ${signItem.signature?.contactInfo}');
      print('${DateTime.now()}  signedDate ${signItem.signature?.signedDate}');
      print(
          '${DateTime.now()}  certificate: ${signItem.signature?.certificate}');
    }
  } else {
    print('PDF without digital signature');
  }

// Dispose the document.
  document.dispose();
}
