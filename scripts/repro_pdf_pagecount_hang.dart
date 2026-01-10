import 'dart:io';
import 'package:dart_pdf/pdf.dart' as pdf;

Future<void> main(List<String> args) async {
  final pdfPath =
      r"C:\MyDartProjects\new_sali\backend\storage\newsali\2026\01\3fd9a349-1f2e-41c8-80da-4cd3d6420a94.pdf";

  final file = File(pdfPath);
  if (!await file.exists()) {
    stderr.writeln('PDF not found: $pdfPath');
    exit(66);
  }

  final bytes = await file.readAsBytes();
  stdout.writeln('PDF size: ${bytes.length} bytes');
    print('before call _parseInIsolate ${DateTime.now()}');
  _parseInIsolate(bytes);
}

void _parseInIsolate(List<int> bytes) {
  final doc = pdf.PdfDocument(inputBytes: bytes);
  final count = doc.pages.count;
  print('count $count');
      print('before after call _parseInIsolate ${DateTime.now()}');
  doc.dispose();
}
