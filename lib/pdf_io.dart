/// The parts of `dart_pdf` that need `dart:io`.
///
/// Kept out of `pdf.dart` so that importing the library does not drag a
/// dependency on the file system into a program that has no file system.
library;

export 'src/pdf/implementation/io/pdf_file_data_source.dart'
    show PdfFileDataSource, PdfFileBlockReader;
