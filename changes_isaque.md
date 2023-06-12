## rename all import
"import 'dart:ui';" to "import 'package:flutter_pdf/src/flutter/ui.dart';"
## add to pdf.dart this: export 'src/flutter/ui.dart';
## change pubspec name: from flutter_pdf to dart_pdf
## rename all package:flutter_pdf to  package:dart_pdf

## in example 
import 'package:flutter_pdf/pdf.dart' as flutter_pdf; and 
change main.dart Rect and Size to flutter_pdf.Size and flutter_pdf.Rect


