import 'package:test/test.dart';
import 'package:dart_pdf/pdf.dart';

void main() {
  group('PdfPen', () {
    test('Default Constructor', () {
      final color = PdfColor(255, 0, 0);
      final pen = PdfPen(color, width: 2.0);
      
      expect(pen.color, equals(color));
      expect(pen.width, equals(2.0));
      // check defaults
      expect(pen.dashStyle, equals(PdfDashStyle.solid));
    });

    test('Set Width', () {
      final pen = PdfPen(PdfColor(0,0,0));
      pen.width = 5.0;
      expect(pen.width, equals(5.0));
    });

    test('Set Line Cap and Join', () {
      final pen = PdfPen(PdfColor(0,0,0));
      
      pen.lineCap = PdfLineCap.round;
      expect(pen.lineCap, equals(PdfLineCap.round));
      
      pen.lineJoin = PdfLineJoin.bevel;
      expect(pen.lineJoin, equals(PdfLineJoin.bevel));
    });

    test('Immutable Pen (fromBrush implies complex logic?)', () {
         // Not exactly immutable via that constructor but there was a _immutable constructor.
         // Let's test standard behavior.
         final pen = PdfPen(PdfColor(0,0,0));
         pen.dashStyle = PdfDashStyle.dash;
         expect(pen.dashStyle, equals(PdfDashStyle.dash));
    });
  });
}
