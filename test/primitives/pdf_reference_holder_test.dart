import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_reference_holder.dart';
import 'package:dart_pdf/src/pdf/implementation/primitives/pdf_number.dart';

void main() {
  group('PdfReferenceHolder', () {
    test('Constructor with primitive', () {
      final primitive = PdfNumber(123);
      final holder = PdfReferenceHolder(primitive);
      expect(holder.object, equals(primitive));
      expect(holder.reference, isNull);
    });

    test('Constructor with null throws', () {
      expect(() => PdfReferenceHolder(null), throwsArgumentError);
    });

     // Testing fromReference requires CrossTable which is complex to mock right now without interfaces/mocks setup across the board.
     // But we can check that it assigns the reference.
     // However, PdfReferenceHolder.fromReference checks for non-null CrossTable.
  });
}
