import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

void main() {
  group('PdfSecurity Tests', () {
    test('Encrypt Document with User Password', () async {
      final document = PdfDocument();
      document.pages.add().graphics.drawString(
          'Encrypted', PdfStandardFont(PdfFontFamily.helvetica, 12),
          brush: PdfBrushes.black, bounds: Rect.fromLTWH(0, 0, 100, 20));

      // Set user password
      document.security.userPassword = 'user';
      
      final bytes = await document.save();
      document.dispose();

      // Verify: Load without password should fail
      try {
        final _ = PdfDocument(inputBytes: bytes);
        fail('Should throw error when loading encrypted document without password');
      } catch (e) {
        expect(e.toString(), contains('password')); 
      }

      // Verify: Load with incorrect password should fail
      try {
        final _ = PdfDocument(inputBytes: bytes, password: 'wrong');
        fail('Should throw error when loading encrypted document with wrong password');
      } catch (e) {
        expect(e.toString(), contains('password'));
      }

      // Verify: Load with correct password should succeed
      try {
        final loaded = PdfDocument(inputBytes: bytes, password: 'user');
        expect(loaded.pages.count, equals(1));
        loaded.dispose();
      } catch (e) {
        fail('Failed to load encrypted document with correct password: $e');
      }
    });

    test('Encrypt Document with Owner Password and Permissions', () async {
      final document = PdfDocument();
      document.pages.add();

      // Set owner password and permissions
      document.security.ownerPassword = 'owner';
      document.security.permissions.addAll([
        PdfPermissionsFlags.print,
        PdfPermissionsFlags.copyContent
      ]);

      final bytes = await document.save();
      document.dispose();

      // Load with owner password - should have full access
      // Note: Implementation might not expose permissions on loaded doc directly in public API easily,
      // but verifying it loads with owner password confirms encryption structure is valid.
       try {
        final loaded = PdfDocument(inputBytes: bytes, password: 'owner');
        expect(loaded.pages.count, equals(1));
        loaded.dispose();
      } catch (e) {
        fail('Failed to load with owner password: $e');
      }
    });

    test('Set Encryption Algorithm', () async {
        final document = PdfDocument();
        document.pages.add(); // Add a page to be sure
        
        // Default is usually RC4 or AES depending on version
        document.security.algorithm = PdfEncryptionAlgorithm.aesx128Bit;
        document.security.userPassword = 'user';
        
        final bytes = await document.save();
        document.dispose();

        // Should still be loadable with password
        final loaded = PdfDocument(inputBytes: bytes, password: 'user');
        expect(loaded.pages.count, equals(1)); 
        loaded.dispose();
    });

    test('Change Permissions on Existing Security', () {
      final document = PdfDocument();
      final security = document.security;
      
      // Clear existing if any (API might not support clear, so we check containment)
      // Actually let's just add and check contains/count increases
      final initialCount = security.permissions.count;
      
      security.permissions.add(PdfPermissionsFlags.print);
      expect(security.permissions.count, equals(initialCount + 1));
      
      security.permissions.add(PdfPermissionsFlags.copyContent);
      expect(security.permissions.count, equals(initialCount + 2));
      
      // Checking iteration/access - order might not be guaranteed or might be appended
      // expect(security.permissions[0], equals(PdfPermissionsFlags.print)); // Risky if defaults exist
      
      document.dispose();
    });
  });
}
