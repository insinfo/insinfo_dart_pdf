import 'dart:convert';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dart_pdf/src/pdf/implementation/security/pdf_encryptor.dart';
import 'package:dart_pdf/src/pdf/implementation/security/enum.dart';

void main() {
  group('PdfEncryptor Tests', () {
    test('RC4 128-bit Encryption/Decryption', () {
      final encryptor = PdfEncryptor();
      encryptor.userPassword = 'password';
      encryptor.ownerPassword = 'owner';
      encryptor.encryptionAlgorithm = PdfEncryptionAlgorithm.rc4x128Bit;

      // Data to encrypt
      final String plainText = 'Hello World';
      final Uint8List data = utf8.encode(plainText);

      // Encrypt
      final encrypted = encryptor.encryptData(1, data, true);

      expect(encrypted, isNot(equals(data)),
          reason: 'Encrypted data should differ from plain data');

      // Decrypt (RC4: encrypting again with same key decrypts)
      // Note: encryptData handles symmetric logic implicitly for RC4 or via separate method for AES?
      // implementation uses _encryptDataByCustom which is RC4 based usually (stream cipher).
      // Let's verify if 'isEncryption' flag matters for RC4 in encryptData implementation.
      // Lines 1515: check if AES -> _aesEncrypt / _aesDecrypt.
      // Else (RC4): _initializeData(), setup key, return _encryptDataByCustom.
      // _encryptDataByCustom is symmetric.

      final decrypted = encryptor.encryptData(1, encrypted, false);

      expect(decrypted, equals(data),
          reason: 'Decrypted data should match original');
    });

    test('Object Number Salt (RC4)', () {
      final encryptor = PdfEncryptor();
      encryptor.userPassword = 'password';
      encryptor.encryptionAlgorithm = PdfEncryptionAlgorithm.rc4x128Bit;

      final Uint8List data = utf8.encode('Hello');

      final enc1 = encryptor.encryptData(1, data, true);
      final enc2 = encryptor.encryptData(2, data, true);

      expect(enc1, isNot(equals(enc2)),
          reason: 'Encryption should depend on object number');
    });
    test('AES 128-bit Encryption/Decryption', () {
      final encryptor = PdfEncryptor();
      encryptor.userPassword = 'password';
      encryptor.ownerPassword = 'owner';
      encryptor.encryptionAlgorithm = PdfEncryptionAlgorithm.aesx128Bit;

      final Uint8List data = utf8.encode('Hello World');

      // Encrypt
      final encrypted = encryptor.encryptData(1, data, true);

      expect(encrypted.length, greaterThanOrEqualTo(data.length),
          reason: 'AES output usually includes padding/IV');
      expect(encrypted, isNot(equals(data)));

      // Decrypt
      final decrypted = encryptor.encryptData(1, encrypted, false);

      expect(decrypted, equals(data));
    });

    test('Algorithm Difference', () {
      final encryptorRC4 = PdfEncryptor();
      encryptorRC4.userPassword = 'password';
      encryptorRC4.encryptionAlgorithm = PdfEncryptionAlgorithm.rc4x128Bit;

      final encryptorAES = PdfEncryptor();
      encryptorAES.userPassword = 'password';
      encryptorAES.encryptionAlgorithm = PdfEncryptionAlgorithm.aesx128Bit;

      final data = utf8.encode('Test Data');

      final rc4Out = encryptorRC4.encryptData(1, data, true);
      final aesOut = encryptorAES.encryptData(1, data, true);

      expect(rc4Out, isNot(equals(aesOut)));
    });
  });
}
