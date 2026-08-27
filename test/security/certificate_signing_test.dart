import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart';
import 'package:test/test.dart';

// Signing a PDF with a certificate held locally: load a PKCS#12 file, put a
// signature field on a page, save, and have a validator agree the result is
// signed and intact.
//
// Nothing tested this path. The signature tests that existed all go through
// PdfSignature() with no certificate -- the external signer used for gov.br
// and for a KMS -- so the whole PKCS#12 reader, 1,287 lines of it, had never
// been run by a test, and neither had the code that builds the CMS blob from
// a private key in hand.
//
// This is one of the three things the library is used for in production, so
// what is checked here is the whole way round: sign, save, load, validate,
// and then damage the result and watch the validator say so.

final File _pfx = File('test/assets/IsaqueNevesSantAna.pfx');
const String _password = '257257';

void main() {
  if (!_pfx.existsSync()) {
    test('the test certificate is available', () {
      markTestSkipped('${_pfx.path} is not available');
    });
    return;
  }
  final List<int> pfxBytes = _pfx.readAsBytesSync();

  PdfCertificate certificate() => PdfCertificate(pfxBytes, _password);

  group('the certificate file', () {
    test('opens with the right password and carries its fields', () {
      final PdfCertificate cert = certificate();
      expect(cert.version, 3);
      expect(cert.serialNumber, isNotEmpty);
      expect(cert.issuerName, isNotEmpty);
      expect(cert.subjectName, isNotEmpty);
      expect(
        cert.validFrom.isBefore(cert.validTo),
        isTrue,
        reason: 'a certificate is valid over an interval, not backwards',
      );
    });

    test('has not expired', () {
      // A signature made with an expired certificate still verifies, but a
      // test written around one starts reporting things that are not about
      // the library. When this fails, replace test/assets with a fresh PKCS#12
      // and put its password in _password.
      final PdfCertificate cert = certificate();
      final DateTime now = DateTime.now().toUtc();
      expect(
        now.isBefore(cert.validTo),
        isTrue,
        reason:
            'the test certificate expired on ${cert.validTo}; the signing '
            'tests need a current one',
      );
    });

    test('the wrong password is refused, and not as an Error', () {
      expect(
        () => PdfCertificate(pfxBytes, 'senha errada'),
        throwsA(isNot(isA<Error>())),
        reason: 'a password comes from a user, so a wrong one is recoverable',
      );
    });

    test('bytes that are not a PKCS#12 file are refused', () {
      expect(
        () => PdfCertificate('isto nao e um certificado'.codeUnits, 'x'),
        throwsA(isNot(isA<Error>())),
      );
      expect(() => PdfCertificate(<int>[], 'x'), throwsA(isNot(isA<Error>())));
    });

    test('a certificate can be loaded more than once', () {
      final PdfCertificate first = certificate();
      final PdfCertificate second = certificate();
      expect(second.serialNumber, first.serialNumber);
      expect(second.subjectName, first.subjectName);
    });
  });

  group('signing a new document', () {
    for (final DigestAlgorithm digest in DigestAlgorithm.values) {
      test('with ${digest.name} the signature verifies', () async {
        final List<int> bytes = _signNew(certificate(), digest: digest);
        final PdfSignatureValidationItem item = await _onlySignature(bytes);
        expect(item.validation.cmsSignatureValid, isTrue);
        expect(item.validation.byteRangeDigestOk, isTrue);
        expect(item.validation.documentIntact, isTrue);
        expect(item.validation.coversWholeDocument, isTrue);
      });
    }

    for (final CryptographicStandard standard
        in CryptographicStandard.values) {
      test('as ${standard.name} the signature verifies', () async {
        final List<int> bytes = _signNew(certificate(), standard: standard);
        final PdfSignatureValidationItem item = await _onlySignature(bytes);
        expect(item.validation.documentIntact, isTrue);
        expect(item.validation.certsPem, isNotEmpty);
      });
    }

    test('an invisible signature verifies just the same', () async {
      final List<int> bytes = _signNew(certificate(), bounds: null);
      final PdfSignatureValidationItem item = await _onlySignature(bytes);
      expect(item.validation.documentIntact, isTrue);
    });

    test('what was written on the signature reads back', () {
      final List<int> bytes = _signNew(
        certificate(),
        signedName: 'Isaque Neves Sant Ana',
        reason: 'Sou o autor deste documento',
        location: 'Rio das Ostras, Brasil',
        contact: 'insinfo@example.com',
      );

      final PdfDocument document = PdfDocument(inputBytes: bytes);
      addTearDown(document.dispose);
      expect(document.form.fields.count, 1);
      final PdfSignatureField field =
          document.form.fields[0] as PdfSignatureField;
      expect(field.name, 'assinatura');
      final PdfSignature? signature = field.signature;
      expect(signature, isNotNull);
      expect(signature!.signedName, 'Isaque Neves Sant Ana');
      expect(signature.reason, 'Sou o autor deste documento');
      expect(signature.locationInfo, 'Rio das Ostras, Brasil');
      expect(signature.contactInfo, 'insinfo@example.com');
      expect(
        signature.signedDate?.toUtc(),
        _signingDate,
        reason: 'the signing instant survives the round trip',
      );
    });

    test('the signed document still opens and reads as a document', () {
      final List<int> bytes = _signNew(certificate());
      final PdfDocument document = PdfDocument(inputBytes: bytes);
      addTearDown(document.dispose);
      expect(document.pages.count, 1);
      expect(
        PdfTextExtractor(document).extractText(),
        contains('documento para assinar'),
        reason: 'signing adds to a document, it does not replace it',
      );
    });
  });

  group('detecting a change after signing', () {
    late List<int> signed;
    late List<int> range;

    setUpAll(() async {
      signed = _signNew(certificate());
      range = (await _onlySignature(signed)).byteRange;
    });

    test('a byte changed inside the signed range breaks the digest', () async {
      // The two signed spans are [0, range[1]) and
      // [range[2], range[2] + range[3]); everything between them is the
      // signature blob itself.
      for (final int at in <int>[range[1] - 20, range[2] + 200]) {
        final Uint8List damaged = Uint8List.fromList(signed);
        damaged[at] ^= 0xFF;
        final PdfSignatureValidationItem item = await _onlySignature(damaged);
        expect(
          item.validation.byteRangeDigestOk,
          isFalse,
          reason: 'byte $at is inside what the signature covers',
        );
        expect(item.validation.documentIntact, isFalse);
      }
    });

    test('a change inside the signature blob is not a change to the '
        'document', () async {
      // The gap between the two spans holds the CMS blob, which the digest
      // deliberately leaves out -- there is no way to hash a value that has
      // not been computed yet. Damaging it does not make the document
      // modified, and a caller who expects otherwise is reading the wrong
      // field.
      final int gap = range[1] + (range[2] - range[1]) ~/ 2;
      final Uint8List damaged = Uint8List.fromList(signed);
      damaged[gap] ^= 0xFF;
      final PdfSignatureValidationItem item = await _onlySignature(damaged);
      expect(item.validation.byteRangeDigestOk, isTrue);
    });

    test('anything appended leaves the signature not covering the file',
        () async {
      final List<int> appended = <int>[
        ...signed,
        ...'\n% acrescentado depois\n'.codeUnits,
      ];
      final PdfSignatureValidationItem item = await _onlySignature(appended);
      expect(
        item.validation.byteRangeDigestOk,
        isTrue,
        reason: 'what was signed is untouched',
      );
      expect(
        item.validation.coversWholeDocument,
        isFalse,
        reason: 'but the signature no longer speaks for the whole file',
      );
    });
  });

  group('signing a document that already exists', () {
    test('a real document from the corpus can be signed', () async {
      final File file = File('test/assets/Invoice.pdf');
      if (!file.existsSync()) {
        markTestSkipped('test/assets/Invoice.pdf is not available');
        return;
      }
      final PdfDocument document = PdfDocument(
        inputBytes: file.readAsBytesSync(),
      );
      final int pages = document.pages.count;
      document.form.fields.add(
        PdfSignatureField(
          document.pages[0],
          'assinatura',
          bounds: const Rect.fromLTWH(350, 700, 200, 60),
          signature: PdfSignature(
            certificate: certificate(),
            signedName: 'Isaque Neves Sant Ana',
            signedDate: _signingDate,
          ),
        ),
      );
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfSignatureValidationItem item = await _onlySignature(bytes);
      expect(item.validation.documentIntact, isTrue);
      expect(item.validation.coversWholeDocument, isTrue);

      final PdfDocument reloaded = PdfDocument(inputBytes: bytes);
      addTearDown(reloaded.dispose);
      expect(
        reloaded.pages.count,
        pages,
        reason: 'signing did not add or lose a page',
      );
    });

    test('a second signature leaves the first valid but no longer whole',
        () async {
      final List<int> once = _signNew(
        certificate(),
        bounds: const Rect.fromLTWH(40, 100, 150, 50),
      );

      final PdfDocument document = PdfDocument(inputBytes: once);
      document.form.fields.add(
        PdfSignatureField(
          document.pages[0],
          'segunda',
          bounds: const Rect.fromLTWH(250, 100, 150, 50),
          signature: PdfSignature(
            certificate: certificate(),
            signedName: 'Segundo signatario',
            signedDate: _signingDate,
          ),
        ),
      );
      final List<int> twice = document.saveSync();
      document.dispose();

      final PdfSignatureValidationReport report = await PdfSignatureValidator()
          .validateAllSignatures(Uint8List.fromList(twice));
      expect(report.signatures.length, 2);
      expect(
        report.allDocumentsIntact,
        isTrue,
        reason: 'the second signature is an incremental update, not a rewrite',
      );

      final PdfSignatureValidationItem first = report.signatures.firstWhere(
        (PdfSignatureValidationItem i) => i.fieldName == 'assinatura',
      );
      final PdfSignatureValidationItem second = report.signatures.firstWhere(
        (PdfSignatureValidationItem i) => i.fieldName == 'segunda',
      );
      expect(first.validation.byteRangeDigestOk, isTrue);
      expect(
        first.validation.coversWholeDocument,
        isFalse,
        reason: 'the first signature predates the second revision',
      );
      expect(second.validation.coversWholeDocument, isTrue);
    });
  });

  group('signing and merging together', () {
    test('a merged document can be signed afterwards', () async {
      final List<int> a = _plain('Primeiro documento');
      final List<int> b = _plain('Segundo documento');
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[a, b]);

      final PdfDocument document = PdfDocument(inputBytes: merged);
      expect(document.pages.count, 2);
      document.form.fields.add(
        PdfSignatureField(
          document.pages[1],
          'assinatura',
          bounds: const Rect.fromLTWH(40, 100, 200, 60),
          signature: PdfSignature(
            certificate: certificate(),
            signedName: 'Isaque Neves Sant Ana',
            signedDate: _signingDate,
          ),
        ),
      );
      final List<int> bytes = document.saveSync();
      document.dispose();

      final PdfSignatureValidationItem item = await _onlySignature(bytes);
      expect(item.validation.documentIntact, isTrue);
      expect(item.validation.coversWholeDocument, isTrue);
      expect(item.pageIndex, 1);
    });

    test('merging a signed document drops the signature, as it must',
        () async {
      final List<int> signed = _signNew(certificate());
      final List<int> merged = PdfDocument.mergeSync(<List<int>>[signed]);

      final PdfSignatureValidationReport report = await PdfSignatureValidator()
          .validateAllSignatures(Uint8List.fromList(merged));
      expect(
        report.signatures,
        isEmpty,
        reason:
            'the pages moved into a new file, so nothing the old signature '
            'covers is still there to cover',
      );
    });
  });
}

final DateTime _signingDate = DateTime.utc(2026, 1, 1);

/// A one page document with [text] on it, unsigned.
List<int> _plain(String text) {
  final PdfDocument document = PdfDocument();
  document.pages.add().graphics.drawString(
    text,
    PdfStandardFont(PdfFontFamily.helvetica, 14),
    bounds: const Rect.fromLTWH(40, 40, 400, 30),
  );
  final List<int> bytes = document.saveSync();
  document.dispose();
  return bytes;
}

/// A one page document signed with [certificate], saved and returned.
List<int> _signNew(
  PdfCertificate certificate, {
  DigestAlgorithm digest = DigestAlgorithm.sha256,
  CryptographicStandard standard = CryptographicStandard.cades,
  Rect? bounds = const Rect.fromLTWH(40, 100, 200, 60),
  String signedName = 'Isaque Neves Sant Ana',
  String? reason,
  String? location,
  String? contact,
}) {
  final PdfDocument document = PdfDocument();
  final PdfPage page = document.pages.add();
  page.graphics.drawString(
    'documento para assinar',
    PdfStandardFont(PdfFontFamily.helvetica, 14),
    bounds: const Rect.fromLTWH(40, 40, 400, 30),
  );
  final PdfSignature signature = PdfSignature(
    certificate: certificate,
    signedName: signedName,
    reason: reason,
    locationInfo: location,
    contactInfo: contact,
    signedDate: _signingDate,
    digestAlgorithm: digest,
    cryptographicStandard: standard,
  );
  document.form.fields.add(
    bounds == null
        ? PdfSignatureField(page, 'assinatura', signature: signature)
        : PdfSignatureField(
            page,
            'assinatura',
            bounds: bounds,
            signature: signature,
          ),
  );
  final List<int> bytes = document.saveSync();
  document.dispose();
  return bytes;
}

/// Validates [bytes] and returns its one signature, failing the test if there
/// is not exactly one.
Future<PdfSignatureValidationItem> _onlySignature(List<int> bytes) async {
  final PdfSignatureValidationReport report = await PdfSignatureValidator()
      .validateAllSignatures(Uint8List.fromList(bytes));
  expect(report.signatures.length, 1, reason: 'expected one signature');
  return report.signatures.single;
}
