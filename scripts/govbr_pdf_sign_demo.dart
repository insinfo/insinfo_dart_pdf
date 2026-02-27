import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf_server.dart' as pdf;

Future<void> main(List<String> args) async {
  final String outputDir =
      args.isNotEmpty ? args.first : '${Directory.current.path}\\govbr_demo';
  final String foxitPath = Platform.environment['FOXIT_PATH'] ??
      r'C:\Program Files\Foxit Software\Foxit PDF Editor\FoxitPDFEditor.exe';

  final Directory dir = Directory(outputDir);
  if (!dir.existsSync()) {
    dir.createSync(recursive: true);
  }

  _ensureOpenSsl();

  final _CertChain chain = await _generateCertificateChain(dir);

  final pdf.PdfDocument doc = pdf.PdfDocument();
  doc.pages.add().graphics.drawString(
        'Gov.br demo assinatura',
        pdf.PdfStandardFont(pdf.PdfFontFamily.helvetica, 12),
      );
  final Uint8List inputBytes = Uint8List.fromList(await doc.save());
  doc.dispose();

  final pdf.PdfExternalSigningResult prepared =
      await pdf.PdfExternalSigning.preparePdf(
    inputBytes: inputBytes,
    pageNumber: 1,
    bounds: pdf.Rect.fromLTWH(100, 120, 220, 60),
    fieldName: 'GovBr_Signature',
    drawAppearance: (graphics, bounds) {
      graphics.drawString(
        'Assinado via Gov.br (demo)',
        pdf.PdfStandardFont(pdf.PdfFontFamily.helvetica, 9),
        bounds: bounds,
      );
    },
  );

  final List<int> byteRange =
      pdf.PdfExternalSigning.extractByteRange(prepared.preparedPdfBytes);
  final Uint8List dataToSign =
      _extractDataByRange(prepared.preparedPdfBytes, byteRange);
  final String hashBase64 = pdf.PdfExternalSigning.computeByteRangeHashBase64(
    prepared.preparedPdfBytes,
    byteRange,
  );

  print('Hash Base64: $hashBase64');

  final String dataPath = '${dir.path}\\data.bin';
  await File(dataPath).writeAsBytes(dataToSign, flush: true);
  final String sigPath = '${dir.path}\\signature.der';
  await _runCmd('openssl', [
    'cms',
    '-sign',
    '-binary',
    '-in',
    dataPath,
    '-signer',
    chain.leafCertPath,
    '-inkey',
    chain.leafKeyPath,
    '-certfile',
    chain.chainCertPath,
    '-outform',
    'DER',
    '-out',
    sigPath,
  ]);

  final Uint8List pkcs7 = await File(sigPath).readAsBytes();
  final Uint8List signedPdf = pdf.PdfExternalSigning.embedSignature(
    preparedPdfBytes: prepared.preparedPdfBytes,
    pkcs7Bytes: pkcs7,
  );
  final String signedPath = '${dir.path}\\signed_demo.pdf';
  await File(signedPath).writeAsBytes(signedPdf, flush: true);

  await _installCert(chain.rootCertPath, 'Root');
  await _installCert(chain.intermediateCertPath, 'CA');

  print('PDF assinado: $signedPath');
  await _openFoxit(foxitPath, signedPath);
}

void _ensureOpenSsl() {
  final ProcessResult result = Process.runSync('openssl', const ['version']);
  if (result.exitCode != 0) {
    throw Exception('OpenSSL not available');
  }
}

Future<void> _runCmd(String cmd, List<String> args) async {
  final ProcessResult result = await Process.run(cmd, args);
  if (result.exitCode != 0) {
    throw Exception(
      'Command failed: $cmd ${args.join(' ')}\n'
      'stdout: ${result.stdout}\n'
      'stderr: ${result.stderr}',
    );
  }
}

Future<void> _installCert(String certPath, String store) async {
  await _runCmd('certutil', ['-user', '-addstore', store, certPath]);
}

Future<void> _openFoxit(String foxitPath, String pdfPath) async {
  if (!File(foxitPath).existsSync()) {
    print('Foxit não encontrado: $foxitPath');
    return;
  }
  await Process.start(foxitPath, [pdfPath]);
}

Uint8List _extractDataByRange(Uint8List pdfBytes, List<int> byteRange) {
  if (byteRange.length != 4) {
    throw ArgumentError.value(byteRange, 'byteRange', 'Invalid length');
  }
  final int start1 = byteRange[0];
  final int len1 = byteRange[1];
  final int start2 = byteRange[2];
  final int len2 = byteRange[3];
  final BytesBuilder builder = BytesBuilder();
  builder.add(pdfBytes.sublist(start1, start1 + len1));
  builder.add(pdfBytes.sublist(start2, start2 + len2));
  return builder.takeBytes();
}

Future<_CertChain> _generateCertificateChain(Directory dir) async {
  final String rootKey = '${dir.path}\\root_key.pem';
  final String rootCert = '${dir.path}\\root_cert.pem';
  await _runCmd('openssl', [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    rootKey,
    '-out',
    rootCert,
    '-days',
    '3650',
    '-subj',
    '/CN=Demo Root CA',
    '-addext',
    'basicConstraints=CA:TRUE',
    '-addext',
    'keyUsage=keyCertSign,cRLSign',
    '-addext',
    'subjectKeyIdentifier=hash',
  ]);

  final String intermediateKey = '${dir.path}\\intermediate_key.pem';
  final String intermediateCsr = '${dir.path}\\intermediate.csr';
  final String intermediateCert = '${dir.path}\\intermediate_cert.pem';
  await _runCmd('openssl', [
    'req',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    intermediateKey,
    '-out',
    intermediateCsr,
    '-subj',
    '/CN=Demo Intermediate CA',
  ]);

  final String intermediateExt = '${dir.path}\\intermediate_ext.cnf';
  await File(intermediateExt).writeAsString('''
[v3_ca]
basicConstraints=CA:TRUE,pathlen:0
keyUsage=keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
''');
  await _runCmd('openssl', [
    'x509',
    '-req',
    '-in',
    intermediateCsr,
    '-CA',
    rootCert,
    '-CAkey',
    rootKey,
    '-CAcreateserial',
    '-out',
    intermediateCert,
    '-days',
    '3650',
    '-sha256',
    '-extfile',
    intermediateExt,
    '-extensions',
    'v3_ca',
  ]);

  final String leafKey = '${dir.path}\\leaf_key.pem';
  final String leafCsr = '${dir.path}\\leaf.csr';
  final String leafCert = '${dir.path}\\leaf_cert.pem';
  await _runCmd('openssl', [
    'req',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    leafKey,
    '-out',
    leafCsr,
    '-subj',
    '/CN=Demo User',
  ]);

  final String leafExt = '${dir.path}\\leaf_ext.cnf';
  await File(leafExt).writeAsString('''
[usr_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,nonRepudiation
extendedKeyUsage=emailProtection
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
''');
  await _runCmd('openssl', [
    'x509',
    '-req',
    '-in',
    leafCsr,
    '-CA',
    intermediateCert,
    '-CAkey',
    intermediateKey,
    '-CAcreateserial',
    '-out',
    leafCert,
    '-days',
    '365',
    '-sha256',
    '-extfile',
    leafExt,
    '-extensions',
    'usr_cert',
  ]);

  final String chainCert = '${dir.path}\\chain.pem';
  final String chainContent = [
    await File(intermediateCert).readAsString(),
    await File(rootCert).readAsString(),
  ].join('\n');
  await File(chainCert).writeAsString(chainContent);

  return _CertChain(
    rootCertPath: rootCert,
    intermediateCertPath: intermediateCert,
    leafCertPath: leafCert,
    leafKeyPath: leafKey,
    chainCertPath: chainCert,
  );
}

class _CertChain {
  _CertChain({
    required this.rootCertPath,
    required this.intermediateCertPath,
    required this.leafCertPath,
    required this.leafKeyPath,
    required this.chainCertPath,
  });

  final String rootCertPath;
  final String intermediateCertPath;
  final String leafCertPath;
  final String leafKeyPath;
  final String chainCertPath;
}
