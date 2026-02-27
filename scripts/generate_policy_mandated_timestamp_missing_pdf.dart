import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:dart_pdf/pdf_server.dart' as pdf;
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/icp_brasil/etsi_policy.dart';
import 'package:dart_pdf/src/pdf/implementation/security/digital_signature/pdf_signature_dictionary.dart'
    show PdfCmsSigner;

Future<void> main(List<String> args) async {
  _ensureOpenSsl();

  final String outPdfPath = args.isNotEmpty
      ? args.first
      : 'test/assets/generated_policy_mandated_timestamp_missing.pdf';
  final Directory workDir = Directory('.dart_tool/generated_policy_pdf');
  if (!workDir.existsSync()) {
    workDir.createSync(recursive: true);
  }

  final String policyOid = _pickPolicyOidRequiringTimestamp();
  stdout.writeln('Using policyOid=$policyOid');

  final _CertChain chain = await _generateCertificateChain(workDir);

  // 1) Create a simple PDF.
  final pdf.PdfDocument doc = pdf.PdfDocument();
  doc.pages.add().graphics.drawString(
        'Generated test PDF (policy mandates timestamp; missing RFC3161)\n'
        'policyOid=$policyOid',
        pdf.PdfStandardFont(pdf.PdfFontFamily.helvetica, 10),
      );
  final Uint8List inputBytes = Uint8List.fromList(await doc.save());
  doc.dispose();

  // 2) Prepare for external signing.
  final pdf.PdfExternalSigningResult prepared =
      await pdf.PdfExternalSigning.preparePdf(
    inputBytes: inputBytes,
    pageNumber: 1,
    bounds: pdf.Rect.fromLTWH(100, 120, 260, 60),
    fieldName: 'Generated_Signature',
    drawAppearance: (graphics, bounds) {
      graphics.drawString(
        'Generated signature (no timestamp)',
        pdf.PdfStandardFont(pdf.PdfFontFamily.helvetica, 9),
        bounds: bounds,
      );
    },
  );

  final List<int> byteRange =
      pdf.PdfExternalSigning.extractByteRange(prepared.preparedPdfBytes);
  final Uint8List dataToSign =
      _extractDataByRange(prepared.preparedPdfBytes, byteRange);

  // 3) Compute digest of ByteRange content.
  final Uint8List contentDigest =
      Uint8List.fromList(crypto.sha256.convert(dataToSign).bytes);

  // 4) Build CMS detached with signedAttrs (includes SignaturePolicyId).
  final String leafKeyPem = File(chain.leafKeyPath).readAsStringSync();
  final String leafCertPem = File(chain.leafCertPath).readAsStringSync();
  final String intermediatePem =
      File(chain.intermediateCertPath).readAsStringSync();
  final String rootPem = File(chain.rootCertPath).readAsStringSync();

  final Uint8List pkcs7 = PdfCmsSigner.signDetachedSha256RsaFromPem(
    contentDigest: contentDigest,
    privateKeyPem: leafKeyPem,
    certificatePem: leafCertPem,
    chainPem: <String>[intermediatePem, rootPem],
    cryptographicStandard: pdf.CryptographicStandard.cms,
    timeStampToken: null, // deliberately omit RFC3161
    signaturePolicyOid: policyOid,
  );

  // 5) Embed CMS into the prepared PDF.
  final Uint8List signedPdf = pdf.PdfExternalSigning.embedSignature(
    preparedPdfBytes: prepared.preparedPdfBytes,
    pkcs7Bytes: pkcs7,
  );

  final File outFile = File(outPdfPath);
  outFile.parent.createSync(recursive: true);
  await outFile.writeAsBytes(signedPdf, flush: true);

  stdout.writeln('Wrote: ${outFile.path} (${outFile.lengthSync()} bytes)');
}

String _pickPolicyOidRequiringTimestamp() {
  final Directory artifactsDir = Directory('assets/policy/engine/artifacts');
  if (!artifactsDir.existsSync()) {
    throw StateError('Policy artifacts not found: ${artifactsDir.path}');
  }

  final List<File> xmlFiles = artifactsDir
      .listSync()
      .whereType<File>()
      .where((f) => f.path.toLowerCase().endsWith('.xml'))
      .toList(growable: false);

  for (final File f in xmlFiles) {
    final String xml = f.readAsStringSync();
    try {
      final EtsiPolicyConstraints c = EtsiPolicyConstraints.parseXml(xml);
      final String? oid = c.policyOid;
      if (oid == null) continue;
      if (!oid.startsWith('2.16.76.1.7.1.')) continue;
      if (!c.requiresSignatureTimeStamp) continue;
      return oid;
    } catch (_) {
      // ignore
    }
  }

  throw StateError(
    'No policy XML found that mandates SignatureTimeStamp (under assets/policy/engine/artifacts).',
  );
}

void _ensureOpenSsl() {
  final ProcessResult result =
      Process.runSync('openssl', const <String>['version']);
  if (result.exitCode != 0) {
    throw Exception('OpenSSL not available (required by this generator).');
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
  final String rootKey = '${dir.path}${Platform.pathSeparator}root_key.pem';
  final String rootCert = '${dir.path}${Platform.pathSeparator}root_cert.pem';
  await _runCmd('openssl', <String>[
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
    '/CN=Generated Root CA',
    '-addext',
    'basicConstraints=CA:TRUE',
    '-addext',
    'keyUsage=keyCertSign,cRLSign',
    '-addext',
    'subjectKeyIdentifier=hash',
  ]);

  final String intermediateKey =
      '${dir.path}${Platform.pathSeparator}intermediate_key.pem';
  final String intermediateCsr =
      '${dir.path}${Platform.pathSeparator}intermediate.csr';
  final String intermediateCert =
      '${dir.path}${Platform.pathSeparator}intermediate_cert.pem';
  await _runCmd('openssl', <String>[
    'req',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    intermediateKey,
    '-out',
    intermediateCsr,
    '-subj',
    '/CN=Generated Intermediate CA',
  ]);

  final String intermediateExt =
      '${dir.path}${Platform.pathSeparator}intermediate_ext.cnf';
  await File(intermediateExt).writeAsString('''
[v3_ca]
basicConstraints=CA:TRUE,pathlen:0
keyUsage=keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
''');
  await _runCmd('openssl', <String>[
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

  final String leafKey = '${dir.path}${Platform.pathSeparator}leaf_key.pem';
  final String leafCsr = '${dir.path}${Platform.pathSeparator}leaf.csr';
  final String leafCert = '${dir.path}${Platform.pathSeparator}leaf_cert.pem';
  await _runCmd('openssl', <String>[
    'req',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    leafKey,
    '-out',
    leafCsr,
    '-subj',
    '/CN=Generated Test Signer',
  ]);

  final String leafExt = '${dir.path}${Platform.pathSeparator}leaf_ext.cnf';
  await File(leafExt).writeAsString('''
[usr_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,nonRepudiation
extendedKeyUsage=emailProtection
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
''');
  await _runCmd('openssl', <String>[
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

  return _CertChain(
    rootCertPath: rootCert,
    intermediateCertPath: intermediateCert,
    leafCertPath: leafCert,
    leafKeyPath: leafKey,
  );
}

class _CertChain {
  _CertChain({
    required this.rootCertPath,
    required this.intermediateCertPath,
    required this.leafCertPath,
    required this.leafKeyPath,
  });

  final String rootCertPath;
  final String intermediateCertPath;
  final String leafCertPath;
  final String leafKeyPath;
}
