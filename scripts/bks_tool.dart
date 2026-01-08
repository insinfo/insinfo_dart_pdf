import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/src/security/keystore/bks_reader.dart';

const String _defaultIcpBrasilBksPassword = 'serprosigner';

void main(List<String> args) {
  if (args.isEmpty || args.contains('--help') || args.contains('-h')) {
    _usage();
    exit(args.isEmpty ? 2 : 0);
  }

  final String cmd = args.first;
  final List<String> rest = args.skip(1).toList(growable: false);

  String password = _defaultIcpBrasilBksPassword;
  final List<String> positional = <String>[];
  for (int i = 0; i < rest.length; i++) {
    final String a = rest[i];
    if (a.startsWith('--password=')) {
      password = a.substring('--password='.length);
      continue;
    }
    if (a == '--password' && i + 1 < rest.length) {
      password = rest[i + 1];
      i++;
      continue;
    }
    positional.add(a);
  }

  if (cmd == 'list') {
    if (positional.isEmpty) {
      stderr.writeln('Missing <store.bks>');
      _usage();
      exit(2);
    }
    final storePath = positional[0];
    final Uint8List bytes = File(storePath).readAsBytesSync();
    final BksStore store =
        BksCodec.decode(bytes, password: password, strictMac: false);

    stdout.writeln('BKS v${store.version} entries=${store.entries.length}');
    for (final e in store.entries) {
      stdout
          .writeln('- ${e.type.name} alias=${e.alias} chain=${e.chain.length}');
    }
    return;
  }

  if (cmd == 'export-pem') {
    if (positional.length < 2) {
      stderr.writeln('Usage: export-pem <store.bks> <outDir>');
      exit(2);
    }
    final storePath = positional[0];
    final outDirPath = positional[1];

    final Uint8List bytes = File(storePath).readAsBytesSync();
    final BksStore store =
        BksCodec.decode(bytes, password: password, strictMac: false);
    final Directory outDir = Directory(outDirPath)..createSync(recursive: true);

    int i = 0;
    for (final e in store.certificateEntries) {
      final cert = e.certificate;
      if (cert == null) continue;
      final String safeAlias =
          e.alias.replaceAll(RegExp(r'[^a-zA-Z0-9._-]+'), '_');
      final String base64Der = base64Encode(cert.encoded);
      final String pem =
          '-----BEGIN CERTIFICATE-----\n$base64Der\n-----END CERTIFICATE-----\n';
      final String outPath =
          '${outDir.path}${Platform.pathSeparator}${i.toString().padLeft(4, '0')}_$safeAlias.pem';
      File(outPath).writeAsStringSync(pem);
      i++;
    }

    stdout.writeln('Exported $i certificate(s) to $outDirPath');
    return;
  }

  if (cmd == 'add-cert') {
    if (positional.length < 3) {
      stderr.writeln(
          'Usage: add-cert <store.bks> <alias> <cert.der|cert.pem> [--out out.bks]');
      exit(2);
    }

    String? outPath;
    final List<String> args2 = <String>[];
    for (int i = 0; i < positional.length; i++) {
      final a = positional[i];
      if (a == '--out' && i + 1 < positional.length) {
        outPath = positional[i + 1];
        i++;
        continue;
      }
      args2.add(a);
    }

    final String storePath = args2[0];
    final String alias = args2[1];
    final String certPath = args2[2];

    final Uint8List storeBytes = File(storePath).readAsBytesSync();
    final BksStore store =
        BksCodec.decode(storeBytes, password: password, strictMac: false);

    final Uint8List certDer = _readCertAsDer(File(certPath));
    store.upsertTrustedCertificate(alias: alias, certificateDer: certDer);

    final String dest = outPath ?? storePath;
    final Uint8List newBytes = store.toBytes(password: password);
    File(dest).writeAsBytesSync(newBytes);
    stdout.writeln('Wrote $dest');
    return;
  }

  if (cmd == 'remove') {
    if (positional.length < 2) {
      stderr.writeln('Usage: remove <store.bks> <alias> [--out out.bks]');
      exit(2);
    }

    String? outPath;
    final List<String> args2 = <String>[];
    for (int i = 0; i < positional.length; i++) {
      final a = positional[i];
      if (a == '--out' && i + 1 < positional.length) {
        outPath = positional[i + 1];
        i++;
        continue;
      }
      args2.add(a);
    }

    final String storePath = args2[0];
    final String alias = args2[1];

    final Uint8List storeBytes = File(storePath).readAsBytesSync();
    final BksStore store =
        BksCodec.decode(storeBytes, password: password, strictMac: false);

    final bool removed = store.removeEntry(alias);
    if (!removed) {
      stderr.writeln('Alias not found: $alias');
      exit(3);
    }

    final String dest = outPath ?? storePath;
    final Uint8List newBytes = store.toBytes(password: password);
    File(dest).writeAsBytesSync(newBytes);
    stdout.writeln('Wrote $dest');
    return;
  }

  stderr.writeln('Unknown command: $cmd');
  _usage();
  exit(2);
}

Uint8List _readCertAsDer(File f) {
  final Uint8List bytes = f.readAsBytesSync();
  final String? asText = _tryUtf8(bytes);
  if (asText != null && asText.contains('-----BEGIN CERTIFICATE-----')) {
    final RegExp re = RegExp(
      r'-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----',
      multiLine: true,
    );
    final Match? m = re.firstMatch(asText);
    if (m == null) {
      throw StateError('PEM does not contain a certificate block: ${f.path}');
    }
    final String b64 = (m.group(1) ?? '').replaceAll(RegExp(r'\s+'), '');
    return Uint8List.fromList(base64Decode(b64));
  }
  return bytes;
}

String? _tryUtf8(Uint8List bytes) {
  try {
    return utf8.decode(bytes);
  } catch (_) {
    return null;
  }
}

void _usage() {
  stdout.writeln('BKS tool (BKS v2)');
  stdout.writeln('');
  stdout.writeln(
    'Usage: dart run scripts/bks_tool.dart <command> [args] [--password <pwd>]',
  );
  stdout.writeln('');
  stdout.writeln(
    'Default password (if omitted): $_defaultIcpBrasilBksPassword',
  );
  stdout.writeln('');
  stdout.writeln('Commands:');
  stdout.writeln('  list <store.bks>');
  stdout.writeln('  export-pem <store.bks> <outDir>');
  stdout.writeln(
      '  add-cert <store.bks> <alias> <cert.der|cert.pem> [--out out.bks]');
  stdout.writeln('  remove <store.bks> <alias> [--out out.bks]');
}
