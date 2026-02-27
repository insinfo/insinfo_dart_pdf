import 'dart:io';
import 'dart:typed_data';

import '../../pdf/implementation/security/digital_signature/x509/x509_certificates.dart';
import '../../pdf/implementation/security/digital_signature/x509/x509_utils.dart';

List<X509Certificate> loadCertPoolFromDirectories(
  List<String> directories, {
  int maxAncestorLevels = 5,
}) {
  final List<File> files = <File>[];

  for (final String dirPath in directories) {
    final Directory? dir = _resolveExistingDirectory(
      dirPath,
      maxAncestorLevels: maxAncestorLevels,
    );
    if (dir == null) {
      continue;
    }

    for (final FileSystemEntity entity
        in dir.listSync(recursive: true, followLinks: false)) {
      if (entity is! File) {
        continue;
      }
      final String lower = entity.path.toLowerCase();
      if (lower.endsWith('.der') ||
          lower.endsWith('.cer') ||
          lower.endsWith('.crt') ||
          lower.endsWith('.pem')) {
        files.add(entity);
      }
    }
  }

  final List<X509Certificate> out = <X509Certificate>[];
  for (final File file in files) {
    try {
      out.addAll(_parseCertificates(file));
    } catch (_) {}
  }
  return out;
}

List<X509Certificate> _parseCertificates(File file) {
  final String lower = file.path.toLowerCase();
  final Uint8List rawBytes = Uint8List.fromList(file.readAsBytesSync());
  final String rawText = String.fromCharCodes(rawBytes);
  final bool looksPem =
      lower.endsWith('.pem') || rawText.contains('-----BEGIN CERTIFICATE-----');

  if (!looksPem) {
    return <X509Certificate>[
      X509Utils.parsePemCertificate(X509Utils.derToPem(rawBytes)),
    ];
  }

  final Iterable<RegExpMatch> blocks = RegExp(
    r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----',
  ).allMatches(rawText);
  final List<X509Certificate> out = <X509Certificate>[];
  for (final RegExpMatch block in blocks) {
    final String? pem = block.group(0);
    if (pem == null) {
      continue;
    }
    out.add(X509Utils.parsePemCertificate(pem));
  }
  return out;
}

Directory? _resolveExistingDirectory(
  String path, {
  required int maxAncestorLevels,
}) {
  final Directory direct = Directory(path);
  if (direct.existsSync()) {
    return direct;
  }

  Directory cursor = Directory.current;
  for (int i = 0; i < maxAncestorLevels; i++) {
    final Directory rooted = Directory('${cursor.path}/$path');
    if (rooted.existsSync()) {
      return rooted;
    }
    final Directory parent = cursor.parent;
    if (parent.path == cursor.path) {
      break;
    }
    cursor = parent;
  }
  return null;
}
