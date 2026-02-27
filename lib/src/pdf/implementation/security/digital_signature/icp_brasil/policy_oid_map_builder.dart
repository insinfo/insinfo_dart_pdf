import 'dart:io';

import 'lpa.dart';

class IcpBrasilPolicyOidMapBuilder {
  static Future<Map<String, String>> loadFromArtifactsDirectory(
    String artifactsDirPath,
  ) async {
    final Directory dir = Directory(artifactsDirPath);
    if (!await dir.exists()) return const <String, String>{};

    final List<File> files = <File>[];
    await for (final FileSystemEntity entity
        in dir.list(recursive: true, followLinks: false)) {
      if (entity is! File) continue;
      final String path = entity.path.toLowerCase();
      if (!path.endsWith('.xml') && !path.endsWith('.der')) continue;
      files.add(entity);
    }

    files.sort((a, b) => a.path.compareTo(b.path));

    final Map<String, _PolicyMapEntry> raw = <String, _PolicyMapEntry>{};

    void putEntry(String oid, String policyName, _PolicySource source) {
      final String normalizedOid = oid.trim();
      final String normalizedPolicyName = policyName.trim();
      if (normalizedOid.isEmpty || normalizedPolicyName.isEmpty) return;

      final _PolicyMapEntry current =
          raw[normalizedOid] ?? _PolicyMapEntry(policyName: '', source: source);
      if (current.policyName.isEmpty ||
          source.priority > current.source.priority) {
        raw[normalizedOid] = _PolicyMapEntry(
          policyName: normalizedPolicyName,
          source: source,
        );
      }
    }

    for (final File file in files) {
      final String localPolicyName = _basenameWithoutExtension(file.path);
      if (file.path.toLowerCase().endsWith('.xml')) {
        final String? xmlText = await _readTextSafe(file);
        if (xmlText == null || xmlText.trim().isEmpty) continue;

        _mapXmlPolicyInfoUri(xmlText, putEntry);
        _mapXmlFallbackUrnOid(xmlText, localPolicyName, putEntry);
        continue;
      }

      final List<int>? bytes = await _readBytesSafe(file);
      if (bytes == null || bytes.isEmpty) continue;

      _mapDerPolicyInfoUri(bytes, putEntry);
      _mapDerFallbackUrnOid(bytes, localPolicyName, putEntry);
    }

    final Map<String, String> out = <String, String>{
      for (final MapEntry<String, _PolicyMapEntry> entry in raw.entries)
        entry.key: entry.value.policyName,
    };
    applyIcpBrasilPolicyAliases(out);
    return out;
  }

  static void applyIcpBrasilPolicyAliases(Map<String, String> map) {
    const String basePrefix = '2.16.76.1.7.1.';
    final Map<String, String> snapshot = Map<String, String>.from(map);

    for (final MapEntry<String, String> entry in snapshot.entries) {
      final String oid = entry.key.trim();
      if (!oid.startsWith(basePrefix)) continue;

      final String suffix = oid.substring(basePrefix.length);
      final List<String> parts = suffix.split('.');
      if (parts.length < 2) continue;

      final int? family = int.tryParse(parts.first);
      if (family == null) continue;

      final int? aliasFamily = (family >= 1 && family <= 5)
          ? family + 5
          : (family >= 6 && family <= 10)
              ? family - 5
              : null;
      if (aliasFamily == null) continue;

      final String tail = parts.skip(1).join('.');
      final String aliasOid = '$basePrefix$aliasFamily.$tail';
      map.putIfAbsent(aliasOid, () => entry.value);
    }
  }

  static void _mapXmlPolicyInfoUri(
    String xmlText,
    void Function(String oid, String policyName, _PolicySource source) putEntry,
  ) {
    Lpa? lpa;
    try {
      lpa = Lpa.fromXmlString(xmlText);
    } catch (_) {
      lpa = null;
    }
    if (lpa == null) return;

    for (final PolicyInfo info in lpa.policyInfos) {
      final String? policyName = _extractPolicyBasenameFromUri(info.policyUri);
      if (policyName == null || policyName.isEmpty) continue;
      putEntry(info.policyOid, policyName, _PolicySource.policyUri);
    }
  }

  static void _mapXmlFallbackUrnOid(
    String xmlText,
    String localPolicyName,
    void Function(String oid, String policyName, _PolicySource source) putEntry,
  ) {
    final RegExp oidRegex = RegExp(r'urn:oid:([0-9.]+)', caseSensitive: false);
    for (final RegExpMatch match in oidRegex.allMatches(xmlText)) {
      final String? oid = match.group(1)?.trim();
      if (oid == null || oid.isEmpty) continue;
      putEntry(oid, localPolicyName, _PolicySource.fallback);
    }
  }

  static void _mapDerPolicyInfoUri(
    List<int> bytes,
    void Function(String oid, String policyName, _PolicySource source) putEntry,
  ) {
    Lpa? lpa;
    try {
      lpa = Lpa.fromBytes(bytes);
    } catch (_) {
      lpa = null;
    }
    if (lpa == null) return;

    for (final PolicyInfo info in lpa.policyInfos) {
      final String? policyName = _extractPolicyBasenameFromUri(info.policyUri);
      if (policyName == null || policyName.isEmpty) continue;
      putEntry(info.policyOid, policyName, _PolicySource.policyUri);
    }
  }

  static void _mapDerFallbackUrnOid(
    List<int> bytes,
    String localPolicyName,
    void Function(String oid, String policyName, _PolicySource source) putEntry,
  ) {
    final String text = _extractAsciiRuns(bytes);
    if (text.isEmpty) return;

    final RegExp oidRegex = RegExp(r'urn:oid:([0-9.]+)', caseSensitive: false);
    for (final RegExpMatch match in oidRegex.allMatches(text)) {
      final String? oid = match.group(1)?.trim();
      if (oid == null || oid.isEmpty) continue;
      putEntry(oid, localPolicyName, _PolicySource.fallback);
    }
  }

  static String _basenameWithoutExtension(String path) {
    final String sep = Platform.pathSeparator;
    final String name = path.split(sep).last;
    final int dot = name.lastIndexOf('.');
    if (dot <= 0) return name;
    return name.substring(0, dot);
  }

  static String? _extractPolicyBasenameFromUri(String? uri) {
    if (uri == null) return null;
    String normalized = uri.trim();
    if (normalized.isEmpty) return null;

    final int queryIdx = normalized.indexOf('?');
    if (queryIdx >= 0) {
      normalized = normalized.substring(0, queryIdx);
    }
    final int fragmentIdx = normalized.indexOf('#');
    if (fragmentIdx >= 0) {
      normalized = normalized.substring(0, fragmentIdx);
    }

    normalized = normalized.replaceAll('\\', '/');
    final String name = normalized.split('/').last.trim();
    if (name.isEmpty) return null;

    final int dot = name.lastIndexOf('.');
    if (dot <= 0) return name;
    return name.substring(0, dot);
  }

  static String _extractAsciiRuns(List<int> bytes) {
    final StringBuffer out = StringBuffer();
    final StringBuffer current = StringBuffer();

    void flush() {
      if (current.length >= 6) {
        if (out.isNotEmpty) out.write(' ');
        out.write(current.toString());
      }
      current.clear();
    }

    for (final int b in bytes) {
      if (b >= 32 && b <= 126) {
        current.writeCharCode(b);
      } else {
        flush();
      }
    }
    flush();
    return out.toString();
  }

  static Future<String?> _readTextSafe(File file) async {
    try {
      return await file.readAsString();
    } catch (_) {
      return null;
    }
  }

  static Future<List<int>?> _readBytesSafe(File file) async {
    try {
      return await file.readAsBytes();
    } catch (_) {
      return null;
    }
  }
}

class _PolicyMapEntry {
  const _PolicyMapEntry({
    required this.policyName,
    required this.source,
  });

  final String policyName;
  final _PolicySource source;
}

enum _PolicySource {
  fallback(1),
  policyUri(2);

  const _PolicySource(this.priority);
  final int priority;
}
