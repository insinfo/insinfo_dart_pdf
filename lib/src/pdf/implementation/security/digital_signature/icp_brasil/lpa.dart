import '../asn1/asn1.dart';
import '../asn1/asn1_stream.dart';
import '../asn1/der.dart';
import '../x509/x509_time.dart';
import '../../../io/stream_reader.dart';

import 'dart:convert';

import 'package:xml/xml.dart' as xml;

/// Represents the ICP-Brasil LPA (Lista de Políticas de Assinatura), v2.
///
/// This is aligned with Demoiselle Signer `asn1/icpb/v2/LPA.java`.
///
/// DER structure:
/// LPA ::= SEQUENCE {
///   version      INTEGER OPTIONAL,
///   policyInfos  SEQUENCE OF PolicyInfo,
///   nextUpdate   GeneralizedTime
/// }
class Lpa {
  Lpa({required this.policyInfos, required this.nextUpdate, this.version});

  final List<PolicyInfo> policyInfos;
  final DateTime nextUpdate;
  final int? version;

  static Lpa? fromAsn1(Asn1 asn1) {
    if (asn1 is! Asn1Sequence || asn1.count < 2) return null;

    int idx = 0;
    int? version;

    // version INTEGER OPTIONAL
    final Asn1? first = asn1[0]?.getAsn1();
    if (first is DerInteger) {
      version = first.value.toInt();
      idx++;
    }

    if (asn1.count - idx < 2) return null;

    // policyInfos SEQUENCE OF PolicyInfo
    final Asn1Sequence? infosSeq = asn1[idx++]?.getAsn1() as Asn1Sequence?;
    if (infosSeq == null) return null;

    final List<PolicyInfo> infos = [];
    for (int i = 0; i < infosSeq.count; i++) {
      final Asn1? item = infosSeq[i]?.getAsn1();
      if (item != null) {
        final pi = PolicyInfo.fromAsn1(item);
        if (pi != null) infos.add(pi);
      }
    }

    // nextUpdate GeneralizedTime
    final Asn1? nextUpdateAsn1 = asn1[idx]?.getAsn1();
    final DateTime? nextUp = (nextUpdateAsn1 is GeneralizedTime)
        ? nextUpdateAsn1.toDateTime()
        : X509Time.getTime(nextUpdateAsn1)?.toDateTime();

    if (nextUp == null) return null;

    return Lpa(policyInfos: infos, nextUpdate: nextUp, version: version);
  }

  static Lpa? fromBytes(List<int> bytes) {
    final Asn1Stream s = Asn1Stream(PdfStreamReader(bytes));
    return fromAsn1(s.readAsn1()!);
  }

  static Lpa? fromXmlString(String xmlString) {
    final xml.XmlDocument doc = xml.XmlDocument.parse(xmlString);
    final xml.XmlElement root = doc.rootElement;

    final String? nextUpdateText = _firstElementText(root, 'NextUpdate');
    if (nextUpdateText == null) return null;
    final DateTime? nextUpdate = DateTime.tryParse(nextUpdateText);
    if (nextUpdate == null) return null;

    final int? version = int.tryParse(_firstElementText(root, 'Version') ?? '');

    final List<PolicyInfo> policies = <PolicyInfo>[];
    for (final xml.XmlElement pi in _allElements(root, 'PolicyInfo')) {
      final PolicyInfo? parsed = PolicyInfo.fromXml(pi);
      if (parsed != null) policies.add(parsed);
    }

    return Lpa(policyInfos: policies, nextUpdate: nextUpdate, version: version);
  }

  static String? _firstElementText(xml.XmlElement root, String localName) {
    final Iterable<xml.XmlElement> elements =
        root.descendantElements.where((e) => e.name.local == localName);
    final xml.XmlElement? first = elements.isEmpty ? null : elements.first;
    return first?.innerText.trim();
  }

  static Iterable<xml.XmlElement> _allElements(
    xml.XmlElement root,
    String localName,
  ) {
    return root.descendantElements.where((e) => e.name.local == localName);
  }
}

/// Represents a PolicyInfo entry in the LPA (v2).
///
/// DER structure (aligned with Demoiselle `PolicyInfo.java`):
/// PolicyInfo ::= SEQUENCE {
///   signingPeriod   SigningPeriod,
///   revocationDate  Time OPTIONAL,
///   policyOID       OBJECT IDENTIFIER,
///   policyURI       IA5String,
///   policyDigest    OtherHashAlgAndValue
/// }
class PolicyInfo {
  PolicyInfo({
    required this.signingPeriod,
    required this.policyOid,
    required this.policyUri,
    required this.policyDigest,
    this.revocationDate,
  });

  final SigningPeriod signingPeriod;
  final DateTime? revocationDate;
  final String policyOid;
  final String policyUri;
  final PolicyDigest policyDigest;

  static PolicyInfo? fromAsn1(Asn1 asn1) {
    if (asn1 is! Asn1Sequence) return null;
    if (asn1.count < 4) return null;

    int idx = 0;
    final SigningPeriod? signingPeriod =
        SigningPeriod.fromAsn1(asn1[idx++]?.getAsn1());
    if (signingPeriod == null) return null;

    DateTime? revocationDate;
    final Asn1? maybeTime = asn1[idx]?.getAsn1();
    final X509Time? timeObj = X509Time.getTime(maybeTime);
    if (timeObj != null &&
        (maybeTime is DerUtcTime || maybeTime is GeneralizedTime)) {
      revocationDate = timeObj.toDateTime();
      idx++;
    }

    final Asn1? oidAsn1 = asn1[idx++]?.getAsn1();
    if (oidAsn1 is! DerObjectID || oidAsn1.id == null) return null;
    final String policyOid = oidAsn1.id!;

    final Asn1? uriAsn1 = asn1[idx++]?.getAsn1();
    final String? policyUri = _readIa5String(uriAsn1);
    if (policyUri == null) return null;

    final Asn1? digestAsn1 = asn1[idx++]?.getAsn1();
    final PolicyDigest? digest = PolicyDigest.fromAsn1(digestAsn1);
    if (digest == null) return null;

    return PolicyInfo(
      signingPeriod: signingPeriod,
      revocationDate: revocationDate,
      policyOid: policyOid,
      policyUri: policyUri,
      policyDigest: digest,
    );
  }

  static PolicyInfo? fromXml(xml.XmlElement policyInfoElement) {
    final xml.XmlElement? signingPeriodEl = policyInfoElement.childElements
        .where((e) => e.name.local == 'SigningPeriod')
        .cast<xml.XmlElement?>()
        .firstWhere((e) => e != null, orElse: () => null);
    if (signingPeriodEl == null) return null;

    final String? notBeforeText = signingPeriodEl.childElements
        .where((e) => e.name.local == 'NotBefore')
      .map((e) => e.innerText.trim())
        .cast<String?>()
        .firstWhere((t) => t != null && t.isNotEmpty, orElse: () => null);
    if (notBeforeText == null) return null;
    final DateTime? notBefore = DateTime.tryParse(notBeforeText);
    if (notBefore == null) return null;

    final String? notAfterText = signingPeriodEl.childElements
        .where((e) => e.name.local == 'NotAfter')
      .map((e) => e.innerText.trim())
        .cast<String?>()
        .firstWhere((t) => t != null && t.isNotEmpty, orElse: () => null);
    final DateTime? notAfter =
        notAfterText == null ? null : DateTime.tryParse(notAfterText);

    final String? revocationText = policyInfoElement.childElements
        .where((e) => e.name.local == 'RevocationDate')
      .map((e) => e.innerText.trim())
        .cast<String?>()
        .firstWhere((t) => t != null && t.isNotEmpty, orElse: () => null);
    final DateTime? revocationDate =
        revocationText == null ? null : DateTime.tryParse(revocationText);

    final String? identifierText = policyInfoElement.descendantElements
        .where((e) => e.name.local == 'Identifier')
      .map((e) => e.innerText.trim())
        .cast<String?>()
        .firstWhere((t) => t != null && t.isNotEmpty, orElse: () => null);
    if (identifierText == null) return null;
    final String policyOid = identifierText.startsWith('urn:oid:')
        ? identifierText.substring('urn:oid:'.length)
        : identifierText;

    final xml.XmlElement? digestAndUri = policyInfoElement.childElements
        .where((e) => e.name.local == 'PolicyDigestAndURI')
        .cast<xml.XmlElement?>()
        .firstWhere((e) => e != null, orElse: () => null);
    if (digestAndUri == null) return null;

    final String? policyUri = digestAndUri.childElements
        .where((e) => e.name.local == 'PolicyURI')
      .map((e) => e.innerText.trim())
        .cast<String?>()
        .firstWhere((t) => t != null && t.isNotEmpty, orElse: () => null);
    if (policyUri == null) return null;

    final xml.XmlElement? policyDigestEl = digestAndUri.childElements
        .where((e) => e.name.local == 'PolicyDigest')
        .cast<xml.XmlElement?>()
        .firstWhere((e) => e != null, orElse: () => null);
    if (policyDigestEl == null) return null;

    final xml.XmlElement? digestMethodEl = policyDigestEl.descendantElements
        .where((e) => e.name.local == 'DigestMethod')
        .cast<xml.XmlElement?>()
        .firstWhere((e) => e != null, orElse: () => null);
    final String? algorithm = digestMethodEl?.getAttribute('Algorithm')?.trim();
    if (algorithm == null || algorithm.isEmpty) return null;

    final String? digestValueB64 = policyDigestEl.descendantElements
        .where((e) => e.name.local == 'DigestValue')
      .map((e) => e.innerText.trim())
        .cast<String?>()
        .firstWhere((t) => t != null && t.isNotEmpty, orElse: () => null);
    if (digestValueB64 == null) return null;

    final List<int> digestValue = base64.decode(digestValueB64);

    return PolicyInfo(
      signingPeriod: SigningPeriod(notBefore: notBefore, notAfter: notAfter),
      revocationDate: revocationDate,
      policyOid: policyOid,
      policyUri: policyUri,
      policyDigest: PolicyDigest(algorithm: algorithm, value: digestValue),
    );
  }

  static String? _readIa5String(Asn1? asn1) {
    if (asn1 is DerAsciiString) return asn1.getString();
    if (asn1 is DerPrintableString) return asn1.getString();
    if (asn1 is DerUtf8String) return asn1.getString();
    return asn1?.toString();
  }
}

class PolicyDigest {
  PolicyDigest({required this.algorithm, required this.value});

  /// For DER this is an OID (e.g. `2.16.840.1.101.3.4.2.1` for SHA-256).
  /// For XML this is the digest method URI (e.g. `http://www.w3.org/2001/04/xmlenc#sha256`).
  final String algorithm;

  /// Digest bytes.
  final List<int> value;

  static PolicyDigest? fromAsn1(Asn1? asn1) {
    if (asn1 is! Asn1Sequence || asn1.count < 2) return null;

    final Asn1? algoSeq = asn1[0]?.getAsn1();
    if (algoSeq is! Asn1Sequence || algoSeq.count < 1) return null;
    final Asn1? oidAsn1 = algoSeq[0]?.getAsn1();
    if (oidAsn1 is! DerObjectID || oidAsn1.id == null) return null;
    final String algorithm = oidAsn1.id!;

    final Asn1? valueAsn1 = asn1[1]?.getAsn1();
    if (valueAsn1 is! DerOctet || valueAsn1.getOctets() == null) return null;
    final List<int> value = valueAsn1.getOctets()!;

    return PolicyDigest(algorithm: algorithm, value: value);
  }
}

/// SigningPeriod ::= SEQUENCE {
///    notBefore Time,
///    notAfter Time OPTIONAL
/// }
class SigningPeriod {
  SigningPeriod({required this.notBefore, this.notAfter});

  final DateTime notBefore;
  final DateTime? notAfter;

  static SigningPeriod? fromAsn1(Asn1? asn1) {
    if (asn1 is! Asn1Sequence) return null;

    final DateTime? nb = X509Time.getTime(asn1[0])?.toDateTime();
    if (nb == null) return null;

    DateTime? na;
    if (asn1.count > 1) {
      na = X509Time.getTime(asn1[1])?.toDateTime();
    }

    return SigningPeriod(notBefore: nb, notAfter: na);
  }
}
