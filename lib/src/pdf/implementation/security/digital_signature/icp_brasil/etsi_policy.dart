import 'package:xml/xml.dart';

class EtsiAlgorithmConstraint {
  const EtsiAlgorithmConstraint({
    required this.algorithmToken,
    required this.minKeyLength,
    this.rawAlgId,
  });

  /// Normalized token like `rsa-sha256`, `rsa-sha512`, etc.
  final String algorithmToken;

  /// Minimum key length in bits.
  final int minKeyLength;

  /// Original AlgId value from XML when available.
  final String? rawAlgId;
}

class EtsiPolicyConstraints {
  const EtsiPolicyConstraints({
    required this.mandatedSignedQProperties,
    required this.mandatedUnsignedQProperties,
    required this.signerAlgorithmConstraints,
    this.policyOid,
  });

  final String? policyOid;

  /// Values like `SigningCertificate`, `SignaturePolicyIdentifier`, etc.
  final Set<String> mandatedSignedQProperties;

  /// Values like `SignatureTimeStamp`, `CompleteCertificateRefs`, etc.
  final Set<String> mandatedUnsignedQProperties;

  final List<EtsiAlgorithmConstraint> signerAlgorithmConstraints;

  bool get requiresSignatureTimeStamp =>
      mandatedUnsignedQProperties.contains('SignatureTimeStamp');

  static EtsiPolicyConstraints parseXml(String xml) {
    final XmlDocument doc = XmlDocument.parse(xml);

    String? policyOid;
    final List<XmlElement> identifiers = doc
        .descendants
        .whereType<XmlElement>()
        .where((e) => e.name.local == 'Identifier')
        .toList(growable: false);
    for (final XmlElement id in identifiers) {
      final String text = id.innerText.trim();
      if (text.startsWith('urn:oid:')) {
        policyOid = text.substring('urn:oid:'.length);
        break;
      }
    }

    Set<String> readQProps(String containerLocalName) {
      final Set<String> out = <String>{};
      for (final XmlElement el
          in doc.descendants.whereType<XmlElement>().where((e) {
        return e.name.local == containerLocalName;
      })) {
        for (final XmlElement q
            in el.descendants.whereType<XmlElement>().where((e) {
          return e.name.local == 'QPropertyID';
        })) {
          final String v = q.innerText.trim();
          if (v.isNotEmpty) out.add(v);
        }
      }
      return out;
    }

    final Set<String> mandatedSigned = readQProps('MandatedSignedQProperties');
    final Set<String> mandatedUnsigned =
        readQProps('MandatedUnsignedQProperties');

    final List<EtsiAlgorithmConstraint> algConstraints = <EtsiAlgorithmConstraint>[];

    final Iterable<XmlElement> algAndLengthEls = doc
        .descendants
        .whereType<XmlElement>()
        .where((e) => e.name.local == 'AlgAndLength');

    for (final XmlElement algAndLength in algAndLengthEls) {
      String? algId;
      int? minKeyLen;

      for (final XmlElement child
          in algAndLength.children.whereType<XmlElement>()) {
        if (child.name.local == 'AlgId') {
          algId = child.innerText.trim();
        } else if (child.name.local == 'MinKeyLength') {
          final String raw = child.innerText.trim();
          final int? parsed = int.tryParse(raw);
          if (parsed != null) minKeyLen = parsed;
        }
      }

      if (algId == null || minKeyLen == null) continue;

      final String token = _normalizeAlgorithmToken(algId);
      if (token.isEmpty) continue;

      algConstraints.add(
        EtsiAlgorithmConstraint(
          algorithmToken: token,
          minKeyLength: minKeyLen,
          rawAlgId: algId,
        ),
      );
    }

    return EtsiPolicyConstraints(
      policyOid: policyOid,
      mandatedSignedQProperties: mandatedSigned,
      mandatedUnsignedQProperties: mandatedUnsigned,
      signerAlgorithmConstraints: algConstraints,
    );
  }

  static String _normalizeAlgorithmToken(String algId) {
    // Common XMLDSIG algorithm URIs look like:
    // - http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    // - http://www.w3.org/2001/04/xmldsig-more#rsa-sha512
    // - http://www.w3.org/2000/09/xmldsig#rsa-sha1
    final int hashIndex = algId.lastIndexOf('#');
    final String tail = hashIndex >= 0 ? algId.substring(hashIndex + 1) : algId;
    return tail.trim().toLowerCase();
  }
}
