import '../pdf/implementation/io/stream_reader.dart';
import '../pdf/implementation/security/digital_signature/asn1/asn1.dart';
import '../pdf/implementation/security/digital_signature/asn1/asn1_stream.dart';
import '../pdf/implementation/security/digital_signature/asn1/der.dart';
import '../pdf/implementation/security/digital_signature/x509/x509_certificates.dart';
import '../pdf/implementation/security/digital_signature/x509/x509_name.dart';
import '../pdf/implementation/security/digital_signature/x509/x509_utils.dart';
import 'certificate_serial.dart';

/// OIDs comuns no SubjectAltName (otherName) de certificados ICP-Brasil.
class IcpBrasilOtherNameOids {
  /// Pessoa Física: otherName contendo DOB(DDMMAAAA) + CPF + demais campos.
  static const String pfDadosTitular = '2.16.76.1.3.1';

  /// Pessoa Jurídica: nome do responsável.
  static const String pjNomeResponsavel = '2.16.76.1.3.2';

  /// Pessoa Jurídica: CNPJ do titular.
  static const String pjCnpjTitular = '2.16.76.1.3.3';

  /// Pessoa Jurídica: otherName contendo DOB(DDMMAAAA) + CPF do responsável + demais campos.
  static const String pjDadosResponsavel = '2.16.76.1.3.4';

  /// Pessoa Física: Título de Eleitor (NÃO é data de nascimento).
  static const String pfTituloEleitor = '2.16.76.1.3.5';

  /// Pessoa Física: CEI.
  static const String pfCei = '2.16.76.1.3.6';

  const IcpBrasilOtherNameOids._();
}

/// Informações extraídas do certificado do assinante.
class PdfSignerInfo {
  PdfSignerInfo({
    this.subject,
    this.issuer,
    this.commonName,
    this.issuerCommonName,
    this.serialNumberHex,
    this.serialNumberDecimal,
    this.issuerSerialNumberHex,
    this.issuerSerialNumberDecimal,
    this.cpf,
    this.dateOfBirth,
    this.certNotBefore,
    this.certNotAfter,
    this.otherNames = const <String, String>{},
  });

  /// DN do sujeito (assinante).
  final String? subject;

  /// DN do emissor.
  final String? issuer;

  /// CN do sujeito.
  final String? commonName;

  /// CN do emissor.
  final String? issuerCommonName;

  /// Número de série do certificado em hex.
  final String? serialNumberHex;

  /// Número de série do certificado em decimal (string).
  final String? serialNumberDecimal;

  /// Número de série do certificado emissor (hex canônico).
  final String? issuerSerialNumberHex;

  /// Número de série do certificado emissor (decimal canônico).
  final String? issuerSerialNumberDecimal;

  /// CPF (apenas dígitos), se presente.
  final String? cpf;

  /// Data de nascimento, se presente e parseável.
  final DateTime? dateOfBirth;

  /// Início da validade do certificado do signatário (notBefore).
  final DateTime? certNotBefore;

  /// Fim da validade do certificado do signatário (notAfter).
  final DateTime? certNotAfter;

  /// OtherNames completos extraídos do SubjectAltName (oid -> valor).
  final Map<String, String> otherNames;

  Map<String, dynamic> toMap() => <String, dynamic>{
        'subject': subject,
        'issuer': issuer,
        'common_name': commonName,
        'issuer_common_name': issuerCommonName,
        'serial_number_hex': serialNumberHex,
        'serial_number_decimal': serialNumberDecimal,
        'issuer_serial_number_hex': issuerSerialNumberHex,
        'issuer_serial_number_decimal': issuerSerialNumberDecimal,
        'cpf': cpf,
        'date_of_birth': dateOfBirth?.toIso8601String(),
        'cert_not_before': certNotBefore?.toIso8601String(),
        'cert_not_after': certNotAfter?.toIso8601String(),
        'other_names': otherNames,
      };

  static PdfSignerInfo? fromCertificatesPem(List<String> certsPem) {
    if (certsPem.isEmpty) return null;
    try {
      final X509Certificate cert =
          X509Utils.parsePemCertificate(certsPem.first);
      final String? subject = cert.c?.subject?.toString();
      final String? issuer = cert.c?.issuer?.toString();
      final BigInt? serial = cert.c?.serialNumber?.value;
      CertificateSerial? serialVo;
      if (serial != null) {
        serialVo = CertificateSerial.fromDecimal(serial.toString());
      }

      CertificateSerial? issuerSerialVo;
      if (certsPem.length > 1) {
        try {
          final issuerCert = _findIssuerCertificate(certsPem, cert);
          final BigInt? issuerSerial = issuerCert?.c?.serialNumber?.value;
          if (issuerSerial != null) {
            issuerSerialVo =
                CertificateSerial.fromDecimal(issuerSerial.toString());
          }
        } catch (_) {
          // Keep signer info partial when issuer certificate is unavailable.
        }
      }

      final Map<String, String> otherNames = _extractOtherNames(cert)
          .fold<Map<String, String>>(<String, String>{}, (map, entry) {
        map[entry.oid] = entry.value;
        return map;
      });

      final String? cpf = _extractCpf(cert, otherNames);
      final DateTime? dob = _extractDateOfBirth(otherNames);
      final DateTime? notBefore = cert.c?.startDate?.toDateTime();
      final DateTime? notAfter = cert.c?.endDate?.toDateTime();

      return PdfSignerInfo(
        subject: subject,
        issuer: issuer,
        commonName: _extractCommonName(cert.c?.subject),
        issuerCommonName: _extractCommonName(cert.c?.issuer),
        serialNumberHex: serialVo?.hex,
        serialNumberDecimal: serialVo?.decimal,
        issuerSerialNumberHex: issuerSerialVo?.hex,
        issuerSerialNumberDecimal: issuerSerialVo?.decimal,
        cpf: cpf,
        dateOfBirth: dob,
        certNotBefore: notBefore,
        certNotAfter: notAfter,
        otherNames: otherNames,
      );
    } catch (_) {
      return null;
    }
  }
}

X509Certificate? _findIssuerCertificate(
  List<String> certsPem,
  X509Certificate signer,
) {
  final String? issuerDn = signer.c?.issuer?.toString();
  if (issuerDn == null || issuerDn.isEmpty) return null;
  for (int i = 1; i < certsPem.length; i++) {
    try {
      final cert = X509Utils.parsePemCertificate(certsPem[i]);
      final String? subjectDn = cert.c?.subject?.toString();
      if (subjectDn != null && subjectDn == issuerDn) {
        return cert;
      }
    } catch (_) {
      // ignore malformed issuer candidate
    }
  }
  return null;
}

class _OtherName {
  const _OtherName(this.oid, this.value);

  final String oid;
  final String value;
}

List<_OtherName> _extractOtherNames(X509Certificate cert) {
  final Asn1Octet? ext = cert.getExtension(DerObjectID('2.5.29.17'));
  if (ext == null) return const <_OtherName>[];

  final List<int>? extBytes = ext.getOctets();
  if (extBytes == null || extBytes.isEmpty) return const <_OtherName>[];

  final Asn1? asn1 = Asn1Stream(PdfStreamReader(extBytes)).readAsn1();
  final Asn1Sequence? seq = Asn1Sequence.getSequence(asn1);
  if (seq == null || seq.objects == null) return const <_OtherName>[];

  final List<_OtherName> out = <_OtherName>[];
  for (final dynamic obj in seq.objects!) {
    if (obj is! Asn1Tag) continue;
    if (obj.tagNumber != 0) continue; // otherName

    final Asn1Sequence? otherNameSeq = _coerceSequence(obj);
    if (otherNameSeq == null || otherNameSeq.objects == null) continue;
    if (otherNameSeq.objects!.length < 2) continue;

    final dynamic oidObj = otherNameSeq.objects!.first;
    final dynamic valueObj = otherNameSeq.objects![1];
    if (oidObj is! DerObjectID) continue;

    final String? value = _extractOtherNameValue(valueObj);
    if (value == null || value.isEmpty) continue;
    out.add(_OtherName(oidObj.id ?? '', value));
  }

  return out;
}

Asn1Sequence? _coerceSequence(dynamic obj) {
  if (obj is Asn1Sequence) return obj;
  if (obj is Asn1Tag) {
    final dynamic inner = obj.getObject();
    if (inner is Asn1Sequence) return inner;
    return Asn1Sequence.getSequence(inner);
  }
  return Asn1Sequence.getSequence(obj);
}

String? _extractOtherNameValue(dynamic valueObj) {
  if (valueObj is Asn1Tag) {
    final dynamic inner = valueObj.getObject();
    return _extractOtherNameValue(inner);
  }

  if (valueObj is DerString) {
    return valueObj.getString();
  }

  if (valueObj is Asn1Octet) {
    final List<int>? octets = valueObj.getOctets();
    if (octets == null || octets.isEmpty) return null;
    try {
      final Asn1? parsed = Asn1Stream(PdfStreamReader(octets)).readAsn1();
      final String? parsedValue = _extractOtherNameValue(parsed);
      if (parsedValue != null && parsedValue.isNotEmpty) {
        return parsedValue;
      }
    } catch (_) {}
    return _bytesToPrintable(octets);
  }

  if (valueObj is Asn1Sequence && valueObj.objects != null) {
    for (final dynamic item in valueObj.objects!) {
      final String? str = _extractOtherNameValue(item);
      if (str != null && str.isNotEmpty) return str;
    }
  }

  if (valueObj is DerObjectID) {
    return valueObj.id;
  }

  try {
    return valueObj?.toString();
  } catch (_) {
    return null;
  }
}

String _bytesToPrintable(List<int> bytes) {
  final StringBuffer buffer = StringBuffer();
  for (final int b in bytes) {
    if (b >= 32 && b <= 126) {
      buffer.writeCharCode(b);
    } else {
      buffer.write('.');
    }
  }
  return buffer.toString();
}

String? _extractCommonName(X509Name? name) {
  if (name == null) return null;
  return name.getFirstValueByOid(X509Name.cn);
}

/// Extrai o valor de serialNumber do DN (OID 2.5.4.5) quando presente.
String? _extractSerialNumberDn(X509Name? name) {
  if (name == null) return null;
  return name.getFirstValueByOid(X509Name.serialNumber);
}

/// Remove todos os caracteres não numéricos.
String _onlyDigits(String s) => s.replaceAll(RegExp(r'\D'), '');

/// Tenta converter o formato DDMMAAAA em [DateTime].
DateTime? _tryParseDdMmAaaa(String digits) {
  if (digits.length < 8) return null;
  final String d = digits.substring(0, 2);
  final String m = digits.substring(2, 4);
  final String y = digits.substring(4, 8);

  final int? day = int.tryParse(d);
  final int? month = int.tryParse(m);
  final int? year = int.tryParse(y);

  if (day == null || month == null || year == null) return null;
  if (year < 1900 || year > 2100) return null;
  if (month < 1 || month > 12) return null;
  if (day < 1 || day > 31) return null;

  try {
    return DateTime(year, month, day);
  } catch (_) {
    return null;
  }
}

/// Extrai CPF e DOB do otherName 2.16.76.1.3.1 (ou 2.16.76.1.3.4).
///
/// O leiaute ICP-Brasil define:
/// - posições 1–8: data de nascimento (DDMMAAAA)
/// - posições 9–19: CPF (11 dígitos)
///
/// Campos podem estar preenchidos com zeros quando não informados.
({DateTime dob, String cpf})? _parseDobCpfFromIcpOtherName(String raw) {
  final String digits = _onlyDigits(raw);
  if (digits.length < 19) return null;

  final String dobPart = digits.substring(0, 8); // DDMMAAAA
  final String cpfPart = digits.substring(8, 19); // 11 dígitos

  // “00000000” é inválido (campo vazio preenchido com zeros)
  if (dobPart == '00000000') return null;

  final DateTime? dob = _tryParseDdMmAaaa(dobPart);
  if (dob == null) return null;

  return (dob: dob, cpf: cpfPart);
}

/// Extrai o CPF priorizando o DN (serialNumber) e, na sequência,
/// os otherName ICP-Brasil (PF/PJ responsável), com fallback no CN.
String? _extractCpf(X509Certificate cert, Map<String, String> otherNames) {
  // 1) Preferência: DN serialNumber (Res. 211/2024)
  final String? dnSerial = _extractSerialNumberDn(cert.c?.subject);
  if (dnSerial != null) {
    final String digits = _onlyDigits(dnSerial);
    if (digits.length == 11) return digits;
    final Match? m = RegExp(r'(\d{11})').firstMatch(digits);
    if (m != null) return m.group(1);
  }

  // 2) otherName PF: 2.16.76.1.3.1
  final String? rawPf = otherNames[IcpBrasilOtherNameOids.pfDadosTitular];
  final parsedPf = rawPf != null ? _parseDobCpfFromIcpOtherName(rawPf) : null;
  if (parsedPf != null) return parsedPf.cpf;

  // 3) otherName PJ responsável: 2.16.76.1.3.4 (se existir)
  final String? rawResp = otherNames[IcpBrasilOtherNameOids.pjDadosResponsavel];
  final parsedResp =
      rawResp != null ? _parseDobCpfFromIcpOtherName(rawResp) : null;
  if (parsedResp != null) return parsedResp.cpf;

  // 4) fallback: CN "NOME:CPF"
  final String? cn = _extractCommonName(cert.c?.subject);
  if (cn != null) {
    final Match? m = RegExp(r':(\d{11})\b').firstMatch(cn);
    if (m != null) return m.group(1);
  }

  return null;
}

/// Extrai a data de nascimento a partir do prefixo dos otherName ICP-Brasil
/// (PF ou responsável PJ). Não usa o OID 2.16.76.1.3.5 (título de eleitor).
DateTime? _extractDateOfBirth(Map<String, String> otherNames) {
  // 1) PF: 2.16.76.1.3.1 (DOB está no prefixo)
  final String? rawPf = otherNames[IcpBrasilOtherNameOids.pfDadosTitular];
  final parsedPf = rawPf != null ? _parseDobCpfFromIcpOtherName(rawPf) : null;
  if (parsedPf != null) return parsedPf.dob;

  // 2) PJ responsável: 2.16.76.1.3.4 (DOB do responsável)
  final String? rawResp = otherNames[IcpBrasilOtherNameOids.pjDadosResponsavel];
  final parsedResp =
      rawResp != null ? _parseDobCpfFromIcpOtherName(rawResp) : null;
  if (parsedResp != null) return parsedResp.dob;

  // NÃO usar 2.16.76.1.3.5 (título de eleitor) como DOB.
  return null;
}
