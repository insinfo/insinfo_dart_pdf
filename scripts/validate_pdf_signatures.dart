import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf.dart' as pdf;
import 'package:dart_pdf/src/security/signer_classifier.dart';

Future<void> main(List<String> args) async {
  if (args.isEmpty || args.contains('--help') || args.contains('-h')) {
    _printUsage();
    exit(args.isEmpty ? 2 : 0);
  }

  final String inputPath = args.firstWhere((a) => !a.startsWith('-'), orElse: () => '');
  if (inputPath.isEmpty) {
    stderr.writeln('Missing input PDF path.');
    _printUsage();
    exit(2);
  }

  final bool useEmbeddedIcpBrasil = args.contains('--embedded-icpbrasil');
  final bool useEmbeddedGovBr = args.contains('--embedded-govbr');
  final bool fetchCrls = args.contains('--fetch-crls');
  final bool strictRevocation = args.contains('--strict-revocation');
  final bool strictPolicyDigest = args.contains('--strict-policy-digest');
  final bool noAutoTrust = args.contains('--no-auto-trust');

  final File f = File(inputPath);
  if (!f.existsSync()) {
    stderr.writeln('File not found: $inputPath');
    exit(2);
  }

  final Uint8List bytes = f.readAsBytesSync();

  // Auto-trust: when enabled (default), include embedded roots so chainTrusted
  // is evaluated without requiring the caller to pass PEM files.
  final bool effectiveEmbeddedIcpBrasil = noAutoTrust ? useEmbeddedIcpBrasil : true;
  final List<pdf.TrustedRootsProvider> extraProviders = <pdf.TrustedRootsProvider>[];
  if (!noAutoTrust) {
    // Add Gov.br roots (in addition to ICP-Brasil roots) so gov.br signatures
    // can be evaluated as trusted.
    extraProviders.add(pdf.GovBrProvider());
  } else if (useEmbeddedGovBr) {
    extraProviders.add(pdf.GovBrProvider());
  }

  final pdf.PdfSignatureValidator validator = pdf.PdfSignatureValidator();
  final pdf.PdfSignatureValidationReport report = await validator.validateAllSignatures(
    bytes,
    useEmbeddedIcpBrasil: effectiveEmbeddedIcpBrasil,
    trustedRootsProviders: extraProviders.isEmpty ? null : extraProviders,
    fetchCrls: fetchCrls,
    strictRevocation: strictRevocation,
    strictPolicyDigest: strictPolicyDigest,
  );

  final bool pdfIntegro = report.allDocumentsIntact;
  final bool allAssinaturasValidas = report.signatures.isNotEmpty &&
      report.signatures.every((s) =>
          s.validation.cmsSignatureValid == true &&
          s.validation.byteRangeDigestOk == true &&
          s.validation.documentIntact == true);

  stdout.writeln('PDF: ${f.path}');
  stdout.writeln('Assinaturas encontradas: ${report.signatures.length}');
  stdout.writeln('PDF íntegro (documentIntact em todas): ${pdfIntegro ? 'SIM' : 'NÃO'}');
  stdout.writeln('Assinaturas válidas (CMS+ByteRange+Intact): ${allAssinaturasValidas ? 'SIM' : 'NÃO'}');

  for (final pdf.PdfSignatureValidationItem item in report.signatures) {
    final SignerClassification signerInfo =
        classifySignerFromCertificatesPem(item.validation.certsPem);

    stdout.writeln('---');
    stdout.writeln('Campo: ${item.fieldName}');
    stdout.writeln('Cobre arquivo atual: ${item.coversCurrentFile ? 'SIM' : 'NÃO'}');
    stdout.writeln('Integridade: ${item.validation.documentIntact ? 'OK' : 'FALHOU'}');
    stdout.writeln('CMS: ${item.validation.cmsSignatureValid ? 'OK' : 'FALHOU'}');
    stdout.writeln('ByteRange digest: ${item.validation.byteRangeDigestOk ? 'OK' : 'FALHOU'}');

    stdout.writeln('Assinante (CN): ${signerInfo.commonName ?? 'desconhecido'}');
    stdout.writeln('Subject: ${signerInfo.subject ?? 'desconhecido'}');
    stdout.writeln('Issuer: ${signerInfo.issuer ?? 'desconhecido'}');
    stdout.writeln('Provedor (heurística): ${signerInfo.providerLabel}');

    if (item.chainTrusted != null) {
      stdout.writeln('Cadeia confiável: ${item.chainTrusted == true ? 'SIM' : 'NÃO'}');
      if (item.chainTrusted == false && item.chainErrors != null && item.chainErrors!.isNotEmpty) {
        stdout.writeln('Erros cadeia: ${item.chainErrors!.join('; ')}');
      }
    } else {
      stdout.writeln('Cadeia confiável: (não avaliado; nenhum root fornecido)');
    }

    stdout.writeln('Revogação: ${item.revocationStatus.status}${item.revocationStatus.details != null ? ' (${item.revocationStatus.details})' : ''}');

    if (item.policyStatus != null) {
      final ps = item.policyStatus!;
      stdout.writeln('Política: ${ps.valid ? 'OK' : 'FALHOU'}${ps.policyOid != null ? ' (${ps.policyOid})' : ''}');
      if (ps.error != null) stdout.writeln('Erro política: ${ps.error}');
      if (ps.warning != null) stdout.writeln('Aviso política: ${ps.warning}');
    }
  }
}

void _printUsage() {
  stdout.writeln('Uso: dart run scripts/validate_pdf_signatures.dart <arquivo.pdf> [opções]');
  stdout.writeln('');
  stdout.writeln('Opções:');
  stdout.writeln('  --no-auto-trust            Não carrega roots automaticamente (mantém comportamento antigo)');
  stdout.writeln('  --embedded-icpbrasil       Usa roots embutidas (ICP-Brasil/ITI/Serpro)');
  stdout.writeln('  --embedded-govbr           Usa roots embutidas do Gov.br');
  stdout.writeln('  --fetch-crls               Baixa CRL/OCSP via URLs (mais lento)');
  stdout.writeln('  --strict-revocation        Requer evidências válidas (assinatura+janela)');
  stdout.writeln('  --strict-policy-digest     Exige digest de SignaturePolicyId quando houver policyOid');
}

