import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pdf/pdf_server.dart' as pdf;
import 'package:test/test.dart';

/// Assinatura `/adbe.pkcs7.detached` **sem atributos assinados** (RFC 5652
/// §5.4).
///
/// Sem `signedAttrs`, o assinante calcula o resumo do conteúdo — aqui, os bytes
/// do ByteRange — e a assinatura RSA cobre esse resumo diretamente; não há
/// `messageDigest` nem conteúdo encapsulado. O validador só conhecia o caso com
/// atributos (compara com `messageDigest`) e o `/adbe.pkcs7.sha1` (conteúdo
/// encapsulado): neste terceiro caso comparava o resumo com um `messageDigest`
/// nulo e não tinha dado para conferir a assinatura, e reprovava como
/// "documento modificado após a assinatura" um PDF que o Validar ITI aprova.
///
/// O edital PE 121/2026 (e-CPF A3 da ICP-Brasil, SHA-1 + `rsaEncryption`) foi
/// recusado pelo SALI em 26/10/2026. Conferido com OpenSSL: o DigestInfo
/// recuperado da assinatura é SHA-1 `142dd987…16a9`, igual ao SHA-1 das
/// faixas do ByteRange.
void main() {
  const caminho =
      'test/assets/PE 121.2026 Edital para 16.11.2026_assinado_23102026055524.pdf';

  test('assinatura detached sem atributos assinados e valida e integra',
      () async {
    final arquivo = File(caminho);
    expect(arquivo.existsSync(), isTrue, reason: 'arquivo não encontrado');

    final relatorio = await pdf.PdfSignatureValidator()
        .validateAllSignatures(arquivo.readAsBytesSync());

    expect(relatorio.signatures, hasLength(1));
    final validacao = relatorio.signatures.single.validation;
    expect(validacao.cmsSignatureValid, isTrue,
        reason: 'a assinatura RSA cobre o SHA-1 das faixas do ByteRange');
    expect(validacao.byteRangeDigestOk, isTrue,
        reason: 'sem messageDigest, a integridade vem da própria assinatura');
    expect(validacao.documentIntact, isTrue);
    expect(validacao.coversWholeDocument, isTrue);
  });

  test('alterar um byte dentro do ByteRange reprova (sem falso integro)',
      () async {
    final bytes = File(caminho).readAsBytesSync();
    final adulterado = Uint8List.fromList(bytes);
    adulterado[10000] ^= 0xFF;

    final relatorio =
        await pdf.PdfSignatureValidator().validateAllSignatures(adulterado);

    expect(relatorio.signatures, isNotEmpty);
    final validacao = relatorio.signatures.first.validation;
    expect(validacao.cmsSignatureValid, isFalse);
    expect(validacao.byteRangeDigestOk, isFalse);
    expect(validacao.documentIntact, isFalse);
  });
}
