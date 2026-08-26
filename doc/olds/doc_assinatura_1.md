Esta biblioteca fornece funcionalidades robustas para assinar digitalmente documentos PDF e preparar assinaturas para validação de longo prazo (LTV).

Visão Geral da Assinatura Digital
O processo de assinatura envolve três classes principais:


PdfCertificate: Representa o certificado digital (geralmente um arquivo .pfx) que contém a chave privada usada para assinar. 


PdfSignature: Contém os detalhes da assinatura, como o certificado, o algoritmo de hash, o padrão criptográfico e informações opcionais (motivo, local, etc.). 


PdfSignatureField: É o campo de formulário visível no documento PDF onde a assinatura é aplicada. 


1. Aplicando uma Assinatura Digital
O fluxo padrão para assinar um documento é criar o certificado, definir os parâmetros da assinatura e, em seguida, adicionar um campo de assinatura ao documento com essa assinatura.

Passo 1: Carregar o Certificado (PdfCertificate)
Primeiro, você deve carregar seu certificado digital (arquivo .pfx) e sua senha.


Construtor: PdfCertificate(List<int> certificateBytes, String password) 

Uso:

Dart

// Supondo que 'pfxBytes' seja sua List<int> lida do arquivo .pfx
// e 'pfxPassword' seja a senha.
PdfCertificate certificate = PdfCertificate(pfxBytes, pfxPassword);
Passo 2: Configurar a Assinatura (PdfSignature)
Em seguida, configure o objeto PdfSignature. Este objeto define como o documento será assinado.


Construtor Principal: PdfSignature({ ... }) 

Parâmetros Chave:


certificate: A instância PdfCertificate que você acabou de criar. 

digestAlgorithm: O algoritmo de hash a ser usado. O padrão é DigestAlgorithm.sha256. 

cryptographicStandard: O padrão da assinatura. O padrão é CryptographicStandard.cms. A biblioteca também suporta CryptographicStandard.cades. 



timestampServer: (Opcional) Se você deseja incluir um carimbo de data/hora de uma Autoridade de Carimbo de Tempo (TSA). 

Uso: TimestampServer(Uri.parse('http://seu.servidor.tsa.com')) 



reason: (Opcional) O motivo da assinatura (ex: "Eu aprovo este documento"). 


locationInfo: (Opcional) O local onde a assinatura foi aplicada. 


contactInfo: (Opcional) Informações de contato do signatário. 

Uso:

Dart

PdfSignature signature = PdfSignature(
    certificate: certificate,
    digestAlgorithm: DigestAlgorithm.sha256,
    cryptographicStandard: CryptographicStandard.cms,
    reason: 'Eu sou o autor',
    locationInfo: 'Minha Cidade',
    timestampServer: TimestampServer(Uri.parse('http://timestamp.digicert.com'))
);
Passo 3: Adicionar o Campo de Assinatura (PdfSignatureField)
Finalmente, crie o PdfSignatureField em uma página e vincule-o ao seu objeto PdfSignature.


Construtor: PdfSignatureField(PdfPage page, String name, {Rect bounds, PdfSignature? signature, ...}) 

Uso:

Dart

// Crie um novo documento ou carregue um existente
PdfDocument document = PdfDocument();
PdfPage page = document.pages.add();

// Crie o campo de assinatura na página
PdfSignatureField signatureField = PdfSignatureField(
    page,
    'MinhaAssinatura',
    bounds: Rect.fromLTWH(50, 50, 200, 100),
    signature: signature // Vincula a assinatura configurada
);

// Adicione o campo ao formulário do documento
document.form.fields.add(signatureField);

// Salve o documento (o processo de assinatura ocorre durante o salvamento)
List<int> bytes = await document.save();
document.dispose();
2. Assinatura Externa (Hardware/Serviço Remoto)
A biblioteca também suporta cenários onde a chave privada não está acessível diretamente (por exemplo, em um HSM, token USB ou serviço de assinatura em nuvem) usando a interface IPdfExternalSigner.

Implemente IPdfExternalSigner: Crie sua própria classe que implementa IPdfExternalSigner.  Você precisará substituir o método sign (ou signSync). A biblioteca chamará este método com os bytes de hash do documento, e sua implementação deverá retorná-los assinados externamente.

Dart

class MeuSignerExterno implements IPdfExternalSigner {
    @override
    DigestAlgorithm get hashAlgorithm => DigestAlgorithm.sha256;

    @override
    Future<SignerResult?> sign(List<int> message) async {
        // 1. Envie 'message' (que são os bytes de hash) para sua API externa/HSM.
        // 2. Receba os bytes da assinatura criptografada.
        List<int> signedBytes = await seuServicoDeAssinaturaExterno(message);

        // 3. Retorne os bytes assinados.
        return SignerResult(signedBytes); [cite: 133322, 133349, 133374]
    }

    @override
    SignerResult? signSync(List<int> message) {
        // Implementação síncrona, se possível
        List<int> signedBytes = seuServicoDeAssinaturaExternoSync(message);
        return SignerResult(signedBytes); [cite: 133337, 133349, 133374]
    }
}
Use addExternalSigner: Em vez de passar um PdfCertificate para o construtor PdfSignature, use o método addExternalSigner.

Dart

PdfSignature signature = PdfSignature(
    digestAlgorithm: DigestAlgorithm.sha256,
    cryptographicStandard: CryptographicStandard.cms
);

// 'publicCertificatesData' é a cadeia de certificados públicos (List<List<int>>)
// necessária para incorporar no PDF.
signature.addExternalSigner(MeuSignerExterno(), publicCertificatesData); [cite: 135929]

// Continue criando o PdfSignatureField como no Passo 3 anterior.
3. Validação de Assinatura
A biblioteca foca principalmente na criação de assinaturas. A validação criptográfica completa (verificar se o hash do documento corresponde ao hash assinado) geralmente é feita por um leitor de PDF (como o Adobe Acrobat).

No entanto, a biblioteca fornece duas funcionalidades principais relacionadas à validação:

Verificação Básica (isSigned)
Você pode verificar se um campo de assinatura em um documento carregado contém dados de assinatura.


Propriedade: bool get isSigned  (em PdfSignatureField)

Uso:

Dart

PdfDocument document = PdfDocument(inputBytes: pdfBytes);
PdfSignatureField signatureField = document.form.fields[0] as PdfSignatureField;

if (signatureField.isSigned) { [cite: 156222]
    print('O campo está assinado.');
    // Nota: Isso não confirma que a assinatura é criptograficamente válida.
} else {
    print('O campo não está assinado.');
}
document.dispose();
Validação de Longo Prazo (LTV)
Para que uma assinatura seja considerada válida a longo prazo, o documento deve incorporar as informações de revogação (listas LCR/CRL ou respostas OCSP) no momento da assinatura.

A biblioteca pode fazer isso usando o método createLongTermValidity no objeto PdfSignature depois que o campo foi assinado (geralmente em um documento carregado).


Método: Future<bool> createLongTermValidity({RevocationType type, bool includePublicCertificates, ...}) 


RevocationType: 

RevocationType.ocsp: Usa o Protocolo de Status de Certificado Online (requer consulta de rede).

RevocationType.crl: Usa Listas de Certificados Revogados (requer consulta de rede).


RevocationType.ocspAndCrl: Tenta ambos. 


RevocationType.ocspOrCrl: Tenta OCSP e, se falhar, tenta CRL. 

Uso (Exemplo para habilitar LTV em um documento assinado):

Dart

// Carregar um documento JÁ assinado
PdfDocument document = PdfDocument(inputBytes: signedPdfBytes);
PdfSignatureField signatureField = document.form.fields[0] as PdfSignatureField;

if (signatureField.isSigned) {
    PdfSignature signature = signatureField.signature!;

    // Busca informações de OCSP/CRL e as incorpora no PDF
    bool ltvEnabled = await signature.createLongTermValidity( [cite: 135993]
        type: RevocationType.ocspAndCrl, [cite: 138033]
        includePublicCertificates: true
    );

    if (ltvEnabled) {
        print('Informações LTV incorporadas com sucesso.');
        // Salve o documento novamente com os dados LTV
        List<int> ltvBytes = await document.save();
    }
}
document.dispose();