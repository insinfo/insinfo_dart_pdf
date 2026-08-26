Documentação da Biblioteca dart_pdf (v31.1.21)

1. Visão Geral
A dart_pdf é uma biblioteca escrita nativamente em Dart, destinada à criação, leitura, edição e proteção de arquivos PDF. Ela foi projetada para ser compatível com as plataformas Android, iOS e Web, conforme descrito em sua documentação.

A biblioteca é estruturada em torno de um núcleo que manipula a estrutura de documentos PDF e um conjunto de módulos para funcionalidades específicas, como gráficos, campos de formulário, anotações e segurança.

2. Classes Principais (Core)
Estas são as classes fundamentais para interagir com um documento PDF:

PdfDocument: Esta é a classe central da biblioteca. Ela representa o arquivo PDF em si. É usada para criar um novo documento, carregar um existente, gerenciar páginas e salvar o documento.

PdfPage: Representa uma única página dentro do PdfDocument. É nesta classe que o conteúdo é desenhado.

PdfGraphics: Atua como o "canvas" de uma PdfPage. Esta classe fornece os métodos necessários para desenhar texto, imagens, formas geométricas (linhas, retângulos, elipses) e outros elementos visuais na página.

PdfDocumentInformation: Gerencia os metadados do documento PDF, como Autor, Título, Assunto, Palavras-chave e Datas de Criação/Modificação.

3. Módulos e Funcionalidades
A biblioteca exporta uma vasta gama de classes, organizadas pelas seguintes funcionalidades:

3.1. Gráficos e Desenho (Drawing)
Este módulo é usado para todo o desenho visual nas páginas:

Fontes (Fonts):

PdfFont: Classe base para fontes.

PdfStandardFont: Permite o uso das 14 fontes padrão do PDF (ex: Helvetica, Times-Roman, Courier).

PdfTrueTypeFont: Permite incorporar fontes TrueType (TTF) personalizadas no documento.

Texto (Text):

PdfTextElement: Usado para desenhar blocos de texto com formatação e quebra de linha automáticas.

PdfLayoutResult: Retorna informações sobre o posicionamento do texto após o desenho, útil para layouts complexos.

Pincéis e Canetas (Brushes & Pens):

PdfBrush: Define como as formas são preenchidas (ex: PdfSolidBrush para cores sólidas).

PdfPen: Define como os contornos das formas são desenhados (cor, espessura, estilo da linha).

Cores (Color):

PdfColor: Representa cores, suportando modelos como RGB, CMYK e Grayscale.

PdfICCColorProfile: Para gerenciamento avançado de perfis de cor.

Imagens (Images):

PdfImage: Classe base para imagens.

PdfBitmap: Permite desenhar imagens bitmap (como JPEG ou PNG) no documento.

Formas (Shapes):

Métodos em PdfGraphics como drawLine, drawRectangle, drawEllipse, drawArc, drawPath.

3.2. Estrutura do Documento
Classes que gerenciam a organização e navegação do PDF:

PdfAttachment: Permite anexar arquivos (como XML, TXT ou outros PDFs) dentro do documento PDF principal.

PdfBookmark: Permite criar marcadores (bookmarks) que funcionam como um índice navegável, permitindo ao usuário saltar para páginas ou visualizações específicas.

PdfPageTemplate: Usado para criar cabeçalhos e rodapés que se repetem em várias páginas.

3.3. Campos de Formulário Interativos (Forms)
A biblioteca oferece suporte robusto para a criação de formulários PDF (AcroForms):

PdfField: Classe base para todos os campos de formulário.

Tipos de Campos:

PdfTextField: Campo para entrada de texto.

PdfCheckBoxField: Caixa de seleção (check-box).

PdfRadioButtonListField: Botões de opção (radio button).

PdfComboBoxField: Lista suspensa (dropdown).

PdfListBoxField: Caixa de listagem.

PdfSignatureField: Campo para assinatura digital.

Formatação e Validação:

PdfNumberField, PdfPercentageField, PdfTimeField: Campos de texto com formatação e validação específicas.

PdfFieldActions: Define ações a serem executadas em eventos de campo (ex: onFocus, onBlur).

3.4. Ações Interativas (Actions)
Define ações que podem ser acionadas por cliques em links, marcadores ou campos:

PdfAction: Classe base para ações.

PdfUriAction: Abre um link da web (URL).

PdfFormAction: Define ações específicas de formulário.

PdfSubmitAction: Envia os dados do formulário para um servidor web (suporta formatos FDF, PDF, XML).

PdfResetAction: Limpa (reseta) os campos do formulário.

PdfJavaScriptAction: Executa um script JavaScript dentro do leitor de PDF.

3.5. Anotações (Annotations)
Permite adicionar comentários e marcações sobre o conteúdo da página:

PdfAnnotation: Classe base para anotações.

Anotações de Link:

PdfLinkAnnotation: Define uma área clicável que leva a outra página, a um link externo (usando PdfUriAction), etc..

Anotações de Marcação de Texto (Markup):

PdfTextMarkupAnnotation: Usada para destacar (Highlight), sublinhar (Underline) ou tachar (StrikeOut) texto.

Outras Anotações:

PdfPopupAnnotation: Uma nota pop-up (como um "post-it").

PdfLineAnnotation, PdfRectangleAnnotation, PdfEllipseAnnotation: Anotações baseadas em formas geométricas.

3.6. Segurança e Assinaturas (Security)
Funcionalidades para proteger o documento:

Criptografia:

PdfSecurity: Classe usada para aplicar criptografia ao documento.

Define senhas (de usuário e de proprietário) e algoritmos de criptografia (ex: PdfEncryptionAlgorithm.rc4_128Bit).

PdfPermissions: Permite definir permissões granulares, como permitir/negar impressão, cópia de conteúdo, modificação, etc..

Assinaturas Digitais:

PdfSignatureField (mencionado nos formulários) e PdfSignatureDictionary: Indicam suporte para a aplicação e gerenciamento de assinaturas digitais.

4. Classes Internas (Helpers e Wrappers)
O arquivo de código revela um grande número de classes com sufixos Helper (ex: PdfDocumentHelper, PdfPageHelper, PdfGraphicsHelper) e interfaces como IPdfWrapper e IPdfWriter. Essas classes são destinadas ao uso interno da biblioteca, gerenciando o estado dos objetos, facilitando a serialização para o formato PDF e manipulando os elementos de baixo nível do PDF.