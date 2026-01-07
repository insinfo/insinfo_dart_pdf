O formato do certificado ICP-Brasil está disponível nas políticas das autoridades certificadoras autorizadas
pelo ICP-Brasil. Exemplo: https://repositorio.acdigital.com.br/docs/pc-a3-ac-digital-multipla.pdf

Ver item 7.1.2.3.a.

Para certificado CNPJ, o procedimento é parecido, só montar os campos de acordo com o item 7.1.2.3.b

```bash
openssl req -new -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 \
-subj '/C=BR/O=ICP-Brasil/OU=AC DIGITAL Múltipla G1/OU=33989214000191/OU=presencial/OU=Certificado PF A3/CN=Fulano de tal:58765136012' \
-addext subjectAltName=\
otherName:2.16.76.1.3.1\;UTF8:171219535876513601242586038731001002005784212000000SSPRS,\
otherName:2.16.76.1.3.6\;UTF8:253764977686,\
otherName:2.16.76.1.3.5\;UTF8:465555610469001047700000000000municipioRS
```

¿É realmente correto UTF8 para os otherNames? De DOC-ICP-04, Versão 7.2:

7.1.2.4 Os campos otherName definidos como obrigatórios pela ICP-Brasil devem estar de acordo
com as seguintes especificações:
a) O conjunto de informações definido em cada campo otherName deve ser
armazenado como uma cadeia de caracteres do tipo ASN.1 OCTET STRING ou
PRINTABLE STRING;

@weltonrodrigo
Author
weltonrodrigo
commented
on Sep 12, 2024
Você tem razão.

No entanto, como PRINTABLE STRING não consegue representar acentos e não pude encontrar na documentação qual character encoding usar com o OCTET STRING, talvez seja melhor usar uma string UTF8 num OCTET STRING, em vez de um UTF8String.

Espero que a especificação não exija ASCII num campo que leva nome de municípios brasileiros como o 2.16.76.1.3.5