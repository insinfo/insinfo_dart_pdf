# TODO

## Do not implement: ICP-Brasil roots v4 and v13 (e-passport chain, not a PDF chain)

ICP-Brasil roots v4 (2015-04-23 to 2035-04-23) and v13 (2025-02-14 to
2045-02-14) have a single CA below them, the Ministry of Foreign Affairs CA
(AC MRE under v4, AC MRE v1 under v13), used exclusively to sign the chip of
Brazilian passports (eMRTD) and its own CRL (AC MRE CPS, item 1.4.1; ITI
Technical Note 10/2024). Its subjects are legal-entity electronic seals, not
people: Itamaraty staff sign PDFs with ordinary RSA e-CPF certificates under
roots v2/v5/v10. No PDF signature chains to these roots.

The key is an elliptic-curve key with the curve written out (512 bits,
apparently brainpoolP512r1). That is not a defect: the ICAO e-passport profile
(Doc 9303, Part 12) requires explicit domain parameters, while the PKIX
profile (RFC 5480) requires a named curve. General-purpose validators
therefore reject the chain:

- dart_pdf: `X509Certificate.getPublicKey` throws
  `UnsupportedError('Unsupported EC public key parameters (expected named curve OID)')`
  (`lib/src/pdf/implementation/security/digital_signature/x509/x509_certificates.dart`);
- OpenSSL 3: `error 94: Certificate public key has explicit ECC parameters`;
- Java (SunEC): refuses the whole keystore (`Only named ECParameters supported`),
  which is why ITI leaves these roots out of its JKS.

If it ever makes sense: compare the explicit parameters (p, a, b, G, n, h)
with those of the known curves and treat a match as the corresponding named
curve.

Do not implement: the chain signs passports, not documents. Tested on
2026-10-28 with the certificates of ITI's ICP-Brasil chain package.
