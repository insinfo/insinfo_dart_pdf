# TODO

## Not worth implementing: EC keys with explicit curve parameters (ICP-Brasil roots v4 and v13)

ICP-Brasil roots v4 (2015-04-23 to 2035-04-23) and v13 (2025-02-14 to
2045-02-14) use an elliptic-curve key whose curve is written out in the
certificate (prime field, 512 bits, apparently brainpoolP512r1) instead of a
named-curve OID. RFC 5480 forbids that, and nobody verifies these chains:

- dart_pdf: `X509Certificate.getPublicKey` throws
  `UnsupportedError('Unsupported EC public key parameters (expected named curve OID)')`
  (`lib/src/pdf/implementation/security/digital_signature/x509/x509_certificates.dart`);
- OpenSSL 3: `error 94: Certificate public key has explicit ECC parameters`;
- Java: refuses the whole keystore (`Only named ECParameters supported`), which
  is why ITI leaves these roots out of its own JKS.

The only CAs under them belong to the Ministry of Foreign Affairs (AC MRE under
v4, AC MRE v1 under v13); no e-CPF/e-CNPJ CA of the market chains to them. A
PDF signed with an MRE certificate therefore shows an untrusted chain.

If it is ever needed: compare the explicit parameters (p, a, b, G, n, h) with
those of the known curves and treat a match as the corresponding named curve.

Not worth it: the defect is in the certificates, and MRE-signed documents are
very rare for the users of this library. Tested on 2026-10-28 with the
certificates of ITI's ICP-Brasil chain package.
