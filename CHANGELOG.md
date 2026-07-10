# Changelog

## 31.1.22

- Fix validation of legacy PDF signatures using `/adbe.pkcs7.sha1`
  (ISO 32000-1 §12.8.3.3). These signatures are encapsulated, not detached: the
  PKCS#7 `eContent` is the SHA-1 digest of the signed ByteRange. The validator
  previously compared `digest(ByteRange)` directly against the (absent)
  `messageDigest`, so legitimate ICP-Brasil documents were reported with an
  invalid CMS signature and a broken ByteRange digest. The CMS parser now
  captures the encapsulated content and document integrity is verified through
  both required links: `hash(ByteRange) == eContent` and, when signed attributes
  are present, `messageDigest == hash(eContent)`. Signatures without signed
  attributes are verified directly over the encapsulated content. This fixes a
  false "tampered/invalid" result without allowing a document tampered together
  with its `eContent` to pass as intact.
- Add regression tests covering the real `/adbe.pkcs7.sha1` corpus samples and a
  tampering case that must break integrity.
