# Draft review findings

These observations concern [revision 11](https://www.ietf.org/archive/id/draft-eastlake-rfc9231bis-xmlsec-uris-11.html). The canonicalization discrepancies are tracked in [repository issue #1](https://github.com/OR13/rfc9231bis-test-vectors/issues/1). They have not been submitted to the draft author or an IETF mailing list.

## C14N 1.1 no-comments identifier has an extra fragment delimiter

Sections 5.1 and 5.2 and Appendix A list:

```text
http://www.w3.org/2006/12/xml-c14n11#
```

[XML Signature 1.1, section 6.5.2](https://www.w3.org/TR/xmldsig-core1/#sec-CanonicalizationMethod) identifies the no-comments algorithm as:

```text
http://www.w3.org/2006/12/xml-c14n11
```

The `#WithComments` variant is correct with its fragment delimiter. SignXML rejects the trailing-`#` no-comments identifier; libxmlsec's registered C14N identifiers do not include it. The corpus verifies working XML signatures using the W3C identifier and regression-tests rejection/nonregistration of the draft spelling. This is a concrete URI interoperability issue, independent of whether the algorithms produce the same bytes.

Suggested correction: remove the trailing `#` from the no-comments C14N 1.1 entries, including the destination in Appendix A.

## Exclusive C14N index also includes a `/TR/` spelling

In addition to the correct `http://www.w3.org/2001/10/xml-exc-c14n#`, the indexes include `http://www.w3.org/TR/2001/10/xml-exc-c14n#` (and, in section 5.2, its WithComments variant). [XML Signature 1.1 section 6.5.3](https://www.w3.org/TR/xmldsig-core1/#sec-CanonicalizationMethod) uses the form without `/TR/`. The no-comments `/TR/` form is rejected by SignXML and absent from libxmlsec's canonicalization identifier set. Review whether those extra index entries should be removed or explicitly marked incorrect.

## Context is application policy as well as signed data

Section 3.3.17 requires the verifier to enforce an application-specified context. Merely verifying against whatever context the document carries is insufficient. The local adapter checks policy before invoking OpenSSL, and the corpus includes mismatched and absent application contexts. The 255-byte bound applies to decoded bytes, not base64 text length. Tests follow the draft's nonempty-context requirement for `eddsa-ed25519ctx`.

The 2026 XML URI namespace and context element are not passed to OpenSSL; the adapter maps them explicitly to the primitive and byte-valued context. Successful OpenSSL verification therefore demonstrates primitive interoperability, not native XML support.

## Encoding distinctions exercised

- ECDSA XML signatures are fixed-width r || s; most OpenSSL interfaces expect DER. The verifier converts explicitly, including 66-byte P-521 components.
- ML-DSA and SLH-DSA fixtures sign messages directly with context. Prehash variants are different operations.
- Same-size malformed ML-KEM ciphertexts produce implicit-rejection secrets; expecting an exception would be an incorrect negative test.
- CBC fixtures include non-PKCS#7 padding bytes, and prefix the IV. AEAD fixtures append the authentication tag and keep the nonce separate.
- HKDF uses a byte length, and includes the RFC 5869 case 1 known answer and the SHA-256 maximum expansion length.

The C14N 1.1 fixtures use simple trees where lxml's available canonical serializer agrees with the expected form. They do not establish general C14N 1.1 support for xml:base fixup or xml:id inheritance in SignXML/lxml; comprehensive canonicalization test suites remain separate work.
