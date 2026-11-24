# Additional PQ XML implementations

Research and execution on 2026-11-24. Results below use original draft-11 algorithm URIs and SignatureContext elements; no URI aliases or context-element rewrites were made. Search indexes were stale for two projects, so conclusions use pinned repository source and actual runs.

| Implementation | Evidence and result |
| --- | --- |
| structured-world/xml-sec | **74 bidirectional cases pass**: 63 PQ (ML-DSA and SLH-DSA-SHA2, original and boundary cases), 8 EdDSA, and 3 classical controls. All 42 SLH-DSA-SHAKE cases report unsupported algorithm. |
| Bergshamra | **36 bidirectional PQ cases pass**: 9 parameter sets × absent context, explicit empty context, wrapped signature, wrapped digest. 27 nonempty-context cases fail verification. 42 SHAKE cases fail key loading. |
| Apache Santuario PR #651 | Concrete open implementation PR for ML-DSA-44/65/87, using draft namespace URIs. Source explicitly rejects SignatureContext, including explicit empty context. Candidate for absent-context ML-DSA cross-tests; not executed here. This is not released-library interoperability. |

## structured-world/xml-sec: independent XML stack with context support

Tested unmodified [commit 7d1795cd8a0747aac7cf224603d670502bc75935](https://github.com/structured-world/xml-sec/tree/7d1795cd8a0747aac7cf224603d670502bc75935), package 0.6.0, CLI built with `experimental-pq` and its default RustCrypto provider. Its [CLI documentation](https://github.com/structured-world/xml-sec/blob/7d1795cd8a0747aac7cf224603d670502bc75935/docs/cli.md) describes an independent pure-Rust implementation, not bindings to libxmlsec or OpenSSL. Its [signature documentation](https://github.com/structured-world/xml-sec/blob/7d1795cd8a0747aac7cf224603d670502bc75935/docs/xmldsig.md) identifies the current namespace and supports reading the context under SignatureMethod, as used by these fixtures.

The same native `exercise()` harness verifies original XML, rejects altered payload/signature/context, signs through the Rust CLI, self-verifies, and independently verifies the reverse signature with PyCryptodome/OpenSSL and local XML/reference checks. The CLI receives a KeyName outside SignedInfo, with canonical-byte equality asserted before verification.

One CLI compatibility adjustment is necessary: its help advertises `--enabled-reference-uris`, but execution rejects that option. The runner omits that option/value pair. Every supplied reference is still `#payload`; reference validation is not disabled, and payload-tamper rejection runs. No upstream source patch is used.

The upstream checkout did not contain Cargo.lock. The initially resolved lock is preserved as [references/xml-sec-Cargo.lock](../references/xml-sec-Cargo.lock), and the reproduction script builds with `--locked`. The report records its SHA-256. The project's maintained RustCrypto ML-DSA dependency patch is part of its upstream dependency selection, not a patch introduced by this corpus.

[Machine-readable results](rust-xml-interoperability.json) include every original extended fixture, all 75 signed boundary fixtures, and all three classical controls. This stack also passes the nonempty Ed448 control that fails in the pinned libxmlsec build. The result is for this source revision, not a blanket statement about published crates or all XML profiles.

## Bergshamra: working pure signatures, older context handling

Tested unmodified [commit 9fcc0c1e1cc0145fb0b8cf417aaa694a635f212c](https://github.com/kushaldas/bergshamra/tree/9fcc0c1e1cc0145fb0b8cf417aaa694a635f212c), package 0.12.0, release build with the default RustCrypto provider and checked-in Cargo.lock.

Its [algorithm identifiers](https://github.com/kushaldas/bergshamra/blob/9fcc0c1e1cc0145fb0b8cf417aaa694a635f212c/crates/bergshamra-core/src/algorithm.rs) recognize the draft ML-DSA and SHA2 SLH-DSA URIs. Its [verification code](https://github.com/kushaldas/bergshamra/blob/9fcc0c1e1cc0145fb0b8cf417aaa694a635f212c/crates/bergshamra-dsig/src/verify.rs) reads the older MLDSAContextString/SLHDSAContextString elements in the experimental aleksey namespace, rather than draft SignatureContext. That source behavior is consistent with all 27 nonempty-context verification failures; no claim of nonempty-context interoperability is made.

Passing cases verify unchanged input, reject payload/signature mutations, sign through the CLI, and independently verify reverse signatures with PyCryptodome/OpenSSL and the local XML/reference checks. Public keys are supplied explicitly with `--trusted-keys-only`. `Id` is recognized by default; adding a redundant `--id-attr Id` registration produced a duplicate-ID error and is not used.

[Machine-readable results](bergshamra-interoperability.json) preserve the 36 passes, 27 verification failures, and 42 unsupported key-format results separately. No URI/context rewriting is used to turn failures into successes.

## Apache Santuario: implementation evidence, not yet an executed cross-test

[PR #651](https://github.com/apache/santuario-xml-security-java/pull/651), checked at head `4dbc5b150b84a26fb462544bf0e0a93ea0c4d738`, is open and unmerged. Its changes register all three draft ML-DSA URIs and add DOM/JSR-105 and StAX tests, including wrong-key and signature-tamper rejection. The patch explicitly rejects SignatureContext rather than ignoring it because its selected JCA integration cannot pass that parameter. The next useful test is the three original absent-context ML-DSA XML fixtures; the current patch is not a candidate for our nonempty-context fixtures.

Related primary evidence: [SANTUARIO-634](https://issues.apache.org/jira/browse/SANTUARIO-634) and [ML-KEM PR #652](https://github.com/apache/santuario-xml-security-java/pull/652). These establish ongoing implementation work, not successful cross-verification of this corpus.

## Reproduce

```sh
uv run python scripts/build_other_xml.py bergshamra
uv run python -m xmlsec_vectors.bergshamra_xml
uv run python scripts/build_other_xml.py xml-sec
uv run python -m xmlsec_vectors.rust_xml
```

Builds are confined to ignored `.interop/` and do not install system-wide. Scripts refuse a different existing source revision or tracked-source changes. Audit commands record failures and unsupported cases; a successful audit process means the matrix was produced, not that every case passed.

The Rust implementations provide additional independence from the OpenSSL-backed path, although they share RustCrypto dependencies with each other. No native XML implementation tested here supports the SHAKE SLH-DSA fixtures; those remain independently verified at the primitive/adapter level. No upstream issues or PR comments were sent as part of this research.
