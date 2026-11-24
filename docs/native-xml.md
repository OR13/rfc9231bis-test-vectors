# Native XML signature interoperability for PQ algorithms

**Confirmed with unmodified upstream libxmlsec**, not just a hand-written canonicalization/signature adapter. The tested source is [commit eb3cd78a4731aaff7b69818d212071a6fd1d75fd](https://github.com/lsh123/xmlsec/commit/eb3cd78a4731aaff7b69818d212071a6fd1d75fd), which identifies itself as **xmlsec1 1.3.14 (openssl)**. It is a development revision, built with experimental ML-DSA and SLH-DSA options against OpenSSL 3.6.4. No upstream source patches or custom algorithm registrations were used.

The [machine-readable results](native-xml-interoperability.json) distinguish successful interoperability, unsupported transforms, and an actual verification failure.

| Family | Parameter sets | Empty + nonempty context cases | Native result |
| --- | --- | --- | --- |
| ML-DSA | 44, 65, 87 | 6 | Bidirectional interoperability confirmed |
| SLH-DSA / SHA2 | 128s, 128f, 192s, 192f, 256s, 256f | 12 | Bidirectional interoperability confirmed |
| SLH-DSA / SHAKE | 128s, 128f, 192s, 192f, 256s, 256f | 12 | Unsupported in this libxmlsec build; transforms absent |
| EdDSA controls | Ed25519, Ed25519ctx, Ed25519ph, Ed448, Ed448ph | 8 total fixture cases | 7 interoperate; Ed448 with nonempty context fails |

Thus **18 PQ cases across 9 signature URIs** interoperate natively, with no PQ verification failures among supported transforms. Including EdDSA controls gives **25 interoperable / 12 unsupported / 1 failed** among 38 extended XML fixtures. These are signature tests; ML-KEM and other KEMs remain separate encryption/key-establishment work.

## What the test proves

1. Our existing PyCryptodome-generated XML signatures are presented to the real libxmlsec CLI. It resolves the XML signature algorithm URI, parses SignatureContext, resolves the payload reference, applies canonicalization, checks its digest, and verifies the signature using its OpenSSL backend.
2. The CLI rejects mutations to the payload and SignatureValue, and mutations to SignatureContext when present.
3. The CLI re-signs the XML using the test private key. These newly produced signatures are verified by libxmlsec, **PyCryptodome**, and OpenSSL. The fixed-profile adapter also checks the XML structure and reference digest on the independent path.
4. Native-generated reverse-direction fixtures are saved in [vectors/libxmlsec](../vectors/libxmlsec). They can be independently verified even without rebuilding the native CLI.

The only addition to the original forward XML fixture is `ds:KeyInfo/ds:KeyName` with value `fixture-key`, outside `SignedInfo`. libxmlsec's CLI uses this to select the explicitly supplied trusted test key. The harness checks byte-for-byte equality of canonicalized SignedInfo before and after this addition. It does **not** rewrite algorithm URIs, re-sign the input to make it pass, disable reference checks, or enable lax key search. Key trust is supplied out of band; X.509 trust-chain interoperability is not tested.

Application-specified context policy remains the caller's responsibility. Successful native verification demonstrates the context in the document is cryptographically processed for the passing cases. The independent adapter additionally enforces the expected application context; this does not establish that libxmlsec's CLI has an application-context policy option.

## Reproduce

Requires the existing Python environment, a C toolchain, Autoconf/Automake/Libtool, pkg-config, libxml2 development files, and OpenSSL 3.6+. Existing Homebrew dependencies were used for the recorded build.

```sh
uv sync --locked
uv run python scripts/build_xmlsec.py
uv run python -m xmlsec_vectors.native_xml
uv run pytest -q -m native_xml
# Full corpus, including stored reverse-direction fixtures:
uv run python -m xmlsec_vectors.report
```

The build script checks out the pinned source under ignored `.interop/`, builds out of tree, and enables only the needed PQ signature features with `--enable-ml-dsa --enable-slh-dsa`. It refuses to silently change an existing checkout at a different commit or build modified tracked source. `OPENSSL_PREFIX` can select a different OpenSSL installation; otherwise pkg-config selects it. `XMLSEC1` can select a separately built CLI for the interoperability harness. A substituted build should be separately identified; the recorded result is for the pinned build above.

The pinned upstream source has a missing end-of-file newline in `apps/unit_tests/list_unit_tests.c`. On Clang, the build script passes `-Wno-error=newline-eof` to make so this formatting warning does not block compilation. No source fix is applied. The script also runs upstream's focused `make check-dsig` test for ML-DSA-44 with SignatureContext; verification of its existing fixture, signing, and verification of its new signature all passed (**3 checks, no skips**).

Optional native tests are skipped when the CLI is absent. Stored reverse-direction fixture verification still runs. The Ed448 nonempty-context failure is a strict expected failure for this revision: a future fix will cause XPASS and require the expectation/documentation to be updated. Unsupported SHAKE transforms remain explicit report entries, not successful tests.

The audit command deliberately reports all 38 outcomes, including known gaps; its successful process exit means the audit completed, not that every algorithm interoperates. For regression gating, use the tests, which enumerate the expected passing cases independently of the report.

## Released-library compatibility and limitations

- **python-xmlsec 1.3.18 / libxmlsec 1.3.13 wheel:** all 30 PQ fixtures fail at key loading in the installed build. Four empty-context EdDSA controls pass; other context-bearing controls do not. This is not a drop-in released-wheel PQ solution.
- **libxmlsec 1.3.13 source:** PQ algorithms exist behind experimental build options, but [its URI constants](https://github.com/lsh123/xmlsec/blob/1.3.13/src/strings.c) use the older `http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#` namespace. This source inspection does not establish interoperability with the draft's 2026 URIs. The development revision uses those draft URIs directly.
- **SignXML 5.3.1:** its registered `SignatureMethod` enum has no ML-DSA or SLH-DSA identifiers. The classical interoperability tests still apply, but native PQ interoperability with SignXML is not established.
- **Santuario/Bouncy Castle:** useful next independent XML-stack target; not executed here. There is no Java runtime installed in this environment. The results on this page concern libxmlsec. Subsequent [additional implementation tests](additional-implementations.md) establish a second independent XML stack with context support and a third stack for empty-context cases.

## Additional Ed448 context finding

The pinned libxmlsec revision verifies the empty-context Ed448 fixture but fails the corresponding nonempty-context fixture that already passes PyCryptodome/OpenSSL checks. Source inspection shows the Ed448 transform uses the standard signature registration macro, whereas Ed25519ctx, Ed25519ph, and Ed448ph register a node-reading callback for SignatureContext. This is consistent with the observed failure; the harness preserves the actual failure rather than classifying it as an unsupported URI. It has not been reported upstream by this task.

The source registrations for ML-DSA and SHA2-based SLH-DSA do have context-reading callbacks. Positive nonempty-context cases and reverse signing are therefore particularly useful interoperability evidence for those new PQ algorithms.
