# PQ release checks

The release-hardening work adds 75 positive signed XML fixtures across every ML-DSA and SLH-DSA parameter set. Each parameter set has explicit empty context, binary context (including NUL and non-UTF-8 octets), a 255-byte context, wrapped SignatureValue, and a wrapped DigestValue that was signed with that whitespace present. The original fixtures are retained.

The local adapter decodes only XML whitespace in base64Binary fields without rewriting SignedInfo. Native reverse verification consumes line wrapping directly; it no longer normalizes SignatureValue in the XML before verification. Negative decoder tests reject non-XML whitespace and punctuation.

Every positive fixture validates against the schemas and verifies with PyCryptodome and OpenSSL. The 45 cases supported by the pinned native libxmlsec build also run the full forward/tamper/reverse harness. SHAKE-based SLH-DSA remains explicitly outside that native implementation's capability.

Fifteen stored negative XML fixtures contain *valid SHA-512 prehash signatures*, checked under their proper prehash operation, which both PyCryptodome and OpenSSL reject under the pure XML signature operation. Additional tests for each of the 15 parameter sets reject a different key of the same parameter set, a key of another parameter set, a truncated signature, and an extended signature. The wrong-key public material and prehash identification are recorded in the boundary manifest. Wrong-key and length mutations are constructed from stored fixtures at test time.

Artifacts: [boundary manifest](../vectors/pq-boundaries.json), [generator](../xmlsec_vectors/pq_boundaries.py), [tests](../tests/test_pq_boundaries.py).

## Publication gate

```sh
uv sync --locked
uv run python scripts/build_xmlsec.py
uv run python -m xmlsec_vectors.release_check
```

Unlike the developer test command, this gate requires the pinned native CLI and checks source revision/provenance. It runs the full suite, requires 73 native interoperability cases (25 original, 3 classical controls, 45 new boundary cases), and rejects unexpected skips. The only permitted exceptions are the explicit MD2 capability skip and an *executed* Ed448-context expected failure; skipping the latter because the executable is missing is a failure. Strict XPASS remains a failure requiring review.

The gate also audits the original 38 extended fixtures and compares each outcome against the pinned expectation: 25 interoperable, 12 unsupported SHAKE cases, one Ed448-context failure. Changed outcomes require review. The audit uses `--no-store` so the gate does not regenerate checked-in reverse signatures. A successful gate writes [release-verification.json](release-verification.json), including fixture/schema SHA-256 hashes. This is an executed interoperability gate, not a cryptographic validation certification.

## Remaining scope limits

This release covers the fixed XML signature profile. It does not claim complete draft coverage, a general XMLDSIG security audit, PQ X.509 trust-chain interoperability, or complete XML Encryption/KEM interoperability. XMSS/XMSSMT, HSS/LMS, FrodoKEM/eFrodoKEM and X-Wing remain explicit inventory gaps. See [additional implementations](additional-implementations.md) for the new independent XML stack results and remaining context/algorithm limitations.
