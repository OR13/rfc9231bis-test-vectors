# RFC 9231bis XML Security URI test vectors

Test vectors and executable interoperability checks for [draft-eastlake-rfc9231bis-xmlsec-uris-11](https://www.ietf.org/archive/id/draft-eastlake-rfc9231bis-xmlsec-uris-11.html), dated November 19, 2026.

This corpus helps implementers distinguish XML fixture and algorithm-binding problems from cryptographic verification failures. It includes classical controls built from the same XML template as the post-quantum signatures, independent primitive verification, and bidirectional tests against existing XML signature libraries.

**Status:** experimental, pinned to draft revision 11. This is not complete draft conformance or cryptographic certification. **All included private keys, seeds, and randomness are public test material. Never use them to protect real data.**

## What is included

| Corpus | Coverage |
| --- | --- |
| 203 primitive vectors | 85 algorithm URIs, including all 3 ML-DSA, all 12 SLH-DSA, all 3 ML-KEM parameter sets, and 5 EdDSA variants |
| 24 classical XML signatures | RSA PKCS#1 v1.5, RSA-PSS, ECDSA, SHA-2/SHA-3 combinations, and canonicalization controls |
| 38 extended XML signatures | 30 ML-DSA/SLH-DSA cases and 8 EdDSA cases |
| 75 additional PQ XML signatures | Explicit empty, binary, and 255-byte contexts; wrapped SignatureValue and correctly signed wrapped DigestValue |
| 15 prehash-negative XML signatures | Valid SHA-512 prehash signatures that must fail under the pure PQ signature operation |
| 3 matched classical controls | RSA-SHA256, ECDSA-P256-SHA256, and RSA-PSS-SHA256 using the PQ XML template |
| 18 context-policy cases | Presence, application policy, duplicate elements, invalid encoding, and length boundaries |
| 25 stored reverse signatures | Signatures produced by the pinned native libxmlsec build |

The suite also checks payload/signature tampering, wrong keys, wrong parameter sets, truncated/extended signatures, XML schemas, and failure stages. See [fixture assurance](docs/fixture-quality.md) and [PQ release checks](docs/pq-release-readiness.md).

## Use the vectors

You can consume the JSON and XML files without running the Python harness.

| Start here | Contents |
| --- | --- |
| [vectors/primitives.json](vectors/primitives.json) | Exact algorithm URIs, inputs, parameters, keys, and expected outputs |
| [vectors/xml-signatures.json](vectors/xml-signatures.json) | Classical XML fixtures, keys, and canonical SignedInfo bytes |
| [vectors/extended-xml-signatures.json](vectors/extended-xml-signatures.json) | PQ/EdDSA XML files linked to primitive keys and application contexts |
| [vectors/pq-boundaries.json](vectors/pq-boundaries.json) | Signed boundary fixtures and prehash-negative fixtures |
| [vectors/harness-controls.json](vectors/harness-controls.json) | Classical controls using the PQ template |
| [vectors/contexts.json](vectors/contexts.json) | Context-policy inputs and expected acceptance/rejection |
| [vectors/coverage.json](vectors/coverage.json) | URI inventory and explicit coverage gaps |

XML manifest `file` paths are relative to `vectors/`. Resolve `primitive_id` against `primitives.json` to obtain the key and algorithm parameters. The classical control manifest embeds its own primitive records. For XML signatures, recompute canonical SignedInfo from the document; `canonical_signed_info_base64` is an exported comparison value, not a substitute for processing the XML. `application_context_hex` is the verifier's expected context policy.

For example, locate an ML-DSA fixture and its public key:

```python
import json
from pathlib import Path

root = Path("vectors")
primitives = {v["id"]: v for v in json.loads((root / "primitives.json").read_text())["vectors"]}
fixtures = json.loads((root / "extended-xml-signatures.json").read_text())["vectors"]
fixture = next(v for v in fixtures if v["primitive_id"] == "ml-dsa-44-empty")
xml = (root / fixture["file"]).read_bytes()
public_key_pem = primitives[fixture["primitive_id"]]["public_key_pem"]
expected_context = bytes.fromhex(fixture["application_context_hex"])
```

Hex fields represent bytes. Base64 is standard base64, not base64url; XML base64 fields may contain XML whitespace. Primitive `message_hex` is the exact signed input and is not implicitly canonicalized. PQ signatures use the pure operation; prehash signatures are separate operations and are used here as negative cases.

Public PEM keys use SubjectPublicKeyInfo. Key trust is supplied out of band; these fixtures do not establish an XML KeyInfo or X.509 trust-chain profile. ECDSA signatures use fixed-width `r || s`, not ASN.1 DER. Fixed RSA-PSS URIs use MGF1 with the signature hash and a salt length equal to the digest size. Additional encoding details are in [the findings](docs/findings.md) and [OpenSSL verification notes](docs/openssl.md).

## Run the checks

Requires Python 3.13+, [uv](https://docs.astral.sh/uv/), and OpenSSL 3.6+ with the default and legacy providers. The recorded environment uses OpenSSL 3.6.4; `uv.lock` pins Python dependencies. The macOS system OpenSSL may not be suitable.

```sh
git clone https://github.com/OR13/rfc9231bis-test-vectors.git
cd rfc9231bis-test-vectors
uv sync --locked
# On macOS with Homebrew openssl@3:
export OPENSSL="$(brew --prefix openssl@3)/bin/openssl"
uv run pytest -q
```

This verifies checked-in fixtures without regenerating them. Native CLI tests are optional for development: without the pinned libxmlsec build, 74 native cases skip explicitly. Stored reverse signatures remain independently testable.

For the full publication check, install a C toolchain, Autoconf, Automake, Libtool, pkg-config, libxml2 development files, and OpenSSL development files, then run:

```sh
uv run python scripts/build_xmlsec.py
uv run python -m xmlsec_vectors.release_check
```

The build stays in ignored `.interop/` and does not install system-wide. `OPENSSL_PREFIX` can select a different OpenSSL installation; otherwise pkg-config selects it. For a nonstandard shared-library installation, set `OPENSSL_LIBCRYPTO` to the matching `libcrypto.3.dylib` or `libcrypto.so.3`.

The release gate requires the pinned native build, checks its provenance, requires 73 passing native cases, rejects unexpected skips, and checks every original interoperability outcome. It permits only the documented MD2 capability skip and an executed Ed448-context expected failure. It writes [release-verification.json](docs/release-verification.json), including fixture/schema SHA-256 hashes.

The recorded full suite has **944 passed, 1 skipped, and 1 expected failure**. [Environment and results](docs/verification.json).

## Confirmed interoperability

Counts refer to the fixture sets in each report; they overlap and should not be added together.

| Implementation | Executed result | Limitations |
| --- | --- | --- |
| OpenSSL 3.6.4 | 202/203 primitive vectors; classical XML crypto checks; PQ adapter and reverse-signature checks | MD2-PSS unavailable; OpenSSL itself does not process XML |
| SignXML 5.3.1 and python-xmlsec 1.3.18 / libxmlsec 1.3.13 | 24 classical XML signatures plus 3 matched controls | These released builds are not established PQ XML verifiers |
| Pinned libxmlsec 1.3.14 development build | 18 original PQ cases plus 45 PQ boundary cases; classical/EdDSA controls | Experimental PQ options; SLH-DSA-SHAKE unsupported; nonempty Ed448 context fails |
| Pinned structured-world/xml-sec | 74 bidirectional cases: 63 PQ, 8 EdDSA, 3 classical controls | SLH-DSA-SHAKE unsupported |
| Pinned Bergshamra | 36 bidirectional PQ cases | Draft nonempty contexts fail; SHAKE keys unsupported |

Bidirectional checks mean the library verifies our fixture and produces a new signature that is independently verified with PyCryptodome and OpenSSL. The harness also checks XML references and rejects tampering. The Rust stacks add independence from the libxml2/OpenSSL path, but share RustCrypto dependencies with each other.

Pinned revisions, commands, exact results, and implementation-specific adjustments are documented in [native libxmlsec interoperability](docs/native-xml.md) and [additional implementations](docs/additional-implementations.md). The latter also records evidence for Apache Santuario's open ML-DSA PR; it has not been cross-tested here.

```sh
uv run python scripts/build_other_xml.py xml-sec
uv run python -m xmlsec_vectors.rust_xml
uv run python scripts/build_other_xml.py bergshamra
uv run python -m xmlsec_vectors.bergshamra_xml
```

These audit commands preserve unsupported algorithms and failures in their reports. Successful audit completion does not mean every case interoperated.

## Coverage limits and known findings

- The inventory includes 200 URIs extracted from sections 3–4 plus baseline digests: 85 have primitive fixtures and 115 remain explicit gaps. It is not the complete section 5 registry.
- XMSS/XMSSMT, HSS/LMS, FrodoKEM/eFrodoKEM, and X-Wing remain uncovered. ML-KEM is tested at the primitive level, not as a complete XML Encryption exchange.
- All twelve SLH-DSA parameter sets have primitive and XML-adapter checks, but the tested native XML libraries do not support the SHAKE variants.
- The PQ XML profile is one same-document payload reference, exclusive canonicalization, and SHA-256 reference digest. Schema validation covers that profile. Arbitrary transforms, full parameterized PSS, comprehensive canonicalization edge cases, certificate trust, and wrapping-attack defenses are outside the claim.
- The draft's canonicalization URI discrepancies are tracked in [issue #1](https://github.com/OR13/rfc9231bis-test-vectors/issues/1). Tests use working W3C identifiers and record the discrepancies.
- A failed signature check can indicate wrong key/context/encoding or algorithm binding. Passing classical controls reduces harness uncertainty; it does not establish that every remaining failure is a cryptographic algorithm bug.

## Regeneration and provenance

Verification is the normal workflow. Regeneration intentionally replaces fixtures and should be followed by review of changed outputs:

```sh
uv run python -m xmlsec_vectors.generate
uv run python -m xmlsec_vectors.extended_xml
uv run python -m xmlsec_vectors.harness_controls
uv run python -m xmlsec_vectors.pq_boundaries
uv run python -m xmlsec_vectors.native_xml
uv run python -m xmlsec_vectors.report
uv run python -m xmlsec_vectors.release_check
```

Primitive and extended XML generation use labeled deterministic public test randomness. SignXML's classical ECDSA/PSS signatures and native reverse signatures can change on regeneration. ML-KEM generation uses the pinned PyCryptodome internal `_encaps(coins)` hook; review it when updating dependencies. Re-run alternative implementation audits after changing fixtures.

The original [IETF draft](references/xmlsec-draft-11.txt) and [W3C XMLDSIG schema](schemas/xmldsig-core-schema.xsd) retain their copyright and license notices. Schema provenance is recorded in [schemas/provenance.json](schemas/provenance.json). Upstream code is built locally from pinned revisions; build directories, virtual environments, and caches are excluded from this repository.
