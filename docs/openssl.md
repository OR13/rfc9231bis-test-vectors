# Explicit OpenSSL backend audit

The [machine-readable report](openssl-verification.json) records **202 passed / 1 unsupported** among all 203 checked-in primitive vectors, plus successful cryptographic checks of all 24 native XML fixtures. The full suite, now including native PQ XML interoperability and same-template classical controls, reports **944 passed, 1 skipped, 1 expected failure**. The MD2 skip belongs to this OpenSSL audit; the expected failure is the separately documented native Ed448/context case. No original primitive vector was regenerated or removed to obtain these results.

The only capability skip is the OpenSSL MD2-PSS check. The original PyCryptodome verification of that fixture still passes, but is not counted as an OpenSSL pass. The 115 URI inventory gaps have no primitive fixture and are outside these totals.

## What runs where

| Operation | Explicit audit path |
| --- | --- |
| Digests, HMAC, Poly1305, SipHash | `openssl dgst` / `openssl mac`; no Python hashlib inference |
| RSA v1.5/PSS, ECDSA, all EdDSA variants, ML-DSA, SLH-DSA | `openssl dgst` / `openssl pkeyutl`, including negative message/signature/context checks |
| X25519/X448 and ML-KEM | `openssl pkeyutl -derive` / `-decap`; low-order peer rejection and KEM implicit rejection checked |
| HKDF | `openssl kdf HKDF` |
| Camellia/SEED CBC | `openssl enc`, explicit XML padding and IV packaging |
| ChaCha20 and ChaCha20-Poly1305 | Direct OpenSSL EVP; AEAD checks include changed ciphertext, tag, nonce, and AAD |
| RC4 | Direct EVP with the **actual three-byte** `Key` fixture key, without padding it to the CLI's default key size |
| Camellia/SEED wrapping | OpenSSL `CRYPTO_128_wrap/unwrap` drives the wrapping mode; a small callback invokes OpenSSL EVP for each cipher block |
| XML reference hashes and signatures | XML processing/canonicalization in lxml, explicit digest and signature operations through the selected OpenSSL CLI |

The wrap check uses OpenSSL's native mode implementation, not the Python wrapping loop from generation. A separate RFC 3394 section 4.1 AES known-answer test validates the callback bridge and integrity rejection. OpenSSL's [wrap implementation](https://raw.githubusercontent.com/openssl/openssl/openssl-3.6.4/crypto/modes/wrap128.c) supports substitution of another 128-bit block cipher.

The [enc CLI does not support AEAD](https://docs.openssl.org/3.6/man1/openssl-enc/), so the audit calls EVP directly for ChaCha20-Poly1305. The Python bridge implements no cryptographic algorithm. It selects an isolated OpenSSL library context with default and legacy providers. Key encodings, ECDSA r||s-to-DER conversion, base64, HMAC truncation, and XML serialization remain adapter responsibilities.

## Backend identity

Recorded run:

- Explicit CLI and EVP library: **OpenSSL 3.6.4**, same release; the report includes the resolved `libcrypto` path.
- Original Python `cryptography` checks: **OpenSSL 4.0.3** bundled in its wheel. This is a separate OpenSSL build, not the CLI's library.
- libxmlsec 1.3.13 reports **`openssl`** through `xmlSecGetDefaultCrypto()`. The installed python-xmlsec wheel bundles its native dependencies; this default-backend probe does not establish its internal OpenSSL patch version.

The direct audit ensures the selected CLI/EVP pair performs the crypto regardless of the Python wheels' bundled versions. It does not make OpenSSL an XML parser/canonicalizer. The 38 extended XML fixtures continue using the fixed-profile adapter with OpenSSL signature verification and application-context enforcement in the main suite.

## MD2 limitation and strict mode

The installed CLI rejects even an empty MD2 digest with default and legacy providers loaded:

```sh
openssl dgst -provider default -provider legacy -md2 -binary </dev/null
```

The report preserves the probe's actual diagnostic. OpenSSL documents [MD2 as disabled by default](https://docs.openssl.org/3.6/man7/OSSL_PROVIDER-legacy/); `enable-md2` is a **build configuration** option, not an option that loading the legacy provider can supply to an already-built library. A custom MD2-enabled build was not installed during this audit. MD2-PSS remains unconfirmed with OpenSSL here.

```sh
uv run python -m xmlsec_vectors.openssl_verify
uv run python -m xmlsec_vectors.openssl_verify --require-all
```

Both commands attempt every primitive and the native XML crypto checks and write the report. The first permits explicitly reported unsupported MD2; the second exits **2** when any primitive is unsupported. Verification mismatches and unexpected errors fail either command instead of becoming skips.

For a different OpenSSL build, set `OPENSSL` and, if needed, `OPENSSL_LIBCRYPTO` to the matching executable and shared library. A CLI/library release mismatch is rejected. If MD2 becomes available, the audit attempts the MD2-PSS signature check rather than retaining a hardcoded skip. This bridge currently targets Unix-style shared library discovery; other layouts can supply the library path explicitly.

The draft canonicalization URI discrepancies are tracked in [issue #1](https://github.com/OR13/rfc9231bis-test-vectors/issues/1). They concern XML dispatch, not the OpenSSL cryptographic backend.
