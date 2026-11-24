"""Explicit OpenSSL-only cryptographic audit of existing fixtures.

No PyCryptodome/hashlib/cryptography verification fallback. XML canonicalization
and key/signature encoding are handled outside OpenSSL, which has no XML stack.
"""
import json
import tempfile
from pathlib import Path
from functools import lru_cache
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils, x25519, x448
from lxml import etree
from .common import ROOT, DS, C14N, openssl, un64, save
from .openssl_evp import evp, Rejected
from .verify import altered, require_rejection, verify_primitive


class UnsupportedOpenSSL(RuntimeError):
    pass


@lru_cache(maxsize=1)
def md2_support():
    result = openssl('dgst', '-provider', 'default', '-provider', 'legacy', '-md2', '-binary', data=b'', check=False)
    if result.returncode == 0:
        return True, ''
    error = result.stderr.decode().strip()
    if 'unsupported' not in error.lower():
        raise RuntimeError('Unexpected MD2 probe failure: ' + error)
    return False, error


def digest(name, message):
    return openssl('dgst', '-provider', 'default', '-provider', 'legacy', '-' + name, '-binary', data=message).stdout


def verify_signature(v):
    """The CLI performs hashing, padding, and signature verification."""
    if v['kind'] in ('pqsig', 'eddsa') or (v['kind'] == 'rsa' and v['hash'] != 'md2'):
        # These branches already invoke the explicit CLI for positive/negative cases.
        result = verify_primitive(v)
        assert result == 'OpenSSL CLI'
        return 'OpenSSL CLI signature verification'
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        key, sigfile, msgfile = [directory / n for n in ('pub.pem', 'sig', 'message')]
        key.write_text(v['public_key_pem'])
        signature = bytes.fromhex(v['signature_hex'])
        if v['kind'] == 'ecdsa':
            # ASN.1 encoding only; no cryptography signature verification occurs here.
            size = {'P-256':32, 'P-384':48, 'P-521':66}[v['curve']]
            assert len(signature) == size * 2
            signature = utils.encode_dss_signature(int.from_bytes(signature[:size], 'big'), int.from_bytes(signature[size:], 'big'))
        sigfile.write_bytes(signature)
        msgfile.write_bytes(bytes.fromhex(v['message_hex']))
        args = ['dgst', '-provider', 'default', '-provider', 'legacy', '-' + v['hash'], '-verify', key, '-signature', sigfile]
        if v['kind'] == 'rsa':
            args += ['-sigopt', 'rsa_padding_mode:pss', '-sigopt', f'rsa_pss_saltlen:{v["salt_bytes"]}']
        args.append(msgfile)
        openssl(*args)
        msgfile.write_bytes(altered(bytes.fromhex(v['message_hex'])))
        assert openssl(*args, check=False).returncode != 0
        msgfile.write_bytes(bytes.fromhex(v['message_hex']))
        sigfile.write_bytes(altered(signature))
        assert openssl(*args, check=False).returncode != 0
    return 'OpenSSL CLI signature verification'


def verify_openssl(v):
    raw = lambda field: bytes.fromhex(v[field])
    kind = v['kind']
    message = raw('message_hex') if 'message_hex' in v else None
    if kind == 'rsa' and v['hash'] == 'md2':
        available, reason = md2_support()
        if not available:
            raise UnsupportedOpenSSL('MD2 unavailable in the selected default/legacy providers: ' + reason)
    if kind in ('rsa', 'ecdsa', 'eddsa', 'pqsig'):
        return verify_signature(v)
    if kind == 'digest':
        assert digest(v['hash'], message) == raw('output_hex')
        return 'OpenSSL CLI digest'
    if kind == 'hmac':
        out = openssl('mac', '-digest', v['hash'], '-macopt', 'hexkey:' + v['key_hex'], '-binary', 'HMAC', data=message).stdout
        assert out[:v['output_bits']//8] == raw('output_hex')
        return 'OpenSSL CLI HMAC (output truncated by adapter)'
    if kind in ('poly1305', 'siphash'):
        options = ['-macopt', 'hexkey:' + v['key_hex']]
        if kind == 'siphash':
            options += ['-macopt', 'size:8', '-macopt', 'c-rounds:2', '-macopt', 'd-rounds:4']
        out = openssl('mac', *options, '-binary', kind.upper(), data=message).stdout
        assert out == raw('output_hex')
        return 'OpenSSL CLI MAC'
    if kind == 'kem':
        result = verify_primitive(v)
        assert result == 'OpenSSL CLI (including implicit rejection)'
        return result
    if kind == 'agreement':
        cls = x25519.X25519PublicKey if v['algorithm'] == 'x25519' else x448.X448PublicKey
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            private, public = directory/'key.pem', directory/'peer.pem'
            private.write_text(v['private_key_pem'])
            def peer(data):
                # Key encoding only; key agreement itself is the CLI pkeyutl operation.
                public.write_bytes(cls.from_public_bytes(data).public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            peer(raw('peer_public_key_hex'))
            args = ['pkeyutl', '-derive', '-inkey', private, '-peerkey', public]
            assert openssl(*args).stdout == raw('shared_secret_hex')
            peer(bytes(len(raw('peer_public_key_hex'))))
            assert openssl(*args, check=False).returncode != 0
        return 'OpenSSL CLI key agreement'
    if kind == 'hkdf':
        out = openssl('kdf', '-keylen', v['length_bytes'], '-kdfopt', 'digest:SHA256',
                      '-kdfopt', 'hexkey:' + v['ikm_hex'], '-kdfopt', 'hexsalt:' + v['salt_hex'],
                      '-kdfopt', 'hexinfo:' + v['info_hex'], '-binary', 'HKDF').stdout
        assert out == raw('output_hex')
        return 'OpenSSL CLI HKDF'
    if kind == 'chacha20':
        iv = v['counter'].to_bytes(4, 'little') + raw('nonce_hex')
        out = evp().crypt('CHACHA20', raw('key_hex'), message, iv)
        assert out == raw('output_hex')
        assert evp().crypt('CHACHA20', raw('key_hex'), out, iv, decrypt=True) == message
        return 'OpenSSL EVP ChaCha20'
    if kind == 'aead':
        native = evp()
        key, nonce, aad = raw('key_hex'), raw('nonce_hex'), raw('aad_hex')
        ct, tag = native.crypt('CHACHA20-POLY1305', key, message, nonce, aad=aad)
        assert ct == raw('ciphertext_hex') and tag == raw('tag_hex')
        assert ct + tag == un64(v['cipher_value_base64'])
        assert native.crypt('CHACHA20-POLY1305', key, ct, nonce, aad=aad, tag=tag, decrypt=True) == message
        for ciphertext, iv, auth, mac in ((altered(ct), nonce, aad, tag), (ct, nonce, aad, altered(tag)),
                                          (ct, altered(nonce), aad, tag), (ct, nonce, altered(aad), tag)):
            require_rejection(lambda: native.crypt('CHACHA20-POLY1305', key, ciphertext, iv, aad=auth, tag=mac, decrypt=True), (Rejected,))
        return 'OpenSSL EVP ChaCha20-Poly1305'
    if kind == 'cbc':
        return verify_primitive(v) # already explicit CLI encrypt/decrypt, no fallback
    if kind == 'arcfour':
        native = evp()
        assert native.crypt('RC4', raw('key_hex'), message) == raw('output_hex')
        assert native.crypt('RC4', raw('key_hex'), raw('output_hex'), decrypt=True) == message
        return 'OpenSSL EVP RC4 with exact variable key length'
    if kind == 'wrap':
        name = 'SEED-ECB' if v['cipher'] == 'seed' else f'CAMELLIA-{len(raw("key_hex"))*8}-ECB'
        native = evp()
        key, wrapped = raw('key_hex'), raw('output_hex')
        assert native.keywrap(name, key, message) == wrapped
        assert native.keywrap(name, key, wrapped, decrypt=True) == message
        for bad in (altered(wrapped), wrapped[:-1]):
            require_rejection(lambda: native.keywrap(name, key, bad, decrypt=True), (Rejected,))
        require_rejection(lambda: native.keywrap(name, altered(key), wrapped, decrypt=True), (Rejected,))
        return 'OpenSSL CRYPTO_128_wrap/unwrap + EVP block cipher'
    raise AssertionError('No explicit OpenSSL verifier for ' + kind)


def verify_xml_crypto(fixture):
    """Check native XML fixture's digest and signature through the selected CLI.

    This supports only the checked-in simple one-reference profile, not general XML.
    Canonicalization stays in lxml. Native SignXML/libxmlsec tests run separately.
    """
    root = etree.parse(str(ROOT/'vectors'/fixture['file'])).getroot()
    si = root.find('.//{' + DS + '}SignedInfo')
    references = si.findall('{' + DS + '}Reference')
    assert len(references) == 1 and references[0].get('URI') == '#payload'
    reference = references[0]
    payload = root.find('{urn:xmlsec:test}Payload')
    transforms = reference.find('{' + DS + '}Transforms')
    assert len(transforms) == 2
    assert transforms[0].get('Algorithm') == DS + 'enveloped-signature'
    canonical_uri = transforms[1].get('Algorithm')
    allowed = {C14N, C14N+'WithComments', 'http://www.w3.org/2006/12/xml-c14n11', 'http://www.w3.org/2006/12/xml-c14n11#WithComments'}
    assert canonical_uri in allowed
    canonical = lambda node, uri: etree.tostring(node, method='c14n', exclusive='xml-exc-c14n' in uri, with_comments=uri.endswith('WithComments'))
    digest_name = reference.find('{' + DS + '}DigestMethod').get('Algorithm').split('#')[-1]
    assert digest(digest_name, canonical(payload, canonical_uri)) == un64(reference.find('{' + DS + '}DigestValue').text)
    signed_info_uri = si.find('{' + DS + '}CanonicalizationMethod').get('Algorithm')
    assert signed_info_uri == fixture['canonicalization_uri'] and signed_info_uri in allowed
    message = canonical(si, signed_info_uri)
    assert message == un64(fixture['canonical_signed_info_base64'])
    uri = si.find('{' + DS + '}SignatureMethod').get('Algorithm')
    assert uri == fixture['uri']
    name = uri.split('#')[-1]
    vector = dict(uri=uri, public_key_pem=fixture['public_key_pem'], message_hex=message.hex(),
                  signature_hex=un64(root.find('.//{' + DS + '}SignatureValue').text).hex())
    if name.startswith('ecdsa-'):
        # Parsing a public key for its curve name is not cryptographic verification.
        curve = serialization.load_pem_public_key(fixture['public_key_pem'].encode()).curve.name
        vector.update(kind='ecdsa', hash=name[6:], curve={'secp256r1':'P-256','secp384r1':'P-384','secp521r1':'P-521'}[curve])
    elif name.endswith('-rsa-MGF1'):
        hash_name = name.removesuffix('-rsa-MGF1')
        vector.update(kind='rsa', padding='pss', hash=hash_name, salt_bytes=len(digest(hash_name, b'')))
    else:
        assert name.startswith('rsa-')
        vector.update(kind='rsa', padding='pkcs1v15', hash=name[4:])
    verify_openssl(vector)
    return 'OpenSSL CLI reference digest + signature; lxml canonicalization'


def audit():
    native = evp()  # Fail early for missing providers or CLI/libcrypto version mismatch.
    results = []
    for vector in json.loads((ROOT/'vectors/primitives.json').read_text())['vectors']:
        row = {'id':vector['id'], 'uri':vector['uri']}
        try:
            row.update(result='pass', verifier=verify_openssl(vector))
        except UnsupportedOpenSSL as exc:
            row.update(result='unsupported', reason=str(exc))
        # Verification errors are deliberately not relabelled as unsupported.
        results.append(row)
    xml_results = []
    for fixture in json.loads((ROOT/'vectors/xml-signatures.json').read_text())['vectors']:
        xml_results.append({'file':fixture['file'], 'result':'pass', 'verifier':verify_xml_crypto(fixture)})
    import ctypes
    import xmlsec
    xmlsec_library = ctypes.CDLL(xmlsec.__file__)
    default_crypto = xmlsec_library.xmlSecGetDefaultCrypto
    default_crypto.restype, default_crypto.argtypes = ctypes.c_char_p, []
    xmlsec_default = default_crypto().decode()
    return {'openssl_cli':openssl('version').stdout.decode().strip(),
            'libxmlsec_default_crypto':xmlsec_default,
            'libcrypto_path':native.path, 'libcrypto_version':native.version,
            'providers':['default','legacy'],
            'scope':'Existing 203 primitive fixtures and 24 native XML fixtures; excludes URI inventory gaps. No non-OpenSSL cryptographic fallback.',
            'primitive_summary':{status:sum(r['result']==status for r in results) for status in ('pass','unsupported')},
            'primitive_results':results, 'xml_results':xml_results}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-all', action='store_true', help='Exit 2 if any primitive lacks OpenSSL support')
    args = parser.parse_args()
    report = audit()
    save('docs/openssl-verification.json', report)
    print(json.dumps(report['primitive_summary']))
    print(f"Verified {len(report['xml_results'])} XML fixture digests/signatures; report: docs/openssl-verification.json")
    if args.require_all and report['primitive_summary']['unsupported']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
