"""All corpus primitives must be attempted with an explicit OpenSSL backend."""
import json
import pytest
from xmlsec_vectors.common import ROOT
from xmlsec_vectors.openssl_evp import evp, Rejected
from xmlsec_vectors.openssl_verify import UnsupportedOpenSSL, verify_openssl, verify_xml_crypto

PRIMITIVES = json.loads((ROOT/'vectors/primitives.json').read_text())['vectors']
XML = json.loads((ROOT/'vectors/xml-signatures.json').read_text())['vectors']


@pytest.mark.parametrize('vector', PRIMITIVES, ids=lambda v:v['id'])
def test_explicit_openssl_primitive(vector):
    try:
        verify_openssl(vector)
    except UnsupportedOpenSSL as exc:
        # Only the probed MD2 provider limitation is allowed to be skipped.
        # Any verification failure, unavailable required provider, or missing
        # implementation for a different vector remains a hard failure.
        assert vector['id'] == 'pss-md2'
        pytest.skip(str(exc))


@pytest.mark.parametrize('fixture', XML, ids=lambda v:v['file'])
def test_explicit_openssl_xml_crypto(fixture):
    verify_xml_crypto(fixture)


def test_native_wrap_bridge_against_rfc3394():
    # RFC3394 section 4.1 grounds the C callback/ABI and native mode with a
    # published AES answer before applying the same mode to Camellia/SEED.
    native = evp()
    key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    plaintext = bytes.fromhex('00112233445566778899aabbccddeeff')
    expected = bytes.fromhex('1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5')
    assert native.keywrap('AES-128-ECB', key, plaintext) == expected
    assert native.keywrap('AES-128-ECB', key, expected, decrypt=True) == plaintext
    with pytest.raises(Rejected):
        native.keywrap('AES-128-ECB', key, expected[:-1], decrypt=True)
    with pytest.raises(Rejected):
        native.keywrap('AES-128-ECB', key, b'\x00' + expected[1:], decrypt=True)
