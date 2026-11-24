"""Signed PQ boundary fixtures and independent rejection checks."""
from copy import deepcopy
import json
import shutil
import pytest
from lxml import etree
from Crypto.Hash import SHA512
from xmlsec_vectors.common import ROOT, DS, b64, xml_un64, un64
from xmlsec_vectors.extended_xml import verify, canonical, SignatureVerificationError
from xmlsec_vectors.harness_controls import schema
from xmlsec_vectors.native_xml import executable, exercise, pycryptodome_verify
from xmlsec_vectors.pq_boundaries import scheme

DATA=json.loads((ROOT/'vectors/pq-boundaries.json').read_text())
PRIMITIVES={v['id']:v for v in json.loads((ROOT/'vectors/primitives.json').read_text())['vectors']}
ORIGINAL=json.loads((ROOT/'vectors/extended-xml-signatures.json').read_text())['vectors']


def load(f): return etree.parse(str(ROOT/'vectors'/f['file'])).getroot()


@pytest.mark.parametrize('fixture',DATA['vectors'],ids=lambda f:f['id'])
def test_signed_boundary(fixture):
    root=load(fixture);schema().assertValid(root)
    assert canonical(root.find('.//{'+DS+'}SignedInfo'))==un64(fixture['canonical_signed_info_base64'])
    pycryptodome_verify(root,fixture,PRIMITIVES[fixture['primitive_id']])


@pytest.mark.native_xml
@pytest.mark.skipif(not shutil.which(executable()),reason='Build pinned libxmlsec first')
@pytest.mark.parametrize('fixture',[f for f in DATA['vectors'] if 'slh-dsa-shake-' not in f['uri']],ids=lambda f:f['id'])
def test_native_boundary(fixture):
    result=exercise(fixture,PRIMITIVES[fixture['primitive_id']])
    assert result['result']=='interoperable',result


@pytest.mark.parametrize('fixture',DATA['negative_vectors'],ids=lambda f:f['id'])
@pytest.mark.parametrize('mutation',['prehash','wrong-key','wrong-parameter','truncated','extended'])
def test_pq_rejection(fixture,mutation):
    primitive=deepcopy(PRIMITIVES[fixture['primitive_id']])
    original=next(f for f in ORIGINAL if f['primitive_id']==fixture['primitive_id'])
    root=load(fixture if mutation=='prehash' else original)
    sv=root.find('.//{'+DS+'}SignatureValue')
    if mutation=='wrong-key': primitive['public_key_pem']=fixture['wrong_public_key_pem']
    elif mutation=='wrong-parameter':
        family='ml-dsa' if primitive['algorithm'].startswith('ml-dsa') else 'slh-dsa'
        other=next(v for v in PRIMITIVES.values() if v['kind']=='pqsig' and v['algorithm'].startswith(family) and v['algorithm']!=primitive['algorithm'])
        primitive['public_key_pem']=other['public_key_pem']
    elif mutation=='truncated': sv.text=b64(xml_un64(sv.text)[:-1])
    elif mutation=='extended': sv.text=b64(xml_un64(sv.text)+b'\x00')
    message=canonical(root.find('.//{'+DS+'}SignedInfo'));signature=xml_un64(sv.text)
    if mutation=='prehash':
        # This is a valid prehash signature, not an arbitrary corrupt value.
        scheme(primitive,key=primitive['public_key_pem']).verify(SHA512.new(message),signature)
    with pytest.raises(ValueError): scheme(primitive,key=primitive['public_key_pem']).verify(message,signature)
    with pytest.raises(SignatureVerificationError): verify(root,fixture,primitive,b'')


@pytest.mark.parametrize('value',['AA\u00a0==','AA! =='])
def test_xml_base64_rejects_non_xml_whitespace(value):
    with pytest.raises(ValueError): xml_un64(value)
