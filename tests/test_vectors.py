import json
import pytest
from lxml import etree
import xmlsec
from signxml import XMLVerifier, SignatureConfiguration
from signxml.exceptions import InvalidInput, InvalidSignature
from xmlsec_vectors.common import ROOT, DS, un64
from xmlsec_vectors.context import resolve_context
from xmlsec_vectors.verify import verify_primitive

PRIMITIVES=json.loads((ROOT/'vectors/primitives.json').read_text())['vectors']
CONTEXTS=json.loads((ROOT/'vectors/contexts.json').read_text())['vectors']
XML=json.loads((ROOT/'vectors/xml-signatures.json').read_text())['vectors']

@pytest.mark.parametrize('v',PRIMITIVES,ids=lambda v:v['id'])
def test_primitive(v):
    verify_primitive(v)

@pytest.mark.parametrize('v',CONTEXTS,ids=lambda v:v['id'])
def test_context(v):
    app=None if v['application_context_hex'] is None else bytes.fromhex(v['application_context_hex'])
    if v['valid']:
        assert resolve_context(v['xml'],app)==bytes.fromhex(v['expected_context_hex'])
    else:
        with pytest.raises(ValueError): resolve_context(v['xml'],app)

def verify_xmlsec(root, pem):
    xmlsec.tree.add_ids(root,['Id'])
    node=xmlsec.tree.find_node(root,xmlsec.Node.SIGNATURE)
    ctx=xmlsec.SignatureContext()
    ctx.key=xmlsec.Key.from_memory(pem,xmlsec.KeyFormat.PEM)
    ctx.verify(node)

@pytest.mark.parametrize('v',XML,ids=lambda v:v['file'])
def test_xml_signxml(v):
    root=etree.parse(str(ROOT/'vectors'/v['file'])).getroot()
    result=XMLVerifier().verify(root,expect_config=SignatureConfiguration(require_x509=False))
    assert result.signed_xml.text=='Hello, XML security!'
    si=root.find('.//{'+DS+'}SignedInfo')
    assert etree.tostring(si,method='c14n',exclusive='xml-exc-c14n' in v['canonicalization_uri'],with_comments=v['canonicalization_uri'].endswith('WithComments'))==un64(v['canonical_signed_info_base64'])
    root.find('{urn:xmlsec:test}Payload').text='Tampered'
    with pytest.raises(InvalidSignature):
        XMLVerifier().verify(root,expect_config=SignatureConfiguration(require_x509=False))

@pytest.mark.parametrize('v',XML,ids=lambda v:v['file'])
def test_xml_libxmlsec(v):
    root=etree.parse(str(ROOT/'vectors'/v['file'])).getroot()
    verify_xmlsec(root,v["public_key_pem"])
    root.find('{urn:xmlsec:test}Payload').text='Tampered'
    with pytest.raises(xmlsec.Error): verify_xmlsec(root,v["public_key_pem"])

EXTENDED=json.loads((ROOT/'vectors/extended-xml-signatures.json').read_text())['vectors']

@pytest.mark.parametrize('v',EXTENDED,ids=lambda v:v['file'])
def test_extended_xml_adapter(v):
    from copy import deepcopy
    from xmlsec_vectors.extended_xml import verify, canonical
    primitive=next(p for p in PRIMITIVES if p['id']==v['primitive_id'])
    root=etree.parse(str(ROOT/'vectors'/v['file'])).getroot()
    ctx=bytes.fromhex(v['application_context_hex'])
    assert canonical(root[1][0])==un64(v['canonical_signed_info_base64'])
    verify(root,v,primitive,ctx)
    bad=deepcopy(root); bad[0].text='Tampered'
    with pytest.raises(ValueError): verify(bad,v,primitive,ctx)
    bad=deepcopy(root); bad[1][1].text='AA=='
    with pytest.raises(AssertionError): verify(bad,v,primitive,ctx)
    with pytest.raises(ValueError): verify(root,v,primitive,b'wrong-context')

@pytest.mark.parametrize('uri',[
    'http://www.w3.org/2001/06/xml-exc-c12n#',
    'http://www.w3.org/2001/06/xml-exc-c12n#WithComments',
    'http://www.w3.org/2006/12/xmlc12n11#',
    'http://www.w3.org/2006/12/xmlc12n11#WithComments',
    'http://www.w3.org/2006/12/xml-c14n11#',
    'http://www.w3.org/TR/2001/10/xml-exc-c14n#',
])
def test_unrecognized_canonicalization_uri(uri):
    from signxml import XMLSigner
    with pytest.raises(InvalidInput): XMLSigner(c14n_algorithm=uri)
    # Inspect libxmlsec's registered identifiers, not just a broken signature.
    known={getattr(xmlsec.Transform,n).href for n in dir(xmlsec.Transform) if 'C14N' in n}
    assert uri not in known


def test_draft_uri_inventory():
    source=(ROOT/'references/xmlsec-draft-11.txt').read_text()
    baselines={'http://www.w3.org/2000/09/xmldsig#sha1',
               'http://www.w3.org/2001/04/xmlenc#sha256',
               'http://www.w3.org/2001/04/xmlenc#ripemd160'}
    for v in PRIMITIVES:
        assert v['uri'] in source or v['uri'] in baselines


def test_hkdf_rfc5869_known_answer():
    vector=next(v for v in PRIMITIVES if v['id']=='hkdf-0')
    assert vector['output_hex']==('3cb25f25faacd57a90434f64d0362f2a'
        '2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865')
