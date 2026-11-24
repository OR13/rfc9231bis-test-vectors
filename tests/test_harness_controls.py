"""Same-template classical controls and failure localization for PQ fixtures."""
from copy import deepcopy
import json
import shutil
import pytest
import xmlsec
from lxml import etree
from signxml import XMLVerifier, SignatureConfiguration
from cryptography.exceptions import InvalidSignature
from xmlsec_vectors.common import ROOT, DS, M26, b64, un64
from xmlsec_vectors import extended_xml as adapter
from xmlsec_vectors.harness_controls import schema, xml_skeleton, with_key_value
from xmlsec_vectors.native_xml import exercise, executable
from xmlsec_vectors.openssl_verify import verify_openssl

CONTROLS=json.loads((ROOT/'vectors/harness-controls.json').read_text())['controls']
EXTENDED=json.loads((ROOT/'vectors/extended-xml-signatures.json').read_text())['vectors']
PRIMITIVES={v['id']:v for v in json.loads((ROOT/'vectors/primitives.json').read_text())['vectors']}
PATHS=sorted((ROOT/'vectors/extended-xml').glob('*.xml'))+sorted((ROOT/'vectors/libxmlsec').glob('*.xml'))+sorted((ROOT/'vectors/harness-controls').glob('*.xml'))


def load(fixture):
    return etree.parse(str(ROOT/'vectors'/fixture['file'])).getroot()


@pytest.mark.parametrize('path',PATHS,ids=lambda p:p.parent.name+'/'+p.name)
def test_fixture_schema(path):
    schema().assertValid(etree.parse(str(path)))


@pytest.mark.parametrize('fixture',EXTENDED,ids=lambda f:f['primitive_id'])
def test_same_xml_profile_as_classical_control(fixture):
    root=load(fixture)
    assert xml_skeleton(root)==xml_skeleton(load(CONTROLS[0]['fixture']))
    assert adapter.canonical(root.find('.//{'+DS+'}SignedInfo'))==un64(fixture['canonical_signed_info_base64'])


def verify_library(root, primitive, library):
    if library=='signxml':
        result=XMLVerifier().verify(with_key_value(root,primitive),expect_config=SignatureConfiguration(require_x509=False))
        assert result.signed_xml.tag=='Payload'
        assert result.signed_xml.text=='New XML signature algorithms'
    else:
        root=deepcopy(root)
        xmlsec.tree.add_ids(root,['Id'])
        ctx=xmlsec.SignatureContext()
        ctx.key=xmlsec.Key.from_memory(primitive['public_key_pem'],xmlsec.KeyFormat.PEM)
        ctx.verify(root.find('{'+DS+'}Signature'))


@pytest.mark.parametrize('control',CONTROLS,ids=lambda c:c['primitive']['id'])
@pytest.mark.parametrize('library',['signxml','xmlsec'])
def test_released_library_same_template(control,library):
    fixture,primitive=control['fixture'],control['primitive']
    root=load(fixture)
    adapter.verify(root,fixture,primitive,b'')
    verify_openssl(primitive)
    verify_library(root,primitive,library)
    for field in ('payload','signature'):
        bad=deepcopy(root)
        if field=='payload': bad.find('Payload').text='tampered'
        else:
            sv=bad.find('.//{'+DS+'}SignatureValue'); raw=un64(sv.text)
            sv.text=b64(bytes([raw[0]^1])+raw[1:])
        with pytest.raises((xmlsec.Error,InvalidSignature)):
            verify_library(bad,primitive,library)


@pytest.mark.native_xml
@pytest.mark.skipif(not shutil.which(executable()),reason='Build pinned libxmlsec first')
@pytest.mark.parametrize('control',CONTROLS,ids=lambda c:c['primitive']['id'])
def test_same_native_bidirectional_harness(control):
    result=exercise(control['fixture'],control['primitive'])
    assert result['result']=='interoperable',result


@pytest.mark.parametrize('mutation,expected',[
    ('payload',adapter.ReferenceDigestError),('reference',adapter.FixtureStructureError),
    ('context',adapter.ContextPolicyError),('duplicate-context',adapter.ContextPolicyError),
    ('algorithm',adapter.FixtureStructureError),('signature',adapter.SignatureVerificationError)])
def test_failure_stage(mutation,expected,monkeypatch):
    fixture=next(f for f in EXTENDED if f['primitive_id']=='ml-dsa-44-786d6c736563')
    root=load(fixture); primitive=PRIMITIVES[fixture['primitive_id']]
    context=bytes.fromhex(fixture['application_context_hex'])
    if mutation=='payload': root.find('Payload').text='tampered'
    elif mutation=='reference': root.find('.//{'+DS+'}Reference').set('URI','#missing')
    elif mutation=='algorithm': root.find('.//{'+DS+'}SignatureMethod').set('Algorithm','urn:unsupported')
    elif mutation=='context': context=b'wrong application context'
    elif mutation=='duplicate-context':
        sm=root.find('.//{'+DS+'}SignatureMethod'); sm.append(deepcopy(sm[0]))
    else:
        sv=root.find('.//{'+DS+'}SignatureValue'); raw=un64(sv.text)
        sv.text=b64(bytes([raw[0]^1])+raw[1:])
    calls=[]; real=adapter.verify_primitive
    def tracked(v):
        calls.append(v)
        return real(v)
    monkeypatch.setattr(adapter,'verify_primitive',tracked)
    with pytest.raises(expected): adapter.verify(root,fixture,primitive,context)
    assert len(calls)==(1 if mutation=='signature' else 0)


@pytest.mark.parametrize('mutation',['invalid-base64','oversized-context','missing-digest'])
def test_schema_rejects_malformed_fixture(mutation):
    fixture=next(f for f in EXTENDED if f['primitive_id']=='ml-dsa-44-786d6c736563')
    root=load(fixture)
    if mutation=='invalid-base64': root.find('.//{'+DS+'}SignatureValue').text='!not base64!'
    elif mutation=='oversized-context': root.find('.//{'+M26+'}SignatureContext').text=b64(b'x'*256)
    else:
        dv=root.find('.//{'+DS+'}DigestValue');dv.getparent().remove(dv)
    with pytest.raises(etree.DocumentInvalid): schema().assertValid(root)


@pytest.mark.parametrize('fixture',[f for f in EXTENDED if PRIMITIVES[f['primitive_id']]['kind']=='pqsig'],ids=lambda f:f['primitive_id'])
def test_context_profile_matches_classical_ed25519ph(fixture):
    control=next(f for f in EXTENDED if f['primitive_id'].startswith('ed25519ph-') and f['application_context_hex']==fixture['application_context_hex'])
    assert xml_skeleton(load(fixture),preserve_context=True)==xml_skeleton(load(control),preserve_context=True)
