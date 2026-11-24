"""Real XML-library forward/reverse PQ interoperability, optional native build."""
import json
from pathlib import Path
import shutil
import pytest
from lxml import etree
from xmlsec_vectors.common import ROOT
from xmlsec_vectors.native_xml import executable, exercise, pycryptodome_verify

PRIMITIVES={v['id']:v for v in json.loads((ROOT/'vectors/primitives.json').read_text())['vectors']}
FIXTURES=json.loads((ROOT/'vectors/extended-xml-signatures.json').read_text())['vectors']
# Expectations are tied to the tested upstream revision, never inferred from
# whichever fixtures happened to pass in the most recent report.
SUPPORTED=[v for v in FIXTURES if 'slh-dsa-shake-' not in v['uri'] and v['primitive_id']!='ed448-786d6c736563']
NATIVE_PRESENT=bool(shutil.which(executable()))


@pytest.mark.parametrize('fixture',SUPPORTED,ids=lambda v:v['primitive_id'])
def test_stored_libxmlsec_signature_independently(fixture):
    path=ROOT/'vectors/libxmlsec'/(fixture['primitive_id']+'.xml')
    pycryptodome_verify(etree.parse(str(path)).getroot(),fixture,PRIMITIVES[fixture['primitive_id']])


@pytest.mark.native_xml
@pytest.mark.skipif(not NATIVE_PRESENT,reason='Build pinned libxmlsec with scripts/build_xmlsec.py or set XMLSEC1')
@pytest.mark.parametrize('fixture',SUPPORTED,ids=lambda v:v['primitive_id'])
def test_native_xml_interoperability(fixture):
    result=exercise(fixture,PRIMITIVES[fixture['primitive_id']])
    assert result['result']=='interoperable',result


@pytest.mark.native_xml
@pytest.mark.skipif(not NATIVE_PRESENT,reason='Build pinned libxmlsec with scripts/build_xmlsec.py or set XMLSEC1')
@pytest.mark.xfail(strict=True,reason='Pinned upstream Ed448 transform does not read SignatureContext; tracked in docs/native-xml.md')
def test_native_ed448_nonempty_context():
    fixture=next(v for v in FIXTURES if v['primitive_id']=='ed448-786d6c736563')
    result=exercise(fixture,PRIMITIVES[fixture['primitive_id']])
    assert result['result']=='interoperable',result
