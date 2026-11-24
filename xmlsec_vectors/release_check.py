"""Strict publication gate: native coverage must run, never silently skip."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from .common import ROOT, save
from .native_xml import executable

PIN='eb3cd78a4731aaff7b69818d212071a6fd1d75fd'
ALLOWED_SKIPS={('tests.test_openssl','test_explicit_openssl_primitive[pss-md2]'),
               ('tests.test_native_xml','test_native_ed448_nonempty_context')}


def check_junit(path):
    tree=ET.parse(path)
    cases=list(tree.iter('testcase'))
    if not cases: raise RuntimeError('No tests collected')
    for case in cases:
        if case.find('failure') is not None or case.find('error') is not None:
            raise RuntimeError('Test failed: '+case.get('name',''))
        skipped=case.find('skipped')
        if skipped is not None:
            identity=(case.get('classname'),case.get('name'))
            if identity not in ALLOWED_SKIPS: raise RuntimeError('Unexpected skip: '+str(identity))
            if identity[1]=='test_native_ed448_nonempty_context' and skipped.get('type')!='pytest.xfail':
                raise RuntimeError('Ed448 must execute as expected failure, not skip')
    required=[c for c in cases if c.get('name','').startswith(('test_native_boundary[','test_native_xml_interoperability[','test_same_native_bidirectional_harness['))]
    if len(required)!=73: raise RuntimeError(f'Expected 73 mandatory native cases, found {len(required)}')
    return dict(tests=len(cases),passed=sum(c.find('skipped') is None for c in cases),allowed_skips=sum(c.find('skipped') is not None for c in cases),mandatory_native_cases=len(required))


def main():
    binary=ROOT/'.interop/build-openssl/apps/xmlsec1'
    if Path(executable()).resolve()!=binary.resolve() or not binary.exists():
        raise RuntimeError('Release requires the pinned native CLI; run scripts/build_xmlsec.py and unset XMLSEC1 overrides')
    metadata=json.loads((ROOT/'.interop/build-metadata.json').read_text())
    if metadata['commit']!=PIN or metadata['source_patches']: raise RuntimeError('Unexpected native build provenance')
    source=ROOT/'.interop/xmlsec'
    if subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()!=PIN: raise RuntimeError('Wrong native source revision')
    subprocess.run(['git','diff','--exit-code','HEAD','--'],cwd=source,check=True)
    with tempfile.TemporaryDirectory() as tmp:
        junit=Path(tmp)/'results.xml'
        env=os.environ.copy();env.pop('PYTEST_ADDOPTS',None)
        subprocess.run([sys.executable,'-m','pytest','-q','--junitxml',str(junit)],cwd=ROOT,env=env,check=True)
        summary=check_junit(junit)
    # Audit every original transform; changes to expected unsupported/failing
    # cases require deliberate review, even if the main passing set still passes.
    subprocess.run([sys.executable,'-m','xmlsec_vectors.native_xml','--no-store'],cwd=ROOT,check=True)
    audit=json.loads((ROOT/'docs/native-xml-interoperability.json').read_text())
    for result in audit['results']:
        expected='unsupported' if 'slh-dsa-shake-' in result['uri'] else 'verification-failed' if result['id']=='ed448-786d6c736563' else 'interoperable'
        if result['result']!=expected: raise RuntimeError(f'Changed interoperability result: {result["id"]}')
    files=sorted(p for folder in ('vectors','schemas') for p in (ROOT/folder).rglob('*') if p.is_file())
    save('docs/release-verification.json',dict(result='pass',native_commit=PIN,suite=summary,
        artifact_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}))
    print('Release gate passed; wrote docs/release-verification.json')

if __name__=='__main__': main()
