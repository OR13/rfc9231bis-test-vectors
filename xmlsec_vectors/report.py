"""Run the suite and write a versioned verification report."""
import importlib.metadata
import json
import platform
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
import xmlsec
from cryptography.hazmat.backends.openssl.backend import backend
from .common import ROOT, DRAFT, openssl, save
from .verify import verify_primitive
from .openssl_verify import audit


def main():
    records=json.loads((ROOT/'vectors/primitives.json').read_text())['vectors']
    checks=[]
    for record in records:
        checks.append({'id':record['id'],'uri':record['uri'],'verifier':verify_primitive(record),'result':'pass'})
    with tempfile.TemporaryDirectory() as temp:
        junit=__import__('pathlib').Path(temp)/'junit.xml'
        subprocess.run([sys.executable,'-m','pytest','-q','--junitxml',str(junit)],cwd=ROOT,check=True)
        suite=ET.parse(junit).getroot().find('testsuite')
        summary={name:int(suite.get(name,'0')) for name in ('tests','failures','errors','skipped')}
    openssl_audit = audit()
    save('docs/openssl-verification.json', openssl_audit)
    coverage=json.loads((ROOT/'vectors/coverage.json').read_text())['algorithms']
    save('docs/verification.json',{'draft':DRAFT,'python':platform.python_version(),
        'packages':{p:importlib.metadata.version(p) for p in ('cryptography','pycryptodome','lxml','signxml','xmlsec','pytest')},
        'openssl_cli':openssl('version').stdout.decode().strip(),
        'cryptography_openssl':backend.openssl_version_text(),
        'libxmlsec_version':'.'.join(map(str,xmlsec.get_libxmlsec_version())),
        'suite':summary,'explicit_openssl_summary':openssl_audit['primitive_summary'],
        'libxmlsec_default_crypto':openssl_audit['libxmlsec_default_crypto'],
        'uri_inventory_status':dict(Counter(r['status'] for r in coverage)),
        'primitive_results':checks})
    print('Wrote docs/verification.json')

if __name__=='__main__': main()
