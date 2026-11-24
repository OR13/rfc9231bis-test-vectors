"""Probe an unmodified second XML stack, preserving failures and exact URIs."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import tempfile
from lxml import etree
from .common import ROOT, DS, b64, xml_un64, save
from .native_xml import pycryptodome_verify

COMMIT='9fcc0c1e1cc0145fb0b8cf417aaa694a635f212c'
SOURCE=ROOT/'.interop/bergshamra'
BINARY=SOURCE/'target/release/bergshamra'


def call(*args):
    return subprocess.run([str(BINARY),*map(str,args)],capture_output=True,text=True)


def exercise(fixture,primitive):
    with tempfile.TemporaryDirectory() as tmp:
        tmp=Path(tmp);pub=tmp/'pub.pem';private=tmp/'key.pem';document=tmp/'input.xml';signed=tmp/'signed.xml'
        pub.write_text(primitive['public_key_pem']);private.write_text(primitive['private_key_pem'])
        original=(ROOT/'vectors'/fixture['file']).read_bytes();document.write_bytes(original)
        def verify(path):return call('verify','--key',pub,'--trusted-keys-only',path)
        result=verify(document)
        if result.returncode:
            return dict(result='verification-failed',diagnostic=(result.stdout+result.stderr).replace(str(tmp),'<temporary>').strip())
        for mutation in ('payload','signature'):
            root=etree.fromstring(original)
            if mutation=='payload': root.find('Payload').text='tampered'
            else:
                sv=root.find('.//{'+DS+'}SignatureValue');raw=xml_un64(sv.text);sv.text=b64(bytes([raw[0]^1])+raw[1:])
            document.write_bytes(etree.tostring(root))
            if verify(document).returncode==0: return dict(result='negative-accepted',mutation=mutation)
        document.write_bytes(original)
        result=call('sign','--key',private,'--output',signed,document)
        if result.returncode: return dict(result='reverse-sign-failed',diagnostic=result.stderr.replace(str(tmp),'<temporary>').strip())
        if verify(signed).returncode: return dict(result='reverse-self-verification-failed')
        pycryptodome_verify(etree.parse(str(signed)).getroot(),fixture,primitive)
        return dict(result='interoperable',negative_checks=['payload','signature'],reverse='PyCryptodome and OpenSSL verify with local XML profile/reference checks')


def main():
    actual=subprocess.check_output(['git','rev-parse','HEAD'],cwd=SOURCE,text=True).strip()
    if actual!=COMMIT: raise RuntimeError('Unexpected Bergshamra revision')
    subprocess.run(['git','diff','--exit-code','HEAD','--'],cwd=SOURCE,check=True)
    primitives={v['id']:v for v in json.loads((ROOT/'vectors/primitives.json').read_text())['vectors']}
    fixtures=json.loads((ROOT/'vectors/extended-xml-signatures.json').read_text())['vectors']
    fixtures=[f for f in fixtures if primitives[f['primitive_id']]['kind']=='pqsig']
    fixtures+=json.loads((ROOT/'vectors/pq-boundaries.json').read_text())['vectors']
    rows=[]
    for f in fixtures:
        outcome=exercise(f,primitives[f['primitive_id']])
        if 'slh-dsa-shake-' in f['uri'] and 'unable to auto-detect key format' in outcome.get('diagnostic',''):
            outcome['result']='unsupported-key-format'
        rows.append(dict(id=f.get('id',f['primitive_id']),uri=f['uri'],**outcome))
    summary={result:sum(r['result']==result for r in rows) for result in sorted({r['result'] for r in rows})}
    save('docs/bergshamra-interoperability.json',dict(repository='https://github.com/kushaldas/bergshamra',commit=COMMIT,
        build='cargo build --release --locked; default RustCrypto provider',scope='Unmodified XML URIs and contexts; no key-info rewrite; explicit trusted public key',summary=summary,results=rows))
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
