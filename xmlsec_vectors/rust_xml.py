"""Unmodified structured-world/xml-sec CLI through the native XML harness."""
import hashlib
import json
import os
import subprocess
from .common import ROOT, save
from .native_xml import exercise

COMMIT='7d1795cd8a0747aac7cf224603d670502bc75935'
SOURCE=ROOT/'.interop/xml-sec'
BINARY=SOURCE/'target/release/xmlsec1'


def cli(*args):
    args=list(map(str,args))
    # This CLI advertises but rejects this donor option. All input fixtures use
    # #payload; no reference checks are disabled and no XML is rewritten.
    index=args.index('--enabled-reference-uris')
    del args[index:index+2]
    return subprocess.run([str(BINARY),*args],capture_output=True,text=True)


def main():
    if subprocess.check_output(['git','rev-parse','HEAD'],cwd=SOURCE,text=True).strip()!=COMMIT:
        raise RuntimeError('Unexpected xml-sec revision')
    subprocess.run(['git','diff','--exit-code','HEAD','--'],cwd=SOURCE,check=True)
    primitives={v['id']:v for v in json.loads((ROOT/'vectors/primitives.json').read_text())['vectors']}
    fixtures=json.loads((ROOT/'vectors/extended-xml-signatures.json').read_text())['vectors']
    fixtures+=json.loads((ROOT/'vectors/pq-boundaries.json').read_text())['vectors']
    controls=json.loads((ROOT/'vectors/harness-controls.json').read_text())['controls']
    for c in controls: primitives[c['primitive']['id']]=c['primitive'];fixtures.append(c['fixture'])
    rows=[]; previous=os.environ.get('XMLSEC1');os.environ['XMLSEC1']=str(BINARY)
    try:
        for f in fixtures:
            outcome=exercise(f,primitives[f['primitive_id']],command_runner=cli)
            if 'slh-dsa-shake-' in f['uri'] and 'unsupported algorithm:' in outcome.get('diagnostic',''):
                outcome['result']='unsupported'
            rows.append(dict(id=f.get('id',f['primitive_id']),uri=f['uri'],**outcome))
    finally:
        if previous is None:os.environ.pop('XMLSEC1',None)
        else:os.environ['XMLSEC1']=previous
    summary={status:sum(r['result']==status for r in rows) for status in sorted({r['result'] for r in rows})}
    save('docs/rust-xml-interoperability.json',dict(repository='https://github.com/structured-world/xml-sec',commit=COMMIT,
        build='cargo build --release -p xml-sec-cli --features experimental-pq',
        cargo_lock_sha256=hashlib.sha256((SOURCE/'Cargo.lock').read_bytes()).hexdigest(),
        scope='Unmodified algorithms and contexts; same native exercise harness, unsupported CLI --enabled-reference-uris omitted; default RustCrypto provider',summary=summary,results=rows))
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
