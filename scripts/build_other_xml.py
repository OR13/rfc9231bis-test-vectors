"""Build pinned alternative XML implementations locally, without installing."""
import argparse
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
SOURCES={
    'bergshamra':('https://github.com/kushaldas/bergshamra','9fcc0c1e1cc0145fb0b8cf417aaa694a635f212c'),
    'xml-sec':('https://github.com/structured-world/xml-sec','7d1795cd8a0747aac7cf224603d670502bc75935')}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('library',choices=SOURCES);args=parser.parse_args()
    url,commit=SOURCES[args.library];source=ROOT/'.interop'/args.library
    source.parent.mkdir(exist_ok=True)
    def run(*cmd):subprocess.run(cmd,cwd=source,check=True)
    if not source.exists():
        source.mkdir();run('git','init');run('git','fetch','--depth=1',url,commit);run('git','checkout','--detach','FETCH_HEAD')
    actual=subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()
    if actual!=commit:raise RuntimeError('Refusing to change a different source revision: '+actual)
    run('git','diff','--exit-code','HEAD','--')
    if args.library=='xml-sec':
        locked=ROOT/'references/xml-sec-Cargo.lock';target=source/'Cargo.lock'
        if target.exists() and target.read_bytes()!=locked.read_bytes():raise RuntimeError('Existing xml-sec lock differs from recorded build')
        shutil.copyfile(locked,target)
        run('cargo','build','--release','--locked','-p','xml-sec-cli','--features','experimental-pq')
    else:run('cargo','build','--release','--locked')

if __name__=='__main__':main()
