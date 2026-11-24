"""Build unmodified upstream libxmlsec locally with its experimental PQ options."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
COMMIT = 'eb3cd78a4731aaff7b69818d212071a6fd1d75fd'
WORK = ROOT / '.interop'
SOURCE = WORK / 'xmlsec'
BUILD = WORK / 'build-openssl'


def run(*args, cwd=ROOT, log=None):
    if log:
        with (WORK / log).open('w') as output:
            subprocess.run(args, cwd=cwd, stdout=output, stderr=subprocess.STDOUT, check=True)
    else:
        subprocess.run(args, cwd=cwd, check=True)


def main():
    WORK.mkdir(exist_ok=True)
    if not SOURCE.exists():
        run('git', 'init', str(SOURCE))
        run('git', 'fetch', '--depth=1', 'https://github.com/lsh123/xmlsec.git', COMMIT, cwd=SOURCE)
        run('git', 'checkout', '--detach', 'FETCH_HEAD', cwd=SOURCE)
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=SOURCE, text=True).strip()
    if actual != COMMIT:
        raise SystemExit(f'Refusing to change existing source checkout {actual}; expected {COMMIT}')
    subprocess.run(['git', 'diff', '--exit-code', 'HEAD', '--'], cwd=SOURCE, check=True)
    prefix = os.environ.get('OPENSSL_PREFIX') or subprocess.check_output(['pkg-config', '--variable=prefix', 'openssl'], text=True).strip()
    run('autoreconf', '-if', cwd=SOURCE, log='autoreconf.log')
    BUILD.mkdir(exist_ok=True)
    options = [f'--with-openssl={prefix}', '--with-default-crypto=openssl', '--disable-crypto-dl',
               '--without-gnutls', '--without-nss', '--without-gcrypt', '--without-libxslt',
               '--enable-ml-dsa', '--enable-slh-dsa']
    run(str(SOURCE/'configure'), *options, cwd=BUILD, log='configure.log')
    # This pinned revision's list_unit_tests.c lacks a final newline. Suppress
    # only Clang's fatal newline warning; do not patch the upstream source.
    compiler = subprocess.check_output([os.environ.get('CC', 'cc'), '--version'], text=True)
    cflags = os.environ.get('CFLAGS', '-O2')
    if 'clang' in compiler.lower():
        cflags += ' -Wno-error=newline-eof'
    run('make', '-j4', 'CFLAGS='+cflags, cwd=BUILD, log='build.log')
    run('make', 'check-dsig', 'XMLSEC_TEST_NAME=aleksey-xmldsig-01/enveloped-sha512-mldsa44-with-signature-context',
        cwd=BUILD, log='upstream-check.log')
    metadata = {'repository':'https://github.com/lsh123/xmlsec', 'commit':COMMIT,
                'configure_options':options, 'make_cflags':cflags,
                'upstream_test':'make check-dsig XMLSEC_TEST_NAME=aleksey-xmldsig-01/enveloped-sha512-mldsa44-with-signature-context',
                'upstream_test_result':'pass', 'source_patches':[]}
    (WORK/'build-metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
    print('Built:', BUILD/'apps/xmlsec1')


if __name__ == '__main__':
    main()
