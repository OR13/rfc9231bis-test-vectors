"""Unmodified libxmlsec CLI interoperability with the new-URI XML fixtures."""
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from lxml import etree
from Crypto.PublicKey import MLDSA, SLHDSA, RSA, ECC
from Crypto.Signature import mldsa, slhdsa, eddsa, pkcs1_15, pss, DSS
from Crypto.Hash import SHA512, SHAKE256, SHA256
from .common import ROOT, DS, M26, un64, xml_un64, b64, save
from .context import resolve_context
from .extended_xml import canonical, verify as verify_profile


def executable():
    return os.environ.get('XMLSEC1', str(ROOT/'.interop/build-openssl/apps/xmlsec1'))


def call(*args):
    return subprocess.run([executable(), *map(str, args)], capture_output=True, text=True)


def public_pem(v):
    return v.get('public_key_pem') or eddsa.import_public_key(bytes.fromhex(v['public_key_hex'])).export_key(format='PEM')


def private_pem(v):
    return v.get('private_key_pem') or eddsa.import_private_key(bytes.fromhex(v['seed_hex'])).export_key(format='PEM', use_pkcs8=True)


def named_document(fixture):
    root = etree.parse(str(ROOT/'vectors'/fixture['file'])).getroot()
    si = root.find('.//{'+DS+'}SignedInfo')
    before = canonical(si)
    signature = root.find('{'+DS+'}Signature')
    info = etree.SubElement(signature, '{'+DS+'}KeyInfo')
    etree.SubElement(info, '{'+DS+'}KeyName').text = 'fixture-key'
    assert before == canonical(si) == un64(fixture['canonical_signed_info_base64'])
    return root


def verify_command(xml, pubkey):
    return call('--verify', '--pubkey-pem:fixture-key', pubkey,
                '--id-attr:Id', 'Payload', '--enabled-reference-uris', 'same-doc', xml)


def pycryptodome_verify(root, fixture, primitive):
    # KeyInfo is an unsigned key-selection hint. Remove it only for the local
    # fixed-profile validation; never alter SignedInfo or the signed payload.
    root = deepcopy(root)
    signature = root.find('{'+DS+'}Signature')
    for info in signature.findall('{'+DS+'}KeyInfo'):
        signature.remove(info)
    context = bytes.fromhex(fixture['application_context_hex'])
    verify_profile(root, fixture, primitive, context)  # digest/profile + OpenSSL
    si = signature.find('{'+DS+'}SignedInfo')
    sm = si.find('{'+DS+'}SignatureMethod')
    assert resolve_context(etree.tostring(sm).decode(), context) == context
    message = canonical(si)
    value = xml_un64(signature.find('{'+DS+'}SignatureValue').text)
    if primitive['kind'] in ('rsa','ecdsa'):
        assert primitive['hash']=='sha256', 'Classical harness controls require SHA-256'
    if primitive['kind'] == 'rsa':
        key = RSA.import_key(public_pem(primitive))
        scheme = pss.new(key, salt_bytes=primitive['salt_bytes']) if primitive['padding']=='pss' else pkcs1_15.new(key)
        scheme.verify(SHA256.new(message),value)
    elif primitive['kind'] == 'ecdsa':
        DSS.new(ECC.import_key(public_pem(primitive)), 'fips-186-3', encoding='binary').verify(SHA256.new(message),value)
    elif primitive['kind'] == 'pqsig':
        module, scheme = (MLDSA,mldsa) if primitive['algorithm'].startswith('ml-dsa') else (SLHDSA,slhdsa)
        scheme.new(module.import_key(public_pem(primitive)), context=context).verify(message,value)
    else:
        key = eddsa.import_public_key(bytes.fromhex(primitive['public_key_hex']))
        data = SHA512.new(message) if primitive['variant']=='ed25519ph' else SHAKE256.new(message) if primitive['variant']=='ed448ph' else message
        eddsa.new(key, 'rfc8032', context=context).verify(data,value)


def exercise(fixture, primitive, output_dir=None, command_runner=None):
    """Native verify, tamper rejection, native re-sign, independent verification."""
    run = command_runner or call
    def native_verify(xml, pubkey):
        return run('--verify', '--pubkey-pem:fixture-key', pubkey,
                   '--id-attr:Id', 'Payload', '--enabled-reference-uris', 'same-doc', xml)
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        pub, private, document, signed = [directory/n for n in ('pub.pem','private.pem','input.xml','signed.xml')]
        pub.write_text(public_pem(primitive)); private.write_text(private_pem(primitive))
        root = named_document(fixture)
        document.write_bytes(etree.tostring(root))
        result = native_verify(document,pub)
        if result.returncode:
            # Preserve the actual failure; the caller classifies capability vs
            # unexpected signature failure using the registered transform list.
            return {'result':'verification-failed','diagnostic':result.stderr.replace(str(directory),'<temporary>').strip()}
        negatives=[]
        for name in ('payload','signature','context'):
            bad = deepcopy(root)
            if name=='payload': bad.find('Payload').text='Tampered'
            elif name=='signature':
                value=bad.find('.//{'+DS+'}SignatureValue')
                raw=xml_un64(value.text); value.text=b64(bytes([raw[0]^1])+raw[1:])
            else:
                ctx=bad.find('.//{'+M26+'}SignatureContext')
                if ctx is None: continue
                ctx.text=b64(b'wrong')
            document.write_bytes(etree.tostring(bad))
            rejection=native_verify(document,pub)
            assert rejection.returncode != 0, f'libxmlsec accepted altered {name}'
            negatives.append(name)
        document.write_bytes(etree.tostring(root))
        result=run('--sign','--privkey-pem:fixture-key',private,'--id-attr:Id','Payload',
                    '--enabled-reference-uris','same-doc','--output',signed,document)
        assert result.returncode==0, result.stderr
        assert native_verify(signed,pub).returncode==0
        reverse=etree.parse(str(signed)).getroot()
        pycryptodome_verify(reverse,fixture,primitive)
        if output_dir:
            output_dir.mkdir(parents=True,exist_ok=True)
            (output_dir/(primitive['id']+'.xml')).write_bytes(etree.tostring(reverse))
        return {'result':'interoperable','forward':'libxmlsec verifies original signature and XML references',
                'reverse':'libxmlsec signs; PyCryptodome and OpenSSL verify; local adapter validates XML profile/digest',
                'negative_checks':negatives,'signed_info_unchanged_by_keyname':True}


def main():
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--no-store',action='store_true',help='Audit without replacing stored reverse fixtures')
    args=parser.parse_args()
    version=call('--version'); assert version.returncode==0, version.stderr
    transforms=call('--list-transforms'); assert transforms.returncode==0, transforms.stderr
    registered=set(re.findall(r'"([^"]+)"',transforms.stdout))
    primitives={v['id']:v for v in json.loads((ROOT/'vectors/primitives.json').read_text())['vectors']}
    fixtures=json.loads((ROOT/'vectors/extended-xml-signatures.json').read_text())['vectors']
    results=[]
    for fixture in fixtures:
        primitive=primitives[fixture['primitive_id']]
        row={'id':primitive['id'],'uri':primitive['uri'],'kind':primitive['kind']}
        outcome=exercise(fixture,primitive,None if args.no_store else ROOT/'vectors/libxmlsec')
        row.update(outcome)
        if outcome['result']=='verification-failed' and primitive['uri'].split('#')[-1] not in registered:
            row['result']='unsupported'; row['reason']='Algorithm transform not registered in this build'
        results.append(row)
    metadata=ROOT/'.interop/build-metadata.json'
    default_binary=(ROOT/'.interop/build-openssl/apps/xmlsec1').resolve()
    is_default=Path(executable()).resolve()==default_binary
    build=json.loads(metadata.read_text()) if metadata.exists() and is_default else {'commit':'unrecorded for selected CLI; no pinned-source provenance claimed'}
    report={'library':version.stdout.strip(),'build':build,
            'scope':'No URI remapping or custom crypto transform. Only KeyInfo/KeyName added outside SignedInfo.',
            'summary':{s:sum(r['result']==s for r in results) for s in ('interoperable','unsupported','verification-failed')},
            'pq_summary':{s:sum(r['result']==s and r['kind']=='pqsig' for r in results) for s in ('interoperable','unsupported','verification-failed')},
            'results':results}
    save('docs/native-xml-interoperability.json',report)
    print(json.dumps({k:report[k] for k in ('library','summary','pq_summary')},indent=2))


if __name__=='__main__': main()
