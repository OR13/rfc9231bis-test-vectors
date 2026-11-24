"""Additional signed context/encoding fixtures; original corpus is unchanged."""
from copy import deepcopy
import json
from lxml import etree
from Crypto.PublicKey import MLDSA, SLHDSA
from Crypto.Signature import mldsa, slhdsa
from Crypto.Hash import SHA512
from .common import ROOT, DS, M26, DRAFT, b64, save, rng
from .extended_xml import canonical
from .harness_controls import schema


def scheme(v,key=None,context=b''):
    module,signer=(MLDSA,mldsa) if v['algorithm'].startswith('ml-dsa') else (SLHDSA,slhdsa)
    return signer.new(module.import_key(key or v['private_key_pem']),context=context,deterministic=True)


def wrap(value):
    return ' \t\n'+'\r\n'.join(value[i:i+64] for i in range(0,len(value),64))+'\n '


def generate():
    primitives=json.loads((ROOT/'vectors/primitives.json').read_text())['vectors']
    fixtures=json.loads((ROOT/'vectors/extended-xml-signatures.json').read_text())['vectors']
    out=[]; negatives=[]
    folder=ROOT/'vectors/pq-boundaries'; folder.mkdir(exist_ok=True)
    for v in primitives:
        if v['kind']!='pqsig' or v['context_hex']: continue
        original=next(f for f in fixtures if f['primitive_id']==v['id'])
        template=etree.parse(str(ROOT/'vectors'/original['file'])).getroot()
        for case,context in [('explicit-empty',b''),('binary-context',b'\x00\xff\x80\r\nxml'),('context-255',bytes(range(255))),('wrapped-signature',b''),('wrapped-digest',b'')]:
            root=deepcopy(template)
            if case in ('explicit-empty','binary-context','context-255'):
                sm=root.find('.//{'+DS+'}SignatureMethod')
                etree.SubElement(sm,'{'+M26+'}SignatureContext').text=b64(context)
            if case=='wrapped-digest':
                dv=root.find('.//{'+DS+'}DigestValue');dv.text=wrap(dv.text)
            message=canonical(root.find('.//{'+DS+'}SignedInfo'))
            signature=scheme(v,context=context).sign(message)
            root.find('.//{'+DS+'}SignatureValue').text=wrap(b64(signature)) if case=='wrapped-signature' else b64(signature)
            schema().assertValid(root)
            name=v['algorithm']+'-'+case
            file='pq-boundaries/'+name+'.xml';(ROOT/'vectors'/file).write_bytes(etree.tostring(root))
            out.append(dict(id=name,file=file,primitive_id=v['id'],uri=v['uri'],canonical_signed_info_base64=b64(message),application_context_hex=context.hex()))
        # A valid HashML/SLH-DSA signature must fail under the pure XML URI.
        root=deepcopy(template);message=canonical(root.find('.//{'+DS+'}SignedInfo'))
        prehash=SHA512.new(message); signature=scheme(v).sign(prehash)
        scheme(v,key=v['public_key_pem']).verify(SHA512.new(message),signature)
        root.find('.//{'+DS+'}SignatureValue').text=b64(signature)
        file='pq-boundaries/'+v['algorithm']+'-wrong-prehash.xml';(ROOT/'vectors'/file).write_bytes(etree.tostring(root))
        module=MLDSA if v['algorithm'].startswith('ml-dsa') else SLHDSA
        key=module.import_key(v['private_key_pem'])
        wrong=module.generate(param_set=key.param_set,randfunc=rng(v['id']+'wrong-key'))
        negatives.append(dict(id=v['algorithm']+'-wrong-prehash',file=file,primitive_id=v['id'],uri=v['uri'],canonical_signed_info_base64=b64(message),application_context_hex='',wrong_public_key_pem=wrong.public_key().export_key(format='PEM'),prehash='sha512',expected='signature-rejected'))
    save('vectors/pq-boundaries.json',dict(draft=DRAFT,vectors=out,negative_vectors=negatives))
    print(f'Generated {len(out)} positive and {len(negatives)} prehash-negative fixtures')

if __name__=='__main__': generate()
