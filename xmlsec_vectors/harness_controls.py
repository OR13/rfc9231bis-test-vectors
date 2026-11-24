"""Classical signatures on the exact extended/PQ fixture XML profile."""
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
from lxml import etree
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15, pss, DSS
from Crypto.Hash import SHA256
from signxml import XMLSigner
from .common import ROOT, DS, M01, M07, M26, C14N, DRAFT, b64, save, rng
from .extended_xml import canonical


@lru_cache(maxsize=1)
def schema():
    parser=etree.XMLParser(load_dtd=False,resolve_entities=False,no_network=True)
    return etree.XMLSchema(etree.parse(str(ROOT/'schemas/fixture-envelope.xsd'),parser))


def xml_skeleton(root, preserve_context=False):
    """Compare every XML-profile detail except algorithm, context and signature.

    RSA/ECDSA cannot legally carry SignatureContext. Ed25519ph fixtures supply
    a classical control for the context-bearing branch without stripping it.
    """
    root=deepcopy(root)
    sm=root.find('.//{'+DS+'}SignatureMethod')
    sm.set('Algorithm','urn:test:algorithm-placeholder')
    if not preserve_context:
        for child in sm.findall('{'+M26+'}SignatureContext'): sm.remove(child)
    root.find('.//{'+DS+'}SignatureValue').text=''
    return etree.tostring(root)


def with_key_value(root, primitive):
    """Add a standards-library-produced key representation outside SignedInfo."""
    root=deepcopy(root)
    before=canonical(root.find('.//{'+DS+'}SignedInfo'))
    # Only obtain KeyInfo from this separate dummy signature. Never replace or
    # re-sign the actual control document's SignedInfo, payload, or signature.
    dummy=XMLSigner(signature_algorithm=primitive['uri'],digest_algorithm='sha256',c14n_algorithm=C14N).sign(
        etree.Element('KeyEncodingOnly'),key=primitive['private_key_pem'])
    info=deepcopy(dummy.find('{'+DS+'}Signature/{'+DS+'}KeyInfo'))
    root.find('{'+DS+'}Signature').append(info)
    assert canonical(root.find('.//{'+DS+'}SignedInfo'))==before
    return root


def generate():
    extended=json.loads((ROOT/'vectors/extended-xml-signatures.json').read_text())['vectors']
    source=next(f for f in extended if f['primitive_id']=='ml-dsa-44-empty')
    template=etree.parse(str(ROOT/'vectors'/source['file'])).getroot()
    rsa=RSA.import_key((ROOT/'vectors/rsa-private.pem').read_bytes())
    ecc=ECC.generate(curve='P-256',randfunc=rng('matched-classical-control'))
    specs=[('control-rsa-sha256',rsa,M01+'rsa-sha256','rsa','pkcs1v15'),
           ('control-ecdsa-sha256',ecc,M01+'ecdsa-sha256','ecdsa',None),
           ('control-pss-sha256',rsa,M07+'sha256-rsa-MGF1','rsa','pss')]
    results=[]
    folder=ROOT/'vectors/harness-controls';folder.mkdir(exist_ok=True)
    for name,key,uri,kind,padding in specs:
        root=deepcopy(template)
        root.find('.//{'+DS+'}SignatureMethod').set('Algorithm',uri)
        message=canonical(root.find('.//{'+DS+'}SignedInfo'))
        if kind=='ecdsa':
            signer=DSS.new(key,'deterministic-rfc6979',encoding='binary')
            private=key.export_key(format='PEM',use_pkcs8=True)
            public=key.public_key().export_key(format='PEM')
        else:
            signer=pkcs1_15.new(key) if padding=='pkcs1v15' else pss.new(key,salt_bytes=32,rand_func=rng(name))
            private=key.export_key(pkcs=8).decode(); public=key.public_key().export_key().decode()
        signature=signer.sign(SHA256.new(message))
        root.find('.//{'+DS+'}SignatureValue').text=b64(signature)
        assert xml_skeleton(root)==xml_skeleton(template)
        schema().assertValid(root)
        file='harness-controls/'+name+'.xml'
        (ROOT/'vectors'/file).write_bytes(etree.tostring(root))
        primitive=dict(id=name,kind=kind,uri=uri,hash='sha256',message_hex=message.hex(),
                       signature_hex=signature.hex(),signature_base64=b64(signature),
                       private_key_pem=private,public_key_pem=public)
        if kind=='ecdsa': primitive['curve']='P-256'
        else: primitive.update(padding=padding,salt_bytes=32)
        fixture=dict(file=file,primitive_id=name,uri=uri,canonical_signed_info_base64=b64(message),application_context_hex='')
        results.append({'fixture':fixture,'primitive':primitive})
    save('vectors/harness-controls.json',{'draft':DRAFT,'template':source['file'],'controls':results})
    save('schemas/provenance.json',{'source_url':'https://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd',
        'source_sha256':hashlib.sha256((ROOT/'schemas/xmldsig-core-schema.xsd').read_bytes()).hexdigest(),
        'source_modified':False,'additional_schemas':['signature-context.xsd','fixture-envelope.xsd']})
    print('Generated 3 classical controls using the PQ XML template')


if __name__=='__main__':generate()
