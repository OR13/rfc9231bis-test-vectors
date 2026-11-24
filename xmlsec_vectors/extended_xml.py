"""Explicit XML adapter for new URIs that general XML libraries may not yet handle.

Fixed profile: one same-document payload reference, exclusive C14N, SHA-256.
This is fixture tooling, not a general XML signature verifier.
"""
import hashlib
from cryptography.exceptions import InvalidSignature
import json
from lxml import etree
from Crypto.PublicKey import MLDSA, SLHDSA
from Crypto.Signature import mldsa, slhdsa, eddsa
from Crypto.Hash import SHA512, SHAKE256
from .common import *
from .context import resolve_context
from .verify import verify_primitive


def canonical(node):
    return etree.tostring(node,method='c14n',exclusive=True,with_comments=False)


def generate():
    vectors=json.loads((ROOT/'vectors/primitives.json').read_text())['vectors']
    out=[]
    folder=ROOT/'vectors/extended-xml'; folder.mkdir(exist_ok=True)
    for v in vectors:
        if v['kind'] not in ('pqsig','eddsa'): continue
        root=etree.Element('Envelope')
        payload=etree.SubElement(root,'Payload',Id='payload'); payload.text='New XML signature algorithms'
        sig=etree.SubElement(root,'{'+DS+'}Signature',nsmap={'ds':DS,'more26':M26})
        si=etree.SubElement(sig,'{'+DS+'}SignedInfo')
        etree.SubElement(si,'{'+DS+'}CanonicalizationMethod',Algorithm=C14N)
        sm=etree.SubElement(si,'{'+DS+'}SignatureMethod',Algorithm=v['uri'])
        context=bytes.fromhex(v['context_hex'])
        if context: etree.SubElement(sm,'{'+M26+'}SignatureContext').text=b64(context)
        ref=etree.SubElement(si,'{'+DS+'}Reference',URI='#payload')
        transforms=etree.SubElement(ref,'{'+DS+'}Transforms')
        etree.SubElement(transforms,'{'+DS+'}Transform',Algorithm=C14N)
        etree.SubElement(ref,'{'+DS+'}DigestMethod',Algorithm=ENC+'sha256')
        etree.SubElement(ref,'{'+DS+'}DigestValue').text=b64(hashlib.sha256(canonical(payload)).digest())
        message=canonical(si)
        if v['kind']=='pqsig':
            mod,scheme=(MLDSA,mldsa) if v['algorithm'].startswith('ml-dsa') else (SLHDSA,slhdsa)
            key=mod.import_key(v['private_key_pem'])
            signature=scheme.new(key,context=context,deterministic=True).sign(message)
        else:
            key=eddsa.import_private_key(bytes.fromhex(v['seed_hex']))
            data=SHA512.new(message) if v['variant']=='ed25519ph' else SHAKE256.new(message) if v['variant']=='ed448ph' else message
            signature=eddsa.new(key,'rfc8032',context=context).sign(data)
        etree.SubElement(sig,'{'+DS+'}SignatureValue').text=b64(signature)
        file='extended-xml/'+v['id']+'.xml'
        (ROOT/'vectors'/file).write_bytes(etree.tostring(root))
        out.append(dict(file=file,primitive_id=v['id'],uri=v['uri'],canonical_signed_info_base64=b64(message),
                        application_context_hex=context.hex()))
    save('vectors/extended-xml-signatures.json',{'draft':DRAFT,'profile':'local adapter; OpenSSL checks signature, not XML processing', 'vectors':out})
    print(f'Generated {len(out)} extended XML signatures')


class FixtureStructureError(ValueError):
    """The XML does not match the fixed fixture profile."""


class ContextPolicyError(ValueError):
    """SignatureContext is invalid or differs from application policy."""


class ReferenceDigestError(ValueError):
    """The canonicalized referenced payload does not match DigestValue."""


class SignatureVerificationError(AssertionError):
    """Signature check failed; this does not imply a cryptographic algorithm bug."""


def verify(root,fixture,primitive,application_context):
    """Validate this fixed fixture profile, then send canonical bytes to OpenSSL."""
    def need(condition):
        if not condition: raise FixtureStructureError('fixture profile mismatch')
    need(root.tag=='Envelope' and len(root)==2)
    payload,sig=root
    need(payload.tag=='Payload' and payload.get('Id')=='payload')
    need(sig.tag=='{'+DS+'}Signature' and len(sig)==2)
    si,sv=sig
    need(si.tag=='{'+DS+'}SignedInfo' and sv.tag=='{'+DS+'}SignatureValue' and len(si)==3)
    cm,sm,ref=si
    need(cm.tag=='{'+DS+'}CanonicalizationMethod' and cm.get('Algorithm')==C14N)
    need(sm.tag=='{'+DS+'}SignatureMethod' and sm.get('Algorithm')==primitive['uri'])
    try:
        context=resolve_context(etree.tostring(sm).decode(),application_context)
    except ValueError as exc:
        raise ContextPolicyError(str(exc)) from exc
    need(ref.tag=='{'+DS+'}Reference' and ref.get('URI')=='#payload' and len(ref)==3)
    transforms,dm,dv=ref
    need(transforms.tag=='{'+DS+'}Transforms' and len(transforms)==1)
    need(transforms[0].tag=='{'+DS+'}Transform' and transforms[0].get('Algorithm')==C14N)
    need(dm.tag=='{'+DS+'}DigestMethod' and dm.get('Algorithm')==ENC+'sha256')
    need(dv.tag=='{'+DS+'}DigestValue')
    if xml_un64(dv.text)!=hashlib.sha256(canonical(payload)).digest():
        raise ReferenceDigestError('canonical payload differs from DigestValue')
    data=canonical(si)
    # Canonical bytes are exported for consumers, but verification computes them anew.
    vector=primitive.copy()
    vector.update(message_hex=data.hex(),signature_hex=xml_un64(sv.text).hex(),signature_base64=b64(xml_un64(sv.text)),context_hex=context.hex())
    try:
        verify_primitive(vector)
    except (AssertionError, InvalidSignature) as exc:
        raise SignatureVerificationError('signature verification failed; inspect key, context, encoding, and backend') from exc

if __name__=='__main__': generate()
