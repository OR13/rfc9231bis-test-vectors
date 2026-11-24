"""Generate deterministic, public test material. Run with python -m."""
import hashlib
import importlib
import re
from lxml import etree
from Crypto.PublicKey import RSA, ECC, MLDSA, SLHDSA, MLKEM
from Crypto.Signature import pkcs1_15, pss, DSS, eddsa, mldsa, slhdsa
from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305, ARC4
from Crypto.Hash import HMAC
from Crypto.Protocol.KDF import HKDF
from Crypto.Protocol.DH import key_agreement
from signxml import XMLSigner, methods
from .common import *

HASHES = {n: importlib.import_module('Crypto.Hash.' + m) for n, m in {
    'md5':'MD5', 'sha1':'SHA1', 'sha224':'SHA224', 'sha256':'SHA256',
    'sha384':'SHA384', 'sha512':'SHA512', 'ripemd160':'RIPEMD160',
    **{f'sha3-{n}':f'SHA3_{n}' for n in (224,256,384,512)}, 'md2':'MD2'
}.items()}

def digest_uri(name):
    if name == 'sha1': return DS + name
    if name in ('sha256', 'sha512', 'ripemd160'): return ENC + name
    return (M07 if name.startswith('sha3-') or name == 'whirlpool' else M01) + name

def generate():
    records = []
    def add(id, kind, uri, **kw):
        records.append(dict(id=id, kind=kind, uri=uri, **kw))
    messages = [b'', b'abc', bytes(range(256)), b'<data>XML security test</data>']
    for name, mod in HASHES.items():
        if name == 'md2': continue  # PSS only, no DigestMethod identifier here.
        for i, msg in enumerate(messages):
            out = mod.new(msg).digest()
            add(f'digest-{name}-{i}', 'digest', digest_uri(name), hash=name,
                message_hex=msg.hex(), output_hex=out.hex(), output_base64=b64(out))
    for i, msg in enumerate(messages):
        out = openssl('dgst', '-provider', 'default', '-provider', 'legacy', '-whirlpool', '-binary', data=msg).stdout
        add(f'digest-whirlpool-{i}', 'digest', M07+'whirlpool', hash='whirlpool', message_hex=msg.hex(), output_hex=out.hex(), output_base64=b64(out))
    for name in ('md5','sha224','sha256','sha384','sha512','ripemd160'):
        for length in (None, 112):
            key, msg = bytes(range(32)), b'XML HMAC input'
            full = HMAC.new(key, msg, HASHES[name]).digest()
            out = full if length is None else full[:length//8]
            add(f'hmac-{name}-{length or "full"}', 'hmac', M01+'hmac-'+name, hash=name,
                key_hex=key.hex(), message_hex=msg.hex(), output_bits=length or len(full)*8,
                output_hex=out.hex(), output_base64=b64(out))
    key = bytes.fromhex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b')
    msg = b'Cryptographic Forum Research Group'
    add('poly1305-rfc8439', 'poly1305', M21+'poly1305', source='RFC 8439 section 2.5.2',
        key_hex=key.hex(), message_hex=msg.hex(), output_hex='a8061dc1305136c6c22b8baf0c0127a9')
    # SipHash reference vectors serialize the 64-bit result little-endian.
    add('siphash-empty', 'siphash', M21+'siphash-2-4', source='SipHash reference vector 0',
        key_hex=bytes(range(16)).hex(), message_hex='', output_hex='310e0edd47db6f72')
    rsa = RSA.generate(2048, randfunc=rng('rsa-2048'))
    (ROOT/'vectors/rsa-private.pem').write_bytes(rsa.export_key(pkcs=8))
    (ROOT/'vectors/rsa-public.pem').write_bytes(rsa.public_key().export_key())
    msg = b'XML security signature primitive input\x00\xff'
    for name in ('md5','sha224','sha256','sha384','sha512','ripemd160'):
        sig = pkcs1_15.new(rsa).sign(HASHES[name].new(msg))
        add('rsa-'+name, 'rsa', M01+'rsa-'+name, hash=name, padding='pkcs1v15',
            message_hex=msg.hex(), signature_hex=sig.hex(), signature_base64=b64(sig), public_key_pem=rsa.public_key().export_key().decode())
    for name in HASHES:
        mod = HASHES[name]
        sig = pss.new(rsa, salt_bytes=mod.digest_size, rand_func=rng('pss-'+name)).sign(mod.new(msg))
        add('pss-'+name, 'rsa', M07+name+'-rsa-MGF1', hash=name, padding='pss', salt_bytes=mod.digest_size,
            message_hex=msg.hex(), signature_hex=sig.hex(), signature_base64=b64(sig), public_key_pem=rsa.public_key().export_key().decode())
    # The parameterized URI defaults to SHA-256, MGF1-SHA256, salt 32, trailer 1.
    default = next(v for v in records if v['id']=='pss-sha256').copy()
    default.update(id='pss-default-parameters', uri=M07+'rsa-pss', parameters_xml='<pss:RSAPSSParams xmlns:pss="'+M07+'"/>')
    records.append(default)
    for curve in ('P-256', 'P-384', 'P-521'):
        key = ECC.generate(curve=curve, randfunc=rng(curve))
        for name in ('sha1','sha224','sha256','sha384','sha512','sha3-224','sha3-256','sha3-384','sha3-512'):
            sig = DSS.new(key, 'deterministic-rfc6979', encoding='binary').sign(HASHES[name].new(msg))
            add(f'ecdsa-{curve}-{name}', 'ecdsa', (M21 if name.startswith('sha3-') else M01)+'ecdsa-'+name,
                hash=name, curve=curve, message_hex=msg.hex(), signature_hex=sig.hex(), signature_base64=b64(sig),
                public_key_pem=key.public_key().export_key(format='PEM'))
    for variant in ('ed25519','ed25519ctx','ed25519ph','ed448','ed448ph'):
        curve = 'Ed25519' if variant.startswith('ed25519') else 'Ed448'
        seed = rng(curve)(32 if curve=='Ed25519' else 57)
        key = eddsa.import_private_key(seed)
        contexts = [b''] if variant=='ed25519' else ([b'xmlsec'] if variant=='ed25519ctx' else [b'', b'xmlsec'])
        for ctx in contexts:
            data = HASHES['sha512'].new(msg) if variant=='ed25519ph' else (SHAKE256.new(msg) if variant=='ed448ph' else msg)
            sig = eddsa.new(key, 'rfc8032', context=ctx).sign(data)
            add(f'{variant}-{ctx.hex() or "empty"}', 'eddsa', M21+'eddsa-'+variant,
                variant=variant, seed_hex=seed.hex(), context_hex=ctx.hex(), public_key_hex=key.public_key().export_key(format='raw').hex(),
                message_hex=msg.hex(), signature_hex=sig.hex(), signature_base64=b64(sig))
    for mod, scheme, prefix, names in (
        (MLDSA, mldsa, 'ml-dsa', ['44','65','87']),
        (SLHDSA, slhdsa, 'slh-dsa', [f'{h}-{n}{s}' for h in ('sha2','shake') for n in (128,192,256) for s in ('s','f')]),
    ):
        for name in names:
            alg = prefix+'-'+name
            attr = alg.replace('-', '_').upper()
            if prefix=='slh-dsa': attr=attr[:-1]+attr[-1].lower()
            key = mod.generate(param_set=getattr(mod, attr), randfunc=rng(alg))
            for ctx in (b'', b'xmlsec'):
                sig = scheme.new(key, context=ctx, deterministic=True).sign(msg)
                add(alg+'-'+(ctx.hex() or 'empty'), 'pqsig', M26+alg, algorithm=alg,
                    message_hex=msg.hex(), context_hex=ctx.hex(), signature_hex=sig.hex(), signature_base64=b64(sig),
                    public_key_hex=key.pk.hex(), public_key_pem=key.public_key().export_key(format='PEM'),
                    private_key_pem=key.export_key(format='PEM'))
    for level in (512,768,1024):
        alg = f'ml-kem-{level}'
        key = MLKEM.generate(param_set=getattr(MLKEM, f'ML_KEM_{level}'), randfunc=rng(alg))
        coins = rng(alg+'-encaps')(32)
        # Pinned PyCryptodome internal hook permits reproducible encapsulation coins.
        ss, ct = key.public_key()._encaps(coins)
        add(alg, 'kem', M26+alg, algorithm=alg, coins_hex=coins.hex(), seed_hex=key.seed.hex(),
            private_key_pem=key.export_key(format='PEM'), public_key_hex=key.ek.hex(),
            ciphertext_hex=ct.hex(), ciphertext_base64=b64(ct), shared_secret_hex=ss.hex())
    for curve in ('Curve25519','Curve448'):
        a, b = [ECC.generate(curve=curve, randfunc=rng(curve+side)) for side in ('a','b')]
        ss = key_agreement(static_priv=a, static_pub=b.public_key(), kdf=lambda x:x)
        name='x25519' if curve=='Curve25519' else 'x448'
        add(name, 'agreement', M21+name, algorithm=name,
            private_key_pem=a.export_key(format='PEM', use_pkcs8=True), peer_public_key_hex=b.public_key().export_key(format='raw').hex(), shared_secret_hex=ss.hex())
    for i, (salt, info, length) in enumerate([(bytes(range(13)), bytes(range(240,250)),42),(b'',b'',32),(b'salt',b'info',8160)]):
        ikm=bytes([11])*22
        out=HKDF(ikm,length,salt,HASHES['sha256'],context=info)
        add(f'hkdf-{i}', 'hkdf', M21+'hkdf', hash='sha256', ikm_hex=ikm.hex(), salt_hex=salt.hex(), info_hex=info.hex(), length_bytes=length, output_hex=out.hex())
    for i, msg in enumerate(messages):
        key, nonce= rng(f'chacha-key-{i}')(32), rng(f'chacha-nonce-{i}')(12)
        c=ChaCha20.new(key=key,nonce=nonce); c.seek(64)
        ct=c.encrypt(msg)
        add(f'chacha20-{i}', 'chacha20', M21+'chacha20', key_hex=key.hex(), nonce_hex=nonce.hex(), counter=1, message_hex=msg.hex(), output_hex=ct.hex())
        for aad in (b'', b'XML AAD'):
            c=ChaCha20_Poly1305.new(key=key,nonce=nonce); c.update(aad)
            ct,tag=c.encrypt_and_digest(msg)
            add(f'chacha20poly1305-{i}-{aad.hex() or "empty"}', 'aead', M21+'chacha20poly1305', key_hex=key.hex(), nonce_hex=nonce.hex(), aad_hex=aad.hex(), message_hex=msg.hex(), ciphertext_hex=ct.hex(), tag_hex=tag.hex(), cipher_value_base64=b64(ct+tag))
    key=b'Key'; msg=b'Plaintext'
    add('arcfour-reference', 'arcfour', M01+'arcfour', key_hex=key.hex(), message_hex=msg.hex(), output_hex=ARC4.new(key).encrypt(msg).hex())
    generate_blocks(add)
    save('vectors/primitives.json', {'draft':DRAFT, 'test_only':True, 'vectors':records})
    generate_contexts()
    generate_xml(rsa)
    catalog(records)
    print(f'Generated {len(records)} primitive vectors')

def generate_blocks(add):
    from .block import cipher, wrap
    from cryptography.hazmat.primitives.ciphers import modes
    for name, bits, uri in [('camellia', n, M01) for n in (128,192,256)]+[('seed',128,M07)]:
        key=rng(name+str(bits))(bits//8)
        for length in (0,1,15,16,17,32):
            msg=bytes(range(length)); iv=rng(f'{name}{bits}-{length}')(16)
            padlen=16-len(msg)%16
            padding=rng(f'padding-{name}{bits}-{length}')(padlen-1)+bytes([padlen])
            padded=msg+padding
            enc=cipher(name,key,modes.CBC(iv)).encryptor()
            ct=enc.update(padded)+enc.finalize()
            add(f'{name}{bits}-cbc-{length}','cbc',uri+f'{name}{bits}-cbc',
                cipher=name,key_hex=key.hex(),iv_hex=iv.hex(),message_hex=msg.hex(),
                padded_plaintext_hex=padded.hex(),ciphertext_hex=ct.hex(),cipher_value_base64=b64(iv+ct))
        for length in (16,24,32):
            msg=bytes(range(length)); ct=wrap(name,key,msg)
            add(f'kw-{name}{bits}-{length}','wrap',uri+f'kw-{name}{bits}',
                cipher=name,key_hex=key.hex(),message_hex=msg.hex(),output_hex=ct.hex(),output_base64=b64(ct))


def generate_contexts():
    vectors=[]
    def add(id, uri=M26+'ml-dsa-65', contexts=(), app=None, valid=True, expected=b''):
        root=etree.Element('{'+DS+'}SignatureMethod', nsmap={'ds':DS,'more':M26}, Algorithm=uri)
        for value in contexts:
            etree.SubElement(root,'{'+M26+'}SignatureContext').text=value
        vectors.append(dict(id=id, xml=etree.tostring(root).decode(), application_context_hex=None if app is None else app.hex(), valid=valid, expected_context_hex=expected.hex()))
    add('absent-empty'); add('explicit-empty',contexts=[''])
    add('nonempty',contexts=[b64(b'xmlsec')],expected=b'xmlsec')
    add('matching-application',contexts=[b64(b'xmlsec')],app=b'xmlsec',expected=b'xmlsec')
    add('mismatched-application',contexts=[b64(b'xmlsec')],app=b'other',valid=False)
    add('absent-required-by-application',app=b'xmlsec',valid=False)
    add('empty-application-mismatch',contexts=[b64(b'xmlsec')],app=b'',valid=False)
    add('maximum-255',contexts=[b64(bytes(range(255)))],expected=bytes(range(255)))
    add('too-long-256',contexts=[b64(bytes(range(256)))],valid=False)
    add('duplicate',contexts=['',''],valid=False)
    add('invalid-base64',contexts=['!!!!'],valid=False)
    add('whitespace',contexts=[' eG1s\nc2Vj '],expected=b'xmlsec')
    add('ed25519-forbids-even-empty',uri=M21+'eddsa-ed25519',contexts=[''],valid=False)
    add('rsa-forbids-context',uri=M01+'rsa-sha256',contexts=[''],valid=False)
    add('unknown-forbids-context',uri=M26+'ml-dsa-999',contexts=[''],valid=False)
    add('ed25519ctx-missing',uri=M21+'eddsa-ed25519ctx',valid=False)
    add('ed25519ctx-empty',uri=M21+'eddsa-ed25519ctx',contexts=[''],valid=False)
    add('ed25519ctx-present',uri=M21+'eddsa-ed25519ctx',contexts=[b64(b'xmlsec')],expected=b'xmlsec')
    save('vectors/contexts.json',{'draft':DRAFT,'vectors':vectors})

def generate_xml(rsa):
    directory=ROOT/'vectors/xml'; directory.mkdir(exist_ok=True)
    manifest=[]
    specs=[('rsa-'+h, rsa.export_key(pkcs=8), h) for h in ('sha224','sha256','sha384','sha512')]
    for curve in ('P-256','P-384','P-521'):
        key=ECC.generate(curve=curve,randfunc=rng('xml-'+curve))
        for h in ('sha256','sha384','sha512'):
            specs.append(('ecdsa-'+h, key.export_key(format='PEM',use_pkcs8=True), h))
    for h in ('sha224','sha256','sha384','sha512','sha3-224','sha3-256','sha3-384','sha3-512'):
        specs.append((h+'-rsa-MGF1',rsa.export_key(pkcs=8),h))
    specs=[(*spec,C14N) for spec in specs]
    for c14n in (C14N+'WithComments','http://www.w3.org/2006/12/xml-c14n11','http://www.w3.org/2006/12/xml-c14n11#WithComments'):
        specs.append(('rsa-sha256',rsa.export_key(pkcs=8),'sha256',c14n))
    for i,(alg,key,hash_name,c14n) in enumerate(specs):
        root=etree.fromstring(b'<Envelope xmlns="urn:xmlsec:test"><Payload Id="payload">Hello, XML security!</Payload></Envelope>')
        signed=XMLSigner(method=methods.enveloped,signature_algorithm=alg,digest_algorithm=hash_name,c14n_algorithm=c14n).sign(root,key=key,reference_uri='#payload')
        file=f'xml/{i:02}-{alg}.xml'
        (ROOT/'vectors'/file).write_bytes(etree.tostring(signed))
        si=signed.find('.//{'+DS+'}SignedInfo')
        pub = RSA.import_key(key).public_key().export_key().decode() if 'rsa' in alg else ECC.import_key(key).public_key().export_key(format='PEM')
        manifest.append({'file':file,'public_key_pem':pub,'canonicalization_uri':c14n,'uri':si.find('{'+DS+'}SignatureMethod').get('Algorithm'),'canonical_signed_info_base64':b64(etree.tostring(si,method='c14n',exclusive='xml-exc-c14n' in c14n,with_comments=c14n.endswith('WithComments')))})
    save('vectors/xml-signatures.json',{'draft':DRAFT,'vectors':manifest})

def catalog(records):
    source=(ROOT/'references'/('xmlsec-draft-11.txt')).read_text()
    body=source[source.index('\n3.  Algorithms\n'):source.index('\n5.  Indexes\n')]
    section=None; rows={}
    for line in body.splitlines():
        match=re.match(r'^(\d+(?:\.\d+)*\.)\s+(.+)$',line)
        if match: section=match.group(1).rstrip('.')
        match=re.match(r'^\s+(http://www\.w3\.org/[^\s<>"\)]+)\s*$',line)
        if match and not match.group(1).endswith('#'):
            uri=match.group(1)
            rows.setdefault(uri,{'uri':uri,'section':section})
    for v in records:
        rows.setdefault(v['uri'],{'uri':v['uri'],'section':'5 (index / baseline)'})
    xml_uris={v['uri'] for v in __import__('json').loads((ROOT/'vectors/xml-signatures.json').read_text())['vectors']}
    for uri,row in rows.items():
        row['primitive_vector_ids']=[v['id'] for v in records if v['uri']==uri]
        row['xml_signature_fixture']=uri in xml_uris
        row['status']='implemented' if row['primitive_vector_ids'] else 'gap'
        if row['status']=='gap': row['reason']='No executable cryptographic fixture yet; URI inventory only.'
    save('vectors/coverage.json',{'draft':DRAFT,'scope':'Standalone URI lines in sections 3–4, plus tested baseline URIs; not the entire section 5 registry.', 'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'algorithms':list(rows.values())})

if __name__=='__main__': generate()
