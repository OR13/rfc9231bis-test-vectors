"""Cross-check stored vectors; never regenerate expected values during verification."""
import hashlib
import hmac
import json
import tempfile
from pathlib import Path
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils, x25519, x448
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.PublicKey import RSA
from Crypto.Signature import pss, eddsa
from Crypto.Hash import MD2
from .common import *

def altered(data):
    return bytes([data[0]^1])+data[1:] if data else b'\x01'

def require_rejection(call, errors=(InvalidSignature, ValueError)):
    try: call()
    except errors: return
    raise AssertionError('corrupted input was accepted')

def verify_primitive(v):
    def raw(name): return bytes.fromhex(v[name])
    kind=v['kind']; msg=raw('message_hex') if 'message_hex' in v else None
    if 'output_base64' in v: assert un64(v['output_base64'])==raw('output_hex')
    if 'signature_base64' in v: assert un64(v['signature_base64'])==raw('signature_hex')
    if kind=='digest':
        if v['hash']=='whirlpool':
            result=openssl('dgst','-provider','default','-provider','legacy','-whirlpool','-binary',data=msg).stdout
            backend='OpenSSL (same implementation as generator)'
        else:
            result=hashlib.new(v['hash'].replace('-','_'),msg).digest(); backend='Python hashlib (explicit OpenSSL audit recorded separately)'
        assert result==raw('output_hex'); return backend
    if kind=='hmac':
        result=hmac.new(raw('key_hex'),msg,v['hash']).digest()[:v['output_bits']//8]
        assert result==raw('output_hex'); return 'Python hmac/hashlib (explicit OpenSSL audit recorded separately)'
    if kind=='poly1305':
        assert Poly1305.generate_tag(raw('key_hex'),msg)==raw('output_hex')
        require_rejection(lambda:Poly1305.verify_tag(raw('key_hex'),msg,altered(raw('output_hex'))))
        return 'cryptography/OpenSSL against RFC 8439'
    if kind=='siphash':
        out=openssl('mac','-macopt','hexkey:'+v['key_hex'],'-macopt','size:8','-macopt','c-rounds:2','-macopt','d-rounds:4','-binary','SIPHASH',data=msg).stdout
        assert out==raw('output_hex'); return 'OpenSSL against SipHash reference'
    if kind=='rsa' and v['hash']=='md2':
        pub=RSA.import_key(v['public_key_pem'])
        verifier=pss.new(pub,salt_bytes=v['salt_bytes'])
        verifier.verify(MD2.new(msg),raw('signature_hex'))
        require_rejection(lambda:verifier.verify(MD2.new(altered(msg)),raw('signature_hex')))
        return 'PyCryptodome (same implementation; no independent MD2 backend)'
    if kind in ('rsa','eddsa','pqsig'):
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp); key=tmp/'public.pem'; sig=tmp/'sig'; data=tmp/'msg'
            pem=v.get('public_key_pem')
            if kind=='eddsa': pem=eddsa.import_public_key(raw('public_key_hex')).export_key(format='PEM')
            key.write_text(pem); sig.write_bytes(raw('signature_hex')); data.write_bytes(msg)
            if kind=='rsa':
                args=['dgst','-'+v['hash'],'-verify',key,'-signature',sig]
                if v['padding']=='pss': args+=['-sigopt','rsa_padding_mode:pss','-sigopt',f'rsa_pss_saltlen:{v["salt_bytes"]}']
                args+=[data]
            else:
                args=['pkeyutl','-verify','-pubin','-inkey',key,'-rawin','-in',data,'-sigfile',sig]
                if kind=='eddsa': args+=['-pkeyopt','instance:Ed'+v['variant'][2:]]
                if v['context_hex']: args+=['-pkeyopt','hexcontext-string:'+v['context_hex']]
            result=openssl(*args,check=False)
            assert result.returncode==0, result.stderr.decode()+result.stdout.decode()
            data.write_bytes(altered(msg))
            assert openssl(*args,check=False).returncode!=0
            data.write_bytes(msg); sig.write_bytes(altered(raw('signature_hex')))
            assert openssl(*args,check=False).returncode!=0
            if kind in ('eddsa','pqsig') and v['context_hex']:
                sig.write_bytes(raw('signature_hex'))
                wrong=args.copy(); wrong[-1]='hexcontext-string:77726f6e67'
                assert openssl(*wrong,check=False).returncode!=0
        return 'OpenSSL CLI'
    if kind=='ecdsa':
        key=serialization.load_pem_public_key(v['public_key_pem'].encode())
        sig=raw('signature_hex'); size=(key.curve.key_size+7)//8
        assert len(sig)==2*size
        der=utils.encode_dss_signature(int.from_bytes(sig[:size],'big'),int.from_bytes(sig[size:],'big'))
        hash_class=getattr(hashes,v['hash'].replace('-','_').upper())
        key.verify(der,msg,ec.ECDSA(hash_class()))
        require_rejection(lambda:key.verify(der,altered(msg),ec.ECDSA(hash_class())))
        require_rejection(lambda:key.verify(der[:-1]+bytes([der[-1]^1]),msg,ec.ECDSA(hash_class())))
        return 'cryptography/OpenSSL (XML r||s converted to DER)'
    if kind=='kem':
        assert un64(v['ciphertext_base64'])==raw('ciphertext_hex')
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp); key=tmp/'key.pem'; ct=tmp/'ct'; out=tmp/'secret'
            key.write_text(v['private_key_pem']); ct.write_bytes(raw('ciphertext_hex'))
            args=['pkeyutl','-decap','-inkey',key,'-in',ct,'-secret',out]
            openssl(*args)
            assert out.read_bytes()==raw('shared_secret_hex')
            ct.write_bytes(altered(raw('ciphertext_hex')))
            openssl(*args) # ML-KEM implicit rejection returns a different secret.
            assert out.read_bytes()!=raw('shared_secret_hex')
            ct.write_bytes(raw('ciphertext_hex')[:-1])
            assert openssl(*args,check=False).returncode!=0
        return 'OpenSSL CLI (including implicit rejection)'
    if kind=='agreement':
        key=serialization.load_pem_private_key(v['private_key_pem'].encode(),None)
        cls=x25519.X25519PublicKey if v['algorithm']=='x25519' else x448.X448PublicKey
        assert key.exchange(cls.from_public_bytes(raw('peer_public_key_hex')))==raw('shared_secret_hex')
        require_rejection(lambda:key.exchange(cls.from_public_bytes(bytes(len(raw('peer_public_key_hex'))))))
        return 'cryptography/OpenSSL'
    if kind=='hkdf':
        result=HKDF(hashes.SHA256(),v['length_bytes'],raw('salt_hex'),raw('info_hex')).derive(raw('ikm_hex'))
        assert result==raw('output_hex'); return 'cryptography/OpenSSL'
    if kind=='chacha20':
        iv=v['counter'].to_bytes(4,'little')+raw('nonce_hex')
        enc=Cipher(algorithms.ChaCha20(raw('key_hex'),iv),None).encryptor()
        assert enc.update(msg)+enc.finalize()==raw('output_hex')
        return 'cryptography/OpenSSL (RFC8439 state; counter does not overflow)'
    if kind=='aead':
        cipher=ChaCha20Poly1305(raw('key_hex')); nonce=raw('nonce_hex'); aad=raw('aad_hex')
        ct=raw('ciphertext_hex')+raw('tag_hex')
        assert ct==un64(v['cipher_value_base64'])
        assert cipher.encrypt(nonce,msg,aad)==ct
        assert cipher.decrypt(nonce,ct,aad)==msg
        require_rejection(lambda:cipher.decrypt(nonce,altered(ct),aad), (InvalidTag,))
        require_rejection(lambda:cipher.decrypt(nonce,ct,altered(aad)), (InvalidTag,))
        require_rejection(lambda:cipher.decrypt(altered(nonce),ct,aad), (InvalidTag,))
        return 'cryptography/OpenSSL'
    if kind=='cbc':
        args=['enc','-'+('seed-cbc' if v['cipher']=='seed' else f"camellia-{len(raw('key_hex'))*8}-cbc"),
              '-provider','default','-provider','legacy','-K',v['key_hex'],'-iv',v['iv_hex'],'-nopad']
        assert openssl(*args,data=raw('padded_plaintext_hex')).stdout==raw('ciphertext_hex')
        padded=openssl(*args,'-d',data=raw('ciphertext_hex')).stdout
        assert padded==raw('padded_plaintext_hex')
        assert 1<=padded[-1]<=16 and padded[:-padded[-1]]==msg
        assert un64(v['cipher_value_base64'])==raw('iv_hex')+raw('ciphertext_hex')
        return 'OpenSSL CLI (same crypto backend; explicit XML padding and IV packaging)'
    if kind=='wrap':
        from .block import unwrap
        assert unwrap(v['cipher'],raw('key_hex'),raw('output_hex'))==msg
        require_rejection(lambda:unwrap(v['cipher'],raw('key_hex'),altered(raw('output_hex'))))
        return 'local RFC3394 round trip (native OpenSSL wrapping audit recorded separately)'
    if kind=='arcfour':
        # cryptography rejects 24-bit RC4 keys: OpenSSL CLI uses fixed default key size.
        # This published 24-bit reference vector is verified with PyCryptodome only.
        from Crypto.Cipher import ARC4 as RC4
        assert RC4.new(raw('key_hex')).encrypt(msg)==raw('output_hex')==bytes.fromhex('bbf316e8d940af0ad3')
        return 'PyCryptodome / published RC4 example (OpenSSL EVP audit recorded separately)'
    raise AssertionError('Unhandled vector kind '+kind)
