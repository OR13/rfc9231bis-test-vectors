"""XML Encryption CBC padding and RFC3394-style wrap test helpers."""
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import SEED, Camellia


def cipher(name,key,mode):
    cls=SEED if name=='seed' else Camellia
    return Cipher(cls(key),mode)


def wrap(name,key,plaintext):
    if len(plaintext)<16 or len(plaintext)%8: raise ValueError('invalid key size')
    a=b'\xa6'*8; r=[plaintext[i:i+8] for i in range(0,len(plaintext),8)]
    enc=cipher(name,key,modes.ECB()).encryptor()
    for j in range(6):
        for i in range(len(r)):
            b=enc.update(a+r[i]); t=len(r)*j+i+1
            a=(int.from_bytes(b[:8],'big')^t).to_bytes(8,'big'); r[i]=b[8:]
    enc.finalize()
    return a+b''.join(r)


def unwrap(name,key,wrapped):
    if len(wrapped)<24 or len(wrapped)%8: raise ValueError('invalid wrapped size')
    a=wrapped[:8]; r=[wrapped[i:i+8] for i in range(8,len(wrapped),8)]
    dec=cipher(name,key,modes.ECB()).decryptor()
    for j in reversed(range(6)):
        for i in reversed(range(len(r))):
            t=len(r)*j+i+1
            b=dec.update((int.from_bytes(a,'big')^t).to_bytes(8,'big')+r[i])
            a=b[:8]; r[i]=b[8:]
    dec.finalize()
    if a!=b'\xa6'*8: raise ValueError('key wrap integrity failure')
    return b''.join(r)
