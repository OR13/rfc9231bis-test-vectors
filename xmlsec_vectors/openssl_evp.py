"""Small ctypes bridge to explicit OpenSSL EVP and native RFC3394 modes.

Used where the openssl CLI cannot express AEAD or a variable-length RC4 key.
No cryptographic algorithm is implemented in Python. Not a production API.
"""
import ctypes as C
import ctypes.util
import os
from pathlib import Path
import shutil
from contextlib import contextmanager
from functools import lru_cache
from .common import openssl


class OpenSSLError(RuntimeError):
    pass


class Rejected(ValueError):
    """An authentication tag or wrapping integrity check was rejected."""


def library_path():
    if os.environ.get('OPENSSL_LIBCRYPTO'):
        return os.environ['OPENSSL_LIBCRYPTO']
    executable = shutil.which(os.environ.get('OPENSSL', 'openssl'))
    if not executable:
        raise OpenSSLError('OpenSSL executable not found')
    prefix = Path(executable).resolve().parent.parent
    for folder in ('lib', 'lib64'):
        for name in ('libcrypto.3.dylib', 'libcrypto.so.3', 'libcrypto.so'):
            candidate = prefix / folder / name
            if candidate.exists():
                return str(candidate)
    found = ctypes.util.find_library('crypto')
    if not found:
        raise OpenSSLError('Set OPENSSL_LIBCRYPTO to the libcrypto used by OPENSSL')
    return found


class EVP:
    def __init__(self):
        self.path = library_path()
        self.lib = C.CDLL(self.path)
        ptr, integer = C.c_void_p, C.c_int
        self.block_type = C.CFUNCTYPE(None, ptr, ptr, ptr)
        signatures = {
            'OpenSSL_version': (C.c_char_p, [integer]),
            'OSSL_LIB_CTX_new': (ptr, []),
            'OSSL_PROVIDER_load': (ptr, [ptr, C.c_char_p]),
            'ERR_clear_error': (None, []),
            'ERR_get_error': (C.c_ulong, []),
            'ERR_error_string_n': (None, [C.c_ulong, ptr, C.c_size_t]),
            'EVP_CIPHER_fetch': (ptr, [ptr, C.c_char_p, C.c_char_p]),
            'EVP_CIPHER_free': (None, [ptr]),
            'EVP_CIPHER_CTX_new': (ptr, []),
            'EVP_CIPHER_CTX_free': (None, [ptr]),
            'EVP_CIPHER_CTX_set_key_length': (integer, [ptr, integer]),
            'EVP_CIPHER_CTX_set_padding': (integer, [ptr, integer]),
            'EVP_CIPHER_CTX_ctrl': (integer, [ptr, integer, integer, ptr]),
            'EVP_CipherInit_ex2': (integer, [ptr, ptr, ptr, ptr, integer, ptr]),
            'EVP_CipherUpdate': (integer, [ptr, ptr, C.POINTER(integer), ptr, integer]),
            'EVP_CipherFinal_ex': (integer, [ptr, ptr, C.POINTER(integer)]),
            'CRYPTO_128_wrap': (C.c_size_t, [ptr, ptr, ptr, ptr, C.c_size_t, self.block_type]),
            'CRYPTO_128_unwrap': (C.c_size_t, [ptr, ptr, ptr, ptr, C.c_size_t, self.block_type]),
        }
        for name, (result, arguments) in signatures.items():
            fn = getattr(self.lib, name)
            fn.restype, fn.argtypes = result, arguments
        self.version = self.lib.OpenSSL_version(0).decode()
        cli_version = openssl('version').stdout.decode().strip()
        # Do not silently mix the system libcrypto with a different selected CLI.
        if self.version.split()[:2] != cli_version.split()[:2]:
            raise OpenSSLError(f'CLI/libcrypto version mismatch: {cli_version} / {self.version}; set OPENSSL_LIBCRYPTO')
        # Keep this isolated context/providers alive for the lifetime of the cached bridge.
        self.context = self.lib.OSSL_LIB_CTX_new()
        if not self.context:
            raise OpenSSLError('Cannot allocate OpenSSL library context')
        self.providers = [self.lib.OSSL_PROVIDER_load(self.context, name) for name in (b'default', b'legacy')]
        if not all(self.providers):
            raise OpenSSLError('OpenSSL default and legacy providers are required')

    def check(self, ok):
        if ok == 1:
            return
        messages = []
        while error := self.lib.ERR_get_error():
            buf = C.create_string_buffer(256)
            self.lib.ERR_error_string_n(error, buf, len(buf))
            messages.append(buf.value.decode())
        raise OpenSSLError('; '.join(messages) or 'OpenSSL EVP operation failed')

    @contextmanager
    def cipher(self, name, key, iv=None, decrypt=False, aead=False):
        self.lib.ERR_clear_error()
        method = self.lib.EVP_CIPHER_fetch(self.context, name.encode(), None)
        if not method:
            raise OpenSSLError('OpenSSL cipher unavailable: ' + name)
        ctx = self.lib.EVP_CIPHER_CTX_new()
        try:
            if not ctx:
                raise OpenSSLError('Cannot allocate cipher context')
            self.check(self.lib.EVP_CipherInit_ex2(ctx, method, None, None, int(not decrypt), None))
            self.check(self.lib.EVP_CIPHER_CTX_set_key_length(ctx, len(key)))
            if aead:
                self.check(self.lib.EVP_CIPHER_CTX_ctrl(ctx, 0x9, len(iv), None))
            self.check(self.lib.EVP_CipherInit_ex2(ctx, None, key, iv, int(not decrypt), None))
            self.check(self.lib.EVP_CIPHER_CTX_set_padding(ctx, 0))
            yield ctx
        finally:
            if ctx:
                self.lib.EVP_CIPHER_CTX_free(ctx)
            self.lib.EVP_CIPHER_free(method)

    def crypt(self, name, key, data, iv=None, *, decrypt=False, aad=None, tag=None):
        aead = aad is not None
        with self.cipher(name, key, iv, decrypt, aead) as ctx:
            length = C.c_int()
            output = C.create_string_buffer(len(data) + 32)
            if aead:
                self.check(self.lib.EVP_CipherUpdate(ctx, None, C.byref(length), aad, len(aad)))
            self.check(self.lib.EVP_CipherUpdate(ctx, output, C.byref(length), data, len(data)))
            count = length.value
            if aead and decrypt:
                if tag is None or len(tag) != 16:
                    raise ValueError('ChaCha20-Poly1305 requires a 16-byte tag')
                self.check(self.lib.EVP_CIPHER_CTX_ctrl(ctx, 0x11, len(tag), tag))
            ok = self.lib.EVP_CipherFinal_ex(ctx, C.byref(output, count), C.byref(length))
            if aead and decrypt and ok != 1:
                self.lib.ERR_clear_error()
                raise Rejected('OpenSSL rejected the AEAD tag')
            self.check(ok)
            result = output.raw[:count + length.value]
            if aead and not decrypt:
                tagbuf = C.create_string_buffer(16)
                self.check(self.lib.EVP_CIPHER_CTX_ctrl(ctx, 0x10, 16, tagbuf))
                return result, tagbuf.raw
            return result

    def keywrap(self, name, key, data, *, decrypt=False):
        """Native OpenSSL wrapping mode with an EVP block-cipher callback.

        CRYPTO_128_wrap/unwrap performs the entire RFC3394 mode/integrity check;
        the callback supplies only one OpenSSL-encrypted/decrypted block.
        """
        with self.cipher(name, key, decrypt=decrypt) as ctx:
            failures = []
            @self.block_type
            def block(source, destination, unused_key):
                # Never propagate a Python exception through a C callback.
                length = C.c_int()
                ok = self.lib.EVP_CipherUpdate(ctx, destination, C.byref(length), source, 16)
                if ok != 1 or length.value != 16:
                    failures.append('EVP block operation failed')
            output = C.create_string_buffer(len(data) + 8)
            operation = self.lib.CRYPTO_128_unwrap if decrypt else self.lib.CRYPTO_128_wrap
            count = operation(None, None, output, data, len(data), block)
            if failures:
                raise OpenSSLError(failures[0])
            if count == 0:
                raise Rejected('OpenSSL rejected wrapped key integrity or length')
            return output.raw[:count]


@lru_cache(maxsize=1)
def evp():
    return EVP()
