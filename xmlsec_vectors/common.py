import base64
import json
import os
import subprocess
from pathlib import Path
from Crypto.Hash import SHAKE256

ROOT = Path(__file__).resolve().parents[1]
DS = 'http://www.w3.org/2000/09/xmldsig#'
ENC = 'http://www.w3.org/2001/04/xmlenc#'
M01 = 'http://www.w3.org/2001/04/xmldsig-more#'
M07 = 'http://www.w3.org/2007/05/xmldsig-more#'
M21 = 'http://www.w3.org/2021/04/xmldsig-more#'
M26 = 'http://www.w3.org/2026/08/xmldsig-more#'
DRAFT = 'draft-eastlake-rfc9231bis-xmlsec-uris-11'
C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#'

def rng(label):
    """Public deterministic TEST randomness. Never use for production keys."""
    return SHAKE256.new(data=('xmlsec-uris-11-test-only:' + label).encode()).read

def b64(value):
    return base64.b64encode(value).decode('ascii')

def un64(value):
    return base64.b64decode(value, validate=True)

def xml_un64(value):
    """Decode XML base64Binary, permitting only XML whitespace."""
    return un64(value.translate(str.maketrans('', '', ' \t\r\n')))

def save(path, value):
    (ROOT / path).write_text(json.dumps(value, indent=2) + '\n')

def openssl(*args, data=None, check=True):
    return subprocess.run([os.environ.get('OPENSSL', 'openssl'), *map(str, args)],
                          input=data, capture_output=True, check=check)
