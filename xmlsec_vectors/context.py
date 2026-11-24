"""Draft section 3.3.17 parameter validation, not a signature verifier."""
import base64
import binascii
from lxml import etree
from .common import DS, M21, M26

CONTEXT_ALGORITHMS = {
    M21 + 'eddsa-' + name for name in ('ed25519ctx', 'ed25519ph', 'ed448', 'ed448ph')
} | {M26 + 'ml-dsa-' + n for n in ('44', '65', '87')} | {
    M26 + f'slh-dsa-{h}-{n}{s}'
    for h in ('sha2', 'shake') for n in (128, 192, 256) for s in ('s', 'f')
}

def resolve_context(xml, application_context=None):
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    root = etree.fromstring(xml.encode(), parser)
    if root.tag != '{' + DS + '}SignatureMethod':
        raise ValueError('expected ds:SignatureMethod')
    nodes = root.findall('{' + M26 + '}SignatureContext')
    if len(nodes) > 1:
        raise ValueError('duplicate context')
    algorithm = root.get('Algorithm')
    if nodes and algorithm not in CONTEXT_ALGORITHMS:
        raise ValueError('context forbidden for algorithm')
    if nodes:
        if len(nodes[0]):
            raise ValueError('context must be simple content')
        # XML Schema base64Binary permits only XML whitespace.
        encoded = (nodes[0].text or '').translate(str.maketrans('', '', ' \t\r\n'))
        try:
            context = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError('invalid base64 context') from exc
        if base64.b64encode(context).decode() != encoded:
            raise ValueError('noncanonical base64 padding bits')
    else:
        context = b''
    if len(context) > 255:
        raise ValueError('context exceeds 255 octets')
    if algorithm == M21 + 'eddsa-ed25519ctx' and not context:
        raise ValueError('ed25519ctx requires nonempty context in this draft')
    if application_context is not None and context != application_context:
        raise ValueError('application context mismatch')
    return context
