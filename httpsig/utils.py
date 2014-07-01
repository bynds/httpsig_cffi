import re
import struct
import hashlib
import base64

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA, SHA256, SHA512

ALGORITHMS = frozenset(['rsa-sha1', 'rsa-sha256', 'rsa-sha512', 'hmac-sha1', 'hmac-sha256', 'hmac-sha512'])
HASHES = {'sha1':   SHA,
          'sha256': SHA256,
          'sha512': SHA512}

class HttpSigException(Exception):
    pass

def generate_message(required_headers, headers, host=None, method=None, path=None):
    headers = CaseInsensitiveDict(headers)
    
    if not required_headers:
        required_headers = ['date']
    
    signable_list = []
    for h in required_headers:
        if h == '(request-line)':
            if not method or not path:
                raise Exception('method and path arguments required when using "(request-line)"')
            signable_list.append('%s: %s %s' % (h, method.lower(), path))

        elif h == 'host':
            # 'host' special case due to requests lib restrictions
            # 'host' is not available when adding auth so must use a param
            # if no param used, defaults back to the 'host' header
            if not host:
                if 'host' in headers:
                    host = headers[h]
                else:
                    raise Exception('missing required header "%s"' % (h))
            signable_list.append('%s: %s' % (h.lower(), host))
        else:
            if h not in headers:
                raise Exception('missing required header "%s"' % (h))

            signable_list.append('%s: %s' % (h.lower(), headers[h]))

    signable = '\n'.join(signable_list)
    return signable

def lkv(d):
    parts = []
    while d:
            len = struct.unpack('>I', d[:4])[0]
            bits = d[4:len+4]
            parts.append(bits)
            d = d[len+4:]
    return parts

def sig(d):
    return lkv(d)[1]

def is_rsa(keyobj):
    return lkv(keyobj.blob)[0] == "ssh-rsa"

# based on http://stackoverflow.com/a/2082169/151401
class CaseInsensitiveDict(dict):
    def __init__(self, d=None, **kwargs):
        super(CaseInsensitiveDict, self).__init__(**kwargs)
        if d:
            self.update((k.lower(), v) for k, v in d.iteritems())

    def __setitem__(self, key, value):
        super(CaseInsensitiveDict, self).__setitem__(key.lower(), value)

    def __getitem__(self, key):
        return super(CaseInsensitiveDict, self).__getitem__(key.lower())

    def __contains__(self, key):
        return super(CaseInsensitiveDict, self).__contains__(key.lower())

# currently busted...
def get_fingerprint(key):
    """
    Takes an ssh public key and generates the fingerprint.

    See: http://tools.ietf.org/html/rfc4716 for more info
    """
    if key.startswith('ssh-rsa'):
        key = key.split(' ')[1]
    else:
        regex = r'\-{4,5}[\w|| ]+\-{4,5}'
        key = re.split(regex, key)[1]

    key = key.replace('\n', '')
    key = key.strip().encode('ascii')
    key = base64.b64decode(key)
    fp_plain = hashlib.md5(key).hexdigest()
    return ':'.join(a+b for a,b in zip(fp_plain[::2], fp_plain[1::2]))

