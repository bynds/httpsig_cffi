
try:
    import ure as re
except ImportError:
    import re
import struct
#import uhashlib as hashlib
import base64
#import six
import gc

#try:
    ## Python 3
from urllib.request import parse_http_list
#except ImportError:
    ## Python 2
    #from urllib2 import parse_http_list

#from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA512
#from uhashlib import sha1, sha256

# We need to pass in the function name because MicroPython doesn't
# supprt the __name__ atribute on methods
def CheapLogger(func_name):
    def wrap(func):
        def new_func(*args, **kwds):
            gc.collect()
            print("Entering: {} with freemem: {}".format(func_name, gc.mem_free()))
            ret_val = func(*args, **kwds)
            gc.collect()
            print("Exited: {} with freemem: {}".format(func_name, gc.mem_free()))
            return ret_val
        return new_func
    return wrap

# This decorator can be used to force a Garbage Collect before and after
# the wrapped function. Note: This uses more ram than using collect in the
# wrapped function. And yes, it's Grimm not Grim.
def GrimmReaper(func):
    def new_func(*args, **kwds):
        gc.collect()
        ret_val = func(*args, **kwds)
        gc.collect()
        return ret_val
    return new_func

# TODO RSA cannot be reintroduced without this changing again.
#ALGORITHMS = frozenset(['rsa-sha1', 'rsa-sha256', 'rsa-sha512', 'hmac-sha1', 'hmac-sha256', 'hmac-sha512'])
ALGORITHMS = frozenset(['hmac-sha1', 'hmac-sha256'])
HASHES = {'sha1':   'sha1',
          'sha256': 'sha256'}#,
          #'sha512': SHA512}


class HttpSigException(Exception):
    pass

#@CheapLogger('generate_message')
def generate_message(required_headers, headers, host=None, method=None, path=None):
        
    if not required_headers:
        required_headers = ['date']
    
    signable_list = []
    for h in required_headers:
        h = h.lower()
        if h == '(request-target)':
            if not method or not path:
                gc.collect()
                raise Exception('method and path arguments required when using "(request-target)"')
            signable_list.append('%s: %s %s' % (h, method.lower(), path))
        
        elif h == 'host':
            # 'host' special case due to requests lib restrictions
            # 'host' is not available when adding auth so must use a param
            # if no param used, defaults back to the 'host' header
            if not host:
                if 'host' in headers:
                    host = headers[h]
                else:
                    gc.collect()
                    raise Exception('missing required header "%s"' % (h))
            signable_list.append('%s: %s' % (h, host))
        else:
            if h not in headers:
                gc.collect()
                raise Exception('missing required header "%s"' % (h))

            signable_list.append('%s: %s' % (h, headers[h]))

    signable = '\n'.join(signable_list).encode("ascii")
    gc.collect()
    return signable

#@CheapLogger('parse_authorization_header')
def parse_authorization_header(header):
    #if not isinstance(header, six.string_types):
        #header = header.decode("ascii") #HTTP headers cannot be Unicode.
    if isinstance(header, (bytes, bytearray)):
        header = str(header)
    
    auth = header.split(" ", 1)
    if len(auth) > 2:
        gc.collect()
        raise ValueError('Invalid authorization header. (eg. Method key1=value1,key2="value, \"2\"")')
    
    # Split up any args into a dictionary.
    values = {}
    if len(auth) == 2:
        auth_value = auth[1]
        if auth_value and len(auth_value):
            # This is tricky string magic.  Let urllib do it.
            fields = parse_http_list(auth_value)
        
            for item in fields:
                # Only include keypairs.
                if '=' in item:
                    # Split on the first '=' only.
                    key, value = item.split('=', 1)
                    if not (len(key) and len(value)):
                        continue
                    
                    # Unquote values, if quoted.
                    if value[0] == '"':
                        value = value[1:-1]
                
                    values[key] = value
    
    # ("Signature", {"headers": "date", "algorithm": "hmac-sha256", ... })
    gc.collect()
    return (auth[0], values)

#@CheapLogger('build_signature_template')
def build_signature_template(key_id, algorithm, headers):
    """
    Build the Signature template for use with the Authorization header.

    key_id is the mandatory label indicating to the server which secret to use
    algorithm is one of the six specified algorithms
    headers is a list of http headers to be included in the signing string.

    The signature must be interpolated into the template to get the final Authorization header value.
    """
    param_map = {'keyId': key_id,
                 'algorithm': algorithm,
                 'signature': '%s'}
    if headers:
        headers = [h.lower() for h in headers]
        param_map['headers'] = ' '.join(headers)
    kv = ['{0}="{1}"'.format(key, value) for key,value in param_map.items()]
    kv_string = ','.join(kv)
    sig_string = 'Signature {0}'.format(kv_string)
    gc.collect()
    return sig_string


def lkv(d):
    parts = []
    while d:
            len = struct.unpack('>I', d[:4])[0]
            bits = d[4:len+4]
            parts.append(bits)
            d = d[len+4:]
    gc.collect()
    return parts

def sig(d):
    gc.collect()
    return lkv(d)[1]

# TODO RSA cannot be reintroduced without this changing again.
#def is_rsa(keyobj):
    #return lkv(keyobj.blob)[0] == "ssh-rsa"

# based on http://stackoverflow.com/a/2082169/151401
# No amount of messing around got the below working on MicroPython
#class CaseInsensitiveDict(dict):
    ##@CheapLogger('CaseInsensitiveDict.init')
    #def __init__(self, d=None, **kwargs):
        #super(CaseInsensitiveDict, self).__init__(**kwargs)
        #if d:
            ##self.update((k.lower(), v) for k, v in six.iteritems(d))
            #for k, v in d.items():
                #print("key is {} and value is {}".format(k, v))
            #self.update((k.lower(), v) for k, v in d.items())
            #try:
                #self.pop(k)
            #except KeyError:
                ## Python 3 -> MicroPython implementation difference
                #pass
            #print('done')

    ##@CheapLogger('CaseInsensitiveDict.setitem')
    #def __setitem__(self, key, value):
        #print("key is {} and value is ".format(key, value))
        #super(CaseInsensitiveDict, self).__setitem__(key.lower(), value)

    ##@CheapLogger('CaseInsensitiveDict.getitem')
    #def __getitem__(self, key):
        #return super(CaseInsensitiveDict, self).__getitem__(key.lower())

    ##@CheapLogger('CaseInsensitiveDict.contains')
    #def __contains__(self, key):
        #dir(super)
        #return super(CaseInsensitiveDict, self).__contains__(key.lower())

# currently busted...
#def get_fingerprint(key):
    #"""
    #Takes an ssh public key and generates the fingerprint.

    #See: http://tools.ietf.org/html/rfc4716 for more info
    #"""
    #if key.startswith('ssh-rsa'):
        #key = key.split(' ')[1]
    #else:
        #regex = r'\-{4,5}[\w|| ]+\-{4,5}'
        #key = re.split(regex, key)[1]

    #key = key.replace('\n', '')
    #key = key.strip().encode('ascii')
    #key = base64.b64decode(key)
    #fp_plain = hashlib.md5(key).hexdigest()
    #return ':'.join(a+b for a,b in zip(fp_plain[::2], fp_plain[1::2]))


