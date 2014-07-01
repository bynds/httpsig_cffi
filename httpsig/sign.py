import base64

from Crypto.Hash import HMAC
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from .utils import generate_message, sig, is_rsa, CaseInsensitiveDict, ALGORITHMS, HASHES, HttpSigException


class Signer(object):
    """
    When using an RSA algo, the secret is a PEM-encoded private key.
    When using an HMAC algo, the secret is the HMAC signing secret.
    
    Password-protected keyfiles are not supported.
    """
    def __init__(self, secret, algorithm='rsa-sha256'):
        assert algorithm in ALGORITHMS, "Unknown algorithm"
        self._rsa = False
        self._hash = None
        self.sign_algorithm, self.hash_algorithm = algorithm.split('-')
        if self.sign_algorithm == 'rsa':
            self._rsa = self._get_key(secret)
            self._hash = HASHES[self.hash_algorithm]
        elif self.sign_algorithm == 'hmac':
            self._hash = HMAC.new(secret, digestmod=HASHES[self.hash_algorithm])

    @property
    def algorithm(self):
        return '%s-%s' % (self.sign_algorithm, self.hash_algorithm)

    def _get_key(self, secret):
        # if not (secret.startswith('-----BEGIN RSA PRIVATE KEY-----') or secret.startswith('-----BEGIN PRIVATE KEY-----')):
        #     raise HttpSigException("Invalid PEM key")
        
        try:
            rsa_key = RSA.importKey(secret)
        except ValueError:
            raise HttpSigException("Invalid key.")
        
        return PKCS1_v1_5.new(rsa_key)

    def _sign_rsa(self, sign_string):
        h = self._hash.new()
        h.update(sign_string)
        return self._rsa.sign(h)

    def _sign_hmac(self, sign_string):
        hmac = self._hash.copy()
        hmac.update(sign_string)
        return hmac.digest()

    def _sign(self, sign_string):
        data = None
        if self._rsa:
            data = self._sign_rsa(sign_string)
        elif self._hash:
            data = self._sign_hmac(sign_string)
        if not data:
            raise SystemError('No valid encryptor found.')
        return base64.b64encode(data)


class HeaderSigner(Signer):
    '''
    Generic object that will sign headers as a dictionary using the http-signature scheme.
    https://github.com/joyent/node-http-signature/blob/master/http_signing.md

    key_id is the mandatory label indicating to the server which secret to use
    secret is the filename of a pem file in the case of rsa, a password string in the case of an hmac algorithm
    algorithm is one of the six specified algorithms
    headers is a list of http headers to be included in the signing string, defaulting to ['date'].
    '''
    def __init__(self, key_id, secret, algorithm='rsa-sha256', headers=None):
        #PyCrypto wants strings, not unicode. We're not so demanding as an API.
        key_id = str(key_id)
        secret = str(secret)
        
        super(HeaderSigner, self).__init__(secret=secret, algorithm=algorithm)
        self.headers = headers
        self.signature_template = self.build_signature_template(key_id, algorithm, headers)

    def build_signature_template(self, key_id, algorithm, headers):
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
        kv = map('{0[0]}="{0[1]}"'.format, param_map.items())
        kv_string = ','.join(kv)
        sig_string = 'Signature {0}'.format(kv_string)
        return sig_string

    def sign(self, headers, host=None, method=None, path=None):
        """
        Add Signature Authorization header to case-insensitive header dict.

        headers is a case-insensitive dict of mutable headers.
        host is a override for the 'host' header (defaults to value in headers).
        method is the HTTP method (required when using '(request-line)').
        path is the HTTP path (required when using '(request-line)').
        """
        headers = CaseInsensitiveDict(headers)
        required_headers = self.headers or ['date']
        signable = generate_message(required_headers, headers, host, method, path)
        
        signature = self._sign(signable)
        headers['Authorization'] = self.signature_template % signature
        
        return headers

