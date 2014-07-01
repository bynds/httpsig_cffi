"""
Module to assist in verifying a signed header.
"""
from Crypto.Hash import HMAC
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from base64 import b64decode

from .sign import Signer
from .utils import generate_message, sig, is_rsa, CaseInsensitiveDict, ALGORITHMS, HASHES, HttpSigException


class Verifier(Signer):
    """
    Verifies signed text against a secret.
    For HMAC, the secret is the shared secret.
    For RSA, the secret is the PUBLIC key.
    """
    def _verify(self, data, signature):
        """
        Verifies the data matches a signed version with the given signature.
        `data` is the message to verify
        `signature` is a base64-encoded signature to verify against `data`
        """
        
        if self.sign_algorithm == 'rsa':
            # Verify RSA
            h = self._hash.new()
            h.update(data)
            
            if self._rsa.verify(h, b64decode(signature)):
                return True
            else:
                return False
        
        elif self.sign_algorithm == 'hmac':
            # Verify HMAC
            h = self._sign_hmac(data)
            return (h == b64decode(signature))
        
        else:
            # Unknown algo
            raise HttpSigException("Unknown signing algorithm.")


class HeaderVerifier(Verifier):
    """
    Verifies an HTTP signature from given headers.
    """
    def __init__(self, headers, secret, required_headers=None, method=None, path=None, host=None):

        required_headers = required_headers or ['date']
        self.auth_dict = self.parse_auth(headers['authorization'])
        self.headers = CaseInsensitiveDict(headers)
        self.required_headers = [s.lower() for s in required_headers]
        self.method = method
        self.path = path
        self.host = host
        
        super(HeaderVerifier, self).__init__(secret, algorithm=self.auth_dict['algorithm'])

    def parse_auth(self, auth):
        """
        Basic Authorization header parsing.
        FIXME: Fails if there is a comma inside a quoted string.
        """
        # split 'Signature kvpairs'
        s, param_str = auth.split(' ', 1)
        
        # split k1="v1",k2="v2",...
        param_list = param_str.split(',')
        
        # convert into [(k1,"v1"), (k2, "v2"), ...]
        param_pairs = [p.split('=', 1) for p in param_list]
        
        # convert into {k1:v1, k2:v2, ...}
        param_dict = {k: v.strip('"') for k, v in param_pairs}
        
        return param_dict

    def get_signable(self):
        """Get the string that is signed"""
        header_dict = self.parse_auth(self.headers['authorization'])
        if self.auth_dict.get('headers'):
            auth_headers = self.auth_dict.get('headers').split(' ')
        else:
            auth_headers = ['date']
        
        if len(set(self.required_headers) - set(auth_headers)) > 0:
            raise Exception('{} is a required header(s)'.format(', '.join(set(self.required_headers)-set(auth_headers))))
        
        signable = generate_message(auth_headers, self.headers, self.host, self.method, self.path)

        return signable

    def verify(self):
        signing_str = self.get_signable()
        return self._verify(signing_str, self.auth_dict['signature'])
