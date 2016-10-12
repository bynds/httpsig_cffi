from .sign import HeaderSigner


class HTTPSignatureAuth:
    '''
    Sign a request using the http-signature scheme.
    https://github.com/joyent/node-http-signature/blob/master/http_signing.md

    key_id is the mandatory label indicating to the server which secret to use
    secret is the filename of a pem file in the case of rsa, a password string in the case of an hmac algorithm
    algorithm is one of the six specified algorithms
    headers is a list of http headers to be included in the signing string, defaulting to "Date" alone.
    '''
    def __init__(self, key_id='', secret='', algorithm=None, headers=None):
        headers = headers or []
        self.header_signer = HeaderSigner(key_id=key_id, secret=secret,
                algorithm=algorithm, headers=headers)
        #self.uses_host = 'host' in [h.lower() for h in headers]

    def __call__(self, r):
        headers = self.header_signer.sign(
                r.headers,
                # 'Host' header must be passed in as part of the request object (r)
                host=r.host,
                method=r.method,
                path=r.path_url)
        return headers
