try:
    import urequests as requests
except ImportError:
    import requests
try:
    import uhmac as hmac
except ImportError:
    import hmac
try:
    from uhttp_signature import sign
except ImportError:
    import httpsig.sign as sign


class SignatureException(Exception):
    pass


def make_request(url, key_id, secret, method='GET', debug=False, headers=None, **kwargs):
    try:
        # http://server.name:8000/path/and/more?attributes=True
        host_port, path = url.split('//')[1].split('/', 1)
    except ValueError:
        # http://server.name:8000
        host_port = url.split('//')[1].split('/', 1)[0]
        path = ''
    path = '/' + path

    hs = sign.HeaderSigner(key_id=key_id, secret=secret, headers=['(request-target)', 'host', 'date'])
    unsigned = { 'Host': host_port, 'Date': time.strftime('%a, %d %b %Y %H:%M:%S GMT')}
    lower_signed = hs.sign(unsigned, method=method, path=path)
    signed = {}
    signed.update({k[0:1:].upper()+k[1::]: v for k, v in lower_signed.items()})
    del lower_signed

    if headers:
        signed.update(headers)

    try:
        return getattr(requests, method.lower())(url, headers=signed, debug=debug, **kwargs)
    except TypeError:
        return getattr(requests, method.lower())(url, headers=signed, **kwargs)


def make_validated_request(url, key_id, secret, method='GET', debug=False, headers=None, **kwargs):
    response = make_request(url, key_id, secret, method=method, debug=debug, headers=headers, **kwargs)
    if not hasattr(response, 'content_hmac'):
        if response.content == b'{"detail":"Invalid signature."}':
            raise SignatureException('Request is rejected: Invalid signature')
        raise SignatureException('Response is not signed')
    if not hmac.compare_digest(response.content_hmac.encode('ascii'), hmac.new(secret, msg=b'date: '+response.date+response.text).hexdigest()):
        raise SignatureException('Invalid response signature')
    return response
