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
try:
    import utime as time
    from utime import localtime as gmt_time
except ImportError:
    import time
    from time import localtime as gmt_time


class SignatureException(Exception):
    pass


def httpdate(dt):
    """Return a string representation of a date according to RFC 1123
    (HTTP/1.1).
    The supplied date must be in UTC.
    """
    try:
        dt_year, dt_month, dt_day, dt_hour, dt_minute, dt_second, dt_weekday, dt_y = dt
    except ValueError:
        dt_year, dt_month, dt_day, dt_hour, dt_minute, dt_second, dt_weekday, dt_y, _ = dt
    del(dt)
    weekday = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][dt_weekday]
    month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
             "Oct", "Nov", "Dec"][dt_month - 1]
    return "%s, %02d %s %04d %02d:%02d:%02d GMT" % (weekday, dt_day, month,
        dt_year, dt_hour, dt_minute, dt_second)


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
    try:
        unsigned = { 'Host': host_port, 'Date': time.strftime('%a, %d %b %Y %H:%M:%S GMT')}
    except AttributeError:
        unsigned = { 'Host': host_port, 'Date': httpdate(gmt_time()),}
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
