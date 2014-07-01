httpsig
=======

Sign HTTP requests with secure signatures. See the original project_, original Python module_, original spec_, and IETF draft_ for details.

.. _project: https://github.com/joyent/node-http-signature
.. _module: https://github.com/zzsnzmn/py-http-signature
.. _spec: https://github.com/joyent/node-http-signature/blob/master/http_signing.md
.. _draft: https://datatracker.ietf.org/doc/draft-cavage-http-signatures/

Requirements
------------

* PyCrypto_

Optional:

* requests_

.. _PyCrypto: https://pypi.python.org/pypi/pycrypto
.. _requests: https://pypi.python.org/pypi/requests

Usage
-----

for simple raw signing::

    import httpsig
    
    secret = open('rsa_private.pem', 'r').read()
    
    sig_maker = httpsig.Signer(secret=secret, algorithm='rsa-sha256')
    sig_maker.sign('hello world!')

for use with requests::

    import json
    import requests
    from httpsig.requests_auth import HTTPSignatureAuth
    
    secret = open('rsa_private.pem', 'r').read()
    
    auth = HTTPSignatureAuth(key_id='Test', secret=secret)
    z = requests.get('https://api.example.com/path/to/endpoint', 
                             auth=auth, headers={'X-Api-Version': '~6.5'})

Class initialization parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    httpsig.Signer(secret, algorithm='rsa-sha256')

``secret``, in the case of an RSA signature, is a string containing private RSA pem. In the case of HMAC, it is a secret password.  
``algorithm`` is one of the six allowed signatures: ``rsa-sha1``, ``rsa-sha256``, ``rsa-sha512``, ``hmac-sha1``, ``hmac-sha256``, 
``hmac-sha512``.

::

    httpsig.requests_auth.HTTPSignatureAuth(key_id, secret, algorithm='rsa-sha256', headers=None)

``key_id`` is the label by which the server system knows your RSA signature or password.  
``headers`` is the list of HTTP headers that are concatenated and used as signing objects. By default it is the specification's minimum, the ``Date`` HTTP header.  
``secret`` and ``algorithm`` are as above.

Tests
-----

To run tests::

    python setup.py test

License
-------

MIT
