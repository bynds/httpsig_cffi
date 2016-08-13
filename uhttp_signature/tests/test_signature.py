#!/usr/bin/env python
#import sys
#import os
#sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    import ujson as json
except ImportError:
    import json
try:
    import uunittest as unittest
except ImportError:
    import unittest

import gc

import uhttp_signature.sign as sign
from uhttp_signature.utils import parse_authorization_header


sign.DEFAULT_SIGN_ALGORITHM = "hmac-sha256"


class TestSign(unittest.TestCase):
    
    # TODO Add tests for uhttp_signature
    #pass

    def setUp(self):
        #self.key_path = os.path.join(os.path.dirname(__file__), 'rsa_private.pem')
        #self.key = open(self.key_path, 'rb').read()
        self.key = b'the_secret'
        gc.collect()

    def test_default(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key)
        unsigned = {
            'Date': 'Thu, 05 Jan 2012 21:31:40 GMT'
        }
        signed = hs.sign(unsigned)
        try:
            unittest.assertIn('date', signed)
            unittest.assertEqual(unsigned['Date'], signed['date'])
            unittest.assertIn('authorization', signed)
            auth = parse_authorization_header(signed['authorization'])
            params = auth[1]
            unittest.assertIn('keyId', params)
            unittest.assertIn('algorithm', params)
            unittest.assertIn('signature', params)
            unittest.assertEqual(params['keyId'], 'Test')
            unittest.assertEqual(params['algorithm'], 'hmac-sha256')
            unittest.assertEqual(params['signature'], 'k/YLGmnxhgerdZbr+cPEjZ0bC82IaQzh4ktqNZJ4BLI=')
        except AttributeError:
            self.assertIn('date', signed)
            self.assertEqual(unsigned['Date'], signed['date'])
            self.assertIn('authorization', signed)
            auth = parse_authorization_header(signed['authorization'])
            params = auth[1]
            self.assertIn('keyId', params)
            self.assertIn('algorithm', params)
            self.assertIn('signature', params)
            self.assertEqual(params['keyId'], 'Test')
            self.assertEqual(params['algorithm'], 'hmac-sha256')
            self.assertEqual(params['signature'], 'k/YLGmnxhgerdZbr+cPEjZ0bC82IaQzh4ktqNZJ4BLI=')
            
        gc.collect()

    def test_all(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key, headers=[
            '(request-target)',
            'host',
            'date',
            'content-length'
        ])
        unsigned = {
            'Host': 'example.com',
            'Date': 'Thu, 05 Jan 2012 21:31:40 GMT',
            'Content-Length': '18',
        }
        signed = hs.sign(unsigned, method='POST', path='/foo?param=value&pet=dog')
        try:
            unittest.assertIn('date', signed)
            unittest.assertEqual(unsigned['Date'], signed['date'])
            unittest.assertIn('authorization', signed)
            auth = parse_authorization_header(signed['authorization'])
            params = auth[1]
            unittest.assertIn('keyId', params)
            unittest.assertIn('algorithm', params)
            unittest.assertIn('signature', params)
            unittest.assertEqual(params['keyId'], 'Test')
            unittest.assertEqual(params['algorithm'], 'hmac-sha256')
            unittest.assertEqual(params['headers'], '(request-target) host date content-length')
            unittest.assertEqual(params['signature'], 'r2onjca8jKtgBun5rDMG4bNf8bIQEke2lBtlfySeS9U=')
        except:
            self.assertIn('date', signed)
            self.assertEqual(unsigned['Date'], signed['date'])
            self.assertIn('authorization', signed)
            auth = parse_authorization_header(signed['authorization'])
            params = auth[1]
            self.assertIn('keyId', params)
            self.assertIn('algorithm', params)
            self.assertIn('signature', params)
            self.assertEqual(params['keyId'], 'Test')
            self.assertEqual(params['algorithm'], 'hmac-sha256')
            self.assertEqual(params['headers'], '(request-target) host date content-length')
            self.assertEqual(params['signature'], 'r2onjca8jKtgBun5rDMG4bNf8bIQEke2lBtlfySeS9U=')
        gc.collect()
