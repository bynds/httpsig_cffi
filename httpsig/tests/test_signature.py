#!/usr/bin/env python
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json
import unittest

from httpsig.sign import HeaderSigner


class TestSign(unittest.TestCase):

    def _parse_auth(self, auth):
        """Basic Authorization header parsing."""
        # split 'Signature kvpairs'
        s, param_str = auth.split(' ', 1)
        self.assertEqual(s, 'Signature')
        # split k1="v1",k2="v2",...
        param_list = param_str.split(',')
        # convert into [(k1,"v1"), (k2, "v2"), ...]
        param_pairs = [p.split('=', 1) for p in param_list]
        # convert into {k1:v1, k2:v2, ...}
        param_dict = {k: v.strip('"') for k, v in param_pairs}
        return param_dict

    def setUp(self):
        self.key_path = os.path.join(os.path.dirname(__file__), 'rsa_private.pem')
        self.key = open(self.key_path, 'r').read()

    def test_default(self):
        hs = HeaderSigner(key_id='Test', secret=self.key)
        unsigned = {
            'Date': 'Thu, 05 Jan 2012 21:31:40 GMT'
        }
        signed = hs.sign(unsigned)
        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        params = self._parse_auth(signed['Authorization'])
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'rsa-sha256')
        self.assertEqual(params['signature'], 'ATp0r26dbMIxOopqw0OfABDT7CKMIoENumuruOtarj8n/97Q3htHFYpH8yOSQk3Z5zh8UxUym6FYTb5+A0Nz3NRsXJibnYi7brE/4tx5But9kkFGzG+xpUmimN4c3TMN7OFH//+r8hBf7BT9/GmHDUVZT2JzWGLZES2xDOUuMtA=')

    def test_all(self):
        hs = HeaderSigner(key_id='Test', secret=self.key, headers=[
            '(request-line)',
            'host',
            'date',
            'content-type',
            'content-md5',
            'content-length'
        ])
        unsigned = {
            'Host': 'example.com',
            'Date': 'Thu, 05 Jan 2012 21:31:40 GMT',
            'Content-Type': 'application/json',
            'Content-MD5': 'Sd/dVLAcvNLSq16eXua5uQ==',
            'Content-Length': '18',
        }
        signed = hs.sign(unsigned, method='POST', path='/foo?param=value&pet=dog')
        
        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        params = self._parse_auth(signed['Authorization'])
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'rsa-sha256')
        self.assertEqual(params['headers'], '(request-line) host date content-type content-md5 content-length')
        self.assertEqual(params['signature'], 'vYJio4AxbN38TKdzE1Qk/3qXhzTaBS7zUIPCqV+NsjLSf8ZK/19L9ErTz8FYBAW8Gko2dEaU70McrIO33k0PUlPsWvbGn/IhnU14rvSPF/F+AnFVFeA9ivvvyVZQYYYp17fnNfiCzHrvUn+VnqMhRKA15Nr8KKwt9Eqi36wQ8Vg=')
