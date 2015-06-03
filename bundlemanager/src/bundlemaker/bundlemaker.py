#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Python modules
"""
from os.path import splitext
import hmac
import hashlib
import base64
import logging
import StringIO
import binascii
"""
Third party modules
"""
import requests
from Crypto.Cipher import AES

class BundleMaker(object):

    def __init__(self, remap_rules, bundler_address):

        self.bundler_address = bundler_address
        self.key = None
        self.iv = None
        self.hmackey = None
        self.remap_rules = remap_rules

    def createBundle(self, request, key, iv, hmackey):
        """
        This is function which ties it altogether
        primarily this is process manager function.
        The stage of execution are delineated by info logging
        Input: Request to bundle, encryption keys
        Output: Encrypted bundle, hmac signature
        """
        logging.debug("Starting bundle creation for: %s", request.url)

        host = request.headers['host']
        remap_domain = self.remap_rules[host]['origin'] if host in \
                    self.remap_rules else None
        if not remap_domain:
            logging.warning("No remap found for domain: %s", host)
            return None

        self.key = key
        self.iv = iv
        self.hmackey = hmackey

        # Pass through request headers directly
        request_headers = dict(request.headers)
        request_headers["Host"] = host

        bundled_page = requests.get(
            self.bundler_address,
            params={"url": request.url},
            headers=request_headers
        )
        if not bundled_page:
            logging.warning("No bundled page returned")
            return None
        if not bundled_page.ok:
            logging.error("Resource requesting failed: %s",
                          reaped_resources.text)
            return None

        logging.debug('Bundle returned')
        bundle = self.encryptBundle(bundled_page.content)
        logging.debug('Bundle encrypted')
        hmac_sig = self.signBundle(bundle)
        logging.debug('Bundle signed.')
        return {
            "bundle": bundle,
            "hmac_sig": hmac_sig
        }

    def signBundle(self, bundle):
        """
        Sha256 sign the bundle and return the digest as signature
        This will be used by the physical debundler JS to authenticate
        the bundle
        """
        return hmac.new(
            self.hmackey,
            bundle,
            hashlib.sha256
        ).hexdigest()

    def encryptBundle(self, content):
        """
        Encrypt the base64 encoded bundle using the generated key and IV
        provided by the calling application
        """
        padded_content = BundleMaker.encode(content)
        key = binascii.unhexlify(self.key)
        iv = binascii.unhexlify(self.iv)

        aes = AES.new(
            key,
            AES.MODE_CFB,
            iv,
            segment_size=128
        )

        return base64.b64encode(aes.encrypt(padded_content))

    @staticmethod
    def encode(text):
        '''
        Pad an input string according to PKCS#7
        '''
        l = len(text)
        output = StringIO.StringIO()
        val = 16 - (l % 16)
        for _ in xrange(val):
            output.write('%02x' % val)
        return text + binascii.unhexlify(output.getvalue())
