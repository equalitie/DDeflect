#!/usr/bin/python
"""
Python Modules
"""
import unittest
import requests
import os

"""
Bundle Manager modules
"""
from bundlemanager.lib.bundler import BundleMaker 

"""
Third party modules
"""
import requests

class TestBundlerLib(unittest.TestCase):

    def setUp(self):
        self.testUrl = "http://nosmo.me"
        self.testKey = '\xdc\xd8\x8dN\xfa\xd41\x16k{\xe4\x8b\xe2\xaau\xa0'
        self.testIV = '\x84GT\xce\xe1\xf8\xb2khe\xdb\x13\xbc\xd8\x1a\xa0'
        self.testHmacKey = '8\xbd\xa8\xf6\xf7\xc2\x05Cf\xf6?\xa3\x82\xda\x83J'
        self.bundleMaker = BundleMaker()

    def testCreateBundle(self):
        
        result = self.bundleMaker.createBundle(self.testUrl,
                                    self.testKey,
                                    self.testIV,
                                    self.testHmacKey
                                    )
        expected_sig = '\xd4\xc3CB\xb9hV\x7f\x003U,|\xa2+j\x1e\x01\xd9\x1c\x0c\xfbJ\x15\xae?2\xe86\xeb+\x08'                                    
        self.assertEqual(result['hmac_sig'], expected_sig)

    def testFetchResources(self):
        testResp1 = requests.Response()
        testResp1.url = "https://deflect.ca/js/deflectca.js"
        testResources = [
            testResp1
        ]
        testResourceDomain = 'deflect.ca/'
        resources = self.bundleMaker.fetchResources(
                                            testResources,
                                            testResourceDomain
                                    )
        self.assertEqual(testResp1.url, resources[0]['url'])

    def testIsSearchableFile(self):
        testFilename = "test.css"

        result = self.bundleMaker.isSearchableFile(testFilename)

        self.assertEqual(result, True)

    def testReplaceResources(self):
                
        testResources = [
            {
                "content": '<script src=\"../some.css\"/>',
                "url": "https://test.computer"
            },
            {
                "content": "some css",
                "url": "https://test.computer/some.css"
            }
        ]
        expectedResources = [
            {
                'content': '<script src="data:text/css;base64,c29tZSBjc3M="/>', 
                'url': 'https://test.computer'
            }, 
            {
                'content': 'some css', 
                'url': 'https://test.computer/some.css'
            }
        ]
        result = self.bundleMaker.replaceResources(testResources)

        self.assertEqual(result, expectedResources)

    def testConvertToDataUri(self):
        
        testContent = "<test content=\"info\">"
        testExtension = ".css"
        expectedDataUri = "data:text/css;base64,PHRlc3QgY29udGVudD0iaW5mbyI+"

        result = self.bundleMaker.convertToDataUri(
                                            testContent,
                                            testExtension
                                            )
        self.assertEqual(result, expectedDataUri)

