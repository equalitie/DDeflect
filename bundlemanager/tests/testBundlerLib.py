#!/usr/bin/python
"""
Python Modules
"""
import unittest
import requests

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
        self.testKey = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
        self.testIV = "94949494949494949494949494949494"
        self.testHmacKey = "f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7"
        self.bundleMaker = BundleMaker()

    def testCreateBundle(self):
        
        result = self.bundleMaker.createBundle(self.testUrl,
                                    self.testKey,
                                    self.testIV,
                                    self.testHmacKey
                                    )

    def testFetchResources(self):
        testResp1 = requests.Response()
        testResp1.url = "https://deflect.ca/js/deflectca.js"
        testResources = [
            testResp1
        ]
        resource = self.bundleMaker.fetchResources(testResources)
        self.assertEqual(True, resource.ok)
        self.assertEqual(testResp1.url, resource.url)

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

