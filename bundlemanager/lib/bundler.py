#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ipdb
"""
Python modules
"""
import hmac
import hashlib
import mimetypes
import re
import base64
import logging

"""
Third party modules
"""
import requests
from ghost import Ghost
from Crypto.Cipher import AES
"""
need to compile all regexes
"""

class BundleMaker(object):
    reGetExt = re.compile(r'\.\w+($|\?)')
    reMatchMime = re.compile(
        '(text|css|javascript|plain|json|xml|octet\-stream)'
    )
    reCatchUri = re.compile(
        '(^https?:\/\/|\.{0,2}\/?)((?:\w|-|@|\.|\?|\=|\&)+)'
    )
    reTestForFile = re.compile(
        '\/(\w|-|@)+(\w|\?|\=|\.)+$'
    )
    reGetExtOnly = re.compile('\.\w+')
    reGetDomain1 = re.compile('^https?:\/\/(\w|\.)+(\/|$)')
    reGetDomain2 = re.compile('\w+\.\w+(\.\w+)?(\/|$)')

    def __init__(self):
        self.key = None
        self.iv = None
        self.hmackey = None
       
        self.ghost = Ghost()

    def createBundle(self, url, key, iv, hmackey):
        self.key = key
        self.iv = iv
        self.hmackey = hmackey

        resources = []
        #pageLoadCutoff = false
        resourceDomain = None
        if 'http' not in url:
            #this is an issue to discuss with nosmo
            return None
        else:
            if not url:
                return None
            resourceDomain = BundleMaker.reGetDomain2.search(
                                BundleMaker.reGetDomain1.search(url).group()
                            ).group()
        if resourceDomain[:-1] != '/':
            resourceDomain = resourceDomain + '/'
            
        page, ext_resources = self.ghost.open(url)
        
        resources = self.fetchResources(ext_resources, resourceDomain)

        logging.info('Resources Collected')

        resources = self.replaceResources(resources)
        logging.info('Resources replaced')
        bundle = self.encryptBundle(resources[0]['content'])
        logging.info('Bundle encrypted')
        hmac_sig = self.signBundle(bundle)
        logging.info('Bundle signed - and now they know when in memory to look :(')
        return {
            "bundle": bundle,
            "hmac_sig": hmac_sig
        }
                            

    def signBundle(self,bundle):
        return hmac.new(
                    self.hmackey, 
                    bundle, 
                    hashlib.sha256
                ).digest()

    def encryptBundle(self, content):
        aes = AES.new(
                        self.key, 
                        AES.MODE_CFB, 
                        self.iv
                    )
        return aes.encrypt(content)

    def fetchResources(self, resources, resourceDomain):
        new_resources = []

        for r in resources:
            #This is not very intelligent, as it heavily restricts using
            #your own CDN for example
            if 'http' in r.url and resourceDomain in r.url:
                enc = 'base64';
                if self.isSearchableFile(str(r.url)) or r.url == resources[0].url: 
                    enc = 'utf8'
                resourcePage = requests.get(
                    str(r.url),
                    timeout=8
                )
                resourcePage.encoding = enc
                if resourcePage.status_code == requests.codes.ok:
                    logging.info('Get resource: %s', str(r.url))
                    new_resources.append(
                        { 
                            "content": resourcePage.content,
                            "url": resourcePage.url
                        }
                    )
                else:
                    logging.error('Failed to get resource: %s',str(r.url))
                    #log error, son
                    return ''
        return new_resources

    def isSearchableFile(self, url):

        ext = BundleMaker.reGetExt.search(url)
        if ext:
	    ext = ext.group()
	    if ext[-1] == '?':
	        ext = ext[:-1];
	    if BundleMaker.reMatchMime.search(
                 mimetypes.types_map[ext]
            ): 
	        return True
	return False

    def replaceResources(self, resources):

        for r in reversed(resources):
            if not r['content']: 
                continue
            if len( r['content'] ) > 262144: 
                continue
            if r['url'] != resources[0]['url']:
                if not self.isSearchableFile(r['url']):
                    continue
            logging.info('Scanning resource: [%s] ', r['url'])
            for j in reversed(resources): 
                if j['url'] == resources[0]['url']: 
                    continue
                filename = BundleMaker.reCatchUri.findall(j['url'])
                filename = filename[1][0] + filename[1][1]

                if not BundleMaker.reTestForFile.search(filename): continue

                filename = filename[1:]
                
                logging.info('Bundling resource: [%s]', j['url'])

                dataURI = self.convertToDataUri(
                    j['content'],
                    filename
                )
                filename = filename.replace('?', '\?')
                resourcePattern1 = re.compile(
                    '(\'|")(\w|:|\/|-|@|\.*)*' + filename + '(\'|\")'
                )
                resourcePattern2 = re.compile(
                    '\((\w|:|\/|-|@|\.*)*' + filename + '\)'
                )

                r['content'] = resourcePattern1.sub(
                    '"' + dataURI + '"', r['content']
                )
                r['content'] = resourcePattern2.sub(
                    '(' + dataURI + ')', r['content']
                )
        return resources

    def convertToDataUri(self, content, extension):
        extension = BundleMaker.reGetExtOnly.search(extension)
        if extension:
            extension = extension.group(0)
        else:
            extension = '.html'

        dataURI = 'data:' + mimetypes.types_map[extension] + ';base64,'
        if self.isSearchableFile(extension):
            dataURI =  dataURI + base64.b64encode(content)
	
        return dataURI

