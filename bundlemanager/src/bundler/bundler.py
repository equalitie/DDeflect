#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Python modules
"""
import hmac
import hashlib
import mimetypes
import re
import base64
import logging
import StringIO
import binascii
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
    """
    Just for the joy of it, let's compile the ton
    of regexes when the object is created
    """
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
    #FIXME these don't account for ports
    reGetDomain1 = re.compile('^https?:\/\/(\w|\.)+(\/|$)')
    reGetDomain2 = re.compile('\w+\.\w+(\.\w+)?(\/|$)')

    def __init__(self, remap_rules):
        """
        Only important thing to setup here is Ghost, which will drive the key
        aspect of bundler - getting the resource list
        """
        self.key = None
        self.iv = None
        self.hmackey = None
        self.remap_rules = remap_rules

    def createBundle(self, request, remap_host, key, iv, hmackey):
        """
        This is function which ties it altogether
        primarily this is process manager function.
        The stage of execution are delineated by info logging
        Input: Request to bundle, encryption keys
        Output: Encrypted bundle, hmac signature
        """
        logging.info("Processing request for: %s", request.url)

        self.key = key
        self.iv = iv
        self.hmackey = hmackey

        ghost = Ghost()
        resources = []
        #pageLoadCutoff = false
        resourceDomain = 'localhost/' #self.getResourceDomain(request.url)

        logging.info("Retrieved resource domain as: %s", resourceDomain)

        #Pass through request headers directly like a proper proxy
        headers = {
            'host': request.headers.get('host')
        }
        logging.info('Getting remap rule for request')
        remapped_url = self.remapReqURL(remap_host, request)
        if not remapped_url:
            logging.error('No remap rule found for: %s', request.headers['host'])
            return None

        logging.info("Attempting to load remapped page: %s", remapped_url)
        page, ext_resources = ghost.open(remapped_url, headers=headers)
        logging.info("Request returned with status: %s", page.http_status)

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

    def remapReqURL(self, remap_domain, request):
        """
        Remap given url based on rules defined by
        conf file
        """
        host = request.headers['host']
        full_path = ''
        if '?' in request.url:
            pos = request.url.rfind(request.path)
            full_path = request.url[:pos]
        else:
            full_path = request.path
        logging.info('URL path: %s', full_path)

        return "http://{0}{1}".format(remap_domain['origin'], full_path)

    def getResourceDomain(self, url):
        """
        Retrieve the domain of the URL/URI, for example:
        https://www.equalit.ie will become
        equalit.ie/
        """
        resourceDomain = None
        if not url:
            return None
        elif 'http' not in url:
            #TODO temporary hack because i dunno
            #this is an issue to discuss with nosmo
            if not url.endswith("/"):
                return url + "/"
        else:
            #TOD0: Add error checking here
            resourceDomain = BundleMaker.reGetDomain2.search(
                                BundleMaker.reGetDomain1.search(url).group()
                            ).group()
            if resourceDomain[-1] != '/':
                resourceDomain = resourceDomain + '/'

        return resourceDomain

    def signBundle(self,bundle):
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
        padded_content = self.encode(content)
        key = binascii.unhexlify(self.key)
        iv = binascii.unhexlify(self.iv)

        aes = AES.new(
                        key,
                        AES.MODE_CFB,
                        iv,
                        segment_size=128
                    )

        return base64.b64encode( aes.encrypt(padded_content) )

    def encode(self, text):
        '''
        Pad an input string according to PKCS#7
        '''
        l = len(text)
        output = StringIO.StringIO()
        val = 16 - (l % 16)
        for _ in xrange(val):
            output.write('%02x' % val)
        return text + binascii.unhexlify(output.getvalue())

    def fetchResources(self, resources, resourceDomain):
        """
        Based on the list of resources provided go and retrieve the physical
        content for each of these pages. Provided to this function are the
        resources as a list of strings and the resourceDomain string. The
        latter is used to ensure that only resources for the requested domain
        are bundled.

        This is a flaw and needs to be addressed more intelligently
        """
        new_resources = []

        for r in resources:
            #This is not very intelligent, as it heavily restricts using
            #your own CDN for example
                resourcePage = requests.get(
                    str(r.url),
                    timeout=8
                )

                content = ''
                if self.isSearchableFile(str(r.url)) or r.url == resources[0].url:
                    content = resourcePage.content.encode('utf8')
                else:
                    content = base64.b64encode(resourcePage.content)

                if resourcePage.status_code == requests.codes.ok:
                    logging.info('Get resource: %s', str(r.url))
                    new_resources.append(
                        {
                            "content": content,
                            "url": resourcePage.url
                        }
                    )
                else:
                    logging.error('Failed to get resource: %s',str(r.url))
                    #log error, son
                    return ''
        return new_resources

    def isSearchableFile(self, url):
        """
        This function is responsible for checking whether or not
        the given url can be considered to be a parasable file, such as,
        XML, CSS or JSON, as opposed to binary data.

        This function is used primarily in the replaceResources function,
        to identify files that must be parsed for occurences of references to
        other bundled resources.
        """

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
        """
        This function is responsible for converting the resources
        into a data URI representation and replacing all references
        within other resources.

        It works as two sliding windows, moving backwards over the same list.
        The outter loop identifies resource that can contain references, such
        as CSS, XML, plain etc. The inner loop bundles each resource as a dataURI
        and then replaces all references with in the outter loop element.

        There is a flaw in this system.
        """
        for r in reversed(resources):
            logging.info('Testing resource: [%s] ', r['url'])
            if not r['content'] or r['content'] < 262144:
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
                logging.info('Bundle created for resource: [%s] ', r['url'])
        return resources

    def convertToDataUri(self, content, extension):
        """
        Taking resource content as input this function constructs a valid
        data URI and returns it
        """

        extension = BundleMaker.reGetExtOnly.search(extension)
        if extension:
            extension = extension.group(0)
        else:
            extension = '.html'

        dataURI = 'data:' + mimetypes.types_map[extension] + ';base64,'
        if self.isSearchableFile(str(extension)):
            dataURI =  dataURI + base64.b64encode(content)
        else:
            dataURI = dataURI + content

        return dataURI
