#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Python modules
"""
import lxml.html
from os.path import splitext
import urlparse
import json
import hmac
import hashlib
import mimetypes
import re
import base64
import logging
import StringIO
import binascii
from urlparse import urlparse
from threading import Thread, currentThread
from Queue import Queue
import HTMLParser
"""
Third party modules
"""
import requests
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
        '(^https?:\/\/|\.{0,2}\/?)((?:\w|-|@|\.|\?|\=|&|%)+)'
    )
    reTestForFile = re.compile(
        '(\w|-|@)+(\w|\?|\=|\.|-|&|%)+$'
    )
    reGetExtOnly = re.compile('\.\w+')

    def __init__(self, remap_rules, reaper_address, http_proxy=None, https_proxy=None):
        """
        Only important thing to setup here is Ghost, which will drive the key
        aspect of bundler - getting the resource list
        """
        self.reaper_address = reaper_address
        self.htmlparser = HTMLParser.HTMLParser()
        self.key = None
        self.iv = None
        self.hmackey = None
        self.remap_rules = remap_rules
        self.proxy = {"http": http_proxy, "https": https_proxy}
        self.resource_queue = Queue(maxsize=0)
        self.resource_result_queue = Queue(maxsize=0)
        self.main_url = None
        self.data_uris = {}
        # Add mime type to handle php
        self.remapped_mimes = [
            '',
            '.php'
        ]
        """
        Setup resource collection threads
        """
        for i in range(40):
            t = Thread(target=self.resourceCollectorThread)
            t.daemon = True
            t.start()

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
        remap_domain = self.remap_rules[host]['origin'] if host in self.remap_rules else None
        if not remap_domain:
            logging.warning("No remap found for domain: %s", host)
            return None

        self.key = key
        self.iv = iv
        self.hmackey = hmackey

        resources = []

        #Pass through request headers directly like a proper proxy
        #TODO pass other headers here, don't just discard them
        headers = {
            #TODO we break IDNs here - allowing this to pass as a
            #simple unicode object instead of a string breaks stuff.
            'Host': str(request.headers.get('host'))
        }

        remapped_url = BundleMaker.remapReqURL(remap_domain, request)

        if not remapped_url:
            logging.error('No remap rule found for: %s', request.headers['host'])
            return None

        work_set = json.dumps({
            "url": remapped_url,
            "host": host,
            "remapped_host": remap_domain
        })
        logging.debug("Sending request to site reaper for domain: %s and page: %s",
                      host, remapped_url)
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        reaped_resources = requests.post(
            self.reaper_address,
            data=work_set,
            headers=headers
        )
        if not reaped_resources:
            logging.warning("No resources returned. Ending process")
            return None
        if not reaped_resources.ok:
            logging.error("Resource requesting failed: %s", reaped_resources.text)
            return None

        ext_resources = reaped_resources.json
        logging.debug("JSON-decoded resources are %s", str(ext_resources))

        resources = self.fetchResources(ext_resources, host)

        logging.debug('Collected %s resources', len(resources))

        parsed_content = self.replaceResources(resources)
        logging.debug('Resources replaced')
        bundle = self.encryptBundle(parsed_content)
        logging.debug('Bundle encrypted')
        hmac_sig = self.signBundle(bundle)
        logging.debug('Bundle signed.')
        return {
            "bundle": bundle,
            "hmac_sig": hmac_sig
        }

    @staticmethod
    def remapReqURL(remap_domain, request):
        """
        Remap given url based on rules defined by
        conf file
        """

        parsed_url = urlparse(request.url)

        return "{0}://{1}{2}{3}".format(
            parsed_url.scheme,
            remap_domain,
            parsed_url.path,
            "?%s" % parsed_url.query if parsed_url.query else "")

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

        return base64.b64encode( aes.encrypt(padded_content) )

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

    def resourceCollectorThread(self):
        """
        This method manages the task for the resource collector
        threads.
        It retrieves and process resource urls appending them to the result Queue
        """

        thread_num = currentThread()
        while True:
            item = self.resource_queue.get()
            url = item['url']

            resourcePage = requests.get(
                item['url'],
                timeout=8,
                headers={"Host": item['host']},
                verify=False,
                proxies=self.proxy
            )

            if resourcePage.status_code == requests.codes.ok:
                content = ''

                if resourcePage.content is None:
                    resourcePage.text = ""
                if BundleMaker.isSearchableFile(url) or url == self.main_url:
                    try:
                        content = self.htmlparser.unescape( resourcePage.text)
                    except TypeError as e:
                        #ewww nested try-s :(
                        try:
                            logging.error("Failed to unescape HTML in url! %s", str(e))
                            content = self.htmlparser.unescape( resourcePage.content)
                        except TypeError as e2:
                            logging.error("Failed to unescape HTML in URL when using content attribute. Giving up: %s", str(e2))

                else:
                    content = base64.b64encode(resourcePage.content)

                self.resource_result_queue.put(
                    {
                        "content": content,
                        "url": resourcePage.url,
                        "position": item['position']
                    }
                )
            else:
                logging.error('%s failed to get resource: %s', thread_num, url)

            self.resource_queue.task_done()

    def fetchResources(self, resources, host):
        """
        Based on the list of resources provided go and retrieve the physical
        content for each of these pages. Provided to this function are the
        resources as a list of strings. The
        latter is used to ensure that only resources for the requested domain
        are bundled.

        This is a flaw and needs to be addressed more intelligently
        """
        #self.resource_queue = Queue( len(resources) )
        #self.resource_result_queue = Queue( len(resources) )

        # TODO: refactor this section - it's a little
        # incomprehensible.
        resource_set = []

        self.main_url = resources[0]['url']
        position = 0
        for r in resources:
            if r['url'] not in resource_set:
                resource_set.append(str(r['url']))

                self.resource_queue.put({
                    'host': host,
                    'url':str(r['url']),
                    'position':position
                })
                position += 1

        logging.debug('Waiting for workers to complete for %s', self.main_url)
        self.resource_queue.join()
        logging.debug('Resources retrieved for %s', self.main_url)
        new_resources = list(self.resource_result_queue.queue )
        # Annoyingly order matters a great deal
        # because if A references B reference C, we have to bundle C then
        # B then A otherwise A might end up with a bundle of B that doesn't
        # have the datauri for C but has the original URI instead

        new_resources.sort(key = lambda k: k['position'])
        self.main_url = new_resources[0]['url']

        return new_resources

    @staticmethod
    def isSearchableFile(url):
        """
        This function is responsible for checking whether or not
        the given url can be considered to be a parsable file, such as,
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
	    if (ext in mimetypes.types_map and BundleMaker.reMatchMime.search(
                mimetypes.types_map[ext])
        ) or ext in [".php", ".html", ".css", ".json"]:
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
        """
        self.data_uris = {}
        resource_list = [item['url'].split('/')[-1] for item in resources]

        for r in reversed(resources):
            if not r['content'] or r['content'] < 262144:
                continue
            if r['url'] != self.main_url:
                if not BundleMaker.isSearchableFile(r['url']):
                    continue
                if not any(
                        resource in r['content'] for resource in resource_list
                ):
                    continue

                r['content'] = self.buildDataURIs(
                    resources,
                    r['content'],
                    r['url'],
                    resources[0]['url']
                )
            else:
                self.buildDataURIs(
                    resources,
                    r['content'],
                    r['url'],
                    r['url']
                )
                r['content'] = lxml.html.rewrite_links(
                    r['content'],
                    self.generate_link_from_datauri
                )

        return resources[0]['content'].encode('utf8')

    def buildDataURIs(self, resources, content, url, main_url):
        for j in reversed(resources):
            if j['url'] == main_url:
                continue

            filename = j['url'].split('/')[-1]
            if not BundleMaker.reTestForFile.search(filename):
                continue

            if filename not in content:
                continue
            if filename not in self.data_uris:
                self.data_uris[filename] = self.convertToDataUri(
                    j['content'],
                    filename
                )
            # use of global variable, how gauche
            if url != main_url:
                filename_clean = filename.replace('?', '\?')
                filename_clean = filename_clean.replace('.', '\.')
                # Error caused by first star in python 2.7.3
                # Removed it and functionality seems uneffected
                resourcePattern1 = re.compile(
                    '[\'|\"|\(]([^\"|\'|\(]*' + filename_clean + ')[\'|\"|\)]'
                )

                content = resourcePattern1.sub(
                     self.data_uris[filename], content
                )
        return content

    def generate_link_from_datauri(self, link):
        filename = link.split('/')[-1]
        if filename in self.data_uris and filename in link:
            return self.data_uris[filename]
        else:
            return link

    def convertToDataUri(self, content, extension):
        """
        Taking resource content as input this function constructs a valid
        data URI and returns it
        """
        # Strip url params
        if '?' in extension:
            pos = extension.index('?')
        else:
            pos = None
        extension = splitext(extension[:pos])[-1]
        if extension in self.remapped_mimes:
            extension = '.html'

        # Deal with files not covered by mimetypes
        # for example .ttf

        mimetype = mimetypes.types_map[extension] if extension in mimetypes.types_map else 'application/octet-stream'

        dataURI = 'data:' + mimetype + ';base64,'
        if BundleMaker.isSearchableFile(str(extension)):
            dataURI =  dataURI + base64.b64encode(content.encode('utf8'))
        else:
            dataURI = dataURI + content

        return dataURI
