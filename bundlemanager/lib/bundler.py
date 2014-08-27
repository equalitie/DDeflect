#!/usr/bin/env python
# -*- coding: utf-8 -*-

import mimetypes
import re

"""
need to compile all regexes
"""

class BundleMaker(object):
    def __init__(self, url, key, iv, hmackey):
        self.url = url
        self.key = key
        self.iv = iv
        self.hmackey = hmackey
        """
        For fun let's compile a bunch of regex
        that we know we're going to use
        """
        self.reGetExt = re.compile(r'\.\w+($|\?)')
        self.reMatchMime = re.compile(
            '(text|css|javascript|plain|json|xml|octet\-stream)'
        )
        self.reCatchUri = re.compile(
            '(^https?:\/\/|\.{0,2}\/?)((?:\w|-|@|\.|\?|\=|\&)+)'
        )
        self.reTestForFile = re.compile(
            '\/(\w|-|@)+(\w|\?|\=|\.)+$'
        )
        self.reGetExtOnly = re.compile('\.\w+')

    def createURLBundle(self):
        
    def fetchResources(self):
 	enc = 'Base64';
	if (Bundler.isSearchableFile(url) 
	|| resourceNumber == 0) { // why?
		enc = 'utf8';
	}
	request(url, {
			method: 'GET',
			encoding: enc,
			timeout: 8000 },
		function(error, response, body) {
			if (error) {
				Bundler.log(
					'ERROR'.red.bold + ' fetching resource'
					+ ' ['.red + url.red + ']'.red);
			}
			else {
				Bundler.log(
					'Fetched resource ' + resourceNumber.toString().inverse
					+ ' ['.green + url.green + ']'.green);
			}
			callback(body, resourceNumber);
		}
	);

    def isSearchableFile(self, url):
        ext = self.reGetExt.search(url)
        if ext:
	    ext = ext.group()
	    if ext[len(ext) - 1] == '?':
	        ext = ext[:-1];
	    if self.reMatchMime.search(
                 mimetypes.types_map[ext]
            ): 
	        return true
	return false

    def replaceResource(self, resources):
	for i = Object.keys(resources).length - 1; i >= 0; i--:
	    if !resources[i].content: continue
	    if resources[i].content.length > 262144: continue
	    if resources[i].url !== resources[0].url:
	        if !Bundler.isSearchableFile(resources[i].url:
		    continue
                """
		Bundler.log(
			'Scanning resource '.bold + i.toString().inverse
			+ ' ' + '['.cyan + resources[i].url.toString().cyan + ']'.cyan);
                """
            for (var o = Object.keys(resources).length - 1; o >= 0; o--) {
	        if resources[o].url == resources[0].url: continue

		filename = self.reCatchUri.findall(resources[o].url)
		filename = filename[1][0] + filename[1][1]

		if !self.reTestForFile.search(filename): continue

		filename = filename[1:]
		"""i
                got to here
                Bundler.log('Bundling ' + '['.blue + resources[o].url.toString().blue + ']'.blue);
                """
		dataURI = self.convertToDataURI(
		    resources[o].content,
		    filename
		)
		var URI = [
		    new RegExp('(\'|")(\\w|:|\\/|-|@|\\.*)*' + filename.replace(/\?/g, '\\?') + '(\'|\")', 'g'),
	            new RegExp('\\((\\w|:|\\/|-|@|\\.*)*' + filename.replace(/\?/g, '\\?') + '\\)', 'g'),
		];
		for p in URI:
		    if p == 0:
		        resources[i].content = resources[i].content.replace(URI[p], '"' + dataURI + '"')
		    if p == 1:
		        resources[i].content = resources[i].content.replace(URI[p], '(' + dataURI + ')')
	return resources

    def convertToDataUri(self, content, extension):
        if extension = self.reGetExtiOnly.search(extension):
            extension = extension.group(0)
	else:
            extension = '.html'

	dataURI = 'data:' + mimetypes.types_map[extension] + ';base64,'
	if Bundler.isSearchableFile(extension):
	    dataURI += new Buffer(content).toString('base64')
	else:
	    dataURI += content
	
	return dataURI

