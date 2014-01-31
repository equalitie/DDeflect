/*
* Load dependencies.
*/

var express = require('express')
var phantom = require('phantom')
var request = require('request')
var nodezip = require('node-zip')
var colors  = require('colors')
var mime    = require('mime')
var http    = require('http')
var path    = require('path')
var fs      = require('fs')

/*
* Disable warnings
*/

console.warn = function() {}

/*
* Initialize Bundler.
*/

var Bundler = express()

Bundler.configure(function() {
	Bundler.use(express.compress())
	Bundler.use(express.bodyParser())
	Bundler.use(express.methodOverride())
})

Bundler.log = function(message) {
	console.log('[BUNDLER]'.red.bold + ' ' + message)
}

http.createServer(Bundler).listen(3000, function() {
	console.log('____  _   _ _   _ ____  _     _____ ____  '.rainbow.bold)
	console.log('| __ )| | | | \\ | |  _ \\| |   | ____|  _ \\ '.rainbow.bold)
	console.log('|  _ \\| | | |  \\| | | | | |   |  _| | |_) |'.rainbow.bold)
	console.log('| |_) | |_| | |\\  | |_| | |___| |___|  _ < '.rainbow.bold)
	console.log('|____/ \\___/|_| \\_|____/|_____|_____|_| \\_\\'.rainbow.bold)
	console.log('')
	Bundler.log('Ready!')
})

/*
* Generate and deliver bundles on the reception of an HTTP GET request.
* GET parameters:
* url: The URL of the webpage to bundle.
*/

Bundler.get('/', function(req, res) {
	if (!req.query.url) { res.end('');return }
	// Initialize object for the collection of resources the website is dependent on.
	// We will fetch these resources as part of the bundle.
	// var zip = new nodezip()
	var resources = {}
	var resourceNumber = 0
	var pageLoadedCutoff = false
	var resourceDomain = req.query.url
		.match(/^https?:\/\/(\w|\.)+(\/|$)/)[0]
		.match(/\w+\.\w+(\.\w+)?(\/|$)/)[0]
	if (resourceDomain[resourceDomain.length - 1] !== '/') { resourceDomain += '/' }
	Bundler.log(
		'Got a request for ' + req.query.url.green + ' ' + '['.inverse
		+ resourceDomain.substring(0, resourceDomain.length - 1).inverse + ']'.inverse
	)
	// Visit the website, determine its HTML and the resources it depends on.
	phantom.create(function(ph) {
		ph.createPage(function(page) {
			Bundler.log('Initializing bundling for ' + req.query.url.green)
			page.set('onResourceRequested', function(request, networkRequest) {
				if (!pageLoadedCutoff) {
					if (request.url.match('^http')
					&& request.url.match(resourceDomain)) {
						resources[resourceNumber] = {
							url: request.url
						}
						resourceNumber++
					}
				}
			})
			page.open(req.query.url, function(status) {
				pageLoadedCutoff = true
				if (status !== 'success') {
					// Handle page load failure here
					// THIS IS NOT DONE NADIM!
					Bundler.log('Abort'.red.bold)
					return false
				}
				// We've loaded the page and know what its resources are.
				// Now we download the resources and throw them into the zip file.
				var fetchedResources = 0
				// zip.file('resources', JSON.stringify(resources))
				Bundler.log('Begin fetching resources.'.inverse)
				for (var i in resources) {
					Bundler.fetchResource(resources[i].url, i, function(body, rn) {
						fetchedResources++
						resources[rn].content = body
						// zip.file(rn, body)
						if (fetchedResources === resourceNumber) {
							Bundler.log('Done fetching resources.'.inverse)
							Bundler.log('Begin scanning resources.'.inverse)
							resources = Bundler.replaceResource(resources)
							//res.end(zip.generate({base64: true, compression: 'DEFLATE'}))
							Bundler.log('Serving bundle: '.bold + resources[0].url.green)
							res.end(resources[0].content)
						}
					})
				}
				ph.exit()
			})
		})
	})
})

Bundler.isSearchableFile = function(url) {
	if (extension = url.match(/\.\w+($|\?)/)) {
		extension = extension[0]
		if (extension[extension.length - 1] === '?') {
			extension = extension.substring(0, extension.length - 1)
		}
		if (mime.lookup(extension).match(
			/(text|css|javascript|plain|json|xml|octet\-stream)/
		)) {
			return true
		}
	}
	return false
}

Bundler.fetchResource = function(url, resourceNumber, callback) {
	var enc = 'Base64'
	if (Bundler.isSearchableFile(url)) {
		enc = 'utf8'
	}
	if (resourceNumber == 0) {
		enc = 'utf8'
	}
	request(url,
		{
			method: 'GET',
			encoding: enc,
			timeout: 8000
		},
		function(error, response, body) {
			if (error) {
				Bundler.log(
					'ERROR'.red.bold + ' fetching resource'
					+ ' ['.red + url.red + ']'.red
				)
			}
			else {
				Bundler.log(
					'Fetched resource ' + resourceNumber
					+ ' ['.green + url.green + ']'.green
				)
			}
			callback(body, resourceNumber)
		}
	)
}

Bundler.replaceResource = function(resources) {
	var catchURI = /(^https?:\/\/|\.{0,2}\/?)((?:\w|-|@|\.|\?|\=|\&)+)/g
	for (var i = Object.keys(resources).length - 1; i >= 0; i--) {
		if (!resources[i].content) { continue }
		if (resources[i].content.length > 262144) { continue }
		if (resources[i].url !== resources[0].url) {
			if (!Bundler.isSearchableFile(resources[i].url)) {
				continue
			}
		}
		Bundler.log(
			'Scanning resource '.bold + i.toString().inverse
			+ ' ' + '['.cyan + resources[i].url.toString().cyan + ']'.cyan
		)
		for (var o = Object.keys(resources).length - 1; o >= 0; o--) {
			Bundler.log('Metascanning ' + '['.blue + resources[o].url.toString().blue + ']'.blue)
			if (resources[o].url == resources[0].url) { continue }
			var filename = resources[o].url.match(catchURI)
			filename = filename[filename.length - 1]
			if (!filename.match(/\/(\w|-|@)+(\w|\?|\=|\.)+$/)) { continue }
			filename = filename.substring(1)
			// console.log(filename)
			var dataURI = Bundler.convertToDataURI(
				resources[o].content,
				filename
			)
			var URI = [
				new RegExp('(\'|")(\\w|:|\\/|-|@|\\.*)*' + filename.replace(/\?/g, '\\?') + '(\'|\")', 'g'),
				new RegExp('\\((\\w|:|\\/|-|@|\\.*)*' + filename.replace(/\?/g, '\\?') + '\\)', 'g'),
			]
			for (var p in URI) {
				if (p == 0) {
					resources[i].content = resources[i].content.replace(URI[p], '"' + dataURI + '"')
				}
				if (p == 1) {
					resources[i].content = resources[i].content.replace(URI[p], '(' + dataURI + ')')
				}
			}
		}
	}
	return resources
}

Bundler.convertToDataURI = function(content, extension) {
	if (extension = extension.match(/\.\w+/)) {
		extension = extension[0]
	}
	else {
		extension = '.html'
	}
	var dataURI = 'data:' + mime.lookup(extension) + ';base64,'
	if (Bundler.isSearchableFile(extension)) {
		dataURI += new Buffer(content).toString('base64')
	}
	else {
		dataURI += content
	}
	return dataURI
}