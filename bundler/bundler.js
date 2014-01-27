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
	Bundler.log('Got a request for ' + req.query.url.green)
	// Initialize object for the collection of resources the website is dependent on.
	// We will fetch these resources as part of the bundle.
	var zip = new nodezip()
	var resources = {}
	var resourceNumber = 0
	var pageLoadedCutoff = false
	// Visit the website, determine its HTML and the resources it depends on.
	phantom.create(function(ph) {
		ph.createPage(function(page) {
			Bundler.log('Bundling has begun for ' + req.query.url.green)
			page.set('onResourceRequested', function(request, networkRequest) {
				if (!pageLoadedCutoff) {
					resources[resourceNumber] = {
						url: request.url
					}
					resourceNumber++
				}
			})
			page.open(req.query.url, function(status) {
				pageLoadedCutoff = true
				if (status !== 'success') {
					// Handle page load failure here
					// THIS IS NOT DONE NADIM!
				}
				// We've loaded the page and know what its resources are.
				// Now we download the resources and throw them into the zip file.
				var bundledResources = 0
				zip.file('resources', JSON.stringify(resources))
				for (var i in resources) {
					Bundler.fetchResource(resources[i].url, i, function(body, rn) {
						bundledResources++
						Bundler.log(
							'Fetching resource ' + rn
							+ ' ['.green + resources[rn].url.green + ']'.green
						)
						resources[rn].content = body
						// zip.file(rn, body)
						if (bundledResources === resourceNumber) {
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

Bundler.fetchResource = function(url, resourceNumber, callback) {
	request(url, { method: 'GET' }, function(error, response, body) {
		callback(body, resourceNumber)
	})
}

Bundler.replaceResource = function(resources) {
	var catchURI = /(^https?:\/\/|\.{0,2}\/?)((?:\w|\-|\.)+)/g
	for (var i = 0; i < Object.keys(resources).length; i++) {
		if (resources[i].content.length > 16384) {
			console.log('not scanning ' + resources[i].url)
			continue
		}
		console.log(resources[i].url)
		for (var o = 0; o < Object.keys(resources).length; o++) {
			if (resources[o].url === resources[0].url) { continue }
			console.log(resources[o].url)
			var filename = resources[o].url.match(catchURI)
			filename = filename[filename.length - 1].substring(1)
			if (!filename.match(/\.\w+$/)) { continue }
			console.log(filename)
			var URI = new RegExp('([a-zA-Z0-9]|\\.|\:|\/)*(\\/)?' + filename, 'g')
			var fullURI = resources[i].content.match(URI)
			if (!fullURI) { continue }
			console.log(fullURI)
			var dataURI = Bundler.convertToDataURI(
				resources[o].content,
				filename.match(/\.\w+$/)[0]
			)
			for (var p in fullURI) {
				resources[i].content = resources[i].content.replace(
					fullURI[p], dataURI
				)
			}
		}
	}
	return resources
}

Bundler.convertToDataURI = function(content, extension) {
	var dataURI = 'data:' + mime.lookup(extension) + ';base64,'
	dataURI += new Buffer(content).toString('base64')
	return dataURI
}