/*
* Load dependencies.
*/

var express = require('express')
var request = require('request')
var nodezip = require('node-zip')
var zombie  = require('zombie')
var http    = require('http')
var path    = require('path')
var fs      = require('fs')

/*
* Initialize Bundler.
*/

var Bundler = express()

Bundler.configure(function() {
	Bundler.use(express.compress())
	//Bundler.use(express.logger('dev'))
	Bundler.use(express.bodyParser())
	Bundler.use(express.methodOverride())
})

Bundler.configure('development', function() {
	Bundler.use(express.errorHandler())
})

Bundler.browser = new zombie()

http.createServer(Bundler).listen(3000, function() {
	console.log('Bundler')
})

/*
* Generate and deliver bundles on the reception of an HTTP GET request.
* GET parameters:
* url: The URL of the webpage to bundle.
*/

Bundler.get('/', function(req, res) {
	// Visit the website.
	// When we're done visiting the website, Bundler.browser.on('done') will be executed (below)
	Bundler.browser.visit(req.query.url, function() {})

	/*
	* Detect when the browser is done visiting a page, and begin bundling.
	*/

	Bundler.browser.on('done', function() {
		// Don't run if we don't obtain a DOM.
		if (!Bundler.browser.document) { return }
		// Initialize array for the collection of resources the website is dependent on.
		// We will fetch these resources as part of the bundle.
		var resources = {}
		var resourceNumber = 0
		var zip = new nodezip()
		// First, add all JS/code resources.
		for (var i in Bundler.browser['resources']) {
			if (Bundler.browser['resources'][i].hasOwnProperty('request')) {
				resources[resourceNumber] = Bundler.browser['resources'][i].request.url
				zip.file(
					resourceNumber,
					Bundler.browser['resources'][i].response.body
				)
			}
		}
		// Detect and add all CSS/link resources.
		var linkResources = Bundler.browser.document.querySelectorAll('link')
		for (var i in linkResources) {
			if (linkResources[i].href) {
				resources[resourceNumber] = linkResources[i].href
			}
		}
		// Work in progress from this point on.
		res.end(zip.generate({base64: true, compression: 'DEFLATE'}))
		//res.end(resources.join('\n'))
		Bundler.browser.close()
	})
})