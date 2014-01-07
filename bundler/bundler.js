/*
* Load dependencies.
*/

var express = require('express')
var request = require('request')
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

http.createServer(Bundler).listen(3000, function() {
	console.log('Bundler')
})

/*
* Generate and deliver bundles on the reception of an HTTP GET request.
* GET parameters:
* url: The URL of the webpage to bundle.
*/

Bundler.get('/', function(req, res) {
	var url = req.query.url
	browser = new zombie()
	// Visit the website.
	browser.visit(url, function() {
		// Initialize array for the collection of resources the website is dependent on.
		// We will fetch these resources as part of the bundle.
		var resources = []
		// When we're done visiting the website...
		browser.on('done', function() {
			// First, add all JS/code resources.
			for (var i in browser['resources']) {
				if (browser['resources'][i].hasOwnProperty('request')) {
					resources.push(browser['resources'][i].request.url)
				}
			}
			// Detect and add all CSS/link resources.
			var linkResources = browser.document.querySelectorAll('link')
			for (var i in linkResources) {
				if (linkResources[i].href) {
					resources.push(linkResources[i].href)
				}
			}
			// Work in progress from this point on.
			res.end(resources.join('\n'))
			browser.close()
		})
	})
})
