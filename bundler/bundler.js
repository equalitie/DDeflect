/*
* Load dependencies.
*/

var express = require('express')
var phantom = require('phantom')
var request = require('request')
var nodezip = require('node-zip')
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
	// Initialize object for the collection of resources the website is dependent on.
	// We will fetch these resources as part of the bundle.
	var zip = new nodezip()
	var resources = {}
	var resourceNumber = 0
	var pageLoadedCutoff = false
	// Visit the website, determine its HTML and the resources it depends on.
	phantom.create(function(ph) {
		ph.createPage(function(page) {
			page.set('onResourceRequested', function(request, networkRequest) {
				if (!pageLoadedCutoff) {
					resources[resourceNumber] = request.url
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
				var bundledResources = 1
				for (var i in resources) {
					Bundler.fetchResource(resources[i], i, function(body, rn) {
						console.log('Bundling resource ' + rn + ' [' + resources[rn] + ']')
						zip.file(rn, body)
						bundledResources++
						if (bundledResources === resourceNumber) {
							res.end(zip.generate({base64: true, compression: 'DEFLATE'}))
						}
					})
				}
				ph.exit()
			})
		})
	})
})

/*
* This is used by Bundler to fetch resources.
*/
Bundler.fetchResource = function(url, rn, callback) {
	request(url, { method: 'GET' }, function(error, response, body) {
		callback(body, rn)
	})
}