/*
* Load dependencies.
*/

var express = require('express')
var phantom = require('phantom')
var request = require('request')
var nodezip = require('node-zip')
var colors  = require('colors')
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
				var pageHTML = ''
				var bundledResources = 0
				Bundler.fetchResource(resources[0], 0, function(body, rn) {
					pageHTML = body
				})
				for (var i in resources) {
					Bundler.fetchResource(resources[i], i, function(body, rn) {
						bundledResources++
						if (rn == 0) { return }
						Bundler.log('Bundling resource ' + rn + ' ['.green + resources[rn].green + ']'.green)
						zip.file(rn, body)
						pageHTML = pageHTML.replace(new RegExp(resources[rn], 'g'), rn)
						if (bundledResources === resourceNumber) {
							//res.end(zip.generate({base64: true, compression: 'DEFLATE'}))
							Bundler.log('Serving bundle: '.bold + resources[0].green)
							res.end(pageHTML)
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
Bundler.fetchResource = function(url, resourceNumber, callback) {
	request(url, { method: 'GET' }, function(error, response, body) {
		callback(body, resourceNumber)
	})
}