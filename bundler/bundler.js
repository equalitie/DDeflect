/*
* Load dependencies.
*/

var portScanner = require('portscanner'),
	CryptoJS    = require('crypto-js'),
	express     = require('express'),
	phantom     = require('phantom'),
	request     = require('request'),
	colors      = require('colors'),
	mime        = require('mime'),
	http        = require('http'),
	path        = require('path'),
	fs          = require('fs')

/*
* Disable warnings.
*/

console.warn = function() {}

/*
 * Catch exceptions so that we don't crash immediately 
 */

process.on('uncaughtException', function(err) {
    console.error(err.stack);
})

/*
* Initialize Bundler.
*/

var Bundler = express()
var Debundler = ''

fs.readFile('debundler.html', function(err, data) {
	if (err) { throw err }
	Debundler = data.toString()
})

Bundler.configure(function() {
	Bundler.use(express.compress())
	Bundler.use(express.bodyParser())
	Bundler.use(express.methodOverride())
})

Bundler.log = function(message) {
	console.log('[BUNDLER]'.red.bold, message)
}

http.createServer(Bundler).listen(3000, "127.0.0.1", function() {
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
	Bundler.beginProcess(req, res)
})

Bundler.beginProcess = function(req, res) {
	// Initialize object for the collection of resources the website is dependent on.
	// We will fetch these resources as part of the bundle.
	var resources = {}
	var resourceNumber = 0
	var pageLoadedCutoff = false
	var resourceDomain = undefined

	if (req.query.url.indexOf("http") == -1) {
		// we're being passed a query with no host - let's see if we can get a passed location
		Bundler.log("No valid url present in query \"" + req.query.url + "\" - attempting to get host")
		if (typeof(req.headers["host"]) !== "undefined") {
			resourceDomain = req.headers["host"] + "/"
			Bundler.log("Got a valid host of " + req.headers["host"])
			// There are two obscenely dumb things happening here.
			// * Under no circumstances should I be forcing http - this will
			// need to be something that we set per-origin
			// * Redefining req.query.url is obviously awful. I did this
			// because I'm no good at this javascripting and didn't want to mess with mainProcess.
			req.query.url = "http://" + resourceDomain + req.query.url
	    	} else {
			Bundler.log("Failed to get a valid host - request invalid")
			res.end('')
			return
	    	}
	} else {
		if (!req.query.url) { res.end('');return }
		resourceDomain = req.query.url
			.match(/^https?:\/\/(\w|\.)+(\/|$)/)[0]
			.match(/\w+\.\w+(\.\w+)?(\/|$)/)[0]
	}

	if (resourceDomain[resourceDomain.length - 1] !== '/') { resourceDomain += '/' }
	Bundler.log(
		'Got a request for ' + req.query.url.green + ' ' + '['.inverse
		+ resourceDomain.substring(0, resourceDomain.length - 1).inverse + ']'.inverse
	)
	// Visit the website, determine its HTML and the resources it depends on.
	portScanner.findAPortNotInUse(40000, 60000, 'localhost', function(err, freePort) {
		phantom.create(function(ph) {
			ph.createPage(function(page) {
				Bundler.mainProcess(
					req, res, {
						ph: ph,
						page: page,
						resourceDomain: resourceDomain
					}
				)
			})
		}, {port: freePort}
		)
	})
}

Bundler.mainProcess = function(req, res, process) {
	process.resources = {}
	process.resourceNumber = 0
	process.pageLoadedCutoff = false
	Bundler.log('Initializing bundling for ' + req.query.url.green)
	process.page.set('onResourceRequested', function(request, networkRequest) {
		if (!process.pageLoadedCutoff) {
			if (request.url.match('^http')
			&& request.url.match(process.resourceDomain)) {
				process.resources[process.resourceNumber] = {
					url: request.url
				}
				process.resourceNumber++
			}
		}
	})
	process.page.open(req.query.url, function(status) {
		process.pageLoadedCutoff = true
		if (status !== 'success') {
			// Handle page load failure here
			// THIS IS NOT DONE NADIM!
			Bundler.log('Abort'.red.bold + ': ' + status)
			return false
		}
		// We've loaded the page and know what its resources are.
		var fetchedResources = 0
		Bundler.log('Begin fetching resources.'.inverse)
		for (var i in process.resources) {
			Bundler.fetchResource(process.resources[i].url, i, function(body, rn) {
				fetchedResources++
				process.resources[rn].content = body
				if (fetchedResources == process.resourceNumber) {
					Bundler.log('Done fetching resources.'.inverse)
					Bundler.log('Begin scanning resources.'.inverse)
					process.resources = Bundler.replaceResource(process.resources)
					Bundler.log('Encrypting bundle: '.bold + process.resources[0].url.green)
					var key     = CryptoJS.enc.Hex.parse('0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a')
					var iVector = CryptoJS.enc.Hex.parse('94949494949494949494949494949494')
					var encrypted = CryptoJS.AES.encrypt(
						process.resources[0].content, key, {iv: iVector}
					).toString()
					Bundler.log('Serving bundle: '.bold + process.resources[0].url.green)
					res.end(Debundler.replace('OTOxRiVdfw1F6vCQZCV1Zs1JrvZKkC2m', encrypted))
				}

			})
		}
		process.ph.exit()
	})
}

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
					'Fetched resource ' + resourceNumber.toString().inverse
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
			if (resources[o].url == resources[0].url) { continue }
			var filename = resources[o].url.match(catchURI)
			filename = filename[filename.length - 1]
			if (!filename.match(/\/(\w|-|@)+(\w|\?|\=|\.)+$/)) { continue }
			filename = filename.substring(1)
			Bundler.log('Bundling ' + '['.blue + resources[o].url.toString().blue + ']'.blue)
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
