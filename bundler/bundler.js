var express = require('express')
var request = require('request')
var zombie  = require('zombie')
var http    = require('http')
var path    = require('path')
var fs      = require('fs')

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

Bundler.get('/', function(req, res) {
	var url = req.query.url
	browser = new zombie()
	browser.visit(url, function() {
		var r = []
		browser.on('done', function() {
			for (var i in browser.resources) {
				if (browser.resources[i].hasOwnProperty('request')) {
					r.push(browser.resources[i].request.url)
				}
			}
			console.log(browser.query('link'))
			res.end(browser.html())
			browser.close()
		})
	})
})

http.createServer(Bundler).listen(3000, function() {
	console.log('Bundler')
})
