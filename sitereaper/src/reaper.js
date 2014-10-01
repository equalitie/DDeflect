#!/usr/bin/env node
// -*- eval: (indent-tabs-mode t) -*-

'use strict';
/*
* Load dependencies.
*/

var portScanner = require('portscanner'),
  zmq         = require('zmq'),
  socket      = zmq.socket('rep'),
	phantom     = require('phantom'),
	path        = require('path'),
	fs          = require('fs'),
	Syslog      = require('node-syslog'),
	yaml        = require('js-yaml');

/*
 * Init logging to syslog (only when not to console anyway)
 */
if (process.argv[2] != '-v') {
	Syslog.init("reaper", Syslog.LOG_PID | Syslog.LOG_ODELAY, Syslog.LOG_LOCAL0);
}


// lol javascript
var configData = {};
var configThing = {};
try {
    var yamlfile = fs.readFileSync('../conf/config.yaml');
    configThing = yaml.safeLoad(yamlfile.toString());
} catch (err) {
    console.error("Error when loading config file: " + err);
}
configData = configThing;
console.log(configData);

var Reaper = {};
// print to commandline if -v
Reaper.log = function(message) {
	if (process.argv[2] == '-v') {
		console.log('[BUNDLER] '.red.bold, message);
	} else {
		Syslog.log(Syslog.LOG_INFO, '[BUNDLER] ' + message);
	}
};

// phantomjs shits itself if it can't find the actual program for
// phantomjs in the path. Jerk.
process.env.PATH = process.env.PATH + ":../node_modules/phantomjs/bin";

Reaper.loadPage = function( requestData ) {
	// Initialize collection of resources the website is dependent on.
	// Will fetch resources as part of the bundle.
  var req = JSON.parse(requestData);

	console.log('Initializing bundling for ' + req.url);
  var resourceDomain = req.resourceDomain;
  var url = req.url;

	// Visit the website, determine its HTML and the resources it depends on.
	var test = portScanner.findAPortNotInUse(40000, 60000, 'localhost', function(err, freePort) {
		phantom.create(function(ph) {
			ph.createPage(function(page) {
				Reaper.retrieveResources(
					url,  {
						ph: ph,
						page: page,
						resourceDomain: resourceDomain
					});
			});
		}, {port: freePort}
		);
	});
  console.log(JSON.stringify(test));
};

Reaper.retrieveResources = function(url, proc) {
	proc.resources = [];
	proc.pageLoadedCutoff = false;
	console.log('Initializing resource collection for ' + url);
	proc.page.set('onResourceRequested', function(request, networkRequest) {
	   console.log('Resource event caught');
		if (!proc.pageLoadedCutoff) {
			if ( request.url.match('^http') &&
					request.url.match(proc.resourceDomain)) {
				proc.resources.push( {
					url: request.url
				});
			}
		}
	});
	proc.page.open(url, function(status) {
	  console.log('Page opened');
		proc.pageLoadedCutoff = true;
		if (status !== 'success') {
                    //TODO https://redmine.equalit.ie/redmine/issues/324
			console.log('Abort'.red.bold + ': ' + status);
			return false;
		}
		// We've loaded the page and know what its resources are.
    
    socket.send( JSON.stringify(proc.resources) );
	  console.log('Resources found: ' + JSON.stringify(proc.resources));
		proc.ph.exit();
	});

};

//Initialise comms sockets
//
console.log('Binding to zmq port');
socket.bind(configData.general.comms_port);
console.log('Bound to zmq port');

console.log('Awaiting requests');

socket.on('message', function( siteRequest ){
	console.log('Received ZMQ request');
	console.log('Request: ' + siteRequest);
  Reaper.loadPage(siteRequest);
});


