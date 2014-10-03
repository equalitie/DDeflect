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
		console.log('[BUNDLER] ', message);
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


	// Visit the website, determine its HTML and the resources it depends on.
	portScanner.findAPortNotInUse(40000, 60000, 'localhost', function(err, freePort) {
		phantom.create(function(ph) {
			ph.createPage(function(page) {
        var headers = {"Host": req.host};
        page.set("customHeaders", headers);
				Reaper.retrieveResources(
					req.url,  {
						ph: ph,
						page: page,
						host: req.host,
            remapped_host: req.remapped_host
					});
			});
		}, {port: freePort}
		);
	});
};

Reaper.retrieveResources = function(url, proc) {
	proc.resources = [];
	proc.pageLoadedCutoff = false;
	console.log('Initializing resource collection for ' + url);
	proc.page.set('onResourceRequested', function(request, networkRequest) {
	   console.log('Resource event caught');
		if (!proc.pageLoadedCutoff) {
      console.log('resource: ' + request.url);
			if ( request.url.match('^http') &&
					( request.url.match(proc.host) ||
            request.url.match(proc.remapped_host ))) {
        var resource_url = (request.url.match(proc.host)) ? request.url.replace(proc.host, proc.remapped_host) : request.url;
      console.log('resource: ' + resource_url);
				proc.resources.push( {
					url: resource_url
				});
			}
		}
	});
	proc.page.open(url, function(status) {
	  console.log('Page opened');
		proc.pageLoadedCutoff = true;
		if (status !== 'success') {
                    //TODO https://redmine.equalit.ie/redmine/issues/324
			console.log('Abort' + ': ' + status);
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


