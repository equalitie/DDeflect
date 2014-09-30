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
    var yamlfile = fs.readFileSync('config.yaml');
    configThing = yaml.safeLoad(yamlfile.toString());
} catch (err) {
    console.error("Error when loading config file: " + err);
}
configData = configThing;


var Reaper = {};
// print to commandline if -v
Reaper.log = function(message) {
	if (process.argv[2] == '-v') {
		console.log('[BUNDLER] '.red.bold, message);
	} else {
		Syslog.log(Syslog.LOG_INFO, '[BUNDLER] '+message.stripColors);
	}
};

// phantomjs shits itself if it can't find the actual program for
// phantomjs in the path. Jerk.
process.env.PATH = process.env.PATH + ":../node_modules/phantomjs/bin";

Reaper.loadPage = function( requestData ) {
	// Initialize collection of resources the website is dependent on.
	// Will fetch resources as part of the bundle.
  var resourceDomain = 
  var url = req.query.url;

	// Visit the website, determine its HTML and the resources it depends on.
	portScanner.findAPortNotInUse(40000, 60000, 'localhost', function(err, freePort) {
		phantom.create(function(ph) {
			ph.createPage(function(page) {
				Reaper.mainProcess(
					url,  {
						ph: ph,
						page: page,
						resourceDomain: resourceDomain
					});
			});
		}, {port: freePort}
		);
	});
};

Reaper.retrieveResources = function(url, proc) {
	proc.resources = {};
	proc.pageLoadedCutoff = false;
	Reaper.log('Initializing bundling for ' + url.green);
	proc.page.set('onResourceRequested', function(request, networkRequest) {
		if (!proc.pageLoadedCutoff) {
			if ( request.url.match('^http') &&
					request.url.match(proc.resourceDomain)) {
				proc.resources[proc.resourceNumber] = {
					url: request.url
				};
			}
		}
	});
	proc.page.open(url, function(status) {
		proc.pageLoadedCutoff = true;
		if (status !== 'success') {
                    //TODO https://redmine.equalit.ie/redmine/issues/324
			Reaper.log('Abort'.red.bold + ': ' + status);
			return false;
		}
		// We've loaded the page and know what its resources are.
    // Return resources
		proc.ph.exit();
	});
};

//Initialise comms sockets
socket.connect(configData.comms_port);
socket.on('message', function( siteRequest ){
  siteResources = Reaper.loadPage(siteRequest);
  socket.send( siteResources );
});


