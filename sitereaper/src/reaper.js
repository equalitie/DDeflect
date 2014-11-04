#!/usr/bin/env node
// -*- eval: (indent-tabs-mode t) -*-

'use strict';
/*
* Load dependencies.
*/

var portScanner = require('portscanner'),
	http 	      = require('http'),
	express     = require('express'),
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

var listenport = 3000;
var listenip = "127.0.0.1";
if ("listen" in configData) {
	if ("host" in configData) {
		listenip = configdata["listen"]["host"];
	}
	if ("port" in configData) {
		listenport = configData["listen"]["port"];
	}
}

var Reaper = express()
.use(require('compression')())
.use(require('body-parser')())
.use(require('method-override')());

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

http.createServer(Reaper).listen(listenport, listenip, function() {
	 //Drop privileges if running as root
	if (process.getuid() === 0) {
		console.log("Dropping privileges");
		// TODO actually have these values read out of config - config
		// is usually read AFTER this point
		if ("group" in configData) {
			console.log("Dropping group to " + configData["general"]["group"]);
			process.setgid(configData["general"]["group"]);
		}
		if ("user" in configData) {
			console.log("Dropping user to " + configData["general"]["user"]);
			process.setuid(configData["general"]["user"]);
		}
	}
});

Reaper.route('/').get(function(req, res) {
	Reaper.loadPage(req, res);
});

Reaper.loadPage = function( req, res ) {
	// Initialize collection of resources the website is dependent on.
	// Will fetch resources as part of the bundle.
	// Visit the website, determine its HTML and the resources it depends on.
	portScanner.findAPortNotInUse(40000, 60000, 'localhost', function(err, freePort) {
		phantom.create(function(ph) {
			ph.createPage(function(page) {
        var headers = {"Host": req.host};
        page.set("customHeaders", headers);
				Reaper.retrieveResources(
					req.data.url, res,  {
						ph: ph,
						page: page,
						host: req.data.host,
            remapped_host: req.data.remapped_host
					});
			});
		}, {port: freePort}, '--ignore-ssl-errors=true', '--ssl-protocol=tlsv1'
		);
	});
};

Reaper.retrieveResources = function(url, res, proc) {
	proc.resources = [];
	proc.pageLoadedCutoff = false;
	console.log('Initializing resource collection for ' + url);
  try {
    proc.page.set('onResourceRequested', function(request, networkRequest) {
       console.log('Resource event caught');
      if (!proc.pageLoadedCutoff) {
        console.log("resource: " + request.url);
        if ( request.url.match('^http') &&
            ( request.url.match(proc.host) ||
              request.url.match(proc.remapped_host ))) {
          //var resource_url = (request.url.match(proc.host)) ? request.url.replace(proc.host, proc.remapped_host) : request.url;
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
        console.log('Abort' + ': ' + status);
      }
      // We've loaded the page and know what its resources are.
      
      res.end( JSON.stringify(proc.resources) );
      console.log('Resources found: ' + JSON.stringify(proc.resources));
      proc.ph.exit();
    });
  } 
  catch (e){
    console.log(e);
    res.end( null );
  }
};



