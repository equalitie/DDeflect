#!/usr/bin/env python
# -*- coding: utf-8 -*-
import ipdb
import flask
import jinja2
import requests
import redis
import yaml

import argparse
import json
import collections
import time
import hashlib
import sys, os, pwd, grp
import signal
import threading
import logging
import atexit

class DebundlerMaker(object):

    def __init__(self, refresh_period):
        self.refresh_period = refresh_period
        self.key = None
        self.iv = None
        self.genKeys()
        self.refresher = threading.Timer(self.refresh_period,
                                         self.genKeys())

    def genKeys(self):
        keybytes = os.urandom(16)
        ivbytes = os.urandom(16)
        if self.key and self.iv:
            logging.info("Rotating keys. Old key was %s and old IV was %s", self.key, self.iv)
        self.key = keybytes.encode("hex")
        self.iv = ivbytes.encode("hex")

class VedgeManager(object):
    def __init__(self, vedge_data):
        self.vedge_data = vedge_data

    def getVedge(self):
        #TODO read the vedge_data to figure out when we should serve
        #via a particular edge etc etc
        return self.vedge_data.keys()

class DebundlerServer(flask.Flask):

    def __init__(self, bundler_url, salt, refresh_period,
                 debundler_maker, vedge_manager, template_directory=""):
        super(DebundlerServer, self).__init__("DebundlerServer")
        if template_directory:
            self.template_folder = template_directory
        self.debundler_maker = debundler_maker
        self.vedge_manager = vedge_manager
        self.bundles = collections.defaultdict(dict)

        self.bundler_url = bundler_url
        self.salt = salt
        self.refresh_period = refresh_period

        self.redis = redis.Redis()

        #wildcard routing
        self.route('/', defaults={'path': ''})(self.rootRoute)
        self.route("/_bundle/")(self.serveBundle)
        #more wildcard routing
        self.route('/<path:path>')(self.rootRoute)

    def cleanBundles(self, stale_time=600):
        #DEPRECATED, replaced by redis expiry
        delete_list = []

        for url, url_data in self.bundles.iteritems():
            if (url_data["fetched"] + stale_time) < time.time():
                delete_list.append(url)

        for url in delete_list:
            del(self.bundles[url])
        return len(delete_list)

    def genBundle(self, host, path):
        bundle_s = requests.Session()
        logging.debug("Bundle request path is %s",  path)
        if not path:
            path = "/"
        if not path.startswith("/"):
            raise Exception("Receieved invalid path for request to host %s: %s" % (host,path))

        url = "%s%s" % (host, path)
        #TODO add to a config file per-site
        url_scheme = "http://"

        bundle_s.headers.update({"Host": host})
        bundle_get = bundle_s.get(self.bundler_url + "%s%s" % (url_scheme, url))

        if bundle_get.status_code > 400:
            logging.error("Failed to get bundle for %s: %s (%s)", url,
                          bundle_get.text, bundle_get.status_code)

        bundle_content = bundle_get.text
        bundle_signature = hashlib.sha512( self.salt + bundle_content).hexdigest()

        self.redis.sadd("bundles", bundle_signature)
        self.redis.set(bundle_signature, json.dumps({
            "host": host,
            "path": path,
            "bundle": bundle_content,
            "fetched": time.time()
        }))
        self.redis.expire(bundle_signature, self.refresh_period)

        return bundle_signature

    def serveBundle(self, bundlehash):
        logging.info("Got a request for bundle with hash of %s", bundlehash)
        if not self.redis.sismember("bundles", bundlehash):
            flask.abort(404)

        bundle_get = json.loads(self.redis.get(bundlehash))
        if "bundle" not in bundle_get:
            logging.error("Failed to get a valid bundle from bundle key %s", bundlehash)
            flask.abort(503)
        else:
            bundle = bundle_get["bundle"]
            return bundle

    def rootRoute(self, path):

        if path.startswith("_bundle"):
            logging.debug("Got a _bundle request at %s", path)
            if "/" not in path:
                logging.error("got request that started with _bundle but had no slash!")
                flask.abort(503)
            return self.serveBundle(path.split("/")[1])

        v_edge = self.vedge_manager.getVedge()
        key = self.debundler_maker.key
        iv = self.debundler_maker.iv

        if not path:
            path = "/"

        #DEBUG given that we're doing a dumb example here, let's just
        #use the first bundle we have
        request_host = flask.request.headers.get('Host')
        url = "%s%s" % (request_host, path)
        logging.debug("Request is for %s", url)

        #TODO set cookies here
        #flask.request.cookies.get()

        #REALLY BAD IDEA FIX ME THIS MAKES REDIS POINTLESS DERPDERP
        bundlehash = None
        for storedbundlehash in self.redis.smembers("bundles"):
            if self.redis.exists(storedbundlehash):
                redis_data = json.loads(self.redis.get(storedbundlehash))
                if redis_data["host"] == request_host and redis_data["path"] == path:
                    bundlehash = storedbundlehash
                    break

        if not bundlehash:
            bundlehash = self.genBundle(request_host, path)

        if not self.redis.sismember("bundles", bundlehash) or not self.redis.exists(bundlehash):
            raise Exception("Site not in bundles after bundling was requested!!")

        render_result = flask.render_template(
            "debundler_template.html.j2",
            key=unicode(key),iv=unicode(iv), v_edge=unicode(v_edge),
            bundle_signature=bundlehash)

        resp = flask.Response(render_result, status=200)
        #response.set_cookie(
        return resp

class bundleManagerDaemon():
    def __init__(self, pidfile, config, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile
 
        self.config = config

    def run(self):

        port = self.config["general"]["port"]
        url_salt = self.config["general"]["url_salt"]

        bundler_url = self.config["general"]["bundler_path"]
        refresh_period = self.config["general"]["refresh_period"]
        template_directory = self.config["general"]["template_directory"]

        vedge_data = self.config["v_edges"]

        d = DebundlerMaker(refresh_period)
        v = VedgeManager(vedge_data)
        s = DebundlerServer(bundler_url, url_salt, refresh_period,
                            d, v, template_directory=template_directory)
        logging.info("Starting to serve on port %d", port)
        s.run(debug=True, threaded=True, port=port)

    def delpid(self):
        if os.path.exists(self.pidfile):
            os.remove(self.pidfile)

    def daemonise(self):
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError, e:
            logging.error("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno,
            e.strerror))
            sys.exit(1)
        pid = str(os.getpid())
        file(self.pidfile, 'w+').write("%s\n" % pid)

    def getpid(self):
        try:
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None
        return pid

    def start(self):
        if self.getpid():
            logging.error(self.getpid())
            logging.error("Bundlemanager already running\n")
            #sys.exit(1)
        self.daemonise()
        self.run()

    def stop(self):
        pid = self.getpid()
        if not pid:
            logging.error("Bundlemanager not running\n")
            sys.exit(1)
        try:
            while 1:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
        except OSError, e:
            e = str(e)
            if e.find("No such process") > 0:
                self.delpid()
            else:
                logging.error(e)
                sys.exit(1)

    def restart(self):
        self.stop()
        self.start()

def dropPrivileges(uid_name='nobody', gid_name='no_group'):
    if os.getuid() != 0:
        return

    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    os.setgroups([])
    try:
        os.setgid(running_gid)
    except OSError, e:
        logging.error('Could net set effective group id: %s' % e)
    try:
        os.setuid(running_uid)
    except OSError, e:
        logging.error('Could net set effective group id: %s' % e)
    old_umask = os.umask(077)


if __name__ == "__main__":

    #TODO here:
    # drop privileges,
    # set up proper logging
    #(log to stdout if we're running interactive, otherwise log to syslog)
    # create a PID file
    # double fork
    # add signal handling (via signal.signal)
    

    parser = argparse.ArgumentParser(description = 'Manage DDeflect bundle serving and retreival.')
    parser.add_argument('command', action = 'store',
                        choices = ('start', 'stop', 'restart'),
                        help = 'start|stop|restart')
    parser.add_argument('-c', dest = 'config_path', action = 'store',
                        default = '/etc/bundlemanager.yaml',
                        help = 'Path to config file.')
    args = parser.parse_args()

    logging.info("Loading config from %s", args.config_path)
    config = yaml.load(open(args.config_path).read())
    dropPrivileges(config["general"]["uid_name"],
                    config["general"]["gid_name"])

    pidfile = config['general']['pidfile']
    daemon = bundleManagerDaemon(pidfile, config)

    def handleSignal(signum, frame):
        daemon.stop()
        logging.warn("Closing on SIGTERM")
    signal.signal(signal.SIGTERM, handleSignal)

    if 'start' == args.command:
        daemon.start()
    elif 'stop' == args.command:
        daemon.stop()
    elif 'restart' == args.command:
        daemon.restart()
