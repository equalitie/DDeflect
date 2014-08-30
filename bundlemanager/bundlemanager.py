#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
import sys
import os
import pwd
import grp
import signal
import threading
import logging
import logging.handlers

from lib.bundler import BundleMaker
from ghost import Ghost

class DebundlerMaker(object):

    def __init__(self, refresh_period):
        self.refresh_period = refresh_period
        self.key = None
        self.iv = None
        self.hmac_key = None
        self.genKeys()
        self.refresher = threading.Timer(self.refresh_period,
                                         self.genKeys())

    def genKeys(self):
        keybytes = os.urandom(16)
        ivbytes = os.urandom(16)
        hmackeybytes = os.urandom(16)
        if self.key and self.iv and self.hmac_key:
            self.logger.info("Rotating keys. Old key was %s, old hmac key was %s and old IV was %s", self.key, self.iv, self.hmac_key)

        self.hmac_key = keybytes.encode('hex')
        self.key = keybytes.encode("hex")
        self.iv = ivbytes.encode("hex")

class VedgeManager(object):
    def __init__(self, vedge_data):
        self.vedge_data = vedge_data

    def getVedge(self):
        #TODO read the vedge_data to figure out when we should serve
        #via a particular edge etc etc
        return self.vedge_data.keys()[0]

class DebundlerServer(flask.Flask):

    def __init__(self, salt, refresh_period,
                 debundler_maker, vedge_manager, template_directory=""):
        super(DebundlerServer, self).__init__("DebundlerServer")
        if template_directory:
            self.template_folder = template_directory
        self.debundler_maker = debundler_maker
        self.vedge_manager = vedge_manager
        self.bundles = collections.defaultdict(dict)

        self.salt = salt
        self.refresh_period = refresh_period

        self.redis = redis.Redis()

        #wildcard routing
        self.route('/', defaults={'path': ''})(self.rootRoute)
        self.route("/_bundle/")(self.serveBundle)
        #more wildcard routing
        self.route('/<path:path>')(self.rootRoute)
        self.bundleMaker = BundleMaker()

    def reloadVEdges(self, vedge_manager):
        self.vedge_manager = vedge_manager

    def cleanBundles(self, stale_time=600):
        #DEPRECATED, replaced by redis expiry
        delete_list = []

        for url, url_data in self.bundles.iteritems():
            if (url_data["fetched"] + stale_time) < time.time():
                delete_list.append(url)

        for url in delete_list:
            del(self.bundles[url])
        return len(delete_list)

    def genBundle(self, url, key, iv, hmac_key):
        logging.debug("Bundle request url is %s",  url)
        bundler_result = self.bundleMaker.createBundle( url,
                                                key,
                                                iv,
                                                hmac_key
                                            )

        if not bundler_result:
            logging.error("Failed to get bundle for %s: %s (%s)", url)
            flask.abort(503)
        logging.debug("Bundle constructed and returned")
       
        #Not 1 thousand percent sure this is the same as what you
        # are currently saving so needs to be rechecked
        rendered_bundle = flask.render_template(
                            "bundle.json",
                            encrypted = bundler_result['content'],
                            hmac = bundler_result['hmac_sig']
                            )

        bundle_content = rendered_bundle
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
            #TODO fix this to not be a wildcard
            resp = flask.Response(bundle, status=200)
            resp.headers['Access-Control-Allow-Origin'] = "*"
            return resp

    def rootRoute(self, path):

        if path.startswith("_bundle"):
            logging.debug("Got a _bundle request at %s", path)
            if "/" not in path:
                logging.error("got request that started with _bundle but had no slash!")
                flask.abort(503)
            return self.serveBundle(path.split("/")[1])
        else:
            v_edge = self.vedge_manager.getVedge()[0]
            key = self.debundler_maker.key
            iv = self.debundler_maker.iv
            hmac_key = self.debundler_maker.hmac_key

            if not path:
                path = "/"

            #DEBUG given that we're doing a dumb example here, let's just
            #use the first bundle we have
            request_host = flask.request.headers.get('Host')
            url = request_host.format(path, key, iv, hmac_key)

            logging.debug("Request is for %s", url)

            #TODO set cookies here
            #flask.request.cookies.get()

            #REALLY BAD IDEA FIX ME THIS MAKES REDIS POINTLESS DERPDERP
            bundlehash = None
            for storedbundlehash in self.redis.smembers("bundles"):
                if self.redis.exists(storedbundlehash):
                    logging.debug("Found bundle in redis")
                    redis_data = json.loads(self.redis.get(storedbundlehash))
                    if redis_data["host"] == request_host and redis_data["path"] == path:
                        logging.debug("Bundle matches current request")
                        bundlehash = storedbundlehash
                        break

            if not bundlehash:
                logging.debug("No bundle hash found. Request new bundle")
                bundlehash = self.genBundle(flask.request.url, key, iv, hmac_key)

            if not self.redis.sismember("bundles", bundlehash) or not self.redis.exists(bundlehash):
                logging.error("Site not in bundles after bundling was requested!!")


            logging.debug("Return found bundle")
            render_result = flask.render_template(
            	"debundler_template.html.j2",
            	hmac_key=unicode(self.hmac_key),
        	key=unicode(key),iv=unicode(iv), v_edge=unicode(v_edge),
            	bundle_signature=bundlehash)


            resp = flask.Response(render_result, status=200)
            #response.set_cookie(
            return resp

class bundleManagerDaemon():
    def __init__(self, pidfile, config, stdin='/dev/stdin',
                stdout='/dev/stdout', stderr='/dev/stderr'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile
        self.config = config
        self.debundleServer = None

    def run(self):

        port = self.config["general"]["port"]
        url_salt = self.config["general"]["url_salt"]

        refresh_period = self.config["general"]["refresh_period"]
        template_directory = self.config["general"]["template_directory"]

        vedge_data = self.config["v_edges"]

        d = DebundlerMaker(refresh_period)
        v = VedgeManager(vedge_data)
        self.debundleServer = DebundlerServer(url_salt, refresh_period,
                                              d, v, template_directory=template_directory)
        logging.info("Starting to serve on port %d", port)
        self.debundleServer.run(debug=True, threaded=True, port=port, use_reloader=False)

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

        with open(self.pidfile, 'w+') as f:
            f.write("%s\n" % pid)

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
            logging.error("Bundlemanager already running\n")
            sys.exit(1)
        self.daemonise()
        self.run()

    def stop(self):
        pid = self.getpid()
        if not pid:
            logging.error("Bundlemanager not running\n")
            sys.exit(1)
        try:
            while 1:
                os.kill(pid, signal.SIGKILL)
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
        logging.error('Could not set effective group id: %s', e)
    try:
        os.setuid(running_uid)
    except OSError, e:
        logging.error('Could not set effective group id: %s', e)
    old_umask = os.umask(077)

def createHandler(daemon,config_path):
    def _handleSignal(signum, frame):
        if signum == signal.SIGTERM:
            daemon.stop()
            logging.warn("Closing on SIGTERM")
        elif signum == signal.SIGHUP:
            if daemon.debundleServer:
                logging.warn("Reload V-Edge list")
                config = yaml.load(open(args.config_path).read())
                daemon.debundleServer.reloadVEdges(
                    VedgeManager(config['v_edges'])
                )
    return _handleSignal


if __name__ == "__main__":
    #ghost = Ghost()

    parser = argparse.ArgumentParser(description = 'Manage DDeflect bundle serving and retreival.')
    parser.add_argument('-c', dest = 'config_path', action = 'store',
                        default = '/etc/bundlemanager.yaml',
                        help = 'Path to config file.')
    parser.add_argument('-v', '--verbose', dest = 'verbose', action = 'store_true',
                        help = 'Verbose mode, not daemonized')

    args = parser.parse_args()

    logger = logging.getLogger()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
    else:
        logger.setLevel(logging.INFO)
        handler = logging.handlers.SysLogHandler(address="/dev/log")
    handler.setFormatter(logging.Formatter("bundlemanager [%(process)d] %(levelname)s %(message)s"))
    logger.addHandler(handler)

    logging.info("Loading config from %s", args.config_path)
    config = yaml.load(open(args.config_path).read())

    dropPrivileges(config["general"]["uid_name"],
                    config["general"]["gid_name"])

    pidfile = config['general']['pidfile']
    daemon = bundleManagerDaemon(pidfile, config)
    signal.signal(signal.SIGTERM, createHandler(daemon, args.config_path))
    signal.signal(signal.SIGHUP, createHandler(daemon, args.config_path))

    if args.verbose:
        daemon.run()
    else:
        daemon.start()
    sys.exit(0)
