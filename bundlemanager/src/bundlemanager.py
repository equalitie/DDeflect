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
#from datetime import datetime, time

from bundler import BundleMaker

def mash_dict(input_dict):
    #Mash together keys and values of a dict
    output_string = "".join([ i for i in input_dict.keys() ])
    output_string += "".join([ str(i) for i in input_dict.values() ])
    return output_string

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

        key_bytes = os.urandom(16)
        iv_bytes = os.urandom(16)
        hmac_key_bytes = os.urandom(16)
        if self.key and self.iv and self.hmac_key:
            logging.info("Rotating keys. Old key was %s, old hmac key was %s and old IV was %s", self.key, self.iv.encode("hex"), self.hmac_key)

        self.hmac_key = hmac_key_bytes.encode('hex')
        self.key = key_bytes.encode("hex")
        self.iv = iv_bytes.encode("hex")

class VedgeManager(object):
    def __init__(self, vedge_data):
        self.vedge_data = vedge_data
        #self.redis = redis.Redis()
        self.vedge_threshold = 100
    '''
    def populateRedisVEdges(self):
        """
        Set initial values for v-edges in redis
        storing time windows and bandwidth constraints
        """
        for edge in self.vedge_data:
            value = json.dumps({
                "start": edge['availability']['start'],
                "end": edge['availability']['end'],
                "total_bandiwdth": edge['total_bandwidth'],
                "used_bandwidth": 0
            })
            self.redis.sadd("vedges", edge.key())
            self.redis.set(edge.key(), value)

            now = datetime.utcnow()
            now_time = now.time()

            start = time.strptime(edge['availability']['start'], "%H:%M")
            end = time.strptime(edge['availability']['end'], "%H:%M")

            if now_time >= start and now_time <= end:
                expiration = now.replace(
                                    hour = end.hour,
                                    minute = end.minute
                            )
                active_key = edge.key() + '_active'
                self.redis.sadd("active_vedges", active_key)
                self.redis.set(active_key, value)
                self.redis.expire(active_key, expiration)

            #Build special set for quick lookup of time windows, represent as hash set

        # Create active set and copy store to it
        # with expiration for keys
        # key should be delted for bandwidth when that quantity is reached
        # in terms of bandwidth, this should be handled by the badnwidth
        # recorder
        '''
    def refreshVedges(self):
        """
        Rebuild v-edge list is number of available v-edges
        has slipped below predefined threshold
        """
        pass

    def getVedge(self):
        """
        This function selects v-edges based on
        their current availability, the time last accessed,
        and the total bandwidth available
        """
        # pop first element in sorted list, reset timestamp
        return self.vedge_data.keys()[0]
        """
        if self.redis.llen("active_vedges") < self.vedge_threshold:
            self.refreshVedges()
        vedge = self.redis.srandmember("active_vedges")
        return vedge
        """

class DebundlerServer(flask.Flask):

    def __init__(self, salt, refresh_period, remap_rules,
                 debundler_maker, vedge_manager, comms_port, template_directory=""):
        super(DebundlerServer, self).__init__("DebundlerServer")
        if template_directory:
            self.template_folder = template_directory
        self.debundler_maker = debundler_maker
        self.vedge_manager = vedge_manager
        self.bundles = collections.defaultdict(dict)
        self.remap_rules = remap_rules
        self.bundleMaker = BundleMaker(remap_rules, comms_port)
        self.salt = salt
        self.refresh_period = refresh_period

        self.redis = redis.Redis()

        #wildcard routing
        self.route('/', defaults={'path': ''})(self.rootRoute)
        self.route('/',  methods=['POST'])(self.postRoute)
        self.route("/_bundle/")(self.serveBundle)
        #more wildcard routing
        self.route('/<path:path>')(self.rootRoute)
        self.route('/<path:path>',  methods=['POST'])(self.postRoute)

    def reloadVEdges(self, vedge_manager):
        self.vedge_manager = vedge_manager

    def _bundleSigContentOnly(self, request, bundle_content):
        return hashlib.sha512(self.salt + bundle_content).hexdigest()

    @staticmethod
    def _bundleCheckHostPath(request_data, redis_data):
        if redis_data["host"] == request_data.headers["host"] and \
                redis_data["path"] == request_data.path:
            return True
        else:
            return False

    def _bundleSigContentUserAgentIP(self, request, bundle_content):
        return hashlib.sha512(
            self.salt + bundle_content + request.user_agent.string \
                + request.environ['REMOTE_ADDR']
        ).hexdigest()

    @staticmethod
    def bundleCheckUserAgentIP(request_data, redis_data):
        if redis_data["host"] == request_data.headers["host"] and \
                redis_data["path"] == request_data.path and\
                request_data.headers["User-Agent"] == redis_data["headers"]["User-Agent"] and\
                request_data.environ["REMOTE_ADDR"] == redis_data["requestor"]:
            return True
        else:
            return False

    def _bundleSigContentUserAgentIPCookies(self, request, bundle_content):

        #Mash together all cookies
        cookie_string = mash_dict(request.cookies)

        return hashlib.sha512(
            self.salt + bundle_content + request.user_agent.string + \
            cookie_string + request.environ['REMOTE_ADDR']
        ).hexdigest()

    def _bundleCheckUserAgentIPCookies(self, request_data, redis_data):
        if self.bundleCheckUserAgentIP(request_data, redis_data) and \
                mash_dict(request_data.cookies) == mash_dict(redis_data["cookies"]):
            return True
        else:
            return False

    def _bundleSigContentUserAgentCookies(self, request, bundle_content):

        #Mash together all headers
        cookie_string = mash_dict(request.headers)

        return hashlib.sha512(
            self.salt + bundle_content + request.user_agent.string + \
            cookie_string
        ).hexdigest()

    def _bundleCheckUserAgentCookies(self, request_data, redis_data):
        if self.bundleCheckUserAgentIP(request_data, redis_data) and \
                mash_dict(request_data.cookies) == mash_dict(redis_data["cookies"]):
            return True
        else:
            return False

    def _bundleSigContentUserAgentIPHeaders(self, request, bundle_content):
        """ The most "secure" mechanism """

        #Mash together all headers
        cookie_string = mash_dict(request.headers)

        return hashlib.sha512(
            self.salt + bundle_content["bundle"] + request.user_agent.string + \
            request.environ['REMOTE_ADDR'] + header_string
        ).hexdigest()

    def genBundleHash(self, request, bundle):
        return self._bundleSigContentUserAgentCookies(request, bundle)

    def checkBundleSig(self, request_data, redis_data):
        return self._bundleCheckUserAgentCookies(request_data, redis_data)

    def genBundle(self, frequest, path, key, iv, hmac_key):
        request_host = frequest.headers.get('Host')
        logging.debug("Bundle request url is %s",  frequest.url)
        bundler_result = self.bundleMaker.createBundle(frequest,
                                                       key,
                                                       iv,
                                                       hmac_key
                                                       )

        if not bundler_result:
            logging.error("Failed to get bundle for %s: %s (%s)", frequest.url)
            flask.abort(503)
        logging.debug("Bundle constructed and returned")

        #Not 1 thousand percent sure this is the same as what you
        # are currently saving so needs to be rechecked
        logging.info("hmac_sig: %s", bundler_result['hmac_sig'])
        rendered_bundle = flask.render_template(
                            "bundle.json",
                            encrypted = bundler_result['bundle'],
                            hmac = bundler_result['hmac_sig']
                            )
        bundle_content = rendered_bundle
        bundle_signature = self.genBundleHash(frequest, rendered_bundle)
        self.redis.sadd("bundles", bundle_signature)
        self.redis.set(bundle_signature, json.dumps({
            "host": request_host,
            "path": path,
            #TODO redundant storage - cookies are part of the headers objects
            "cookies": frequest.cookies,
            "headers": dict(frequest.headers),
            "requestor": frequest.environ["REMOTE_ADDR"],
            "bundle": bundle_content,
            "fetched": time.time()
        }))
        self.redis.expire(bundle_signature, self.refresh_period)

        return bundle_signature

    def postRoute(self):
        """
        Passes POST request directly to the remapped origin
        returns the server's response
        """
        request_host = flask.request.headers.get('Host')
        remap_host = ''
        if request_host in self.remap_rules:
            remap_host = self.remap_rules[request_host]
        else:
            #Return 404
            return None
        
        # Whitelist a few headers to pass on
        request_headers = {}
        for h in ["Cookie", "Referer", "X-Csrf-Token", "Content-Length"]:
            if h in flask.request.headers:
                request_headers[h] = flask.request.headers[h]
        
        request_headers['Host'] = request_host

        remapped_origin = self.bundleMaker.remapReqURL(remap_host, flask.request)
        
        proxied_response = requests.post(
                remapped_origin,
                headers = request_headers,
                files = flask.request.files,
                data = flask.request.form,
                cookies = flask.request.cookies,

        )
        
        return flask.Response(
                    response=proxied_response
                )
    def serveBundle(self, bundlehash):
        logging.info("Got a request for bundle with hash of %s", bundlehash)
        if not self.redis.sismember("bundles", bundlehash):
             logging.error("Got request for bundle %s but it is not in the bundles list", bundlehash)
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
        #TODO this may be causing issues with premature broken pipes
        #if path == "favicon.ico":
        #    flask.abort(501)

        if path.startswith("_bundle"):
            logging.debug("Got a _bundle request at %s", path)
            if "/" not in path:
                logging.error("got request that started with _bundle but had no slash!")
                flask.abort(503)
            return self.serveBundle(path.split("/")[1])
        else:
            v_edge = self.vedge_manager.getVedge()
            key = self.debundler_maker.key
            iv = self.debundler_maker.iv
            hmac_key = self.debundler_maker.hmac_key

            if not path:
                path = "/"

            request_host = flask.request.headers.get('Host')
            logging.debug("Request is for %s", flask.request.url)

            #TODO set cookies here
            #flask.request.cookies.get()

            #REALLY BAD IDEA FIX ME THIS MAKES REDIS POINTLESS DERPDERP
            bundlehash = None
            for storedbundlehash in self.redis.smembers("bundles"):
                if self.redis.exists(storedbundlehash):
                    redis_data = json.loads(self.redis.get(storedbundlehash))

                    #TODO this needs testing
                    if self.checkBundleSig(flask.request, redis_data):
                        #if redis_data["host"] == request_host and redis_data["path"] == path:
                        logging.debug("Bundle %s matches current request", storedbundlehash)
                        bundlehash = storedbundlehash
                        break

            if not bundlehash:
                logging.debug("No bundle hash found. Requesting new bundle")
                bundlehash = self.genBundle(flask.request, path,
                                            key, iv, hmac_key)
                if not bundlehash:
                    logging.error("Failing because bundlehash was null")
                    flask.abort(404)

            if not self.redis.sismember("bundles", bundlehash) or not self.redis.exists(bundlehash):
                logging.error("Site not in bundles after bundling was requested!!")
                flask.abort(503)

            render_result = flask.render_template(
                "debundler_template.html.j2",
                hmac_key=unicode(hmac_key),
                key=unicode(key),iv=unicode(iv),
                v_edge=unicode(v_edge),
                bundle_signature=bundlehash)

            logging.debug("Returning template to user for signature %s", bundlehash)
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
        host = self.config["general"]["host"]
        url_salt = self.config["general"]["url_salt"]

        refresh_period = self.config["general"]["refresh_period"]
        template_directory = self.config["general"]["template_directory"]

        vedge_data = self.config["v_edges"]
        remap_rules = self.config["remap"]
        comms_port = self.config["general"]["comms_port"]

        d = DebundlerMaker(refresh_period)
        v = VedgeManager(vedge_data)
        self.debundleServer = DebundlerServer(url_salt, refresh_period,
                                            remap_rules, d, v, comms_port,
                                            template_directory=template_directory)
        logging.info("Starting to serve on port %d", port)
        self.debundleServer.run(debug=False, threaded=True, host=host, port=port, use_reloader=False)

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
            logging.error("Stale pidfile exists.\n")

        self.daemonise()
        self.run()

    def stop(self):
        pid = self.getpid()
        #TODO wat? How can we not be running if we're called from
        #inside ourself.
        if not pid:
            logging.error("Bundlemanager not running\n")
            sys.exit(1)
        #TODO simplify this, it's more than a little overcomplicated.
        try:
            while 1:
                self.delpid()
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

    #TODO Dropping here breaks binding to ports less than 1025
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
