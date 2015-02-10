#!/usr/bin/env python
# -*- coding: utf-8 -*-
import flask
import requests
import redis

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
import random
import logging.handlers

# Stop requests from spamming our logs
logging.getLogger("requests").setLevel(logging.WARNING)

try:
    from bundler import settings
except IOError:
    # IO Error means that we can't load the default settings file.
    if __name__ == "__main__":
        # We'll reload the settings file in main
        pass
    else:
        # We're being imported as a module, there is no hope of
        # recovery.
        raise

from bundler import BundleMaker


def mash_dict(input_dict):
    # Mash together keys and values of a dict
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
            logging.info(("Rotating keys. Old key was %s, "
                          "old hmac key was %s and old IV was %s"),
                         self.key, self.iv.encode("hex"), self.hmac_key)

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
        """
        if self.redis.llen("active_vedges") < self.vedge_threshold:
            self.refreshVedges()
        vedge = self.redis.srandmember("active_vedges")
        return vedge
        """

        #For now, just return a random Vedge
        return self.vedge_data.keys()[random.randint(0,len(self.vedge_data.keys())-1)]


class DebundlerServer(flask.Flask):


    def __init__(self):
        super(DebundlerServer, self).__init__("DebundlerServer")
        if "template_directory" in settings.general:
            self.template_folder = settings.general["template_directory"]

        self.debundler_maker = DebundlerMaker(settings.general["refresh_period"])
        self.vedge_manager = VedgeManager(settings.v_edges)

        self.bundles = collections.defaultdict(dict)
        self.remap_rules = settings.remap
        self.bundleMaker = BundleMaker(
            self.remap_rules,
            settings.general["bundler_location"]
        )

        self.salt = settings.general["url_salt"]
        self.refresh_period = settings.general["refresh_period"]

        redis_host = "localhost"
        if "redis_host" in settings.general:
            redis_host = settings.general["redis_host"]
        self.redis = redis.Redis(host=redis_host)

        # wildcard routing
        self.route('/', defaults={'path': ''})(self.rootRoute)
        self.route('/', methods=['POST'])(self.postRoute)
        self.route("/_bundle/")(self.serveBundle)
        # more wildcard routing
        self.route('/<path:path>')(self.rootRoute)
        self.route('/<path:path>', methods=['POST'])(self.postRoute)

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

        # Mash together all cookies
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

        # Mash together all headers
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

        # Mash together all headers
        header_string = mash_dict(request.headers)

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
        logging.debug("Bundle request url is %s", frequest.url)

        try:
            bundler_result = self.bundleMaker.createBundle(
                frequest,
                key,
                iv,
                hmac_key
            )
        except requests.ConnectionError as e:
            logging.error("Failed to request resources from Reaper! %s", str(e))
            flask.abort(503)

        if not bundler_result:
            logging.error("Failed to get bundle for %s", frequest.url)
            flask.abort(503)

        #Not 1 thousand percent sure this is the same as what you
        # are currently saving so needs to be rechecked
        logging.info("hmac_sig: %s", bundler_result['hmac_sig'])
        rendered_bundle = flask.render_template(
            "bundle.json",
            encrypted=bundler_result['bundle'],
            hmac=bundler_result['hmac_sig']
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

        remapped_origin = self.bundleMaker.remapReqURL(
            remap_host, flask.request
        )

        proxied_response = requests.post(
            remapped_origin,
            headers=request_headers,
            files=flask.request.files,
            data=flask.request.form,
            cookies=flask.request.cookies,
        )

        return flask.Response(
            response=proxied_response
        )

    def serveBundle(self, bundlehash):
        logging.info("Got a request for bundle with hash of %s", bundlehash)
        if not self.redis.sismember("bundles", bundlehash):
            logging.error("Got request for bundle %s but it is not in the bundles list",
                           bundlehash)
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
        if path == "favicon.ico":
            flask.abort(404)

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
            logging.debug("New request received - request is for %s", flask.request.url)

            # HACK - Flask doesn't behave properly as an
            # endpoint. There is a TODO - add header_filter to ATS to
            # pass this properly. For now we hack around it because
            # fuck computers.
            via_header = flask.request.headers.get("Via")
            if via_header and via_header.startswith("https"):
                flask.request.url = flask.request.url.replace("http", "https", 1)
            else:
                logging.info("Got a request for %s request_host with no Via header", request_host)

            #TODO set cookies here
            #flask.request.cookies.get()

            # REALLY BAD IDEA FIX ME THIS MAKES REDIS POINTLESS
            # DERPDERP: Replacement idea - remove the bundle content
            # from the hashing process. Bundles expire anyway. We
            # still guarantee content freshness through expiry, we
            # don't need to pull this bullshit of iterating.
            bundlehash = None
            for storedbundlehash in self.redis.smembers("bundles"):
                if self.redis.exists(storedbundlehash):
                    redis_data = json.loads(self.redis.get(storedbundlehash))

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
                key=unicode(key),
                iv=unicode(iv),
                v_edge=unicode(v_edge),
                bundle_signature=bundlehash
            )

            logging.debug("Returning template to user for signature %s", bundlehash)
            resp = flask.Response(render_result, status=200)

            return resp

class bundleManagerDaemon():
    def __init__(self, stdin='/dev/stdin',
                 stdout='/dev/stdout',
                 stderr='/dev/stderr'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.debundleServer = None

    def run(self):

        port = settings.general["port"]
        host = settings.general["host"]

        self.debundleServer = DebundlerServer()
        logging.info("Starting to serve on port %d", port)
        self.debundleServer.run(debug=False, threaded=True, host=host, port=port, use_reloader=False)

    def delpid(self):
        if os.path.exists(settings.general["pidfile"]):
            os.remove(settings.general["pidfile"])

    def daemonise(self):
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError, e:
            logging.error("fork #1 failed: %d (%s)\n" % (e.errno,
                                                         e.strerror))
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

        with open(settings.general["pidfile"], 'w+') as f:
            f.write("%s\n" % pid)

    def getpid(self):
        try:
            pf = file(settings.general["pidfile"], 'r')
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
    #TODO what is old_umask supposed to be for?
    old_umask = os.umask(077)

def createHandler(daemon):
    def _handleSignal(signum, frame):
        if signum == signal.SIGTERM:
            daemon.stop()
            logging.warn("Closing on SIGTERM")
        elif signum == signal.SIGHUP:
            if daemon.debundleServer:
                logging.warn("Reload V-Edge list")
                settings = reload(settings)
                daemon.debundleServer.reloadVEdges(
                    VedgeManager(settings.v_edges)
                )
    return _handleSignal


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Manage DDeflect bundle serving and retreival.')
    parser.add_argument('-c', dest='config_path', action='store',
                        default='/etc/bundlemanager.yaml',
                        help='Path to config file.')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        help='Verbose mode, not daemonized')

    args = parser.parse_args()
    if "BUNDLEMANAGER_CONFIG" not in os.environ:
        #Backwards compatability
        os.environ["BUNDLEMANAGER_CONFIG"] = args.config_path

    #Make settings import/reimport available everywhere.
    global settings
    from bundler import settings

    logger = logging.getLogger()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
    else:
        logger.setLevel(logging.INFO)
        handler = logging.handlers.SysLogHandler(address="/dev/log")
    handler.setFormatter(logging.Formatter("bundlemanager [%(process)d] %(levelname)s %(message)s"))
    logger.addHandler(handler)

    #TODO Dropping here breaks binding to ports less than 1025
    dropPrivileges(settings.general["uid_name"],
                   settings.general["gid_name"])

    daemon = bundleManagerDaemon()
    signal.signal(signal.SIGTERM, createHandler(daemon))
    signal.signal(signal.SIGHUP, createHandler(daemon))

    if args.verbose:
        daemon.run()
    else:
        daemon.start()
    sys.exit(0)
