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
import os
import threading
import logging

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

        #for storedbundlehash, data in self.bundles.iteritems():
        #    if data["host"] == request_host and data["path"] == path:
        ##        bundlehash = storedbundlehash
        #        break

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

def main(config):

    port = config["general"]["port"]
    url_salt = config["general"]["url_salt"]

    bundler_url = config["general"]["bundler_path"]
    refresh_period = config["general"]["refresh_period"]
    template_directory = config["general"]["template_directory"]

    vedge_data = config["v_edges"]

    d = DebundlerMaker(refresh_period)
    v = VedgeManager(vedge_data)
    s = DebundlerServer(bundler_url, url_salt, refresh_period,
                        d, v, template_directory=template_directory)
    logging.info("Starting to serve on port %d", port)
    print port
    s.run(debug=True, threaded=True, port=port)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description = 'Manage DDeflect bundle serving and retreival.')
    parser.add_argument('-c', dest = 'config_path', action = 'store',
                        default = '/etc/bundlemanager.yaml',
                        help = 'Path to config file.')
    args = parser.parse_args()

    logging.info("Loading config from %s", args.config_path)
    config = yaml.load(open(args.config_path).read())

    main(config)
