#!/usr/bin/env python
# -*- coding: utf-8 -*-

import flask
import jinja2
import requests
import yaml

import argparse
import collections
import time
import hashlib
import os
import threading
import logging

class DebundlerMaker(object):

    def __init__(self, refresh_period):
        self.genKeys()
        self.refresh_period = refresh_period
        self.refresher = threading.Timer(self.refresh_period,
                                         self.genKeys())

    def genKeys(self):
        #TODO add expiry mechanism

        keybytes = os.urandom(16)
        ivbytes = os.urandom(16)
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

    def __init__(self, bundler_url, salt, debundler_maker, vedge_manager):
        super(DebundlerServer, self).__init__("DebundlerServer")
        self.debundler_maker = debundler_maker
        self.vedge_manager = vedge_manager
        #TODO storing bundles here is duuuuumb but let's do it for now.
        self.bundles = collections.defaultdict(dict)

        self.bundler_url = bundler_url
        self.salt = salt

        #wildcard routing
        self.route('/', defaults={'path': ''})(self.rootRoute)
        self.route("/_bundle/")(self.serveBundle)
        #more wildcard routing
        self.route('/<path:path>')(self.rootRoute)

    def cleanBundles(self, stale_time=600):
        #TODO replace this with redis and expiry. this is largely
        #bullshit.
        delete_list = []

        for url, url_data in self.bundles.iteritems():
            if (url_data["fetched"] + stale_time) < time.time():
                delete_list.append(url)

        for url in delete_list:
            del(self.bundles[url])
        return len(delete_list)

    def genBundle(self, host, path):
        bundle_s = requests.Session()
        print "Path is %s" % path
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

        #TODO keep this in redis
        self.bundles[bundle_signature] = {
            "host": host,
            "path": path,
            "bundle": bundle_content,
            "fetched": time.time()
        }

        return bundle_signature

    def serveBundle(self, bundlehash):
        logging.info("Got a request for bundle with hash of %s", bundlehash)
        if bundlehash not in self.bundles:
            flask.abort(404)

        bundle = self.bundles[bundlehash]["bundle"]
        return bundle

    def rootRoute(self, path):

        if path.startswith("_bundle"):
            print "Path starts with _bundle"
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
        print "Request is for %s" % url

        #TODO set cookies here
        #flask.request.cookies.get()

        bundlehash = None
        for storedbundlehash, data in self.bundles.iteritems():
            if data["host"] == request_host and data["path"] == path:
                bundlehash = storedbundlehash
                break

        if not bundlehash:
            bundlehash = self.genBundle(request_host, path)

        if bundlehash not in self.bundles:
            raise Exception("Site not in bundles after bundling was requested!!")

        render_result = flask.render_template("debundler_template.html.j2", key=unicode(key),
                                             iv=unicode(iv), v_edge=unicode(v_edge),
                                              bundle_signature=bundlehash)

        resp = flask.Response(render_result, status=200)
        #response.set_cookie(
        return resp

def main(config):

    port = config["general"]["port"]
    url_salt = config["general"]["url_salt"]

    bundler_url = config["general"]["bundler_path"]
    refresh_period = config["general"]["refresh_period"]

    vedge_data = config["v_edges"]

    d = DebundlerMaker(refresh_period)
    v = VedgeManager(vedge_data)
    s = DebundlerServer(bundler_url, url_salt, d, v)
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
