#!/usr/bin/env python
# -*- coding: utf-8 -*-

import flask
import jinja2
import requests

import collections
import time
import hashlib
import os
import threading
import logging

REFRESH_PERIOD=18000
PORT=80

#BUNDLER="http://localhost:3000/?url="
BUNDLER="http://wheezy1.local:3000/?url="
SALT="feise4iephohng4ahteequu3paKoaQuaeviashim"

class DebundlerMaker(object):

    def __init__(self):
        self.genKeys()
        self.refresher = threading.Timer(REFRESH_PERIOD, self.genKeys())

    def genKeys(self):
        #TODO add expiry mechanism

        keybytes = os.urandom(16)
        ivbytes = os.urandom(16)
        self.key = keybytes.encode("hex")
        self.iv = ivbytes.encode("hex")

class VedgeManager(object):
    #This is one massive TODO
    def __init__(self):
        pass

    def getVedge(self):
        return "http://nosmo.me"

class DebundlerServer(flask.Flask):

    def __init__(self, port, debundler_maker, vedge_manager):
        super(DebundlerServer, self).__init__("DebundlerServer")
        self.debundler_maker = debundler_maker
        self.vedge_manager = vedge_manager
        #TODO storing bundles here is duuuuumb but let's do it for now.
        self.bundles = collections.defaultdict(dict)

        #wildcard routing
        self.route('/', defaults={'path': ''})(self.rootRoute)
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
        bundle_get = bundle_s.get(BUNDLER + "%s%s" % (url_scheme, url))

        if bundle_get.status_code > 400:
            logging.error("Failed to get bundle for %s: %s (%s)", url,
                          bundle_get.text, bundle_get.status_code)

        bundle_content = bundle_get.text
        bundle_signature = hashlib.sha512( SALT + bundle_content).hexdigest()

        #TODO keep this in redis
        self.bundles[bundle_signature] = {
            "host": host,
            "path": path,
            "bundle": bundle_content,
            "fetched": time.time()
        }

        return bundle_signature

    def rootRoute(self, path):
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
            if data["host"] == host and data["path"] == path:
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

def main():

    d = DebundlerMaker()
    v = VedgeManager()
    s = DebundlerServer(8000, d, v)
    s.run(debug=True, threaded=True)

if __name__ == "__main__":
    main()
