#!/usr/bin/env python
# -*- coding: utf-8 -*-

import jinja2
import os
import threading
import flask

REFRESH_PERIOD=18000
PORT=80

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

        self.route("/")(self.rootRoute)

    def rootRoute(self):
        v_edge = self.vedge_manager.getVedge()
        key = self.debundler_maker.key
        iv = self.debundler_maker.iv

        render_result = flask.render_template("debundler_template.html.j2", key=unicode(key),
                                             iv=unicode(iv), v_edge=unicode(v_edge))

        resp = flask.Response(render_result, status=200)
        return resp

def main():

    d = DebundlerMaker()
    v = VedgeManager()
    s = DebundlerServer(8000, d, v)
    s.run(debug=True)

if __name__ == "__main__":
    main()
