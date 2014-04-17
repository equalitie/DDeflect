#!/usr/bin/env python

import jinja2
import os
import threading

TEMPLATE_PATH="."
REFRESH_PERIOD=18000
PORT=80

class DebundlerMarker(object):

    def __init__(self, template_path):
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_path))
        self.genKeys()

        self.refresher = threading.Timer(REFRESH_PERIOD, self.genKeys())

    def genKeys(self):
        #TODO add expiry mechanism
        self.key = os.urandom(16)
        self.iv = os.urandom(16)

    def getVedge(self):
        return "10.0.0.1:1800"

    def renderPage(self):
        template = env.get_template('debundler_template.html.j2')
        template.render(key=self.key, iv=self.iv, v_edge_redirect=self.getVedge())

def main():

    d = DebundlerMarker(TEMPLATE_PATH)

if __name__ == "__main__":
    main()
