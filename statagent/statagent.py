#!/usr/bin/env python

"""
  Simple Python agent to retrieve stats from Volunteer edges.

 This agent simply runs a local webserver that T-edges will query
for stats about system state.

"""

import SocketServer
import SimpleHTTPServer
import urllib
import json
import commands
import logging

PORT = 81000
PACKAGE_LIST = [ "python-swabber" ]

def getPlatform():
    #TODO
    return "debian"

def getTrafficStats():
    #TODO
    pass

def scanPackagesApt():
    packagedata = {}
    status, output = commands.getstatusoutput("/usr/bin/dpkg -l")
    if status:
        logging.error("Couldn't list packages!")
        return {"status": status, "message": "Couldn't list packages!"}

    for line in output:
        line = line.strip().split(" ")
        state, name, version, arch = line[:4]
        description = line[4:]

        if name in PACKAGE_LIST:
            packagedata[name] = version
    return packagedata

scanPackages = {
    "debian": scanPackagesApt,
    "ubuntu": scanPackagesApt
}[getPlatform()]

class StatGetter(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):

        alldata = {}
        alldata["packagedata"] = scanPackages()

        self.send_response(200)
        self.send_header('Content-type','application/json')
        self.end_headers()
        self.wfile.write(json.dump(alldata))
        return

httpd = SocketServer.ForkingTCPServer(('', PORT), StatGetter)
print "serving at port", PORT
httpd.serve_forever()
