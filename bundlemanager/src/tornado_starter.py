#!/usr/bin/env python2

from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
import settings

http_server = HTTPServer(WSGIContainer(DebundlerServer()))
http_server.listen(settings.general["wsgi_port"])
IOLoop.instance().start()
