#!/usr/bin/python
from __future__ import absolute_import, division, print_function, unicode_literals
import django.core.handlers.wsgi
import django.core.management
import gevent.wsgi
import ThreatIntel.settings

if __name__ == b"__main__":
    django.core.management.setup_environ(ThreatIntel.settings)
    app = django.core.handlers.wsgi.WSGIHandler()
    svr = gevent.wsgi.WSGIServer(("127.0.0.1", 8080), app)
    svr.serve_forever()
