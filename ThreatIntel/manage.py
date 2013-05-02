#!/usr/bin/python
import gevent.monkey
gevent.monkey.patch_all()
import django.core.management
import os
import sys

if __name__ == b"__main__":
    os.environ.setdefault(b"DJANGO_SETTINGS_MODULE", b"ThreatIntel.settings")
    django.core.management.execute_from_command_line(sys.argv)
