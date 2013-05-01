#!/usr/bin/env python
#import gevent.monkey
#gevent.monkey.patch_all()
import sys
sys.path = sys.path + ['', '/usr/lib/python2.7', '/usr/lib/python2.7/plat-linux2', '/usr/lib/python2.7/lib-tk', '/usr/lib/python2.7/lib-old', '/usr/lib/python2.7/lib-dynload', '/usr/local/lib/python2.7/dist-packages', '/usr/lib/python2.7/dist-packages', '/usr/lib/python2.7/dist-packages/PIL', '/usr/lib/python2.7/dist-packages/gst-0.10', '/usr/lib/python2.7/dist-packages/gtk-2.0', '/usr/lib/pymodules/python2.7', '/usr/lib/python2.7/dist-packages/ubuntu-sso-client', '/usr/lib/python2.7/dist-packages/ubuntuone-client', '/usr/lib/python2.7/dist-packages/ubuntuone-control-panel', '/usr/lib/python2.7/dist-packages/ubuntuone-couch', '/usr/lib/python2.7/dist-packages/ubuntuone-installer', '/usr/lib/python2.7/dist-packages/ubuntuone-storage-protocol'] 

import os
import sys


if __name__ == "__main__":
    import gevent
    from gevent import monkey
    monkey.patch_all()

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ThreatIntel.settings")

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
