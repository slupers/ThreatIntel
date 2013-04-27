from __future__ import absolute_import, division, print_function, unicode_literals
import gevent.monkey
import isodate
import requests
from .base import *

gevent.monkey.patch_socket()

class PhishTankDataProvider(DataProvider):
    _urlbase = "http://checkurl.phishtank.com/checkurl/"

    def __init__(self, apikey=None):
        self._apikey = apikey

    def _dolookup(self, url):
        # Perform a query against PhishTank
        args = {}
        args["url"] = url
        args["format"] = "json"
        if self._apikey != None:
            args["app_key"] = self._apikey
        r = requests.post(self._urlbase, args)
        jdata = r.json()
        return jdata["results"]

    @property
    def name(self):
        return "phishtank"

    def query(self, target, qtype):
        # Bail out if this isn't a URL query
        if qtype != QUERY_URL:
            return None
        
        # Produce an output information set
        jres = self._dolookup(target)
        if jres["in_database"] != True:
            return None
        info = {}
        disp = DISP_NEGATIVE
        if jres["verified"] == "n":
            disp = DISP_INDETERMINATE
        else:
            dval = isodate.parse_datetime(jres["verified_at"])
            info["last_event_ts"] = dval
            if jres["valid"] != "n":
                disp = DISP_POSITIVE
        info["report_id"] = int(jres["phish_id"])
        info["report_url"] = jres["phish_detail_page"]
        return InformationSet(disp, **info)
