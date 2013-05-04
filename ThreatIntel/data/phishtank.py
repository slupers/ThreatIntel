from __future__ import absolute_import, division, print_function, unicode_literals
import gevent.monkey
gevent.monkey.patch_socket()
import isodate
import requests
from .base import *
from manage.presentation import *

class PhishTankClient(object):
    _endpoint = "http://checkurl.phishtank.com/checkurl/"

    def __init__(self, apikey=None):
        self._apikey = apikey

    def query_url(self, url):
        args = {"url": url, "format": "json"}
        if self._apikey != None:
            args["app_key"] = self._apikey
        r = requests.post(self._endpoint, args)
        r.raise_for_status()
        jdata = r.json()
        print(jdata)
        return jdata["results"]

class PhishTankDataProvider(DataProvider):
    def __init__(self, apikey=None):
        self._client = PhishTankClient(apikey)

    @property
    def name(self):
        return "phishtank"

    def _query(self, target, qtype):
        # Bail out if this isn't a URL query
        if qtype != QUERY_URL:
            return None
        
        # Produce an output information set
        jres = self._client.query_url(target)
        if jres["in_database"] != True:
            return None
        info = AttributeList()
        disp = DISP_NEGATIVE
        if jres["verified"] == "n":
            disp = DISP_INDETERMINATE
        else:
            dval = isodate.parse_datetime(jres["verified_at"])
            info.append(("last_event_ts", dval))
            if jres["valid"] != "n":
                disp = DISP_POSITIVE
        info.append(("report_id", int(jres["phish_id"])))
        info.append(("report_url", jres["phish_detail_page"]))
        return InformationSet(disp, info)

__all__ = [
    b"PhishTankDataProvider"
]
