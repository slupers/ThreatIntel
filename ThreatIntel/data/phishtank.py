from __future__ import absolute_import, division, print_function, unicode_literals
import gevent.monkey
gevent.monkey.patch_socket()
import isodate
import requests
from data.base import *
from frontend.presentation import *

class PhishTankDataProvider(DataProvider):
    def __init__(self, apikey=None):
        if apikey != None:
            assert isinstance(apikey, basestring)
            apikey = apikey.lower()
            if self._keyregex.match(apikey) == None:
                raise ValueError(b"Invalid PhishTank API key")
        self._apikey = apikey
    
    @property
    def name(self):
        return "phishtank"
    
    def _query(self, target, qtype):
        # Early-exit if this isn't a URL query
        if qtype != QUERY_URL:
            return None
        
        # Perform the query
        args = {"url": target, "format": "json"}
        if self._apikey != None:
            args["app_key"] = self._apikey
        r = requests.post(self._endpoint, args)
        r.raise_for_status()
        
        # Produce an InformationSet
        try:
            jres = r.json()["results"]
            if jres["in_database"] != True:
                return None
            info = AttributeList()
            disp = DISP_NEGATIVE
            if jres["verified"] == True:
                dval = isodate.parse_datetime(jres["verified_at"])
                info.append(("update_ts", dval))
                if jres["valid"] == True:
                    disp = DISP_POSITIVE
            else:
                disp = DISP_INDETERMINATE
            info.append(("report_id", int(jres["phish_id"])))
            info.append(("report_url", jres["phish_detail_page"]))
        except Exception:
            raise QueryError(b"Received data in unexpected format")
        return InformationSet(disp, info)
    
    _endpoint = "http://checkurl.phishtank.com/checkurl/"
    _keyregex = re.compile(r"^[a-f0-9]{64}$")

__all__ = [
    b"PhishTankDataProvider"
]
