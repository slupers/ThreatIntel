import gevent.monkey
import isodate
import requests
from . import DataProvider

gevent.monkey.patch_socket()

class PhishTankDataProvider(DataProvider):
    _urlbase = "http://checkurl.phishtank.com/checkurl/"

    def __init__(self, apikey=None):
        self._apikey = apikey

    @staticmethod
    def _dolookup(url):
        # Perform a query against PhishTank
        args = {}
        args["url"] = url
        args["format"] = u"json"
        if self._apikey != None:
            args["app_key"] = self._apikey
        r = requests.post(PhishTankDataProvider._urlbase, args)
        jdata = r.json
        return jdata["results"]

    def query(self, target, qtype):
        # Bail out if this isn't a URL query
        if qtype != DataProvider.URL_QUERY:
            return None
        
        # Produce an output information set
        jres = PhishTankDataProvider._dolookup(query)
        info = {}
        disp = InformationSet.NEGATIVE
        if jres["in_database"] == True:
            if jres["verified"] == u"n":
                disp = InformationSet.INDETERMINATE
            else:
                info["verif_ts"] = isodate.parse_datetime(jres["verified_at"])
                if jres["valid"] != u"n":
                    disp = InformationSet.POSITIVE
            info["report_id"] = int(jres["phish_id"])
            info["report_url"] = jres["phish_detail_page"]
        return InformationSet(disp, info)
