import isodate
import requests
from . import DataProvider

class PhishTankDataProvider(DataProvider):
    _urlbase = "http://checkurl.phishtank.com/checkurl/"
    _apikey = None

    @staticmethod
    def _phishquery(url):
        # Perform a query against PhishTank
        args = {}
        args["url"] = url
        args["format"] = u"json"
        if PhishTankDataProvider._apikey != None:
            args["app_key"] = PhishTankDataProvider._apikey
        r = requests.post(PhishTankDataProvider._urlbase, args)
        jdata = r.json
        return jdata["results"]

    def lookup(self, query, type):
        # Produce an output information set
        jres = PhishTankDataProvider._phishquery(query)
        info = {}
        disp = DataProvider.Result.NEGATIVE
        if jres["in_database"] == True:
            if jres["verified"] == u"n":
                disp = DataProvider.Result.INDETERMINATE
            else:
                info["verif_ts"] = isodate.parse_datetime(jres["verified_at"])
                if jres["valid"] != u"n":
                    disp = DataProvider.Result.POSITIVE
            info["report_id"] = int(jres["phish_id"])
            info["report_url"] = jres["phish_detail_page"]
        return DataProvider.Result(disp, info)
