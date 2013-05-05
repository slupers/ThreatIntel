import requests
import json

class CIFDataProvider(DataProvider):

    _server = "https://192.17.19.200/api/"
    

    if __init__(self, key):
        global key = key
        
    @property
    def name(self):
        return "CIF"
 
    def _parser(self, data):
        return data

    def _query(self, target, qtype):

        if qtype != QUERY_IPV4:
            return None
 
        args = {"apikey": key, "q": target}
        r = request.get(self._server, params=args)
        r.raise_for_status()
        output = r.json()
        return self._parser(output)
