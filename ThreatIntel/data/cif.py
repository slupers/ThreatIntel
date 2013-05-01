from __future__ import absolute_import, division, print_function, unicode_literals
import gevent.monkey



class CIFDataProvider(DataProvider):

    def __init__(self, svr):
        self._svr = svr

    @property
    def name(self):
        return "CIF"

    def parse_json(j):
        

    def _query(self):
        r = request.get("address")
        j = r.json()
        self.parse_json(j)
