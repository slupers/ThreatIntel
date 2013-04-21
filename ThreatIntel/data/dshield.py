import datetime
import gevent.monkey
import isodate
import requests
import xml.etree.cElementTree
from .base import DataProvider, InformationSet

gevent.monkey.patch_socket()

class DShieldDataProvider(DataProvider):
    _urlbase = "http://www.dshield.org/api/ip/{0}"
    
    @classmethod
    def _dolookup(cls, ip):
        url = cls._urlbase.format(ip)
        r = requests.get(url)
        xfile = xml.etree.cElementTree.fromstring(r.text)
        info = {}
        for e in xfile.iter():
            try:
                k, v = cls._mapelement(e)
                if k != None:
                    info[k] = v
            except:
                pass
        attacks = info.get("attacks")
        if attacks == None:
            disp = InformationSet.INDETERMINATE
        elif attacks < 10:
            disp = InformationSet.NEGATIVE
        elif attacks > 50:
            disp = InformationSet.POSITIVE
        else:
            disp = InformationSet.INDETERMINATE
        return InformationSet(disp, **info)

    @staticmethod
    def _mapelement(e):
        if e.tag == "count":
            return ("n_attack_packets", int(e.text))
        elif e.tag == "attacks":
            return ("n_attack_targets", int(e.text))
        elif e.tag == "maxdate":
            if e.text == "0":
                return None
            dval = datetime.datetime.strptime(e.text, "%Y-%m-%d")
            return ("data_end", dval.date())
        elif e.tag == "mindate":
            if e.text == "0":
                return None
            dval = datetime.datetime.strptime(e.text, "%Y-%m-%d")
            return ("data_start", dval.date())
        elif e.tag == "updated":
            if e.text == "0":
                return None
            dval = datetime.datetime.strptime(e.text, "%Y-%m-%d %H:%M:%S")
            return ("update_ts", dval)
        elif e.tag == "country":
            return ("country", e.text)
        elif e.tag == "as":
            return ("as_number", int(e.text))
        elif e.tag == "asname":
            return ("as_name", e.text)
        elif e.tag == "network":
            return ("network_prefix", e.text)
        elif e.tag == "comment":
            return ("comment", e.text)
        elif e.tag == "abusecontact":
            return ("abuse_contact", e.text)
        else:
            return None

    @property
    def name(self):
        return "dshield"
    
    def query(self, target, qtype):
        if qtype == DataProvider.IPV4_QUERY:
            return self._dolookup(target)
        elif qtype == DataProvider.IPV6_QUERY:
            return self._dolookup(target)
        else:
            return None
