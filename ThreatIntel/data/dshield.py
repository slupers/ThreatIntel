from __future__ import absolute_import, division, print_function, unicode_literals
import gevent.monkey
gevent.monkey.patch_socket()
import datetime
import isodate
import requests
import xml.etree.cElementTree
from .base import *

class DShieldDataProvider(DataProvider):
    _urlbase = "http://www.dshield.org/api/ip/{0}"
    
    @classmethod
    def _dolookup(cls, ip):
        url = cls._urlbase.format(ip)
        r = requests.get(url)
        xp = xml.etree.cElementTree.XMLParser(encoding="utf-8")
        xp.feed(r.text.encode("utf-8"))
        xtree = xp.close()
        info = {}
        for e in xtree.iter():
            try:
                cls._mapelement(e, info)
            except:
                pass
        attacks = info.get("attacks")
        if attacks == None:
            disp = DISP_INDETERMINATE
        elif attacks < 10:
            disp = DISP_NEGATIVE
        elif attacks > 50:
            disp = DISP_POSITIVE
        else:
            disp = DISP_INDETERMINATE
        return InformationSet(disp, **info)

    @staticmethod
    def _mapelement(e, info):
        ev = unicode(e.text, "utf-8").strip()
        if e.tag == "count":
            info["n_attack_packets"] = int(ev)
        elif e.tag == "attacks":
            info["n_attack_targets"] = int(ev)
        elif e.tag == "maxdate":
            if e.text == "0":
                return None
            dval = datetime.datetime.strptime(ev, "%Y-%m-%d")
            info["last_event_ts"] = dval.date()
        elif e.tag == "mindate":
            if e.text == "0":
                return None
            dval = datetime.datetime.strptime(ev, "%Y-%m-%d")
            info["first_event_ts"] = dval.date()
        elif e.tag == "updated":
            if e.text == "0":
                return None
            dval = datetime.datetime.strptime(ev, "%Y-%m-%d %H:%M:%S")
            info["update_ts"] = dval
        elif e.tag == "country":
            info["country"] = ev
        elif e.tag == "as":
            info["as_number"] = int(ev)
        elif e.tag == "asname":
            info["as_name"] = ev
        elif e.tag == "network":
            info["network_prefix"] = ev
        elif e.tag == "comment":
            info["comment"] = ev
        elif e.tag == "abusecontact":
            info["abuse_contact"] = ev

    @property
    def name(self):
        return "dshield"
    
    def _query(self, target, qtype):
        if qtype in (QUERY_IPV4, QUERY_IPV6):
            return self._dolookup(target)
        return None
