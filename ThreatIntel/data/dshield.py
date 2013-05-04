from __future__ import absolute_import, division, print_function, unicode_literals
import gevent.monkey
gevent.monkey.patch_socket()
import datetime
import isodate
import requests
import xml.etree.cElementTree
from .base import *
from manage.presentation import *

class DShieldDataProvider(DataProvider):
    _endpoint = "http://www.dshield.org/api/ip/{0}"

    @classmethod
    def _mapelement(cls, e, info):
        ev = unicode(e.text, "utf-8").strip()
        if e.tag == "count":
            info["n_attack_packets"] = int(ev)
        elif e.tag == "attacks":
            info["n_attack_targets"] = int(ev)
        elif e.tag == "maxdate":
            if e.text == "0":
                return None
            dv = datetime.datetime.strptime(ev, "%Y-%m-%d").date()
            info["last_event_ts"] = dv
        elif e.tag == "mindate":
            if e.text == "0":
                return None
            dv = datetime.datetime.strptime(ev, "%Y-%m-%d").date()
            info["first_event_ts"] = dv
        elif e.tag == "updated":
            if e.text == "0":
                return None
            dtv = datetime.datetime.strptime(ev, "%Y-%m-%d %H:%M:%S")
            info["update_ts"] = dtv
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

    @classmethod
    def _parse(cls, tree):
        info = {}
        for e in tree.iter():
            try:
                cls._mapelement(e, info)
            except:
                pass
        attacks = info.get("n_attack_targets")
        if attacks == None:
            disp = DISP_INFORMATIONAL
        elif attacks < 10:
            disp = DISP_NEGATIVE
        elif attacks > 50:
            disp = DISP_POSITIVE
        else:
            disp = DISP_INDETERMINATE
        info2 = AttributeList()
        for k, v in info.iteritems():
            info2.append((k, v))
        return InformationSet(disp, info2)

    @property
    def name(self):
        return "dshield"
        
    @classmethod
    def _query_ip(cls, ip):
        url = cls._endpoint.format(ip)
        r = requests.get(url)
        xp = xml.etree.cElementTree.XMLParser(encoding="utf-8")
        xp.feed(r.text.encode("utf-8"))
        tree = xp.close()
        return tree
    
    def _query(self, target, qtype):
        if qtype in (QUERY_IPV4, QUERY_IPV6):
            return self._parse(self._query_ip(target))
        return None
