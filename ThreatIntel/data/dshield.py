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
    def _parse(cls, data):
        # Produce an AttributeList from the data
        info = AttributeList()
        attacks = None
        ev = data.get("mindate")
        if ev != None:
            if ev == "0":
                return None
            dv = datetime.datetime.strptime(ev, "%Y-%m-%d").date()
            info.append(("first_event_ts", dv))
        ev = data.get("maxdate")
        if ev != None:
            if ev == "0":
                return None
            dv = datetime.datetime.strptime(ev, "%Y-%m-%d").date()
            info.append(("last_event_ts", dv))
        ev = data.get("updated")
        if ev != None:
            if ev == "0":
                return None
            dtv = datetime.datetime.strptime(ev, "%Y-%m-%d %H:%M:%S")
            info.append(("update_ts", dtv))
        ev = data.get("count")
        if ev != None:
            info.append(("n_attack_packets", int(ev)))
        ev = data.get("attacks")
        if ev != None:
            attacks = int(ev)
            info.append(("n_attack_targets", attacks))
        ev = data.get("country")
        if ev != None:
            info.append(("country", ev))
        ev = data.get("as")
        if ev != None:
            info.append(("as_number", int(ev)))
        ev = data.get("asname")
        if ev != None:
            info.append(("as_name", ev))
        ev = data.get("network")
        if ev != None:
            info.append(("network_prefix", ev))
        ev = data.get("comment")
        if ev != None:
            info.append(("comment", ev))
        ev = data.get("abusecontact")
        if ev != None:
            info.append(("abuse_contact", ev))
        
        # Determine a disposition and return the InformationSet
        if attacks == None:
            disp = DISP_INFORMATIONAL
        elif attacks < 10:
            disp = DISP_NEGATIVE
        elif attacks > 50:
            disp = DISP_POSITIVE
        else:
            disp = DISP_INDETERMINATE
        return InformationSet(disp, info)
    
    @property
    def name(self):
        return "dshield"
    
    def _query(self, target, qtype):
        if qtype not in (QUERY_IPV4, QUERY_IPV6):
            return None
        endpoint = self._endpoint.format(target)
        r = requests.get(endpoint)
        r.raise_for_status()
        xp = xml.etree.cElementTree.XMLParser(encoding="utf-8")
        xp.feed(r.text.encode("utf-8"))
        root = xp.close()
        data = {}
        for e in root:
            if e.text == None:
                continue
            tag = unicode(e.tag, "utf-8")
            value = unicode(e.text, "utf-8").strip()
            if len(value) != 0:
                data[tag] = value
        return self._parse(data)
