from __future__ import absolute_import, division, print_function, unicode_literals
import gevent.monkey
gevent.monkey.patch_socket()
from datetime import datetime
import isodate
import requests
from xml.etree.cElementTree import XMLParser
from data.base import *
from frontend.presentation import *

class DShieldDataProvider(DataProvider):
    def _handle_date(value):
        if value == "0":
            return None
        return datetime.strptime(value, "%Y-%m-%d").date()

    def _handle_datetime(value):
        if value == "0":
            return None
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    
    @classmethod
    def _parse(cls, data):
        # Produce an AttributeList from the data
        info = AttributeList()
        for key, newkey, fn in cls._handlers:
            value = data.get(key)
            if value != None:
                newvalue = fn(value)
                if newvalue != None:
                    info.append((newkey, newvalue))
        
        # Determine a disposition and return the InformationSet
        attacks = int(data["attacks"]) if "attacks" in data else None
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
        xp = XMLParser(encoding="utf-8")
        xp.feed(r.text.encode("utf-8"))
        root = xp.close()
        data = {}
        for e in root:
            if e.text == None:
                continue
            tag = e.tag.decode("utf-8")
            value = e.text.decode("utf-8").strip()
            if len(value) != 0:
                data[tag] = value
        return self._parse(data)
    
    _endpoint = "http://www.dshield.org/api/ip/{0}"
    _handlers = [
        ("mindate", "first_event_ts", _handle_date),
        ("maxdate", "last_event_ts", _handle_date),
        ("updated", "update_ts", _handle_datetime),
        ("count", "n_attack_packets", int),
        ("attacks", "n_attack_targets", int),
        ("country", "country", lambda x: x),
        ("as", "as_number", int),
        ("asname", "as_name", lambda x: x),
        ("network", "network_prefix", lambda x: x),
        ("comment", "comment", lambda x: x),
        ("abusecontact", "abuse_contact", lambda x: x)
    ]

__all__ = [
    b"DShieldDataProvider"
]
