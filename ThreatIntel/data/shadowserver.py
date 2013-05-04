from __future__ import absolute_import, division, print_function, unicode_literals
import gevent.monkey
gevent.monkey.patch_socket()
import binascii
import contextlib
import csv
from datetime import datetime
from io import BytesIO
import json
import re
import requests
import socket
from socket import AF_INET, IPPROTO_TCP, SOCK_STREAM
from .base import *

class ShadowServerDataProvider(DataProvider):
    _whoissvr = "asn.shadowserver.org"
    _urlbase = "http://innocuous.shadowserver.org/api/"
    _wregex = re.compile("^! Whitelisted: (.*?), (.*), (.*)$")
    
    @classmethod
    def _avlookup(cls, target):
        # Retrieve malware information by MD5/SHA1 hash
        args = {"query": target}
        r = requests.get(cls._urlbase, params=args)
        r.raise_for_status()
        output = r.text
        if output[0] == "!":
            if output.startswith("! Whitelisted:"):
                return cls._parsewhitelist(output)
            elif output.startswith("! Sorry"):
                raise QueryError(b"Query failed")
            elif not output.startswith("! No match found"):
                raise QueryError(b"Invalid response from server")
            return None
        csvend = output.index("\n")
        csvdata = output[0:csvend]
        jsondata = output[csvend + 1:]
        return cls._parseav(csvdata, jsondata)
    
    @staticmethod
    def _parseav(csvdata, jsondata):
        # Produce an AttributeList from positive malware query results
        info = AttributeList()
        with BytesIO(csvdata.encode("utf-8")) as bio:
            cr = csv.reader(bio)
            row = [f.decode("utf-8") for f in cr.next()]
            if len(row[2]) > 0:
                dtv = datetime.strptime(row[2], "%Y-%m-%d %H:%M:%S")
                info.append(("first_event_ts", dtv))
            if len(row[3]) > 0:
                dtv = datetime.strptime(row[3], "%Y-%m-%d %H:%M:%S")
                info.append(("last_event_ts", dtv))
            if len(row[0]) > 0:
                info.append(("sample_md5", binascii.unhexlify(row[0])))
            if len(row[1]) > 0:
                info.append(("sample_sha1", binascii.unhexlify(row[1])))
            if len(row[5]) > 0:
                info.append(("sample_ssdeep", row[5]))
            if len(row[4]) > 0:
                info.append(("file_type", row[4]))
        rlocs = EntityList(("av_engine", "av_record_locator"))
        for t in json.loads(jsondata).iteritems():
            rlocs.append(t)
        info.append(("av_record_locators", rlocs))
        return InformationSet(DISP_POSITIVE, info)

    @classmethod
    def _parsewhitelist(cls, wdata):
        # Produce an AttributeList from whitelisted malware query results
        m = cls._wregex.match(wdata)
        if m == None:
            return None
        info = AttributeList()
        package_vendor = m.group(1)
        if len(package_vendor) != 0 and package_vendor != "null":
            info.append(("package_vendor", package_vendor))
        package_name = m.group(2)
        if len(package_name) != 0 and package_name != "null":
            info.append(("package_name", package_name))
        file_name = m.group(3)
        if len(file_name) != 0 and file_name != "null":
            info.append(("file_name", file_name))
            
        # ShadowServer is bugged and returns bogus results for non-matches
        if len(info) == 0:
            return None
        return InformationSet(DISP_NEGATIVE, info)
    
    @classmethod
    def _peerlookup(cls, target):
        # Retrieve AS information by IPv4 address
        s = socket.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        with contextlib.closing(s):
            s.connect((cls._whoissvr, 43))
            s.send("peer {0}\n".format(target).encode("utf-8"))
            resp = s.recv(1024)
        cmps = resp.decode("utf-8").split(" | ")
        if cmps[-1].endswith("\n"):
            cmps[-1] = cmps[-1][:-1]
        
        # Produce an InformationSet from the data
        peers = EntityList(("as_number", ))
        for asn in cmps[0].split(" "):
            peers.append((int(asn), ))
        info = AttributeList()
        info.append(("country", cmps[4]))
        info.append(("as_number", int(cmps[1])))
        info.append(("as_name", cmps[3]))
        info.append(("network_prefix", cmps[2]))
        info.append(("peer_as_list", peers))
        info.append(("domain", cmps[5]))
        info.append(("isp", cmps[6]))
        return InformationSet(DISP_INFORMATIONAL, info)
    
    @property
    def name(self):
        return "shadowserver"

    def _query(self, target, qtype):
        if qtype == QUERY_IPV4:
            return self._peerlookup(target)
        elif qtype in (QUERY_MD5, QUERY_SHA1):
            return self._avlookup(target)
        return None
