from __future__ import absolute_import, division, print_function, unicode_literals
gevent.monkey.patch_socket()
import gevent.monkey
import binascii
import contextlib
import csv
import datetime
import io
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
    def _avlookup(cls, target, qtype):
        # Retrieve malware information by MD5/SHA1 hash
        args = {"query": target}
        r = requests.get(cls._urlbase, params=args)
        output = unicode(r.text)
        if output[0] == "!":
            if output.startswith("! Whitelisted:"):
                info = cls._processresw(output)
                if info != None:
                    return InformationSet(DISP_NEGATIVE, **info)
            elif output.startswith("! Sorry"):
                raise RuntimeError("The API query returned an error")
            elif not output.startswith("! No match found"):
                raise RuntimeError("Invalid response from ShadowServer")
            return None
        csvend = output.index("\n")
        csvdata = output[0:csvend]
        jsondata = output[csvend + 1:]
        info = cls._processres(csvdata, jsondata)
        return InformationSet(DISP_POSITIVE, **info)
    
    @classmethod
    def _peerlookup(cls, target):
        # Retrieve AS information by IPv4 address
        s = socket.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        with contextlib.closing(s):
            s.connect((cls._whoissvr, 43))
            s.send("peer {0}\n".format(target).encode("utf-8"))
            resp = s.recv(1024)
            cmps = unicode(resp, "utf-8").split(" | ")
            if cmps[-1].endswith("\n"):
                cmps[-1] = cmps[-1][:-1]
            info = {}
            info["peer_as_numbers"] = [int(asn) for asn in cmps[0].split(" ")]
            info["as_number"] = int(cmps[1])
            info["network_prefix"] = cmps[2]
            info["as_name"] = cmps[3]
            info["country"] = cmps[4]
            info["domain"] = cmps[5]
            info["isp"] = cmps[6]
            return InformationSet(DISP_INFORMATIONAL, **info)

    @staticmethod
    def _processres(csvdata, jsondata):
        # Produce a dictionary from positive malware query results
        info = {}
        with io.BytesIO(csvdata.encode("utf-8")) as bio:
            cr = csv.reader(bio)
            row = [unicode(f, "utf-8") for f in cr.next()]
            info["sample_md5"] = binascii.unhexlify(row[0])
            info["sample_sha1"] = binascii.unhexlify(row[1])
            dval = datetime.datetime.strptime(row[2], "%Y-%m-%d %H:%M:%S")
            info["first_event_ts"] = dval
            dval = datetime.datetime.strptime(row[3], "%Y-%m-%d %H:%M:%S")
            info["last_event_ts"] = dval
            info["file_type"] = row[4]
            info["sample_ssdeep"] = row[5]
        info["av_record_locators"] = json.loads(jsondata)
        return info

    @classmethod
    def _processresw(cls, wdata):
        # Produce a dictionary from whitelisted malware query results
        m = cls._wregex.match(wdata)
        if m == None:
            return None
        info = {}
        package_vendor = m.group(1)
        if len(package_vendor) != 0 and package_vendor != "null":
            info["package_vendor"] = package_vendor
        package_name = m.group(2)
        if len(package_name) != 0 and package_name != "null":
            info["package_name"] = package_name
        file_name = m.group(3)
        if len(file_name) != 0 and file_name != "null":
            info["file_name"] = file_name
            
        # ShadowServer is bugged and returns bogus results for non-matches
        if len(info) == 0:
            return None
        return info

    @property
    def name(self):
        return "shadowserver"

    def _query(self, target, qtype):
        if qtype == QUERY_IPV4:
            return self._peerlookup(target)
        elif qtype in (QUERY_MD5, QUERY_SHA1):
            return self._avlookup(target, qtype)
        return None
