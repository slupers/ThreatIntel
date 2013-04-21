import binascii
import contextlib
import csv
import cStringIO
import datetime
import gevent.monkey
import json
import socket
from socket import AF_INET, IPPROTO_TCP, SOCK_STREAM
import requests
from .base import DataProvider, InformationSet

gevent.monkey.patch_socket()

class ShadowServerDataProvider(DataProvider):
    _whoissvr = "64.71.137.251" # ShadowServer's DNS is FUBAR
    _urlbase = "http://innocuous.shadowserver.org/api/"
    _urlbasew = "http://bin-test.shadowserver.org/api"
    
    @classmethod
    def _avlookup(cls, target, qtype):
        # Retrieve malware information by MD5/SHA1 hash
        args = {"query": target}
        r = requests.get(cls._urlbase, params=args)
        output = r.text
        if output[0] == "!":
            if output[2] == "W":
                if output != "! Whitelisted: null, null, null\n":
                    return cls._wlookup(target, qtype)
            return None
        csvend = output.index("\n")
        csvdata = output[0:csvend]
        jsondata = output[csvend + 1:]
        info = cls._processres(csvdata, jsondata)
        return InformationSet(InformationSet.POSITIVE, **info)
    
    @classmethod
    def _peerlookup(cls, target):
        # Retrieve AS information by IPv4 address
        s = socket.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        with contextlib.closing(s):
            s.connect((cls._whoissvr, 43))
            s.send("peer {0}\n".format(target))
            resp = s.recv(1024)
            cmps = resp.split(" | ")
            if cmps[-1].endswith("\n"):
                cmps[-1] = cmps[-1][:-1]
            info = {}
            info["peer_as_numbers"] = [int(asn) for asn in cmps[0].split(" ")]
            info["as_number"] = int(cmps[1])
            info["network_prefix"] = unicode(cmps[2])
            info["as_name"] = unicode(cmps[3])
            info["country"] = unicode(cmps[4])
            info["domain"] = unicode(cmps[5])
            info["isp"] = unicode(cmps[6])
            return InformationSet(InformationSet.INFORMATIONAL, **info)

    @staticmethod
    def _processres(csvdata, jsondata):
        # Produce a dictionary from malware query results
        info = {}
        sio = cStringIO.StringIO(csvdata)
        with contextlib.closing(sio):
            cr = csv.reader(sio)
            row = cr.next()
            info["sample_md5"] = binascii.unhexlify(row[0])
            info["sample_sha1"] = binascii.unhexlify(row[1])
            dval = datetime.datetime.strptime(row[2], "%Y-%m-%d %H:%M:%S")
            info["first_event_ts"] = dval
            dval = datetime.datetime.strptime(row[3], "%Y-%m-%d %H:%M:%S")
            info["last_event_ts"] = dval
            info["file_type"] = unicode(row[4])
            info["sample_ssdeep"] = unicode(row[5])
        info["av_record_locators"] = json.loads(unicode(jsondata))
        return info

    @staticmethod
    def _processresw(jsondata):
        # Produce a dictionary from whitelist query results
        jdict = json.loads(unicode(jsondata))
        if len(jdict) == 0:
            return None
        info = {}
        for k, v in jdict.iteritems():
            if k == "source":
                info["entry_contributor"] = v
            elif k == "filename":
                info["file_name"] = v
            elif k == "crc32":
                info["sample_crc32"] = binascii.unhexlify(v)
            elif k == "product_name":
                info["origin_package"] = v
            elif k == "mfg_name":
                info["originator"] = v
            elif k == "os_name":
                info["target_os"] = v
            elif k == "language":
                info["package_language"] = v
            elif k == "product_version":
                info["package_version"] = v
            elif k == "os_version":
                info["target_os_version"] = v
            elif k == "application_type":
                info["package_category"] = v
            elif k == "filesize":
                info["file_size"] = int(v)
            elif k == "os_mfg":
                info["target_os_vendor"] = v
        return info

    @classmethod
    def _wlookup(cls, target, qtype):
        # Retrieve whitelist information by MD5/SHA1 hash
        if qtype == DataProvider.MD5_QUERY:
            args = {"md5": target}
        elif qtype == DataProvider.SHA1_QUERY:
            args = {"sha1": target}
        r = requests.get(cls._urlbasew, params=args)
        output = r.text
        hashend = output.find(" ")
        if hashend == -1:
            return None
        jsondata = output[hashend + 1:]
        info = cls._processresw(jsondata)
        if info == None:
            return None
        return InformationSet(InformationSet.NEGATIVE, **info)

    @property
    def name(self):
        return "shadowserver"

    def query(self, target, qtype):
        if qtype == DataProvider.IPV4_QUERY:
            return self._peerlookup(target)
        elif qtype == DataProvider.MD5_QUERY:
            return self._avlookup(target, qtype)
        elif qtype == DataProvider.SHA1_QUERY:
            return self._avlookup(target, qtype)
        return None
