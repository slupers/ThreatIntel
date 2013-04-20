import contextlib
import gevent.monkey
import socket
import urllib2
from base import DataProvider, InformationSet

#gevent.monkey.patch_socket()

class ShadowServerDataProvider(DataProvider):
    _whoissvr = "asn.shadowserver.org"
    
    @staticmethod
    def _peerlookup(target):
        dest = (ShadowServerDataProvider._whoissvr, 43)
        with contextlib.closing(socket.create_connection(dest)) as s:
            s.send("peer {0}\n".format(target))
            resp = s.recv(1024)
            cmps = resp.split(" | ")
            info = {}
            info["peer_as_numbers"] = [int(asn) for asn in cmps[0].split(" ")]
            info["as_number"] = cmps[1]
            info["network_prefix"] = cmps[2]
            info["as_name"] = cmps[3]
            info["country"] = cmps[4]
            info["domain"] = cmps[5]
            info["isp"] = cmps[6]
            return InformationSet(InformationSet.INFORMATIONAL, **info)
    
    @staticmethod
    def _avlookup(md5):
        return None
        #response = urllib2.urlopen("http://innocuous.shadowserver.org/api/?query=" + md5 + ":43")

    @property
    def name(self):
        return "shadowserver"

    def query(self, target, qtype):
        if qtype == DataProvider.IPV4_QUERY:
            return ShadowServerDataProvider._peerlookup(target)
        elif qtype == DataProvider.MD5_QUERY:
            return ShadowServerDataProvider._avlookup(target)
        elif qtype == DataProvider.SHA1_QUERY:
            return ShadowServerDataProvider._avlookup(target)
        return None
