from contextlib import closing
import gevent.monkey
from socket import inet_ntoa, socket, AF_INET, IPPROTO_TCP, SOCK_STREAM
from .base import DataProvider, InformationSet

gevent.monkey.patch_socket()

class ShadowServerDataProvider(DataProvider):
    _whoissvr = "64.71.137.251" # ShadowServer's DNS is FUBAR
    
    @classmethod
    def _peerlookup(cls, target):
        with closing(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) as s:
            s.connect((cls._whoissvr, 43))
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
            return self._peerlookup(target)
        elif qtype == DataProvider.MD5_QUERY:
            return self._avlookup(target)
        elif qtype == DataProvider.SHA1_QUERY:
            return self._avlookup(target)
        return None
