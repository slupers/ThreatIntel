import gevent.monkey
import socket
import urllib2
from .base import DataProvider, InformationSet

gevent.monkey.patch_socket()

class ShadowServerDataProvider(DataProvider):
    @staticmethod
    def _peerlookup(target):
        self.sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sockfd.connect(("asn.shadowserver.org",43))
        sent = self.sockfd.send("peer {0}\n".format(ip))
        response = self.sockfd.recv(1024)
        cmps = response.split(' | ', response.count(' | '))
        info = {}
        info['peer_as_numbers'] = [int(asn) for asn in cmps[0].split(' ')]
        info['as_number'] = cmps[1]
        info['network_prefix'] = cmps[2]
        info['as_name'] = cmps[3]
        info['country'] = cmps[4]
        info['domain'] = cmps[5]
        info['isp'] = cmps[6]
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
            return _peerlookup(target)
        elif qtype == DataProvider.MD5_QUERY:
            return _avlookup(target)
        elif qtype == DataProvider.SHA1_QUERY:
            return _avlookup(target)
        return None
