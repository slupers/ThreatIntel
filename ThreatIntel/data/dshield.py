import gevent.monkey
import isodate
import requests
import urllib2
import xml.etree.cElementTree as xml
from base import DataProvider, InformationSet

class DShieldDataProvider(DataProvider):
    def lookup_ip(self,ip):
        urlbase = "http://www.dshield.org/api/ip/"
        result=urllib2.urlopen(urlbase+ip)
        xmldata = {}
        xmlfile = xml.parse(result)
        for xmltag in xmlfile.iter():
            xmldata[xmltag.tag] = xmltag.text
        return xmldata

    @property
    def name(self):
        return "dshield"
    
    def query(self, target, qtype):
        if qtype != DataProvider.IPV4_QUERY and qtype != DataProvider.IPV6_QUERY:
            return None

        xmlres = self.lookup_ip(target)
        return InformationSet(InformationSet.POSITIVE, **xmlres)

