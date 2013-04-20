import gevent.monkey
import isodate
import requests
import urllib2
import xml.etree.cElementTree as xml
from .base import DataProvider, InformationSet

gevent.monkey.patch_socket()

class DShieldDataProvider(DataProvider):
    def lookup_ip(self,ip):
        urlbase = "http://www.dshield.org/api/ip/"
        result=urllib2.urlopen(urlbase+ip)
        xmldata = {}
        xmlfile = xml.parse(result)
        for xmltag in xmlfile.iter():
            if xmltag.tag == "attacks" or xmltag.tag =="updated" or xmltag.tag == "country" or xmltag.tag =="asname" or xmltag.tag=="abusecontact":
                xmldata[xmltag.tag] = xmltag.text
        return xmldata

    @property
    def name(self):
        return "dshield"
    
    def query(self, target, qtype):
        if qtype != DataProvider.IPV4_QUERY and qtype != DataProvider.IPV6_QUERY:
            return None

        xmlres = self.lookup_ip(target)
        threat=InformationSet.FAILURE
        if int(xmlres["attacks"])< 10:
            threat=InformationSet.NEGATIVE
        if int(xmlres["attacks"])>=10 and int(xmlres["attacks"])<=50:
            threat=InformationSet.INDETERMINATE
        if int(xmlres["attacks"])>50:
            threat=InformationSet.POSITIVE
        return InformationSet(threat, **xmlres)

