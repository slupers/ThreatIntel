from __future__ import absolute_import, division, print_function, unicode_literals
import gevent.monkey
gevent.monkey.patch_socket()
gevent.monkey.patch_ssl()
import binascii
import datetime
import gevent
import requests
from .base import *

class VirusTotalClient(object):
    _endpoint = "https://www.virustotal.com/vtapi/v2/{0}/report"
    
    def __init__(self, apikey):
        self._apikey = apikey
    
    def _get_report(self, rtype, method, **params):
        endpoint = VirusTotalClient._endpoint.format(rtype)
        params["apikey"] = self._apikey
        while True:
            if method == "GET":
                r = requests.request(method, endpoint, params=params)
            elif method == "POST":
                r = requests.request(method, endpoint, data=params)
            else:
                assert False
            r.raise_for_status()
            if r.status_code == 200:
                break
            elif r.status_code == 204:
                gevent.sleep(60)
            else:
                msg = b"Query failed: HTTP error {0}".format(r.status_code)
                raise QueryError(msg)
        res = r.json()
        rcode = res.get("response_code")
        if rcode == None or rcode < 0:
            msg = res.get("verbose_msg")
            if msg == None:
                msg = "(unknown)"
            raise QueryError(b"Query failed: {0}".format(msg))
        return res
    
    def query_fqdn(self, domain):
        assert domain.endswith(".")
        domain = domain[:-1] # Strip the trailing period
        return self._get_report("domain", "GET", domain=domain)
    
    def query_ipv4(self, ip):
        return self._get_report("ip-address", "GET", ip=ip)
    
    def query_url(self, resource, scan):
        scan = 1 if scan else 0
        return self._get_report("url", "POST", resource=resource, scan=scan)

class VirusTotalDataProvider(DataProvider):
    _keyregex = re.compile(r"^[A-F0-9]{64}$", re.I)

    def __init__(self, apikey):
        if not isinstance(apikey, basestring):
            raise ValueError(b"Invalid VirusTotal API key")
        if self._keyregex.match(apikey) == None:
            raise ValueError(b"Invalid VirusTotal API key")
        self._client = VirusTotalClient(apikey)

    @property
    def name(self):
        return "virustotal"

    @staticmethod
    def _parse(res):
        # Process each unit of data returned
        info = {}
        positives = None
        for k, v in res.iteritems():
            if k in ("md5", "sha1", "sha256"):
                info["sample_" + k] = binascii.unhexlify(v)
            elif k == "scan_date":
                dtv = datetime.datetime.strptime(v, "%Y-%m-%d %H:%M:%S")
                info["last_event_ts"] = dtv
            elif k == "positives":
                info["n_scans_positive"] = positives = v
            elif k == "total":
                info["n_scans"] = v
            elif k == "scans":
                info["scan_details"] = v # FIXME
            elif k == "permalink":
                info["report_url"] = v
            elif k == "resolutions":
                info["fqdn_matches"] = v # FIXME
            elif k == "detected_communicating_samples":
                info["dcs"] = v # FIXME
            elif k == "detected_urls":
                info["malware_matches"] = v # FIXME
        
        # Decide on a disposition
        if positives == None:
            disp = DISP_INFORMATIONAL
        elif positives > 2:
            disp = DISP_POSITIVE
        elif positives == 0:
            disp = DISP_NEGATIVE
        else:
            disp = DISP_INDETERMINATE
        return InformationSet(disp, **info)
        
    def _query(self, target, qtype):
        if qtype == QUERY_URL:
            res = self._client.query_url(target, True)
        elif qtype == QUERY_IPV4:
            res = self._client.query_ipv4(target)
        elif qtype == QUERY_DOMAIN:
            res = self._client.query_fqdn(target)
        else:
            return None
        return self._parse(res)

__all__ = [
    b"VirusTotalDataProvider"
]
