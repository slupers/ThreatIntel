from __future__ import absolute_import, division, print_function, unicode_literals
import gevent.monkey
gevent.monkey.patch_socket()
gevent.monkey.patch_ssl()
import binascii
from datetime import datetime
import gevent
import operator
import requests
from .base import *

class VirusTotalClient(object):
    _endpoint = "https://www.virustotal.com/vtapi/v2/{0}/report"
    
    def __init__(self, apikey):
        self._apikey = apikey
    
    def _get_report(self, rtype, method, **params):
        # Perform the request
        endpoint = self._endpoint.format(rtype)
        params["apikey"] = self._apikey
        while True:
            if method == "GET":
                r = requests.get(endpoint, params=params)
            elif method == "POST":
                r = requests.post(endpoint, data=params)
            else:
                assert False
            r.raise_for_status()
            if r.status_code == 204:
                gevent.sleep(60)
            else:
                break
        
        # Decode and check for errors
        res = r.json()
        rcode = res.get("response_code")
        if rcode == None or rcode < 0:
            msg = res.get("verbose_msg")
            if msg == None:
                msg = "(unknown)"
            raise QueryError(b"Query failed: {0}".format(msg))
        return res
    
    def query_fqdn(self, domain):
        """Retrieve VirusTotal information for the specified fully qualified
           domain name."""
        assert domain.endswith(".")
        domain = domain[:-1] # Strip the trailing period
        return self._get_report("domain", "GET", domain=domain)
    
    def query_ipv4(self, ip):
        """Retrieve VirusTotal information for the specified IPv4 address."""
        return self._get_report("ip-address", "GET", ip=ip)
    
    def query_scan(self, resource):
        """Retrieve VirusTotal information for the specified scan ID."""
        return self._get_report("file", "POST", resource=resource)
    
    def query_url(self, resource, scan):
        """Retrieve VirusTotal information for the specified Web address."""
        scan = int(scan)
        return self._get_report("url", "POST", resource=resource, scan=scan)

class VirusTotalDataProvider(DataProvider):
    def __init__(self, apikey):
        assert isinstance(apikey, basestring)
        if self._keyregex.match(apikey) == None:
            raise ValueError(b"Invalid VirusTotal API key")
        self._client = VirusTotalClient(apikey)
    
    @property
    def name(self):
        return "virustotal"

    def _parse(self, data):
        # Process each unit of data returned
        info = AttributeList()
        for key, newkey, fn in self._handlers:
            value = data.get(key)
            if value != None:
                newvalue = fn(value)
                if newvalue != None:
                    info.append((newkey, newvalue))
        fsid = data.get("filescan_id")
        if fsid != None:
            data2 = self._client.query_scan(fsid)
            for key, newkey, fn in self._fhandlers:
                value = data2.get(key)
                if value != None:
                    newvalue = fn(value)
                    if newvalue != None:
                        info.append((newkey, newvalue))
        
        # Decide on a disposition
        positives = int(data["positives"]) if "positives" in data else None
        if positives == None:
            disp = DISP_INFORMATIONAL
        elif positives > 2:
            disp = DISP_POSITIVE
        elif positives == 0:
            disp = DISP_NEGATIVE
        else:
            disp = DISP_INDETERMINATE
        return InformationSet(disp, info)
    
    def _parse_dcs(dcs):
        # Construct an EntityList from the detected communicating samples
        hdrs = ("occurrence_ts", "hit_ratio", "sample_sha256")
        info = EntityList(hdrs)
        for entry in dcs:
            occurrence_ts = datetime.strptime(entry["date"], "%Y-%m-%d %H:%M:%S")
            p = entry["positives"]
            t = entry["total"]
            hit_ratio = "{0}/{1}".format(present(p), present(t))
            sample_sha256 = binascii.unhexlify(entry["sha256"])
            info.append((occurrence_ts, hit_ratio, sample_sha256))
        return info
    
    def _parse_file_scans(scans):
        # Construct an EntityList from the scan details
        if len(scans) == 0:
            return None
        hdrs = ("av_engine", "av_engine_ver", "scan_result", "av_definition_ver")
        info = EntityList(hdrs)
        scaninfo = scans.items()
        scaninfo.sort(key=operator.itemgetter(0))
        for av_engine, entry in scaninfo:
            av_engine_ver = entry.get("version")
            scan_result = entry.get("result")
            if scan_result == None:
                continue
            av_definition_ver = entry.get("update")
            if av_definition_ver != None:
                av_definition_ver = datetime.strptime(av_definition_ver, "%Y%m%d").date()
            info.append((av_engine, av_engine_ver, scan_result, av_definition_ver))
        return info
    
    def _parse_resolutions(res):
        # Construct an EntityList from the resolutions
        if len(res) == 0:
            return None
        hdrs = ("occurrence_ts", "correspondance")
        info = EntityList(hdrs)
        for entry in res:
            occurrence_ts = entry.get("last_resolved")
            correspondance = entry.get("hostname")
            if correspondance == None:
                correspondance = entry.get("ip_address")
            if occurrence_ts != None:
                occurrence_ts = datetime.strptime(occurrence_ts, "%Y-%m-%d %H:%M:%S").date()
            info.append((occurrence_ts, correspondance))
        return info
    
    def _parse_url_scans(scans):
        # Construct an EntityList from the scan details
        if len(scans) == 0:
            return None
        hdrs = ("av_engine", "scan_result")
        info = EntityList(hdrs)
        scaninfo = scans.items()
        scaninfo.sort(key=operator.itemgetter(0))
        for av_engine, entry in scaninfo:
            scan_positive = entry.get("detected", True)
            scan_result = entry.get("result")
            if scan_result == "clean site":
                scan_result = None
            if not scan_positive and scan_result == None:
                continue
            info.append((av_engine, scan_result))
        return info
    
    def _parse_urls(urls):
        # Construct an EntityList from the detected URLs
        if len(urls) == 0:
            return None
        hdrs = ("occurrence_ts", "hit_ratio", "url")
        info = EntityList(hdrs)
        for entry in urls:
            occurrence_ts = datetime.strptime(entry["scan_date"], "%Y-%m-%d %H:%M:%S")
            p = entry["positives"]
            t = entry["total"]
            hit_ratio = "{0}/{1}".format(present(p), present(t))
            url = entry["url"]
            info.append((occurrence_ts, hit_ratio, url))
        return info
    
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

    _keyregex = re.compile(r"^[A-F0-9]{64}$", re.I)
    _handlers = [
        ("scan_date", "update_ts", lambda v: datetime.strptime(v, "%Y-%m-%d %H:%M:%S")),
        ("md5", "sample_md5", binascii.unhexlify),
        ("sha1", "sample_sha1", binascii.unhexlify),
        ("sha256", "sample_sha256", binascii.unhexlify),
        ("positives", "n_scans_positive", lambda v: v),
        ("total", "n_scans", lambda v: v),
        ("scans", "scan_details", _parse_url_scans),
        ("permalink", "report_url", lambda v: v),
        ("resolutions", "correspondances", _parse_resolutions),
        ("detected_communicating_samples", "communicating_samples", _parse_dcs),
        ("detected_urls", "detections", _parse_urls)
    ]
    _fhandlers = [
        ("scan_date", "update_ts", lambda v: datetime.strptime(v, "%Y-%m-%d %H:%M:%S")),
        ("md5", "sample_md5", binascii.unhexlify),
        ("sha1", "sample_sha1", binascii.unhexlify),
        ("sha256", "sample_sha256", binascii.unhexlify),
        ("positives", "n_scans_positive", lambda v: v),
        ("total", "n_scans", lambda v: v),
        ("scans", "scan_details", _parse_file_scans),
        ("permalink", "report_url", lambda v: v)
    ]

__all__ = [
    b"VirusTotalDataProvider"
]
