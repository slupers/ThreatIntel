from __future__ import absolute_import, division, print_function, unicode_literals
import gevent.monkey
gevent.monkey.patch_socket()
gevent.monkey.patch_ssl()
import binascii
import datetime
import json
import numbers
import os
import requests
import pprint
from .base import *
from frontend.presentation import *

class TitanClient(object):
    SORT_ASCENDING = 1
    SORT_DESCENDING = -1
    _queryurl = "https://titan.gtri.gatech.edu/submitqueryexternal"
    
    def __init__(self, cert_pem, key_pem):
        if isinstance(cert_pem, unicode):
            cert_pem = cert_pem.encode("utf-8")
        if isinstance(key_pem, unicode):
            key_pem = key_pem.encode("utf-8")
        assert isinstance(cert_pem, str)
        assert isinstance(key_pem, str)
        self._cert_pem = cert_pem
        self._key_pem = key_pem
    
    def query(self, collection, query, limit=None, skip=None, sort=None):
        # Encode the query payload
        queryj = json.dumps(query, allow_nan=False, ensure_ascii=False)
        if isinstance(queryj, str):
            queryj = queryj.decode()
        
        # Produce form parameters
        params = {}
        params["function"] = "find_one" if limit == 1 else "find"
        params["collection"] = collection
        params["query"] = queryj
        if skip != None:
            params["skip"] = skip
        if limit != None and limit != 1:
            params["limit"] = limit
        if sort != None:
            sortj = json.dumps(sort, allow_nan=False, ensure_ascii=False)
            if isinstance(sortj, str):
                sortj = sortj.decode()
            params["sort"] = sortj
        
        # Perform the request, using pipes to load the certificate/key
        cpiper, cpipew = os.pipe()
        kpiper = kpipew = None
        try:
            os.write(cpipew, self._cert_pem)
            os.close(cpipew)
            cpipew = None
            kpiper, kpipew = os.pipe()
            os.write(kpipew, self._key_pem)
            os.close(kpipew)
            kpipew = None
            cpath = "/dev/fd/{0}".format(cpiper)
            kpath = "/dev/fd/{0}".format(kpiper)
            r = requests.post(self._queryurl, cert=(cpath, kpath), data=params, verify=False)
        finally:
            for fd in (cpiper, cpipew, kpiper, kpipew):
                if fd != None:
                    os.close(fd)
        
        # Process the result
        outputj = r.json()
        ok = outputj.get("ok")
        if ok == None:
            raise RuntimeError(b"Invalid response received from Titan")
        if outputj.get("ok") != True:
            raise RuntimeError(b"The request returned an error")
        result = outputj.get("result", [])
        if not isinstance(result, list):
            raise RuntimeError(b"Invalid response received from Titan")
        return result

class TitanDataProvider(DataProvider):    
    def __init__(self, cert_pem, key_pem):
        self._client = TitanClient(cert_pem, key_pem)
    
    def _format_av(entry):
        info = AttributeList()
        status = entry["status"]
        if status == "clean":
            info.append(("scan_positive", False))
        elif status == "infected":
            info.append(("scan_positive", True))
            info.append(("av_record_locator", entry["virus"]))
        elif status == "error":
            info.append(("error", entry["error"]))
        return info
    
    def _format_jpeg(entry):
        info = AttributeList()
        comment = entry["comment"]
        standard = entry["standard"]
        info.append(("comment", comment))
        info.append(("standard", standard))
        return info
    
    def _format_none(entry):
        info = AttributeList()
        info.append((entry, ))
        return info

    @property
    def name(self):
        return "titan"
    
    @classmethod
    def _parse(cls, sample, analyses):
        # Process sample metadata
        info = AttributeList()
        v = sample.get("ingest_date")
        if v != None:
            info.append(("first_event_ts", cls._parse_date(v)))
        v = sample.get("last_ingested")
        if v != None:
            info.append(("last_event_ts", cls._parse_date(v)))
        v = sample.get("hashes")
        for k in ("md5", "sha1", "sha256"):
            v2 = v.get(k)
            if v2 != None:
                info.append(("sample_" + k, binascii.unhexlify(v2["@Hash"])))
        v = sample.get("filename")
        if v != None:
            info.append(("file_name", v))
        
        # Dump analysis information into its own entry
        adata = EntityList(("analysis", ))
        for analysis in analyses:
            atdata = AttributeList()
            st = analysis.get("start_time")
            if st != None:
                atdata.append(("update_ts", cls._parse_date(st)))
            for atype in analysis["types"]:
                fn = cls._aformatters.get(atype)
                if fn != None:
                    key = "analysis_{0}".format(atype)
                    atdata.append((key, fn(analysis[atype])))
            adata.append((atdata, ))
        info.append(("analyses", adata))
        return InformationSet(DISP_INFORMATIONAL, info)
    
    @classmethod
    def _parse_date(cls, value):
        return datetime.datetime.utcfromtimestamp(long(value["$date"]) / 1000)
    
    def _query(self, target, qtype):
        if qtype == QUERY_MD5:
            return self._qhash(target, "md5")
        elif qtype == QUERY_SHA1:
            return self._qhash(target, "sha1")
        else:
            return None
    
    def _qhash(self, hashval, hashtype):
        # Retrieve sample information
        squery = {"hashes.{0}".format(hashtype): {"@Hash": hashval}}
        sres = self._client.query("sample", squery, 1)
        if len(sres) == 0:
            return None
        sample = sres[0]
        
        # Retrieve corresponding analysis information
        rquery = {"sample_id": sample["_id"]}
        sort = [("time", TitanClient.SORT_DESCENDING)]
        analyses = self._client.query("result", rquery, sort=sort)
        
        # Process the output
        return self._parse(sample, analyses)

    _aformatters = {
        "pcap": None,
        "network": None,
        "av": _format_av,
        "syscall": None,
        "dropped_files": None,
        "nids": None,
        "screenshots": None,
        "url": None,
        "executable": None,
        "android": None,
        "cdf": None,
        "flash": None,
        "jpeg": None,
        "other": None
    }    

__all__ = [
    b"TitanDataProvider"
]
