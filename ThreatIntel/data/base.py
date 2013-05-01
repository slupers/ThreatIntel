from __future__ import absolute_import, division, print_function, unicode_literals
import abc
import collections
import gevent.pool
import re
import rfc3987
import socket
from socket import AF_INET, AF_INET6
import string

QUERY_IPV4 = 1
QUERY_IPV6 = 2
QUERY_URL = 3
QUERY_DOMAIN = 4
QUERY_MD5 = 5
QUERY_SHA1 = 6
DISP_POSITIVE = 1       # The target represents a probable threat
DISP_INDETERMINATE = 2  # The target may or may not be a probable threat
DISP_NEGATIVE = 3       # The target is not believed to be a threat
DISP_FAILURE = 4        # The query was not successfully completed
DISP_INFORMATIONAL = 5  # The query did not return information about threats

class DataProvider(object):
    __metaclass__ = abc.ABCMeta
    _dnssegment = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.I)

    # Courtesy of http://stackoverflow.com/questions/2532053/validate-a-hostname-string
    @staticmethod
    def _validatefqdn(fqdn):
        if len(fqdn) > 255:
            return False
        if fqdn[-1:] == ".":
            fqdn = fqdn[:-1]
        segments = fqdn.split(".")
        return all(DataProvider._dnssegment.match(x) for x in segments)
    
    @abc.abstractproperty
    def name(self):
        """Return an identifier for this provider"""
        pass
    
    def query(self, target):
        """Perform a blocking query against this provider"""
        ntarget, qtype = DataProvider._sanitize(target)
        try:
            return self._query(ntarget, qtype)
        except Exception:
            return InformationSet(DISP_FAILURE)
    
    @staticmethod
    def queryn(target, providers):
        """Return a generator that yields an InformationSet produced by
           querying each specified provider"""
        ntarget, qtype = DataProvider._sanitize(target)
        def query1(p):
            try:
                return (p, p._query(ntarget, qtype))
            except:
                return (p, InformationSet(DISP_FAILURE))
        g = gevent.pool.Group()
        l = g.imap_unordered(query1, providers)
        for p, iset in l:
            if iset != None:
                yield (p, iset)
    
    @abc.abstractmethod
    def _query(self, target, qtype):
        pass
    
    @staticmethod
    def _sanitize(target):
        # Attempt to process as a hash
        if all((c in string.hexdigits for c in target)):
            if len(target) == 32:
                return target.lower(), QUERY_MD5
            elif len(target) == 40:
                return target.lower(), QUERY_SHA1
        
        # Attempt to process as a canonicalized IPv4 address
        try:
            packed = socket.inet_pton(AF_INET, target)
            target = socket.inet_ntop(AF_INET, packed)
            return target, QUERY_IPV4
        except Exception:
            pass
        
        # Attempt to process as a canonicalized IPv6 address
        try:
            packed = socket.inet_pton(AF_INET6, target)
            target = socket.inet_ntop(AF_INET6, packed)
            return target, QUERY_IPV6
        except Exception:
            pass
        
        # Attempt to process as a domain
        if DataProvider._validatefqdn(target):
            return target, QUERY_DOMAIN
        
        # Attempt to process as a URL
        try:
            res = rfc3987.parse(target, b"absolute_IRI")
            scheme = res[b"scheme"].lower()
            authority = res[b"authority"]
            if authority == None:
                authority = ""
            if scheme in ("http", "https") and len(authority) > 0:
                return target, QUERY_URL
        except Exception:
            pass
        
        # If we're here, the input is invalid
        raise ValueError(b"Unrecognized query input")
    
class InformationSet(object):
    def __init__(self, disposition, **facets):
        assert disposition in xrange(1, 6)
        self.disposition = disposition
        self.facets = facets.items()
