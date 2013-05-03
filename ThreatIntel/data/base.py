# FIXME: SWLC - Put Django's license here

from __future__ import absolute_import, division, print_function, unicode_literals
import abc
import collections
import gevent.pool
import re
import rfc3987
import socket
from socket import AF_INET, AF_INET6
import string
import urllib

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
    _tldsegment = re.compile(r"^[A-Z0-9][A-Z0-9-]*[A-Z0-9]$", re.I)
    
    @abc.abstractproperty
    def name(self):
        """Return an identifier for this provider"""
        pass
    
    def query(self, target):
        """Perform a blocking query against this provider"""
        ntarget, qtype = DataProvider._sanitize(target)
        try:
            return self._query(ntarget, qtype)
        except QueryError as e:
            msg = e.message
        except Exception as e:
            msg = "An internal error occurred"
        return InformationSet(DISP_FAILURE, message=msg)
    
    @staticmethod
    def queryn(target, providers):
        """Return a generator that yields an InformationSet produced by
           querying each specified provider"""
        ntarget, qtype = DataProvider._sanitize(target)
        def query1(p):
            try:
                return (p, p._query(ntarget, qtype))
            except QueryError as e:
                msg = e.message
            except Exception as e:
                msg = "An internal error occurred"
            return (p, InformationSet(DISP_FAILURE, message=msg))
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
        # Ensure that we received a Unicode string
        assert isinstance(target, unicode)
        if len(target) == 0:
            raise ValueError(b"Unrecognized query input")
        
        # Attempt to process as a hash
        if all((c in string.hexdigits for c in target)):
            if len(target) == 32:
                return target.lower(), QUERY_MD5
            elif len(target) == 40:
                return target.lower(), QUERY_SHA1
        
        # Attempt to process as a canonicalized IPv4 address
        try:
            packed = socket.inet_pton(AF_INET, target)
            ntarget = socket.inet_ntop(AF_INET, packed)
            return ntarget, QUERY_IPV4
        except Exception:
            pass
        
        # Attempt to process as a canonicalized IPv6 address
        try:
            packed = socket.inet_pton(AF_INET6, target)
            ntarget = socket.inet_ntop(AF_INET6, packed)
            return ntarget, QUERY_IPV6
        except Exception:
            pass
        
        # Attempt to process as a URL
        try:
            ntarget = DataProvider._sanitizewebiri(target)
            return ntarget, QUERY_URL
        except Exception:
            pass
        
        # Attempt to process as a domain
        try:
            ntarget = DataProvider._sanitizefqdn(target)
            return ntarget, QUERY_DOMAIN
        except Exception:
            pass
        
        # If we're here, the input is invalid
        raise ValueError(b"Unrecognized query input")
    
    @staticmethod
    def _sanitizefqdn(fqdn):
        if fqdn.endswith("."):
            fqdn = fqdn[:-1]
        if len(fqdn) == 0:
            raise ValueError() # Is the root domain
        punycode = fqdn.encode("idna")
        if len(punycode) > 254:
            raise ValueError() # Overlength FQDN
        segments = punycode.split(".")
        if any(len(s) not in xrange(1, 64) for s in segments):
            raise ValueError() # Overlength segment
        tld = segments[-1]
        if DataProvider._tldsegment.match(tld) == None:
            raise ValueError() # Doesn't meet TLD naming rules
        if tld.isdigit():
            raise ValueError() # Doesn't meet TLD naming rules
        return punycode + "."
        
    @staticmethod
    def _sanitizewebiri(iri):
        res = rfc3987.parse(iri, b"IRI")
        scheme = res[b"scheme"]
        if scheme == None or scheme.lower() not in ("http", "https"):
            raise ValueError() # Not a Web address
        authority = res[b"authority"]
        if authority == None or len(authority) == 0:
            raise ValueError() # No host specified
        res[b"authority"] = DataProvider._sanitizefqdn(authority)[:-1]
        iri = rfc3987.compose(**res)
        uri = urllib.quote(iri.encode("utf-8"), safe=b"/#%[]=:;$&()+,!?*@'~")
        return unicode(uri)
    
class InformationSet(object):
    def __init__(self, disposition, **facets):
        assert disposition in xrange(1, 6)
        self.disposition = disposition
        self.facets = facets.items()

class QueryError(RuntimeError):
    pass
