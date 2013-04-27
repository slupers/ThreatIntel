from __future__ import absolute_import, division, print_function, unicode_literals
import abc
import collections
import gevent.pool

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
    
    @abc.abstractproperty
    def name(self):
        pass
    
    @abc.abstractmethod
    def query(self, target, qtype):
        """Perform a blocking query against this provider"""
        pass
    
    @staticmethod
    def queryn(target, qtype, providers):
        """Return a generator that yields an InformationSet produced by
           querying each specified provider"""
        assert qtype in xrange(1, 7)
        def query1(p, target, qtype):
            try:
                return (p, p.query(target, qtype))
            except:
                raise
                return (p, InformationSet(DISP_FAILURE))
        g = gevent.pool.Group()
        l = g.imap_unordered(lambda p: query1(p, target, qtype), providers)
        for p, iset in l:
            if iset != None:
                yield (p, iset)
    
class InformationSet(object):
    def __init__(self, disposition, **facets):
        assert disposition in xrange(1, 6)
        self.disposition = disposition
        self.facets = facets.items()
