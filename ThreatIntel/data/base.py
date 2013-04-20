import abc
import gevent.pool

class DataProvider(object):
    __metaclass__ = abc.ABCMeta
    IPV4_QUERY = 1
    IPV6_QUERY = 2
    URL_QUERY = 3
    DOMAIN_QUERY = 4
    MD5_QUERY = 5
    SHA1_QUERY = 6
    
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
        def query1(p, target, qtype):
            try:
                return p.query(target, qtype)
            except:
                return InformationSet(p.name, InformationSet.FAILURE)
        g = gevent.pool.Group()
        l = g.imap_unordered(lambda p: query1(p, target, qtype), providers)
        for iset in l:
            if iset != None:
                yield iset
    
class InformationSet(object):
    POSITIVE = 1
    INDETERMINATE = 2
    NEGATIVE = 3
    FAILURE = 4
    INFORMATIONAL = 5

    def __init__(self, pname, disposition, **facets):
        self._pname = pname
        self._disposition = disposition
        self._facets = frozenset(facets.iteritems())
    
    @property
    def disposition(self):
        return self._disposition
    
    @property
    def facets(self):
        return self._facets
    
    @property
    def pname(self):
        return self._pname
