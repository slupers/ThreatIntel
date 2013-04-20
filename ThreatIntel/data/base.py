import abc

class DataProvider(object):
    __metaclass__ = abc.ABCMeta
    IPV4_QUERY = 1
    IPV6_QUERY = 2
    URL_QUERY = 3
    DOMAIN_QUERY = 4
    MD5_QUERY = 5
    SHA1_QUERY = 6
    
    @abc.abstractmethod
    def beginq(self, query, qtype, pool):
        pass
    
class InformationSet(object):
    POSITIVE = 1
    INDETERMINATE = 2
    NEGATIVE = 3

    def __init__(self, pname, disposition, **facets):
        self._pname = pname
        self._disposition = disposition
        self._facets = frozenset(facets.iteritems())
    
    @property
    def disposition(self):
        return self.disposition
    
    @property
    def facets(self):
        return self.facets
    
    @property
    def pname(self):
        return self._pname
