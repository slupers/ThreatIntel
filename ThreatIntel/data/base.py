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
            #try:
            return (p, p.query(target, qtype))
            #except:
                #return (p, InformationSet(InformationSet.FAILURE))
        g = gevent.pool.Group()
        l = g.imap_unordered(lambda p: query1(p, target, qtype), providers)
        for p, iset in l:
            if iset != None:
                yield (p, iset)
    
class InformationSet(object):
    POSITIVE = 1       # The target represents a probable threat
    INDETERMINATE = 2  # The target may or may not be a probable threat
    NEGATIVE = 3       # The target is not believed to be a threat
    FAILURE = 4        # The query was not successfully completed
    INFORMATIONAL = 5  # The query did not return information about threats

    def __init__(self, disposition, **facets):
        self.disposition = disposition
        self.facets = facets.items()
