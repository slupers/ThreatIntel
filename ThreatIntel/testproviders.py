#!/usr/bin/python
import itertools
from data import *

providers = [
    PhishTankDataProvider(),
    DShieldDataProvider(),
    ShadowServerDataProvider()
]
queries = [
    ("http://onbe.ru/lISy", DataProvider.URL_QUERY),
    ("http://www.google.com/", DataProvider.URL_QUERY),
    ("4.2.2.1", DataProvider.IPV4_QUERY),
    ("aca4aad254280d25e74c82d440b76f79", DataProvider.MD5_QUERY),
    ("000000206738748edd92c4e3d2e823896700f848", DataProvider.SHA1_QUERY)
]

res = (DataProvider.queryn(q, t, providers) for (q, t) in queries)
for p, iset in itertools.chain(*res):
    print "Provider: {0}".format(p.name)
    print "Disposition: {0}".format(iset.disposition)
    for k, v in iset.facets:
        print "{0}: {1}".format(k, repr(v))
    print
