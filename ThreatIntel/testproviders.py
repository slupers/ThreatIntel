#!/usr/bin/python
from data import *

providers = [
    PhishTankDataProvider(),
    DShieldDataProvider(),
    ShadowServerDataProvider()
]
queries = [
    ("http://onbe.ru/lISy", DataProvider.URL_QUERY),
    ("4.2.2.1", DataProvider.IPV4_QUERY),
    ("00000142988AFA836117B1B572FAE4713F200567", DataProvider.SHA1_QUERY)
]

for target, qtype in queries:
    res = DataProvider.queryn(target, qtype, providers)
    for p, iset in res:
        print "Provider: {0}".format(p.name)
        print "Disposition: {0}".format(iset.disposition)
        for k, v in iset.facets:
            print "{0}: {1}".format(k, v)
        print
