#!/usr/bin/python
from __future__ import absolute_import, division, print_function, unicode_literals
from data import *

providers = [
    PhishTankDataProvider(),
    DShieldDataProvider(),
    ShadowServerDataProvider(),
    #TitanDataProvider("data/titan.pem"),
    VirusTotalDataProvider("dbce9de07aa81b144cba2d2a2cb0bdd5d5c6ce5283af40a2544ed9e4301e7526")
]
queries = [
    ("http://onbe.ru/lISy"),
    ("http://www.google.com/"),
    ("4.2.2.1"),
    #("aca4aad254280d25e74c82d440b76f79"),
    #("000000206738748edd92c4e3d2e823896700f849"),
    #("f099be48e15f5ee375e0b97c18304d813421da79")
]

for q in queries:
    for p, iset in DataProvider.queryn(q, providers):
        print("Query: {0}".format(q))
        print("Provider: {0}".format(p.name))
        print("Disposition: {0}".format(iset.disposition))
        for k, v in iset.facets:
            print("{0}: {1}".format(k, repr(v)))
        print()
