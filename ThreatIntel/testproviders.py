#!/usr/bin/python
from data import *

def printresult(res):
    for p, iset in res:
        print "Provider: {0}".format(p.name)
        print "Disposition: {0}".format(iset.disposition)
        for k, v in iset.facets:
            print "{0}: {1}".format(k, v)

pdp = PhishTankDataProvider()
ddp = DShieldDataProvider()
printresult(DataProvider.queryn("http://onbe.ru/lISy", DataProvider.URL_QUERY, [ddp, pdp]))
printresult(DataProvider.queryn("4.2.2.1", DataProvider.IPV4_QUERY, [ddp, pdp]))
