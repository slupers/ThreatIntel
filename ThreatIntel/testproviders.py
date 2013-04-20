from data import *

pdp = PhishTankDataProvider()
res = DataProvider.queryn("http://onbe.ru/lISy", DataProvider.URL_QUERY, [pdp])
for p, iset in res:
    print "Provider: {0}".format(p.name)
    print "Disposition: {0}".format(iset.disposition)
    for k, v in iset.facets:
        print "{0}: {1}".format(k, v)
