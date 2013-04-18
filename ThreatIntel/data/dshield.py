import urllib2

urlbase =  "http://www.dshield.org/api/topips/records/10/"

datelist=["2013-04-16","2013-04-15","2013-04-14","2013-04-13","2013-04-12","2013-04-11"]
for element in datelist:
    ipdata=urllib2.urlopen(urlbase+element)
    fp=open(element+".xml","w")
    fp.write(ipdata.read())
    fp.close()



