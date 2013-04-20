import urllib2

class DShield():
    def __init__(self):
        self= "test"

    def lookup_ip(ip):
	urlbase = "http://www.dshield.org/api/ip/"
        return urllib2.urlopen(urlbase+ip).read()


    print(lookup_ip("4.2.2.1"))

