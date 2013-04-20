import sys
import getopt
import json
import urllib
import urllib2

'''
Accept input
Store data
Error handling
'''

API_KEY="dbce9de07aa81b144cba2d2a2cb0bdd5d5c6ce5283af40a2544ed9e4301e7526"

URL_SLOC="https://www.virustotal.com/vtapi/v2/url/report" #Location of URL scan API.
IP_SLOC="https://www.virustotal.com/vtapi/v2/ip-address/report" #Location of IP scan API.




def scanURL():
    print 'Scanning URL'

    scanURL="http://www.reddit.com"
    parameters={"resource":scanURL, "apikey":API_KEY}

    data=urllib.urlencode(parameters)
    req=urllib2.Request(URL_SLOC,data)
    response=urllib2.urlopen(req)
    jsonStr=response.read()

    jStr=json.loads(jsonStr)
    print 'Positives:'+str(jStr['positivess'])
    print 'Total Scans:'+str(jStr['total'])
    print json


def scanIP():
    print 'Scanning IP;'

    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    parameters = {'ip': '90.156.201.27', 'apikey':API_KEY}
    response = urllib.urlopen('%s?%s' % (IP_SLOC, urllib.urlencode(parameters))).read()
    response_dict = json.loads(response)
    print 'Response code :'+str(response_dict['response_code'])
    print 'Verbose Message :'+str(response_dict['verbose_msg'])
    print 'Number of resolutions: '+str(len(response_dict['resolutions']))
    print response_dict

def retrieveReport():
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    parameters = {'domain': '027.ru', 'apikey':API_KEY}
    response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
    response_dict = json.loads(response)
    print response_dict

def main():

   scanURL.name="Scan URL"

   aDict={"1":scanURL,"2":scanIP,"3":retrieveReport}
  
   while True:
       var=''
       try:
           var=raw_input("0:quit,1:scanURL, 2:scanIP, 3:retrieveReport")
           if var=='0':
              break
           aDict[var]()
       except KeyError:
           print "Issue with JSON data received"
	   print "Error is in function:"+aDict[var].name
       except ValueError:
           print "Issue with "+aDict[var].name


if __name__ == "__main__":
    main()

