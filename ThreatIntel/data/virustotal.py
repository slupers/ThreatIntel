import sys
import getopt
import json
import urllib
import urllib2

API_KEY="dbce9de07aa81b144cba2d2a2cb0bdd5d5c6ce5283af40a2544ed9e4301e7526"
URL_SLOC="https://www.virustotal.com/vtapi/v2/url/report" #Location of URL scan API.
IP_SLOC="https://www.virustotal.com/vtapi/v2/ip-address/report" #Location of IP scan API.
SCAN_LOC="" #Location of place that will be scanned.

TEST_IP="90.156.201.27" #This is a test IP address.
class Query:
    def __init__(self,qLoc):
        self.queryLoc=qLoc
        self.resultJSON=dict()
    def getQueryLoc(self):
        return self.queryLoc
    def setResults(self,data):
	'''Saves the results as a dictionary'''
        self.resultJSON=data
    def getResultData(self):
	return self.resultJSON
       
def scanURL(query): 
    '''This method scans a URL and prints the number of positive scans'''
    parameters={"resource":query.getQueryLoc(), "apikey":API_KEY}
    data=urllib.urlencode(parameters)
    req=urllib2.Request(URL_SLOC,data)
    response=urllib2.urlopen(req)
    jsonStr=response.read()
    jStr=json.loads(jsonStr)
    print 'Positives:'+str(jStr['positives'])
    print 'Total Scans:'+str(jStr['total'])
    query.setResults(jStr)    

def scanIP(query):
    '''This method scans an IP address'''
    parameters = {'ip':TEST_IP, 'apikey':API_KEY}
    response = urllib.urlopen('%s?%s' % (IP_SLOC, urllib.urlencode(parameters))).read()
    response_dict = json.loads(response)
    print 'Response code :'+str(response_dict['response_code'])
    print 'Verbose Message :'+str(response_dict['verbose_msg'])
    print 'Number of resolutions: '+str(len(response_dict['resolutions']))
    query.setResults(response_dict)

def retrieveReport(query):
    '''This method scans a domain and returns results for that domain'''
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    parameters = {'domain': '027.ru', 'apikey':API_KEY}
    response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
    response_dict = json.loads(response)
    query.setResults(response_dict)

def printFunctionError(function):
    print "Issue with "+function.name

def main():

   scanURL.name="URL Scan"
   scanIP.name="IP scan"
   retrieveReport.name="Retrieve domain report"
   aDict={"1":scanURL,"2":scanIP,"3":retrieveReport}    
  
   while True:
       qLoc=raw_input("Enter location to query")
       query=Query(qLoc)
       var=''
       var=raw_input("0:quit,1:scanURL, 2:scanIP, 3:retrieveReport")
       if var=='0':
           break
       try:
           aDict[var](query)
           print query.getResultData()
       except KeyError:
           print "Issue with JSON data received."
	   printFunctionError(aDict[var])
       except ValueError:
           print "Value error when attempting to get data from JSON."
	   printFunctionError(aDict[var])

if __name__ == "__main__":
    main()

