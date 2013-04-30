import gevent.monkey
import sys
import getopt
import json
import urllib
import urllib2
import pprint
from base import DataProvider, InformationSet


#gevent.monkey.patch_socket()

class Query:
    def __init__(self,qLoc):
        self.queryLoc=qLoc
        self.resultJSON=dict()
        self.result=InformationSet.INDETERMINATE
    def setThreat(self,res):
    	self.result=res
    def getThreatCode(self):
    	return self.result
    def getQueryLoc(self):
        return self.queryLoc
    def setResults(self,data):
	'''Saves the results as a dictionary'''
        self.resultJSON=data
    def getResultData(self):
	return self.resultJSON
    def getResultSummary(self):
        '''This returns important data about the result as a dictionary'''
	results=dict()
	#If we are looking at IPs, we may have to look in a specific key.
	if 'response_code' in self.resultJSON:
		results['response_code']=self.resultJSON['response_code']
	if 'permalink' in self.resultJSON:
		results['permalink']=self.resultJSON['permalink']
        if 'positives' in self.resultJSON:
		results['positives']=self.resultJSON['positives']
	if 'total' in self.resultJSON:
		results['total']=self.resultJSON['total']
	if 'scan_date' in self.resultJSON:
		results['scan_date']=self.resultJSON['scan_date']
	if 'url' in self.resultJSON:
		results['scan_url']=self.resultJSON['url']
	return results

class VirusTotalDataProvider(DataProvider):

    API_KEY="dbce9de07aa81b144cba2d2a2cb0bdd5d5c6ce5283af40a2544ed9e4301e7526"
    URL_SLOC="https://www.virustotal.com/vtapi/v2/url/report" #Location of URL scan API.
    IP_SLOC="https://www.virustotal.com/vtapi/v2/ip-address/report" #Location of IP scan API.
	SCAN_LOC="" #Location of place that will be scanned.
	TEST_IP="90.156.201.27" #This is a test IP address.

    def __init__(self):

	def scanURL(self,query): 
		'''This method scans a URL and prints the number of positive scans'''
		parameters={"resource":query.getQueryLoc(), "apikey":self.API_KEY}
		data=urllib.urlencode(parameters)
		req=urllib2.Request(self.URL_SLOC,data)
		response=urllib2.urlopen(req)
		jsonStr=response.read()
		jStr=json.loads(jsonStr)
		print 'Positives:'+str(jStr['positives'])
		print 'Total Scans:'+str(jStr['total'])

		if jStr['positives']>2:
		query.setThreat(InformationSet.POSITIVE)
		elif jStr['positives']==0:
		query.setThreat(InformationSet.NEGATIVE)
		else:
		query.setThreat(InformationSet.INDETERMINATE)
		query.setResults(jStr)    

	def scanIP(query):
		'''This method scans an IP address
		   There is currently a socket error here'''
		parameters = {'ip':'173.194.46.67', 'apikey':self.API_KEY}
		response = urllib.urlopen('%s?%s' % (self.IP_SLOC, urllib.urlencode(parameters))).read()
		response_dict = json.loads(response)

		if('resolutions' in response_dict)==False: #We are querying an invalid IP address.
			query.setThreat(InformationSet.INDETERMINATE)
		query.setResults(response_dict)
		return

		print 'Response code :'+str(response_dict['response_code'])
		print 'Verbose Message :'+str(response_dict['verbose_msg'])
		print 'Number of resolutions: '+str(len(response_dict['resolutions']))  
		pp=pprint.PrettyPrinter(indent=4)
		pp.pprint(response_dict)
		
		if  ('detected_urls' in response_dict)==False:#Sometimes, data about the scan is not sent.
			query.setThreat(InformationSet.POSITIVE)
		query.setResults(response_dict)
		return
		sumData=response_dict['detected_urls']
		if sumData['positives']>2: 
			query.setThreat(InformationSet.POSITIVE)
		elif sumData['positives']==0:
		query.setThreat(InformationSet.NEGATIVE)
		else:
			query.setThreat(InformationSet.INDETERMINATE) 
			query.setResults(response_dict)

	def retrieveReport(query):
		'''This method scans a domain and returns results for that domain'''
		url = 'https://www.virustotal.com/vtapi/v2/domain/report'
		parameters = {'domain': '027.ru', 'apikey':self.API_KEY}
		response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
		response_dict = json.loads(response)
		query.setResults(response_dict)

	def printFunctionError(function):
		print "Issue with "+function.name

		
	def __query(self,target,qtype)

	   scanURL.name="URL Scan"
	   scanIP.name="IP scan"
	   retrieveReport.name="Retrieve domain report"
	   aDict={"1":scanURL,"2":scanIP,"3":retrieveReport}    
	  
	   while True:
		   #qLoc=raw_input("Enter location to query")
		   qLoc=target
		   query=Query(qLoc)
	 
		   var='' 
		   if qtype==QUERY_URL:
		       var='1'
		   elif qtype==QUERY_IPV6:
		       var='2'
		   elif qtype=QUERY_DOMAIN:
		       var='3'

		   try:
			   aDict[var](query)
		       pp=pprint.PrettyPrinter(indent=4)
			   pp.pprint(query.getResultData())
		   except ValueError:
			   print "Issue with JSON data received."
		       printFunctionError(aDict[var])
		   except ValueError:
			   print "Value error when attempting to get data from JSON."
		       printFunctionError(aDict[var])

		   results=InformationSet(query.getThreatCode(),**query.getResultSummary())
		   return results.
	  
	if __name__ == "__main__":
		main()

