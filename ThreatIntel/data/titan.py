import requests
import json
#from base import DataProvider

PUBCERT_LOC = './titancert.pem'
PUBCERT_KEY_LOC = './titancert_key.pem'

MAX_RESULTS = 50

class InvalidType(Exception):
    pass

class TitanDataProvider(object):
    _url_base = 'https://titan.qtri.gatech.edu/sample{type}external'
    _supported_types = ('url', 'query', 'sample')
    
    @staticmethod
    def request(type, params, method='get'):
        ''' HTTP request Titan with supplied credentials '''
        if type not in _supported_types:
            raise InvalidType(type)
        
        url = TitanDataProvider._url_base.format(type=type)
        req_method = getattr(requests, method)
        return req_method(url, cert=(PUBCERT_LOC, PUBCERT_KEY_LOC), data=params).json()

            
    @staticmethod
    def submit(type, params):
        ''' Submit data to Titan's database '''
        return TitanDataProvider.request(type, params, 'post')

    @staticmethod
    def query(type, params):
        ''' Query information from Titan '''

        req_params = {
                'function': 'find',
                'collection': type,
                'limit': MAX_RESULTS,
                'query': params
        }
        return TitanDataProvider.request('query', params, 'get')
        
    
def query_hash(hash_val, hash_type='sha256'):
    ''' Obtain audit results for a file's hash '''
    query = {'hashes.{}'.format(hash_type): {'@Hash': hash_val}}
    return TitanDataProvider.query('sample', json.dumps(query)) 
    
def query_domain(domain):
    ''' Obtain audit results for a domain '''
    query = {'_id': domain}
    return TitanDataProvider.query('domain_yesterday', json.dumps(query)) 

def query_url(url):
    ''' Obtain audit results for a URL '''
    query = {'url': {'url': url}}
    return TitanDataProvider.query('result', json.dumps(query)) 

def query_address(addr):
    ''' Obtain audit results for an IP address '''
    query = {'_id': addr}
    return TitanDataProvider.query('ip_yesterday', json.dumps(query)) 

if __name__ == '__main__':
    pass
