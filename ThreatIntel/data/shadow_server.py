import socket
import urllib2

class shadow_server():
    
    global sockfd
    
    def __init__(self):
        self.sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sockfd.connect(("asn.shadowserver.org",43))

    def peer(self, ip):
        
        #send and receive the response
        sent = self.sockfd.send("peer {0}\n".format(ip))
        response = self.sockfd.recv(1024)
            
        #process the response
        response_list = response.split(' | ', response.count(' | '))

        response_dict = {}
        response_dict['peers'] = response_list[0].split(' ',response_list[0].count(' '))
        response_dict['asn'] = response_list[1]        
        response_dict['prefix'] = response_list[2]
        response_dict['as_name'] = response_list[3]
        response_dict['cn'] = response_list[4]
        response_dict['domain'] = response_list[5]
        response_dict['isp'] = response_list[6]

        #return InformationSet(self.name, InformationSet.INFORMATIONAL, **response_dict)
    
    def av(self, md5):
        response = urllib2.urlopen("http://innocuous.shadowserver.org/api/?query=" + md5 + ":43")
            

    def close(self):
        self.sockfd.close()

if __name__ == '__main__':
    s = shadow_server()
    #s.peer("8.8.8.8")
    s.av("00000142988AFA836117B1B572FAE4713F200567")
    s.close()

