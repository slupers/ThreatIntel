import os
import json as simplejson
import sys

class shadow_server(object):

    def print_file(self, filename):
        f = open(filename)
        s = f.read()
        print s
    
    def whitelisted(self, hashfile):
        p = os.popen('curl -s http://bin-test.shadowserver.org/api -F filename.1=@%s' % hashfile)
        data = p.read()
        p.close()
        res = {}
        for line in data.split('\n'):
            l = line.split(' ', 1)
            if len(l) == 2:
                try: res[l[0]] = simplejson.loads(l[1])
                except: pass
        return res

    def whois_origin(self, ip):
        command = "whois -h asn.shadowserver.org origin " + ip + " > whois_origin.txt"
        os.system(command)
        self.print_file("whois_origin.txt")

    def whois_peer(self, ip):
        command = "whois -h asn.shadowserver.org peer " + ip + " > whois_peer.txt"
        os.system(command)
        self.print_file("whois_peer.txt")

    def whois_prefix(self, pre):
        command = "whois -h asn.shadowserver.org prefix " + pre + " > whois_prefix.txt"
        os.system(command)
        self.print_file("whois_prefix.txt")
    
    def dns_origin(self, ip):
        command = "dig +short " + ip + ".origin.asn.shadowserver.org TXT > dns_origin.txt"
        os.system(command)
        self.print_file("dns_origin.txt")

    def dns_peer(self, ip):
        command = "dig +short " + ip + ".peer.asn.shadowserver.org TXT > dns_peer.txt"
        os.system(command)
        self.print_file("dns_peer.txt")

    def av(self, md5):
        command = "wget -q -o - http://innocuous.shadowserver.org/api/?query=" + md5 + " > av.txt"
        os.system(command)
        self.print_file("av.txt")

    def execute_ip(self, ip):
        self.whois_origin(ip)
        self.whois_peer(ip)
        self.dns_origin(ip)
        self.dns_peer(ip)

    def execute_md5(self, md5):
        self.av(md5)

    def execute_hash(self, hashfile):
        self.whitelisted(hashfile)

    def __init__(self):
        print "hello from init"
        

if __name__ == '__main__':
    ss = shadow_server()
    print "hello"
    
