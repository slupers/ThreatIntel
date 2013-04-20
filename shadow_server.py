import os
import json as simplejson
import sys


def print_file(filename):
	f = open(filename)
	s = f.read()
	print s
	
def whitelisted(hashfile):
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

def whois_origin(ip):
	command = "whois -h asn.shadowserver.org origin " + ip + " > whois_origin.txt"
	os.system(command)
	print_file("whois_origin.txt")

def whois_peer(ip):
	command = "whois -h asn.shadowserver.org peer " + ip + " > whois_peer.txt"
	os.system(command)
	print_file("whois_peer.txt")

def whois_prefix(pre):
	command = "whois -h asn.shadowserver.org prefix " + pre + " > whois_prefix.txt"
	os.system(command)
	print_file("whois_prefix.txt")
	
def dns_origin(ip):
	command = "dig +short " + ip + ".origin.asn.shadowserver.org TXT > dns_origin.txt"
	os.system(command)
	print_file("dns_origin.txt")

def dns_peer(ip):
	command = "dig +short " + ip + ".peer.asn.shadowserver.org TXT > dns_peer.txt"
	os.system(command)
	print_file("dns_peer.txt")

def av(md5):
	command = "wget -q -o - http://innocuous.shadowserver.org/api/?query=" + md5 + " > av.txt"
	os.system(command)
	print_file("av.txt")

def menu():
	print "1: whitelisted"
	print "2: whois_origin"
	print "3: whois_peer"
	print "4: whois_prefix"
	print "5: dns_origin"
	print "6: dns_peer"
	print "7: av"
	
	choice = raw_input()
	
	if choice == "1":
			print "enter a hashfile"
			hashfile = raw_input()
			whitelisted(hashfile)
	if choice == "2":
			print "enter ip"
			ip = raw_input()
			whois_origin(ip)
	if choice == "3":
			print "enter ip"
			ip = raw_input()
			whois_peer(ip)
	if choice == "4":
			print "enter prefix"
			pre = raw_input()
			whois_prefix(pre)
	if choice == "5":
			print "enter ip"
			ip = raw_input()
			dns_origin(ip)
	if choice == "6":
			print "enter ip"
			ip = raw_input()
			dns_peer(ip)
	if choice == "7":
			print "enter md5"
			md5 = raw_input()
			av(md5)
	

if __name__ == '__main__':
	cont = "yes"
	while(cont == "yes"):
		menu()
		print("continue?")
		cont = raw_input()
	