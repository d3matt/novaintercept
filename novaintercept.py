# -*- coding: utf-8 -*-

"""
    InterceptResolver - proxy requests to upstream server 
                        (optionally intercepting)
        
"""
from __future__ import print_function

import binascii
import copy
import os
import socket
import struct
import sys
import time

from dnslib import DNSRecord,RR,QTYPE,RCODE,parse_time
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger
from dnslib.label import DNSLabel
from dnslib.intercept import InterceptResolver
from novaclient.client import Client as novaclient


def get_nova_creds():
    d = {}
    d['username'] = os.environ['OS_USERNAME']
    d['api_key'] = os.environ['OS_PASSWORD']
    d['auth_url'] = os.environ['OS_AUTH_URL']
    d['project_id'] = os.environ['OS_TENANT_NAME']
    return d

class CachedNovaLookup(object):
    _cache = None
    _cache_time = None

    @classmethod
    def _do_lookup(cls):
        creds = get_nova_creds()
        nova = novaclient('2', **creds)
        print('performing nova lookup')
        cls._cache = nova.servers.list()
        cls._cache_time = time.time()

    @classmethod
    def get_list(cls, timeout=60):
        if cls._cache is None or abs(cls._cache_time - time.time()) > 60:
            cls._do_lookup()
        return cls._cache

class NovaResolver(InterceptResolver):

    def resolve(self,request,handler):
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]

        qname = str(qname).split('.')
        if qname[-1] == '':
            qname.pop(-1)
        if qname[-1] == 'novalocal' and qtype in ['A', 'AAAA', 'MX']:
            reply = request.reply()
            servername = qname[-2]
            if len(qname) == 2:
                query = 'fixed'
            elif len(qname) == 3:
                query = qname[0]
            else:
                return reply
            if query not in ['fixed', 'floating']:
                return reply

            print(qname)
            for server in CachedNovaLookup.get_list():
                if server.name == servername:
                    for interface in server.addresses.values():
                        for ip in interface:
                            if ip['OS-EXT-IPS:type'] == query and qtype == 'A':
                                ans = RR.fromZone('{} 60 IN A {}'.format(request.q.qname, ip['addr']))[0]
                                print(ans)
                                ans.rname = request.q.qname
                                reply.add_answer(ans)

            return reply
        else:
            return super(NovaResolver,self).resolve(request, handler)



if __name__ == '__main__':

    import argparse,sys,time

    p = argparse.ArgumentParser(description="DNS Intercept Proxy")
    p.add_argument("--port","-p",type=int,default=53,
                    metavar="<port>",
                    help="Local proxy port (default:53)")
    p.add_argument("--address","-a",default="",
                    metavar="<address>",
                    help="Local proxy listen address (default:all)")
    p.add_argument("--upstream","-u",default="8.8.8.8:53",
            metavar="<dns server:port>",
                    help="Upstream DNS server:port (default:8.8.8.8:53)")
    p.add_argument("--tcp",action='store_true',default=False,
                    help="TCP proxy (default: UDP only)")
    p.add_argument("--intercept","-i",action="append",
                    metavar="<zone record>",
                    help="Intercept requests matching zone record (glob) ('-' for stdin)")
    p.add_argument("--skip","-s",action="append",
                    metavar="<label>",
                    help="Don't intercept matching label (glob)")
    p.add_argument("--nxdomain","-x",action="append",
                    metavar="<label>",
                    help="Return NXDOMAIN (glob)")
    p.add_argument("--ttl","-t",default="60s",
                    metavar="<ttl>",
                    help="Intercept TTL (default: 60s)")
    p.add_argument("--timeout","-o",type=float,default=5,
                    metavar="<timeout>",
                    help="Upstream timeout (default: 5s)")
    p.add_argument("--log",default="request,reply,truncated,error",
                    help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix",action='store_true',default=False,
                    help="Log prefix (timestamp/handler/resolver) (default: False)")
    args = p.parse_args()

    args.dns,_,args.dns_port = args.upstream.partition(':')
    args.dns_port = int(args.dns_port or 53)

    resolver = NovaResolver(args.dns,
                            args.dns_port,
                            args.ttl,
                            args.intercept or [],
                            args.skip or [],
                            args.nxdomain or [],
                            args.timeout)
    logger = DNSLogger(args.log,args.log_prefix)

    print("Starting Intercept Proxy (%s:%d -> %s:%d) [%s]" % (
                        args.address or "*",args.port,
                        args.dns,args.dns_port,
                        "UDP/TCP" if args.tcp else "UDP"))

    for rr in resolver.zone:
        print("    | ",rr[2].toZone(),sep="")
    if resolver.nxdomain:
        print("    NXDOMAIN:",", ".join(resolver.nxdomain))
    if resolver.skip:
        print("    Skipping:",", ".join(resolver.skip))
    print()


    DNSHandler.log = { 
        'log_request',      # DNS Request
        'log_reply',        # DNS Response
        'log_truncated',    # Truncated
        'log_error',        # Decoding error
    }

    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           logger=logger)
    udp_server.start_thread()

    if args.tcp:
        tcp_server = DNSServer(resolver,
                               port=args.port,
                               address=args.address,
                               tcp=True,
                               logger=logger)
        tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)

