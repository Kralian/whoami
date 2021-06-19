#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring

import os
import time
import json
import ipaddress
from configparser import ConfigParser
import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.exception
import dns.rdatatype
import dns.reversename
from flask import Flask
from flask import jsonify
from flask import request
from flask import abort
from flask import make_response
from flask import render_template
from flask import send_from_directory
from flask.logging import create_logger
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

## finding myself and my things
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
arch = os.uname()[4]

SPECIAL_NETWORKS = [
        {"cidr": "0.0.0.0/8", "asn": "rfc1122", "cc": "any",  "rir": "host", "date": "1981-09", },
        {"cidr": "10.0.0.0/8", "asn": "rfc1918", "cc": "any",  "rir": "private-use", "date": "1996-02", },
        {"cidr": "100.64.0.0/10", "asn": "rfc6598", "cc": "any", "rir": "shared", "date": "2012-04", },
        {"cidr": "127.0.0.0/8", "asn": "rfc1122", "cc": "any", "rir": "loopback", "date": "1981-09", },
        {"cidr": "169.254.0.0/16", "asn": "rfc3927", "cc": "any", "rir": "link-local", "date": "1996-02", },
        {"cidr": "172.16.0.0/12", "asn": "rfc1918", "cc": "any", "rir": "private-use", "date": "1996-02", },
        {"cidr": "192.0.0.8/32", "asn": "rfc7600", "cc": "any", "rir": "ipv4-dummy", "date": "2015-03", },
        {"cidr": "192.0.0.9/32", "asn": "rfc7723", "cc": "any", "rir": "pcp-anycast", "date": "2015-10", },
        {"cidr": "192.0.0.10/32", "asn": "rfc8155", "cc": "any", "rir": "nat-anycast-traversal", "date": "2017-02", },
        {"cidr": "192.0.0.170/32", "asn": "rfc7050", "cc": "any", "rir": "nat64/dns64 discovery", "date": "2013-02", },
        {"cidr": "192.0.0.171/32", "asn": "rfc7050", "cc": "any", "rir": "nat64/dns64 discovery", "date": "2013-02", },
        {"cidr": "192.0.0.0/29", "asn": "rfc7335", "cc": "any", "rir": "ipv4-continuity", "date": "2011-06", },
        {"cidr": "192.0.0.0/24", "asn": "rfc6890", "cc": "any", "rir": "IETF-protocol", "date": "2010-01", },
        {"cidr": "192.0.2.0/24", "asn": "rfc5737", "cc": "any", "rir": "documentation-1", "date": "2010-01", },
        {"cidr": "192.31.196.0/24", "asn": "rfc7424", "cc": "any", "rir": "as112-v4", "date": "2014-12", },
        {"cidr": "192.52.193.0/24", "asn": "rfc7450", "cc": "any", "rir": "amt", "date": "2014-12", },
        {"cidr": "192.88.99.0/24", "asn": "rfc7526", "cc": "any", "rir": "deprecated", "date": "2001-06", },
        {"cidr": "192.168.0.0/16", "asn": "rfc1918", "cc": "any", "rir": "private-use", "date": "1996-02", },
        {"cidr": "192.175.48.0/24", "asn": "rfc7534", "cc": "any", "rir": "as112-service", "date": "1996-01", },
        {"cidr": "198.18.0.0/15", "asn": "rfc2544", "cc": "any", "rir": "benchmark", "date": "1999-03", },
        {"cidr": "198.51.100.0/24", "asn": "rfc5737", "cc": "any", "rir": "documentation-2", "date": "2010-01", },
        {"cidr": "203.0.113.0/24", "asn": "rfc5737", "cc": "any", "rir": "documentation-3", "date": "2010-01", },
        {"cidr": "240.0.0.0/4", "asn": "rfc1112", "cc": "any", "rir": "reserved", "date": "1989-08", },
        {"cidr": "255.255.255.255/32", "asn": "rfc8190", "cc": "any", "rir": "broadcast", "date": "1984-10", },
        {"cidr": "fc00::/7", "asn": "rfcXXXX", "cc": "any", "rir": "unique-local", "date": "1970-01", },
        {"cidr": "fe80::/10", "asn": "rfcXXXX", "cc": "any", "rir": "link-local", "date": "1970-01", },
        {"cidr": "ff00::/8", "asn": "rfcXXXX", "cc": "any", "rir": "multicast", "date": "1970-01", },
        {"cidr": "0::/128", "asn": "rfcXXXX", "cc": "any", "rir": "unspecified", "date": "1970-01", },
        {"cidr": "0::1/128", "asn": "rfcXXXX", "cc": "any", "rir": "loopback", "date": "1970-01", },
        {"cidr": "::ffff:0:0/96", "asn": "rfcXXXX", "cc": "any", "rir": "ipv4-mapped", "date": "1970-01", },
        {"cidr": "::ffff:0:0:0/96", "asn": "rfcXXXX", "cc": "any", "rir": "ipv4-translated", "date": "1970-01", },
        {"cidr": "64:ff9b::/96", "asn": "rfcXXXX", "cc": "any", "rir": "nat64-translated", "date": "1970-01", },
        {"cidr": "100::/64", "asn": "rfcXXXX", "cc": "any", "rir": "discard", "date": "1970-01", },
        {"cidr": "2001::/32", "asn": "rfcXXXX", "cc": "any", "rir": "teredo", "date": "1970-01", },
        {"cidr": "2001:20::/28", "asn": "rfcXXXX", "cc": "any", "rir": "orchidv2", "date": "1970-01", },
        {"cidr": "2001:db8::/32", "asn": "rfcXXXX", "cc": "any", "rir": "documentation", "date": "1970-01", },
        {"cidr": "2002::/16", "asn": "rfcXXXX", "cc": "any", "rir": "6to4", "date": "1970-01", },
        {"cidr": "0::/0", "asn": "rfcXXXX", "cc": "any", "rir": "default-route", "date": "1970-01", },
        ]

pidfile = os.path.join(BASE_DIR, '.w.slave.pid')
app = Flask(__name__)
CORS(app)
LOG = create_logger(app)
app.wsgi_app = ProxyFix(app.wsgi_app)

def get_address_info(info):
    hostip = ipaddress.ip_address(info['IP'])
    if hostip.is_global:
        try:
            coa = []
            cpa = None
            for c_o in [str(x)[1:-1] for x in cymru_origins(info['IP'])]:
                thisc = [z.strip() for z in c_o.split('|')]
                coa.append({
                    "ASN": thisc[0],
                    "CIDR": thisc[1],
                    "CC": thisc[2],
                    "RIR": thisc[3],
                    "Date": thisc[4]})
                cpa = []
            for c_p in [str(x)[1:-1] for x in cymru_peers(info['IP'])]:
                thisc = [z.strip() for z in c_p.split('|')]
                hostip = ipaddress.ip_address(info['IP'])
                network = ipaddress.ip_network(thisc[1])
                if hostip in network:
                    cpa.append({
                        "ASPATH": thisc[0],
                        "CIDR": thisc[1],
                        "CC": thisc[2],
                        "RIR": thisc[3],
                        "Date": thisc[4]})
                    info['origins'] = coa
            info['peers'] = cpa
        except TypeError:
            info['origins'] = None
            info['peers'] = None
        return info
    for net in SPECIAL_NETWORKS:
        if hostip in ipaddress.ip_network(net['cidr']):
            coa = []
            coa.append({
                "ASN": net['asn'],
                "CIDR": net['cidr'],
                "CC": net['cc'],
                "RIR": net['rir'],
                "Date": net['date']})
            cpa = []
            try:
                for c_p in [str(x)[1:-1] for x in cymru_peers(hostip)]:
                    thisc = [z.strip() for z in c_p.split('|')]
                    hostip = ipaddress.ip_address(info['IP'])
                    network = ipaddress.ip_network(thisc[1])
                    if hostip in network:
                        cpa.append({
                            "ASPATH": thisc[0],
                            "CIDR": thisc[1],
                            "CC": thisc[2],
                            "RIR": thisc[3],
                            "Date": thisc[4]})
            except dns.exception.DNSException as dns_exception:
                LOG.error("dns error {error}", error=dns_exception)
                cpa = None
            except AttributeError as attribute_exception:
                LOG.info('{hostip} results in dns error {error}', hostip=hostip, error=attribute_exception)
                cpa = None
            info['origins'] = coa
            info['peers'] = cpa
            return info
    info['origins'] = None
    info['peers'] = None
    return info


def cymru_origins(addr):
    reverseaddr = dns.reversename.from_address(addr).to_text()
    reverseaddr = reverseaddr.replace('.in-addr.arpa.', '.{0}')
    reverseaddr = reverseaddr.replace('.ip6.arpa.', '.{1}')
    originquery = reverseaddr.format('origin.asn.cymru.com.', 'origin6.asn.cymru.com')
    try:
        answers = dns.resolver.query(originquery, 'TXT')
    except dns.exception.DNSException as dns_exception:
        LOG.error("dns error {error}", error=dns_exception)
        return None
    return answers

def cymru_peers(addr):
    reverseaddr = dns.reversename.from_address(addr).to_text()
    reverseaddr = reverseaddr.replace('.in-addr.arpa.', '.{0}')
    reverseaddr = reverseaddr.replace('.ip6.arpa.', '.{}')
    peerquery = reverseaddr.format('peer.asn.cymru.com.')
    try:
        answers = dns.resolver.query(peerquery, 'TXT')
    except dns.exception.DNSException as dns_exception:
        LOG.error("dns error {error}", error=dns_exception)
        return None
    return answers

def cymru_descr(asn):
    asnquery = "as{}.asn.cymru.com".format(asn.strip())
    try:
        answers = dns.resolver.query(asnquery, 'TXT')
    except dns.exception.DNSException as dns_exception:
        LOG.error("dns error {error}", error=dns_exception)
        return None
    return answers

def parserequest(thisrequest): #pylint: disable=too-many-branches
    info = {}
    if 'X-Forwared-For' in thisrequest.headers:
        info['IP'] = thisrequest.headers['X-Forwarded-For']
    else:
        info['IP'] = thisrequest.remote_addr
    if 'X-Forwared-Proto' in thisrequest.headers:
        info['scheme'] = thisrequest.headers['X-Forwarded-Proto']
    else:
        info['scheme'] = thisrequest.scheme
    if 'Host' in thisrequest.headers:
        info['host'] = thisrequest.headers['Host']
        if info['host'] in ['w.7f.dk', 'w.7f.io']:
            info['v4host'] = 'w4.'+".".join(info['host'].split(".")[1:])
            info['v6host'] = 'w6.'+".".join(info['host'].split(".")[1:])
        elif info['host'] in ['127.0.0.1', '::1']:
            info['v4host'] = '127.0.0.1'
            info['v6host'] = '::1'
        else:
            info['v4host'] = info['host']
            info['v6host'] = info['host']
    for key in ['Referer', 'From']:
        if key in thisrequest.headers:
            info[key] = thisrequest.headers[key]
    info = get_address_info(info)
    return info

# Hack for old browsers that don't understand the rel="shortcut icon"
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static/images'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/')
def landing():
    info = parserequest(request)
    if ['Accept'] in request.headers and 'text/plain' in request.headers['Accept']:
        resp = make_response(info['IP'])
        resp.mimetype = "text/plain"
        return resp
    response = make_response(render_template("index.html", info=info))
    return response

@app.route('/dynamic/<scriptname>')
def dynamic(scriptname):
    info = parserequest(request)
    if not scriptname in ['script.js']:
        return render_template('404.html'), 404
    response = make_response(render_template(scriptname, info=info))
    response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
    response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
    return response

@app.route('/txt')
@app.route('/asc')
@app.route('/text')
@app.route('/plain')
@app.route('/ascii')
def plain_response():
    info = parserequest(request)
    resp = make_response(info['IP'])
    resp.mimetype = "text/plain"
    return resp

@app.route('/json')
def json_response():
    info = parserequest(request)
    LOG.info("Connection: {ip} -> {host}", ip=info['IP'], host=info['host'])
    LOG.info("Origins: {origins}", origins=info['origins'])
    LOG.info("Peers: {peers}", peers=info['peers'])
    return jsonify(info)

@app.route('/version')
def version():
    if 'Content-Type' in request.headers and request.headers['Content-Type'] == 'application/json':
        return json.dumps({'version': 0.8})
    return jsonify({'version': 0.8})

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=True)
