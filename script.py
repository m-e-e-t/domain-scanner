#!/usr/bin/env python3
import requests
import subprocess
import argparse
import logging
import socket
import os
import concurrent.futures
import json
import csv
import re
import urllib3
import random
import time
import dns.resolver
import platform
from urllib.parse import urljoin, urlparse
from datetime import datetime
from tqdm import tqdm
from urllib3.exceptions import InsecureRequestWarning
from colorama import init, Fore, Style
from pathlib import Path
import xml.etree.ElementTree as ET
import yaml  # For configuration file
from jinja2 import Environment, FileSystemLoader  # For HTML report
# Initialize colorama for cross-platform colored terminal output
init()
# Suppress insecure request warnings
urllib3.disable_warnings(InsecureRequestWarning)
BANNER = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════╗
║ Domain Scanner - A Comprehensive Recon Tool     ║
╚═══════════════════════════════════════════════╝{Style.RESET_ALL}
"""
class DomainScanner:
    def __init__(self, domain, output_dir=None, verbose=False, threads=10, timeout=5, scan_ports=False, check_dns=True, use_wordlist=None, delay=0, use_proxy=None, max_retries=3, custom_ports=None, config_file=None, nuclei_templates=None):
        self.config = {}
        if config_file:
            try:
                with open(config_file, 'r') as f:
                    self.config = yaml.safe_load(f) or {}
                logging.info(f"{Fore.BLUE}[+] Loaded configuration from: {config_file}{Style.RESET_ALL}")
            except FileNotFoundError:
                logging.warning(f"{Fore.YELLOW}[!] Configuration file not found: {config_file}{Style.RESET_ALL}")
            except yaml.YAMLError as e:
                logging.error(f"{Fore.RED}[-] Error parsing configuration file: {e}{Style.RESET_ALL}")
        self.domain = self._validate_domain(domain or self.config.get('domain'))
        self.output_dir = output_dir or self.config.get('output_dir') or os.path.join(os.getcwd(), "scan_results")
        self.verbose = verbose or self.config.get('verbose', False)
        self.threads = max(1, min(threads or self.config.get('threads', 10), 50))
        self.timeout = timeout or self.config.get('timeout', 5)
        self.enable_port_scanning = scan_ports or self.config.get('scan_ports', False)
        self.check_dns = check_dns if check_dns is not None else self.config.get('check_dns', True)
        self.use_wordlist = use_wordlist or self.config.get('wordlist')
        self.delay = delay or self.config.get('delay', 0)
        self.proxy = use_proxy or self.config.get('proxy')
        self.max_retries = max_retries or self.config.get('retries', 3)
        self.subdomains = set()
        self.results = []
        self.scan_start_time = datetime.now()
        self.common_ports = custom_ports if custom_ports is not None else self.config.get('ports') or [21, 22, 23, 25, 53, 80, 443, 445, 8080, 8443, 3389]
        self.user_agents = self.config.get('user_agents') or [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Mobile/15E148 Safari/604.1"
        ]
        self.nuclei_templates = nuclei_templates or self.config.get('nuclei_templates')
        self.setup_http_session()
        self.setup_logging()
        self.log_system_info()        

    def setup_http_session(self):
        self.session = requests.Session()
        retry_strategy = urllib3.Retry(total=self.max_retries, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=["GET", "HEAD"])
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        if self.proxy:
            self.session.proxies = {"http": self.proxy, "https": self.proxy}
            logging.info(f"{Fore.BLUE}[+] Using proxy: {self.proxy}{Style.RESET_ALL}")

    def log_system_info(self):
        if self.verbose:
            logging.debug(f"System: {platform.system()} {platform.release()}")
            logging.debug(f"Python: {platform.python_version()}")
            logging.debug(f"Machine: {platform.machine()}")

    def _validate_domain(self, domain):
        if not domain:
            raise ValueError("Target domain must be specified.")
        domain = domain.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = re.sub(r"^https?://", "", domain)
        domain = domain.split("/")[0]
        if not re.match(r"^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", domain):
            raise ValueError(f"Invalid domain format: {domain}")
        return domain

    def setup_logging(self):

        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        log_file = os.path.join(self.output_dir, f"{self.domain}_{self.timestamp}.log")

        log_level = logging.DEBUG if self.verbose else logging.INFO

        for handler in logging.root.handlers[:]:

            logging.root.removeHandler(handler)

        logging.basicConfig(level=log_level, format="%(asctime)s - %(levelname)s - %(message)s", handlers=[logging.FileHandler(log_file), logging.StreamHandler()])

        logging.info(f"{Fore.GREEN}[+] Started scan for {Fore.YELLOW}{self.domain}{Style.RESET_ALL}")


    def fingerprint_waf(self, url):

        """Fingerprints the Web Application Firewall (WAF) for a given URL using wafw00f."""

        logging.info(f"{Fore.BLUE}[+] Fingerprinting WAF for: {url}{Style.RESET_ALL}")

        try:

            command = f"wafw00f {url} --json"

            output, error = self.run_command(command)

            if output:

                try:

                    waf_data = json.loads(output)

                    detected_waf = waf_data.get('detectedby')

                    if detected_waf:

                        logging.warning(f"{Fore.YELLOW}[WAF DETECTED] {url} - {', '.join(detected_waf)}{Style.RESET_ALL}")

                        return detected_waf

                    else:

                        logging.info(f"{Fore.GREEN}[+] No WAF detected for: {url}{Style.RESET_ALL}")

                        return None

                except json.JSONDecodeError:

                    logging.error(f"{Fore.RED}[-] Error decoding wafw00f output for {url}: {output}{Style.RESET_ALL}")

                    return None

            elif error and "wafw00f not found" not in error:

                logging.error(f"{Fore.RED}[-] wafw00f error for {url}: {error}{Style.RESET_ALL}")

                return None

        except FileNotFoundError:

            logging.warning(f"{Fore.YELLOW}[!] wafw00f not found. Ensure it is installed and in your PATH.{Style.RESET_ALL}")

            return "wafw00f not found"

        except Exception as e:

            logging.error(f"{Fore.RED}[-] Error running wafw00f for {url}: {e}{Style.RESET_ALL}")

            return None

   

    def run_command(self, command):

        logging.info(f"Executing command: {command}")

        try:

            args = command.split() if isinstance(command, str) else command

            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            stdout, stderr = process.communicate(timeout=self.timeout * 2)

            output = stdout.decode()

            error = stderr.decode()

            if output and self.verbose:

                logging.info(f"Command Output:\n{output}")

            if error:

                logging.error(f"Command Error:\n{error}")

            return output, error

        except subprocess.TimeoutExpired:

            logging.error(f"Command timed out after {self.timeout * 2} seconds")

            return "", "Command timed out"

        except Exception as e:

            logging.error(f"Command execution failed: {e}")

            return "", str(e)


    def run_subfinder(self):

        logging.info(f"{Fore.BLUE}[+] Running subfinder for {self.domain}{Style.RESET_ALL}")

        subdomains = set()

        try:

            command = f"subfinder -d {self.domain} -all -silent"

            output, error = self.run_command(command)

            if output:

                for subdomain in output.splitlines():

                    subdomains.add(subdomain.strip())

            if error and "subfinder not found" not in error:

                logging.error(f"{Fore.RED}[-] Subfinder error: {error}{Style.RESET_ALL}")

        except FileNotFoundError:

            logging.warning(f"{Fore.YELLOW}[!] Subfinder not found. Ensure it is installed and in your PATH.{Style.RESET_ALL}")

        return list(subdomains)


    def attempt_dns_zone_transfer(self):

        """Attempts a DNS zone transfer for the target domain."""

        logging.info(f"{Fore.BLUE}[+] Attempting DNS zone transfer for {self.domain}{Style.RESET_ALL}")

        zone_transfer_results = []

        try:

            ns_records = dns.resolver.resolve(self.domain, 'NS')

            for ns in ns_records:

                ns_server = str(ns)

                try:

                    zone = dns.zone.from_xfr(dns.query.xfr(ns_server, self.domain, timeout=self.timeout))

                    logging.warning(f"{Fore.RED}[DNS ZONE TRANSFER] Successful zone transfer from: {ns_server}{Style.RESET_ALL}")

                    records = {}

                    for name, rdataset in zone.items():

                        records[f"{name}.{self.domain}"] = [str(rdata) for rdata in rdataset]

                        logging.debug(f"[DNS RECORD] {name}.{self.domain}: {rdataset}")

                    zone_transfer_results.append({"server": ns_server, "records": records})

                except dns.xfr.TransferError as e:

                    logging.debug(f"Zone transfer failed from {ns_server}: {e}")

                except socket.timeout:

                    logging.debug(f"Timeout attempting zone transfer from {ns_server}")

        except dns.resolver.NoAnswer:

            logging.info(f"No NS records found for {self.domain}, cannot attempt zone transfer.")

        except dns.resolver.NXDOMAIN:

            logging.error(f"Domain {self.domain} does not exist.")

        except Exception as e:

            logging.error(f"An error occurred while attempting DNS zone transfer: {e}")


        if zone_transfer_results:

            self.results.append({"domain": self.domain, "dns_zone_transfer": zone_transfer_results, "timestamp": datetime.now().isoformat()})

    def monitor_ct_logs(self):

        """Monitors Certificate Transparency logs for the target domain using crt.sh API."""

        logging.info(f"{Fore.BLUE}[+] Monitoring Certificate Transparency logs for {self.domain}{Style.RESET_ALL}")

        ct_subdomains = set()

        url = f"https://crt.sh/?q=%.{self.domain}&output=json"

        try:

            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:

                try:

                    data = response.json()

                    for entry in data:

                        name_value = entry.get('name_value')

                        if name_value:

                            # Handle both wildcard and non-wildcard certificates

                            if name_value.startswith("*."):

                                subdomain = name_value[2:]

                                if subdomain == self.domain:

                                    continue # Avoid adding the base domain

                                ct_subdomains.add(subdomain)

                            elif name_value.endswith(f".{self.domain}"):

                                ct_subdomains.add(name_value)

                    logging.info(f"{Fore.GREEN}[+] Found {len(ct_subdomains)} subdomains from CT logs.{Style.RESET_ALL}")

                    self.subdomains.update(ct_subdomains)

                except json.JSONDecodeError:

                    logging.error(f"{Fore.RED}[-] Error decoding CT log response.{Style.RESET_ALL}")

            else:

                logging.error(f"{Fore.RED}[-] Failed to retrieve CT logs. Status code: {response.status_code}{Style.RESET_ALL}")

        except requests.exceptions.RequestException as e:

            logging.error(f"{Fore.RED}[-] Error querying CT logs: {e}{Style.RESET_ALL}")

        return list(ct_subdomains)

    def enumerate_subdomains(self):

        logging.info(f"{Fore.BLUE}[+] Enumerating subdomains for: {self.domain}{Style.RESET_ALL}")

        try:

            ip_address = socket.gethostbyname(self.domain)

            logging.info(f"{Fore.GREEN}[+] Resolved {self.domain} to: {ip_address}{Style.RESET_ALL}")

            self.results.append({"domain": self.domain, "ip_address": ip_address, "is_main_domain": True, "timestamp": datetime.now().isoformat()})

        except socket.gaierror:

            logging.error(f"{Fore.RED}[-] Could not resolve {self.domain}.{Style.RESET_ALL}")

        self.subdomains.add(self.domain)


        subfinder_subdomains = self.run_subfinder()

        logging.info(f"{Fore.GREEN}[+] Found {len(subfinder_subdomains)} subdomains via subfinder.{Style.RESET_ALL}")

        self.subdomains.update(subfinder_subdomains)


        wordlist_subdomains = self._load_wordlist()

        self._probe_wordlist_subdomains(wordlist_subdomains)


        ct_log_subdomains = self.monitor_ct_logs() # Call the CT log monitoring function

        logging.info(f"{Fore.GREEN}[+] Found {len(ct_log_subdomains)} subdomains from CT logs.{Style.RESET_ALL}")

        self.subdomains.update(ct_log_subdomains)


        if self.check_dns:

            self._check_dns_records()


        self.attempt_dns_zone_transfer() # Attempt DNS zone transfer


        logging.info(f"{Fore.GREEN}[+] Found {len(self.subdomains)} potential domains/subdomains.{Style.RESET_ALL}")

        return list(self.subdomains)


    def _load_wordlist(self):

        if self.use_wordlist and os.path.exists(self.use_wordlist):

            with open(self.use_wordlist, "r", encoding="utf-8", errors="ignore") as f:

                subdomains_to_try = [line.strip() for line in f if line.strip()]

            logging.info(f"{Fore.GREEN}[+] Loaded {len(subdomains_to_try)} subdomains from wordlist{Style.RESET_ALL}")

            return subdomains_to_try

        else:

            default_subdomains = ["www", "mail", "ftp", "admin", "blog", "dev", "api", "shop", "support", "portal", "staging", "test", "secure", "vpn", "cdn", "cloud", "img", "images", "login", "m", "mobile", "app", "auth", "docs", "status", "internal", "remote", "git", "gitlab", "github", "jenkins", "jira", "confluence", "wiki", "hr", "intranet", "media", "store", "payment", "payments", "checkout", "cart", "forum", "dashboard", "analytics", "beta", "demo", "help", "ns1", "ns2", "webmail", "smtp", "pop", "imap", "calendar", "drive", "database", "db", "sql", "mysql", "postgres", "api-dev", "stage", "production", "monitor", "monitoring", "grafana", "prometheus", "kibana", "elastic"]

            return default_subdomains


    def _probe_wordlist_subdomains(self, subdomains_to_try):

        with tqdm(total=len(subdomains_to_try), desc="Enumerating subdomains (wordlist)", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar, concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:

            futures = {executor.submit(self._check_subdomain, f"{sub}.{self.domain}"): sub for sub in subdomains_to_try}

            for future in concurrent.futures.as_completed(futures):

                pbar.update(1)

                if self.delay > 0:

                    time.sleep(self.delay)


    def run_nuclei(self, url):

        logging.info(f"{Fore.BLUE}[+] Running nuclei scan on: {url}{Style.RESET_ALL}")

        results = []

        try:

            command = f"nuclei -u {url} -json -silent"

            if self.nuclei_templates:

                command += f" -t {self.nuclei_templates}"

            output, error = self.run_command(command)

            if output:

                for line in output.splitlines():

                    try:

                        results.append(json.loads(line))

                    except json.JSONDecodeError:

                        logging.error(f"{Fore.RED}[-] Could not decode nuclei output: {line}{Style.RESET_ALL}")

            if error and "nuclei not found" not in error:

                logging.error(f"{Fore.RED}[-] Nuclei error: {error}{Style.RESET_ALL}")

        except FileNotFoundError:

            logging.warning(f"{Fore.YELLOW}[!] Nuclei not found. Ensure it is installed and in your PATH.{Style.RESET_ALL}")

        return results


    def vulnerability_scan(self, subdomain_list):

        logging.info(f"{Fore.BLUE}[+] Starting vulnerability scan on {len(subdomain_list)} domains/subdomains.{Style.RESET_ALL}")

        with tqdm(total=len(subdomain_list), desc="Scanning for vulnerabilities", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:

            for subdomain in subdomain_list:

                http_url = f"http://{subdomain}"

                https_url = f"https://{subdomain}"

                nuclei_results_http = self.run_nuclei(http_url)

                nuclei_results_https = self.run_nuclei(https_url)

                for result in nuclei_results_http:

                    logging.warning(f"{Fore.RED}[VULNERABILITY] {http_url} - {result.get('info', {}).get('name', 'N/A')} - Severity: {result.get('info', {}).get('severity', 'N/A')}{Style.RESET_ALL}")

                    self.results.append({"domain": subdomain, "vulnerability": result, "protocol": "http", "timestamp": datetime.now().isoformat()})

                for result in nuclei_results_https:

                    logging.warning(f"{Fore.RED}[VULNERABILITY] {https_url} - {result.get('info', {}).get('name', 'N/A')} - Severity: {result.get('info', {}).get('severity', 'N/A')}{Style.RESET_ALL}")

                    self.results.append({"domain": subdomain, "vulnerability": result, "protocol": "https", "timestamp": datetime.now().isoformat()})

                pbar.update(1)

                if self.delay > 0:

                    time.sleep(self.delay)

        logging.info(f"{Fore.GREEN}[+] Vulnerability scan completed.{Style.RESET_ALL}")


    def _check_dns_records(self):

        logging.info(f"{Fore.BLUE}[+] Checking DNS records for: {self.domain}{Style.RESET_ALL}")

        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV"]

        dns_results = {}

        for record_type in record_types:

            try:

                answers = dns.resolver.resolve(self.domain, record_type)

                dns_results[record_type] = [str(rdata) for rdata in answers]

                if record_type in ["CNAME", "MX", "NS", "SRV"]:

                    for rdata in answers:

                        hostname = str(rdata).rstrip(".")

                        if self.domain in hostname and hostname != self.domain:

                            subdomain = hostname

                            self._check_subdomain(subdomain)

                logging.info(f"{Fore.GREEN}[+] {record_type} records for {self.domain}: {dns_results[record_type]}{Style.RESET_ALL}")

            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):

                dns_results[record_type] = []

                if self.verbose:

                    logging.debug(f"No {record_type} records found for {self.domain}")

            except Exception as e:

                logging.error(f"{Fore.RED}[-] Error querying {record_type} records: {e}{Style.RESET_ALL}")

        self.results.append({"domain": self.domain, "dns_records": dns_results, "timestamp": datetime.now().isoformat()})


    def _check_subdomain(self, subdomain):

        try:

            ip_address = socket.gethostbyname(subdomain)

            logging.info(f"{Fore.GREEN}[+] Found subdomain: {subdomain} ({ip_address}){Style.RESET_ALL}")

            self.subdomains.add(subdomain)

            if not any(r.get("domain") == subdomain for r in self.results):

                self.results.append({"domain": subdomain, "ip_address": ip_address, "is_main_domain": False, "timestamp": datetime.now().isoformat()})

            return True

        except socket.gaierror:

            if self.verbose:

                logging.debug(f"{Fore.RED}[-] Could not resolve {subdomain}{Style.RESET_ALL}")

            return False


    def basic_scan(self, url):

        if self.delay > 0:

            time.sleep(self.delay)

        logging.info(f"{Fore.BLUE}[+] Scanning: {url}{Style.RESET_ALL}")

        headers = {"User-Agent": random.choice(self.user_agents)}

        try:

            response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)

            status_code = response.status_code

            server = response.headers.get("Server", "Unknown")

            content_type = response.headers.get("Content-Type", "Unknown")

            title_match = re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE)

            title = title_match.group(1) if title_match else "No title"

            favicon_match = re.search(r"<link[^>]*rel=[\'\"](shortcut icon|icon)[\'\"][^>]*href=[\'\"]([^\'\"]+)", response.text, re.IGNORECASE)

            favicon = favicon_match.group(2) if favicon_match else None

            if favicon and not favicon.startswith(("http://", "https://")):

                favicon = urljoin(url, favicon)

            technologies = self._detect_technologies(response)

            cert_info = self._get_certificate_info(url) if url.startswith("https://") else None

            logging.info(f"{Fore.GREEN}[+] {url} - Status: {status_code} - Title: {title[:50]}{Style.RESET_ALL}")

            result = {"url": url, "status_code": status_code, "server": server, "content_type": content_type, "title": title, "headers": dict(response.headers), "technologies": technologies, "favicon": favicon, "content_length": len(response.content), "redirect_url": response.url if response.url != url else None, "certificate": cert_info, "timestamp": datetime.now().isoformat()}

            self.results.append(result)

            return response

        except requests.exceptions.RequestException as e:

            logging.error(f"{Fore.RED}[-] {url} - Error: {e}{Style.RESET_ALL}")

            self.results.append({"url": url, "error": str(e), "timestamp": datetime.now().isoformat()})

            return None


    def _detect_technologies(self, response):

        technologies = {}

        server = response.headers.get("Server")

        if server:

            technologies["server"] = server

        content = response.text.lower()

        if "wp-content" in content or "wp-includes" in content:

            technologies["cms"] = "WordPress"

        elif "/components/com_" in content:

            technologies["cms"] = "Joomla"

        elif "drupal.js" in content or "drupal.min.js" in content:

            technologies["cms"] = "Drupal"

        if "react" in content or "reactjs" in content:

            technologies["js_framework"] = "React"

        elif "angular" in content:

            technologies["js_framework"] = "Angular"

        elif "vue.js" in content or "vue.min.js" in content:

            technologies["js_framework"] = "Vue.js"

        if "google-analytics.com" in content or "ga.js" in content:

            technologies["analytics"] = "Google Analytics"

        return technologies


    def _get_certificate_info(self, url):

        try:

            parsed_url = urlparse(url)

            hostname = parsed_url.netloc.split(":")[0]

            port = parsed_url.port or 443

            import ssl

            context = ssl.create_default_context()

            context.check_hostname = False

            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:

                with context.wrap_socket(sock, server_hostname=hostname) as ssock:

                    cert = ssock.getpeercert(binary_form=False)

                    not_after = cert.get("notAfter", "")

                    not_before = cert.get("notBefore", "")

                    cert_expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")

                    days_to_expiry = (cert_expiry - datetime.now()).days

                    return {"subject": dict(x[0] for x in cert.get("subject", [])), "issuer": dict(x[0] for x in cert.get("issuer", [])), "version": cert.get("version", ""), "not_before": not_before, "not_after": not_after, "days_to_expiry": days_to_expiry, "serial_number": cert.get("serialNumber", "")}

        except Exception as e:

            logging.error(f"{Fore.RED}[-] Error getting certificate info: {e}{Style.RESET_ALL}")

            return {"error": str(e)}


    def scan_ports(self, domain, ports):

        results = {}

        try:

            ip = socket.gethostbyname(domain)

            logging.info(f"{Fore.BLUE}[+] Scanning ports on {domain} using nmap{Style.RESET_ALL}")

            command = f"nmap -sV -p {','.join(map(str, ports))} -oX - {ip}"

            output, error = self.run_command(command)

            if output:

                try:

                    root = ET.fromstring(output)

                    for host in root.findall('host'):

                        for port_element in host.findall('ports/port'):

                            port_id = int(port_element.get('portid'))

                            state = port_element.find('state').get('state')

                            service = port_element.find('service').get('name', 'unknown')

                            version = port_element.find('service').get('product', 'unknown') + " " + port_element.find('service').get('version', 'unknown')

                            if state == 'open':

                                results[port_id] = {"open": True, "service": service, "version": version.strip()}

                                logging.info(f"{Fore.GREEN}[+] {domain}:{port_id} - Open ({service} {version.strip()}){Style.RESET_ALL}")

                except ET.ParseError as e:

                    logging.error(f"{Fore.RED}[-] Error parsing nmap XML output: {e}\nOutput: {output}{Style.RESET_ALL}")

            if error and "nmap not found" not in error:

                logging.error(f"{Fore.RED}[-] Nmap error: {error}{Style.RESET_ALL}")

        except socket.gaierror:

            logging.error(f"{Fore.RED}[-] Could not resolve {domain} for port scanning.{Style.RESET_ALL}")

        except FileNotFoundError:

            logging.warning(f"{Fore.YELLOW}[!] Nmap not found. Ensure it is installed and in your PATH.{Style.RESET_ALL}")

        except Exception as e:

            logging.error(f"{Fore.RED}[-] Port scan error for {domain}: {e}{Style.RESET_ALL}")

        return results


    def scan_domains(self):

        subdomain_list = self.enumerate_subdomains()

        logging.info(f"{Fore.BLUE}[+] Starting scans on {len(subdomain_list)} enumerated domains/subdomains.{Style.RESET_ALL}")

        scan_tasks = []

        for subdomain in subdomain_list:

            http_url = f"http://{subdomain}"

            scan_tasks.append(http_url)

            https_url = f"https://{subdomain}"

            scan_tasks.append(https_url)

            if self.enable_port_scanning:

                logging.info(f"{Fore.BLUE}[+] Scanning ports for {subdomain}{Style.RESET_ALL}")

                port_results = self.scan_ports(subdomain, self.common_ports)

                for result in self.results:

                    if result.get("domain") == subdomain:

                        result["port_scan"] = port_results

                        break


        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:

            list(tqdm(executor.map(self.basic_scan, scan_tasks), total=len(scan_tasks), desc="Scanning URLs", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"))


        self.vulnerability_scan(subdomain_list)


        logging.info(f"{Fore.GREEN}[+] Scan completed for all enumerated domains/subdomains.{Style.RESET_ALL}")

        self.save_results()

        self.print_summary()

        self.generate_html_report()


    def generate_html_report(self):

        """Generates an HTML report of the scan results using Jinja2."""

        logging.info(f"{Fore.BLUE}[+] Generating HTML report...{Style.RESET_ALL}")

        env = Environment(loader=FileSystemLoader('.')) # Load templates from the current directory

        template = env.get_template('report_template.html')

        base_filename = os.path.join(self.output_dir, f"{self.domain}_{self.timestamp}")

        html_file = f"{base_filename}.html"

        try:

            rendered_report = template.render(results=self.results, scan_start_time=self.scan_start_time, scan_duration=datetime.now() - self.scan_start_time, domain=self.domain, subdomains=self.subdomains)

            with open(html_file, "w", encoding="utf-8") as f:

                f.write(rendered_report)

            logging.info(f"{Fore.GREEN}[+] HTML report generated: {html_file}{Style.RESET_ALL}")

        except Exception as e:

            logging.error(f"{Fore.RED}[-] Error generating HTML report: {e}{Style.RESET_ALL}")


    def print_summary(self):

        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}SCAN SUMMARY FOR {self.domain.upper()}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        scan_duration = datetime.now() - self.scan_start_time

        print(f"{Fore.YELLOW}Scan Duration: {scan_duration}{Style.RESET_ALL}")

        subdomains_count = len(self.subdomains)

        print(f"{Fore.GREEN}Discovered Subdomains: {subdomains_count}{Style.RESET_ALL}")

        successful_scans = sum(1 for r in self.results if r.get("status_code"))

        print(f"{Fore.GREEN}Successfully Scanned URLs: {successful_scans}{Style.RESET_ALL}")

        errors = sum(1 for r in self.results if r.get("error") and "vulnerability" not in r)

        print(f"{Fore.RED}Failed Scans: {errors}{Style.RESET_ALL}")

        vulnerabilities_found = sum(1 for r in self.results if r.get("vulnerability"))

        print(f"{Fore.RED}Vulnerabilities Found: {vulnerabilities_found}{Style.RESET_ALL}")

        web_servers = [r for r in self.results if r.get("status_code") in [200, 301, 302, 307, 308]]

        print(f"\n{Fore.YELLOW}Open Web Servers (Top 10):{Style.RESET_ALL}")

        for server in web_servers[:10]:

            status = server.get("status_code", "???")

            url = server.get("url", "")

            title = server.get("title", "No title")[:50]

            print(f"{Fore.GREEN}- {url} [{status}] - {title}{Style.RESET_ALL}")

        if len(web_servers) > 10:

            print(f"{Fore.YELLOW}...and {len(web_servers)-10} more{Style.RESET_ALL}")

        base_filename = os.path.join(self.output_dir, f"{self.domain}_{self.timestamp}")

        print(f"\n{Fore.CYAN}Results saved to:{Style.RESET_ALL}")

        print(f"{Fore.GREEN}- JSON: {base_filename}.json{Style.RESET_ALL}")

        print(f"{Fore.GREEN}- CSV: {base_filename}.csv{Style.RESET_ALL}")

        print(f"{Fore.GREEN}- Log: {base_filename}.log{Style.RESET_ALL}")

        print(f"{Fore.GREEN}- HTML: {base_filename}.html{Style.RESET_ALL}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


    def save_results(self):

        base_filename = os.path.join(self.output_dir, f"{self.domain}_{self.timestamp}")

        json_file = f"{base_filename}.json"

        with open(json_file, "w", encoding="utf-8") as f:

            json.dump(self.results, f, indent=4, default=str)

        logging.info(f"{Fore.GREEN}[+] Results saved to JSON: {json_file}{Style.RESET_ALL}")

        if self.results:

            csv_file = f"{base_filename}.csv"

            try:

                flattened_results = []

                for result in self.results:

                    flat_result = {}

                    for key, value in result.items():

                        if isinstance(value, dict):

                            for subkey, subvalue in value.items():

                                flat_result[f"{key}_{subkey}"] = str(subvalue)

                        else:

                            flat_result[key] = str(value)

                    flattened_results.append(flat_result)

                keys = set()

                for result in flattened_results:

                    keys.update(result.keys())

                with open(csv_file, "w", newline="", encoding="utf-8") as f:

                    writer = csv.DictWriter(f, fieldnames=sorted(keys))

                    writer.writeheader()

                    for result in flattened_results:

                        writer.writerow({k: result.get(k, "") for k in keys})

                logging.info(f"{Fore.GREEN}[+] Results saved to CSV: {csv_file}{Style.RESET_ALL}")

            except Exception as e:

                logging.error(f"{Fore.RED}[-] Error saving CSV: {e}{Style.RESET_ALL}")


def check_requirements():
    required_modules = ["requests", "dns.resolver", "tqdm", "colorama", "urllib3", "yaml", "jinja2"]
    missing_modules = []
    
    for module in required_modules:
        try:
            if "." in module:
                parent, child = module.split(".", 1)
                parent_module = __import__(parent)
                # Check if the submodule is available
                if not hasattr(parent_module, child.split(".")[0]):
                    missing_modules.append(module)
            else:
                __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"Missing dependencies: {', '.join(missing_modules)}")
        print("Please install all dependencies with: pip install requests dnspython tqdm colorama urllib3 pyyaml jinja2")
        return False
    
    return True


def main():

    print(BANNER)

    if not check_requirements():

        return


    parser = argparse.ArgumentParser(description="Scan domains and subdomains associated with a given domain")

    parser.add_argument("-d", "--domain", help="Target domain to scan")

    parser.add_argument("-o", "--output", help="Output directory for scan results")

    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")

    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")

    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds")

    parser.add_argument("--scan-ports", action="store_true", help="Scan ports")

    parser.add_argument("--ports", help="Comma-separated list of ports to scan (e.g. 80,443,8080)")

    parser.add_argument("--wordlist", help="Path to subdomain wordlist file")

    parser.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds")

    parser.add_argument("--no-dns", action="store_true", help="Skip DNS record checks")

    parser.add_argument("--proxy", help="Use proxy for requests (e.g., http://127.0.0.1:8080)")

    parser.add_argument("--retries", type=int, default=3, help="Maximum number of retries for failed requests")

    parser.add_argument("--config", help="Path to YAML configuration file")

    parser.add_argument("--nuclei-templates", help="Path to directory containing custom nuclei templates")

    args = parser.parse_args()


    domain = args.domain

    if not domain and not args.config:

        domain = input(f"{Fore.YELLOW}Enter the domain to scan (e.g., example.com): {Style.RESET_ALL}")


    custom_ports = None

    if args.ports:

        try:

            custom_ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]

        except ValueError:

            print(f"{Fore.RED}Invalid ports format. Use comma separated integers (e.g. 80,443).{Style.RESET_ALL}")

            return


    try:

        scanner = DomainScanner(

            domain=domain,

            output_dir=args.output,

            verbose=args.verbose,

            threads=args.threads,

            timeout=args.timeout,

            scan_ports=args.scan_ports,

            check_dns=not args.no_dns,

            use_wordlist=args.wordlist,

            delay=args.delay,

            use_proxy=args.proxy,

            max_retries=args.retries,

            custom_ports=custom_ports,

            config_file=args.config,

            nuclei_templates=args.nuclei_templates

        )

        scanner.scan_domains()

    except ValueError as e:

        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    except KeyboardInterrupt:

        print(f"\n{Fore.YELLOW}Scan interrupted by user. Partial results may have been saved.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()