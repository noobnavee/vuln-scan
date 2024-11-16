import requests
import socket
import ssl
import datetime
import nmap
import whois
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
import json
import os
from colorama import Fore, Style, init

init()  # Initialize colorama

class WebSecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.scan_results = {}
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

    def generate_report_header(self):
        return f"""
{'='*80}
WEBSITE SECURITY SCAN REPORT
{'='*80}
Target URL: {self.target_url}
Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*80}
"""

    def check_ssl_certificate(self):
        try:
            hostname = self.target_url.split('://')[1].split('/')[0]
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.connect((hostname, 443))
                cert = s.getpeercert()
                
                self.scan_results['ssl'] = {
                    'valid': True,
                    'expiry': cert['notAfter'],
                    'issuer': dict(x[0] for x in cert['issuer'])
                }
        except Exception as e:
            self.scan_results['ssl'] = {
                'valid': False,
                'error': str(e)
            }
            self.vulnerabilities.append("SSL Certificate Issues Detected")

    def check_http_headers(self):
        try:
            r = requests.head(self.target_url, headers=self.headers)
            headers = r.headers
            
            security_headers = {
                'Strict-Transport-Security': False,
                'X-Frame-Options': False,
                'X-XSS-Protection': False,
                'X-Content-Type-Options': False,
                'Content-Security-Policy': False
            }

            for header in security_headers.keys():
                if header in headers:
                    security_headers[header] = True
                else:
                    self.vulnerabilities.append(f"Missing Security Header: {header}")

            self.scan_results['security_headers'] = security_headers

        except Exception as e:
            self.scan_results['security_headers'] = {'error': str(e)}

    def check_open_ports(self):
        try:
            nm = nmap.PortScanner()
            hostname = self.target_url.split('://')[1].split('/')[0]
            nm.scan(hostname, '21-443')
            
            open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        if nm[host][proto][port]['state'] == 'open':
                            open_ports.append({
                                'port': port,
                                'service': nm[host][proto][port]['name']
                            })
            
            self.scan_results['open_ports'] = open_ports
            if len(open_ports) > 0:
                self.vulnerabilities.append(f"Found {len(open_ports)} open ports")

        except Exception as e:
            self.scan_results['open_ports'] = {'error': str(e)}

    def check_whois_info(self):
        try:
            hostname = self.target_url.split('://')[1].split('/')[0]
            w = whois.whois(hostname)
            self.scan_results['whois'] = {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date
            }
        except Exception as e:
            self.scan_results['whois'] = {'error': str(e)}

    def generate_report(self):
        report = self.generate_report_header()
        
        # Add vulnerability summary
        report += f"\n{Fore.RED}VULNERABILITIES FOUND: {len(self.vulnerabilities)}{Style.RESET_ALL}\n"
        for vuln in self.vulnerabilities:
            report += f"• {vuln}\n"

        # Add detailed results
        report += f"\n{Fore.BLUE}DETAILED SCAN RESULTS{Style.RESET_ALL}\n"
        
        # SSL Certificate
        report += "\nSSL Certificate Info:\n"
        ssl_info = self.scan_results.get('ssl', {})
        if ssl_info.get('valid'):
            report += f"✓ Valid SSL Certificate\n"
            report += f"  Expiry: {ssl_info['expiry']}\n"
        else:
            report += f"✗ SSL Certificate Issues: {ssl_info.get('error', 'Unknown error')}\n"

        # Security Headers
        report += "\nSecurity Headers:\n"
        headers = self.scan_results.get('security_headers', {})
        for header, present in headers.items():
            if isinstance(present, bool):
                report += f"{'✓' if present else '✗'} {header}\n"

        # Open Ports
        report += "\nOpen Ports:\n"
        ports = self.scan_results.get('open_ports', [])
        if isinstance(ports, list):
            for port in ports:
                report += f"• Port {port['port']}: {port['service']}\n"

        # WHOIS Information
        report += "\nWHOIS Information:\n"
        whois_info = self.scan_results.get('whois', {})
        for key, value in whois_info.items():
            report += f"• {key}: {value}\n"

        # Recommendations
        report += f"\n{Fore.GREEN}RECOMMENDATIONS{Style.RESET_ALL}\n"
        if self.vulnerabilities:
            for vuln in self.vulnerabilities:
                if "Security Header" in vuln:
                    report += "• Implement missing security headers in server configuration\n"
                if "open ports" in vuln.lower():
                    report += "• Review and close unnecessary open ports\n"
                if "SSL Certificate" in vuln:
                    report += "• Update or fix SSL certificate configuration\n"

        return report

    def run_scan(self):
        print(f"{Fore.YELLOW}Starting security scan...{Style.RESET_ALL}")
        
        # Run all checks
        self.check_ssl_certificate()
        self.check_http_headers()
        self.check_open_ports()
        self.check_whois_info()
        
        # Generate and save report
        report = self.generate_report()
        
        # Save report to file
        filename = f"security_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(report)
            
        print(f"\n{Fore.GREEN}Scan completed! Report saved to {filename}{Style.RESET_ALL}")
        print(report)

def main():
    try:
        target_url = input("Enter the target URL (including http:// or https://): ")
        scanner = WebSecurityScanner(target_url)
        scanner.run_scan()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()

