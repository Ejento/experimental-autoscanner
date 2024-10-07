import argparse
import re, time
from web_scanner import WebScanner
from port_scanner import NetScanner

# Static Variables
IPV4_PATTERN = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
DOMAIN_PATTERN = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}(?:\.[a-zA-Z]{2,})?'


# Main logic
parser = argparse.ArgumentParser(description="Nmap Port Scanner")
parser.add_argument("target", help="Target IP address or hostname")
#parser.add_argument("-p", "--ports", default="1-1000", help="Port range to scan (default: 1-1000)")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

args = parser.parse_args()
ipv4_regex = re.compile(IPV4_PATTERN)

nmap_scanner = NetScanner(args.target)

[step1_ports,step1_tech] = nmap_scanner.scan_all_ports(args.target, args.verbose)
print("="*100+"\n")
services = nmap_scanner.scan_port_services(args.target, step1_ports, args.verbose)
print("="*100)

http_ports = []
gobuster_scanner = WebScanner(args.target)

for ip, ports in services.items():
    for port, info in ports.items():
        if info['name'] == 'http' and 'scripts' in info:
            if 'http-title' in info['scripts']:
                http_ports.append(port)
                if ipv4_regex.match(args.target):
                    domain = gobuster_scanner.extract_domain(" ".join({info['scripts']['http-title']}))
                else:
                    domain = args.target

if ipv4_regex.match(args.target):
    answer = "n"
else:
    answer = "y"
while answer.lower() != "y":
    answer = input(f"You should go and add the {domain}, for the IP address {args.target}, in your /etc/hosts file.\nDid you do it? [Y/n] ")
    time.sleep(1)    

http_directories = gobuster_scanner.directory_scanner(http_ports)
http_directories = gobuster_scanner.clean_gobuster_directories(http_directories)

for port, results in http_directories.items():
    print(f"Results for port {port}:")
    for result in results:
        print(result)

print("-"*100)

print(f"Scanning for subdomains of the {domain} domain.")
subdomains_list = gobuster_scanner.vhost_scanner(domain)
subdomains_list = gobuster_scanner.clean_gobuster_vhosts(subdomains_list)

for result in subdomains_list:
    print(result)

exit(0)