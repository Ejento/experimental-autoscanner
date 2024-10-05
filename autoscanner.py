import argparse
import re, time
import subprocess, nmap, sys 

# Static Variables
VHOST_DICTIONARY = "/home/george/Git/SecLists/Discovery/DNS/namelist.txt"
# DIR_DICTIONARY = "/home/george/Git/SecLists/Discovery/Web-Content/quickhits.txt"
DIR_DICTIONARY = "/home/george/Git/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
IPV4_PATTERN = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
DOMAIN_PATTERN= r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}(?:\.[a-zA-Z]{2,})?'

def scan_all_ports(target,verbose=False):
    nm = nmap.PortScanner()
    if verbose:
        print(f"Scanning target: {target} ,y -p- -sT -T4")
        
    try:
        nm.scan(target, arguments=f'-p- -sT -T4')
    except nmap.PortScannerError as e:
        print(f"Error occured during scan: {e}")
        sys.exit(1)

    open_ports = []
    possible_tech = []
    
    for host in nm.all_hosts():
        if verbose:
            print(f"IP or host: {host}")
        
        for protocol in nm[host].all_protocols():
            if verbose:
                print(f"Protocol: {protocol}")

            port_keys = nm[host][protocol].keys()
            for port in port_keys:
                state = nm[host][protocol][port]['state']
                name = nm[host][protocol][port]['name']
                if state == 'open':
                    open_ports.append(port)
                    possible_tech.append(name)
                    if verbose:
                        print(f"The port {port} is {state}. Possible technology: {name}")

    return [open_ports, possible_tech]


def scan_port_services(target,port_list,verbose=False):
    nm = nmap.PortScanner()
    port_list = ",".join(str(i) for i in port_list)

    if verbose:
        print(f"Scanning target: {target} , -p {port_list} -sC -sV")

    try:
        nm.scan(target, arguments=f'-p {port_list} -sC -sV')
    except nmap.PortScannerError as e:
        print(f"Error occured during scan: {e}")
        sys.exit(1)

    all_port_info = {}

    for host in nm.all_hosts():
        if verbose:
            print(f"IP or host: {host}")

        for protocol in nm[host].all_protocols():
            if verbose:
                print(f"Protocol: {protocol}")

            port_keys = nm[host][protocol].keys()
            
            all_port_info[host] = {
                port: {
                    'name': nm[host][protocol][port]['name'],
                    'product': nm[host][protocol][port]['product'],
                    'version': nm[host][protocol][port]['version'],
                    'extraInfo': nm[host][protocol][port]['extrainfo'],
                    'scripts': nm[host][protocol][port]['script']
                }
                for port in port_keys
            }

            if verbose:
                for port, info in all_port_info[host].items():
                    print(f"Port: {port}")
                    print(f"Name: {info['name']}")
                    print(f"Product: {info['product']}")
                    print(f"Version: {info['version']}")
                    print(f"Extra Info: {info['extraInfo']}")
                    for script in info['scripts']:
                        print(f"Script: {script}")
                    print()

    return all_port_info


def extract_domain(input_string):
    domain_regex = re.compile(DOMAIN_PATTERN)
    match = re.search(domain_regex, input_string)
    
    if match:
        return match.group(0)
    
    return None


def directory_scanner(target, port_list, wordlist):
    for port in port_list:
        host = "http://"+target+":"+str(port)
        print(f"\nNow we are scanning the {host}")
        command = [
            "gobuster",
            "dir",
            "-u",host,
            "-w",wordlist,
            "-t",str(40),
            "-q"
        ]
        
        try:
            results = subprocess.run(command, capture_output=True, text=True, check=True)
            return results.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error running Gobuster (exit code {e.returncode}):")
            print(f"Command: {e.cmd}")
            print(f"Stdout: {e.stdout}")
            print(f"Stderr: {e.stderr}")


def subdomain_scanner(target,domain,wordlist):
    host = "http://"+target
    command = [
            "gobuster",
            "vhost",
            "-u",host,
            "-w",wordlist,
            "--append-domain",
            "--domain",domain,
            "-t",str(40),
            "-q"
        ]

    try:
        results = subprocess.run(command, capture_output=True, text=True, check=True)
        return results.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running Gobuster (exit code {e.returncode}):")
        print(f"Command: {e.cmd}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")


def gobuster_list_cleaner(listing):
    cleaned_lines = [line.replace('\x1b[2K', '').strip() for line in listing.split('\n') if line.strip()]
    status_200 = [line for line in cleaned_lines if "Status: 200" in line]
    other_status = [line for line in cleaned_lines if "Status: 200" not in line]
    return status_200, other_status


# Main logic
parser = argparse.ArgumentParser(description="Nmap Port Scanner")
parser.add_argument("target", help="Target IP address or hostname")
#parser.add_argument("-p", "--ports", default="1-1000", help="Port range to scan (default: 1-1000)")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

args = parser.parse_args()
ipv4_regex = re.compile(IPV4_PATTERN)

[step1_ports,step1_tech] = scan_all_ports(args.target, args.verbose)
print("="*60+"\n")
services = scan_port_services(args.target, step1_ports, args.verbose)
print("="*60)

http_ports = []

for ip, ports in services.items():
    for port, info in ports.items():
        if info['name'] == 'http' and 'scripts' in info:
            if 'http-title' in info['scripts']:
                http_ports.append(port)
                if ipv4_regex.match(args.target):
                    domain = extract_domain(" ".join({info['scripts']['http-title']}))
                else:
                    domain = args.target

answer = "n"
while answer.lower() != "y":
    answer = input(f"You should go and add the {domain}, for the IP address {args.target}, in your /etc/hosts file.\nDid you do it? [Y/n] ")
    time.sleep(1)    

http_directories = directory_scanner(domain, http_ports, DIR_DICTIONARY)
dir_status_200, dir_status_other = gobuster_list_cleaner(http_directories)

if dir_status_200 or dir_status_other:
    print(f"\nDirectories with status code 200:")
    for i in dir_status_200:
        print(i)
    print(f"\nDirectories with status code XXX:")
    for i in dir_status_other:
        print(i)
else:
    print(f"\nNot valid directories found for the {domain} domain!")

subdomains_list = subdomain_scanner(args.target, domain, VHOST_DICTIONARY)
sub_status_200, sub_status_other = gobuster_list_cleaner(subdomains_list)

if sub_status_200:
    print(f"The following valid subdomains found for the {domain} domain:\n")
    for i in sub_status_200:
        print(i)
if sub_status_other:
    print(f"\nThe following subdomains with `status code 400` were found for the {domain} domain:")
    for i in sub_status_other:
        print(i)
else:
    print(f"\nNo luck. Try another dictionary!")

exit(0)