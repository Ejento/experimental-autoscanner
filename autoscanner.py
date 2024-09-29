import argparse
import re
import subprocess, nmap, sys 

# Static Variables
VHOST_DICTIONARY = "/home/george/Git/SecLists/Discovery/DNS/namelist.txt"
DIR_DICTIONARY = "/home/george/Git/SecLists/Discovery/Web-Content/quickhits.txt"
DIR_DICTIONARY = "/home/george/Git/SecLists/Discovery/Web-Content/raft-medium-directories.txt"

def scan_all_ports(target,verbose=False):
    nm = nmap.PortScanner()
    
    if verbose:
        print(f"Scanning target: {target} , -p- -sT -T4")
        
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
    # pattern = r'\d+\.\d+\.\d+\.\d+,\s*\d+,\s*Did not follow redirect to http://([a-zA-Z0-9.-]+)'
    pattern = r'Did not follow redirect to http://([a-zA-Z0-9.-]+)'
    match = re.search(pattern, input_string)
    
    if match:
        return match.group(1)
    
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
            # print(f"\nDirectories found: {results.stdout}")
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
        print(f"\nDirectories found: {results.stdout}")
        # return results.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running Gobuster (exit code {e.returncode}):")
        print(f"Command: {e.cmd}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")


# Main logic
parser = argparse.ArgumentParser(description="Nmap Port Scanner")
parser.add_argument("target", help="Target IP address or hostname")
#parser.add_argument("-p", "--ports", default="1-1000", help="Port range to scan (default: 1-1000)")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

args = parser.parse_args()

[step1_ports,step1_tech] = scan_all_ports(args.target, args.verbose)
print("="*30+"\n")
services = scan_port_services(args.target, step1_ports, args.verbose)
print("="*30)

http_ports = []

for ip, ports in services.items():
    for port, info in ports.items():
        if info['name'] == 'http' and 'scripts' in info:
            if 'http-title' in info['scripts']:
                http_ports.append(port)     
                domain = extract_domain(" ".join({info['scripts']['http-title']}))
            
input(f"You should go and add the {domain}, for the IP address {args.target}, in your /etc/hosts file.\nDid you do it?[Y/n]")
# directory_scanner("editorial.htb",http_ports,DIR_DICTIONARY)
http_directories = directory_scanner(domain, http_ports, DIR_DICTIONARY)
print(http_directories)
test_run = subdomain_scanner(args.target, domain, VHOST_DICTIONARY)
# print(test_run)
exit(0)