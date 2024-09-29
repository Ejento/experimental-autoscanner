import argparse
import sys
import nmap

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
        print(nm.scan(target, arguments=f'-p {port_list} -sC -sV'))
    except nmap.PortScannerError as e:
        print(f"Error occured during scan: {e}")
        sys.exit(1)

    for host in nm.all_hosts():
        if verbose:
            print(f"IP or host: {host}")

        for protocol in nm[host].all_protocols():
            if verbose:
                print(f"Protocol: {protocol}")

            port_keys = nm[host][protocol].keys()
            for port in port_keys:
                name = nm[host][protocol][port]['name']
                product = nm[host][protocol][port]['product']
                version = nm[host][protocol][port]['version']
                extraInfo = nm[host][protocol][port]['extrainfo']
                for i in nm[host][protocol][port]['script']:
                    print(f"For {port} the sripts are: {i}")



parser = argparse.ArgumentParser(description="Nmap Port Scanner")
parser.add_argument("target", help="Target IP address or hostname")
#parser.add_argument("-p", "--ports", default="1-1000", help="Port range to scan (default: 1-1000)")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

args = parser.parse_args()

[step1_ports,step1_tech] = scan_all_ports(args.target, args.verbose)
print("="*30)
scan_port_services(args.target, step1_ports, args.verbose)

exit(0)