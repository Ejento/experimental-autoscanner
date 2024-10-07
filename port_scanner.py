import nmap, sys

class NetScanner:
    def __init__(self,target,verbose=True):
        self.target = target
        self.verbose = verbose

    def scan_all_ports(self,target,verbose):
        nm = nmap.PortScanner()
        if self.verbose:
            print(f"Scanning target: {self.target} ,y -p- -sT -T4")
            
        try:
            nm.scan(self.target, arguments=f'-p- -sT -T4')
        except nmap.PortScannerError as e:
            print(f"Error occured during scan: {e}")
            sys.exit(1)

        open_ports = []
        possible_tech = []
        
        for host in nm.all_hosts():
            if self.verbose:
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


    def scan_port_services(self,target,port_list,verbose):
        nm = nmap.PortScanner()
        port_list = ",".join(str(i) for i in port_list)

        if verbose:
            print(f"Scanning target: {self.target} , -p {port_list} -sC -sV")

        try:
            nm.scan(self.target, arguments=f'-p {port_list} -sC -sV')
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