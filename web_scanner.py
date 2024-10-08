from dotenv import load_dotenv
import subprocess, sys, os, re

load_dotenv()
DOMAIN_PATTERN = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}(?:\.[a-zA-Z]{2,})?'
DIR_DICTIONARY = os.getenv("DIR_DICTIONARY")
VHOST_DICTIONARY = os.getenv("VHOST_DICTIONARY")

class WebScanner:
    def __init__(self, target):
        self.target = target
        self.threads = "40" 

    def change_target(self,target):
        self.target = target

    def directory_scanner(self, port_list):
        all_results = {}
        self.wordlist = DIR_DICTIONARY

        for port in port_list:
            if port == 80:
                host = f"http://{self.target}"
            else:
                host = f"http://{self.target}:{port}"
            
            print(f"\nNow scanning {host}")
            command = [
                "gobuster",
                "dir",
                "-u", host,
                "-w", self.wordlist,
                "-t", self.threads,
                "-q"
            ]

            try:
                results = self.run_gobuster(command)
                if results:
                    all_results[port] = results
                else:
                    print(f"No results found for {host}")
            except subprocess.CalledProcessError as e:
                error = e.stderr.strip()
                if "Error: the server returns a status code that matches the provided options for non existing urls" in error:
                    match = re.search(r'=> (\d+) \(Length: (\d+)\)', error)
                    if match:
                        status_code, length = match.groups()
                        print(f"Gobuster encountered a false positive issue. Status code: {status_code}, Length: {length}")
                        print("Rerunning Gobuster with adjusted parameters...")
                        adjusted_command = command + ['-b', status_code, '--exclude-length', length]
                        try:
                            results = self.run_gobuster(adjusted_command)
                            if results:
                                all_results[port] = results
                            else:
                                print(f"No results found for {host} after adjustment")
                        except Exception as e2:
                            print(f"Error in adjusted Gobuster run: {str(e2)}", file=sys.stderr)
                    else:
                        print("Couldn't parse Gobuster error message.")
                else:
                    print(f"Error running Gobuster: {error}", file=sys.stderr)
            except Exception as e:
                print(f"Unexpected error running Gobuster for {host}: {str(e)}", file=sys.stderr)

        return all_results

    def vhost_scanner(self, domain):
        host = "http://"+self.target
        self.wordlist = VHOST_DICTIONARY
        command = [
                "gobuster",
                "vhost",
                "-u",host,
                "-w",self.wordlist,
                "--append-domain",
                "--domain",domain,
                "-t", self.threads,
                "-q"
            ]

        try:
            results = self.run_gobuster(command)
            return results
        except subprocess.CalledProcessError as e:
            error = e.stderr.strip()
            print(error)
        

    def run_gobuster(self, command):
        results = []
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

            for line in process.stdout:
                line = line.strip()
                # print(line)  # Print each line as it comes in
                if line.strip():  # This will exclude empty lines
                    if line.startswith("Found: "):
                        # Handle the "Found: " format
                        _, url, status_size = line.split(None, 2)
                        results.append(f"{url} {status_size}")
                    else:
                        # Handle the original format
                        results.append(line)
            process.wait()
            
            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, command, process.stderr.read())
            
        except subprocess.CalledProcessError as e:
            raise e
        except Exception as e:
            print(f"Error in Gobuster subprocess: {str(e)}", file=sys.stderr)
        
        return results

    def extract_domain(self,input_string):
        domain_regex = re.compile(DOMAIN_PATTERN)
        match = re.search(domain_regex, input_string)
    
        if match:
            return match.group(0)
    
        return None

    def clean_gobuster_directories(self,output_dict):
        cleaned_results = {}
        for port, results in output_dict.items():
            unique_results = set()
            for result in results:
                # Remove ANSI escape codes
                cleaned = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', result)
                # Strip whitespace
                cleaned = cleaned.strip()
                # Extract the path, status, size, and redirection
                match = re.match(r'(/[^\s]+)\s+\(Status: (\d+)\)\s+\[Size: (\d+)\](\s+\[--> (.+)])?', cleaned)
                if match:
                    path, status, size, _, redirect = match.groups()
                    redirect_info = f" --> {redirect}" if redirect else ""
                    unique_results.add(f"{path} (Status: {status}) [Size: {size}]{redirect_info}")
            cleaned_results[port] = sorted(list(unique_results))
        return cleaned_results


    def clean_gobuster_vhosts(self,output_list):
        cleaned_results = []
        for line in output_list:
            # Remove ANSI escape codes and strip whitespace
            cleaned = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line).strip()
            # Remove "Found: " prefix if present
            if cleaned.startswith("Found: "):
                cleaned = cleaned[7:]
            # Add the cleaned line to the results
            cleaned_results.append(cleaned)

        # Remove duplicates and sort
        return sorted(set(cleaned_results))