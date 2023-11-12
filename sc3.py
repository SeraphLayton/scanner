import sys
import dns.resolver
import nmap
from colorama import init, Fore, Style

init()

banner = """ 
┓          
┃ ┏┓┓┏╋┏┓┏┓
┗┛┗┻┗┫┗┗┛┛┗
     ┛ 
"""

def load_wordlist(wordlist_path):
    try:
        with open(wordlist_path, 'r') as file:
            subdomains = [line.strip() for line in file.readlines()]
        return subdomains
    except FileNotFoundError:
        print(Fore.RED + f"Wordlist file not found at: {wordlist_path}" + Style.RESET_ALL)
        return []

def find_subdomains(target, wordlist_path):
    try:
        subdomains = load_wordlist(wordlist_path)

        found_subdomains = []

        for subdomain in subdomains:
            full_domain = f"{subdomain}.{target}"
            try:
                answers = dns.resolver.query(full_domain, 'A')
                for answer in answers:
                    found_subdomains.append(full_domain)
                    print(Fore.GREEN + f"Found Subdomain: {full_domain} - IP: {answer}" + Style.RESET_ALL)
            except dns.resolver.NXDOMAIN:
                print(Fore.RED + f"Subdomain not found: {full_domain}" + Style.RESET_ALL)
            except dns.resolver.NoAnswer:
                print(Fore.RED + f"No A records found for {full_domain}" + Style.RESET_ALL)

        return found_subdomains
    except Exception as e:
        print(Fore.RED + f"An error occurred during subdomain enumeration: {e}" + Style.RESET_ALL)
        return []

def nmap_scan(target, port):
    print(f"Scanning port: {port}")  # (<- more verbose)
    nm = nmap.PortScanner()
    nm.scan(target, arguments=f'-sC -sV -T5 -p {port}')  # Make adjustments if needed!
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for scanned_port in lport:
                if int(scanned_port) == port:
                    state = nm[host][proto][scanned_port]['state']
                    if state in ['open', 'filtered']:
                        print(Fore.CYAN + f"Port: {scanned_port} - State: {state}" + Style.RESET_ALL)
                        service = nm[host][proto][scanned_port]['name']
                        product = nm[host][proto][scanned_port]['product']
                        version = nm[host][proto][scanned_port]['version']
                        cpe = nm[host][proto][scanned_port]['cpe']
                        scripts = nm[host][proto][scanned_port].get('script')
                        if service:
                            service_info = f"Service: {service} ({product})"
                            if version:
                                service_info += f" Version: {version}"
                            if cpe:
                                service_info += f" CPE: {cpe}"
                            print(Fore.YELLOW + f"{service_info}" + Style.RESET_ALL)
                        if scripts:
                            print(Fore.YELLOW + "Scripts:")
                            for script_name, script_output in scripts.items():
                                print(Fore.YELLOW + f"  {script_name}:")
                                print(Fore.YELLOW + f"    {script_output}" + Style.RESET_ALL)
                        print()
                        print(f" ---------------------------------------------------------------------------------- ")

def parse_ports(port_arg):
    if '-' in port_arg:
        port_range = port_arg.split('-')
        return list(range(int(port_range[0]), int(port_range[1]) + 1))
    elif ',' in port_arg:
        return list(map(int, port_arg.split(',')))
    else:
        return [int(port_arg)]

def get_port_list():
    if '-p' in sys.argv:
        port_index = sys.argv.index('-p') + 1
        return parse_ports(sys.argv[port_index])
    else:
        return [i for i in range(1, 65536)]  # Make adjustments if needed!

def display_usage():
    print(banner)
    print(Fore.YELLOW + "Usage: " + Fore.MAGENTA + "python script_name.py " + Fore.GREEN + "<target IP/domain> " + Fore.BLUE + " -p <port(s)>" + Style.RESET_ALL)
    print(Fore.YELLOW + "Example: " + Fore.MAGENTA + "python script_name.py " + Fore.GREEN + "8.8.8.8 " + Fore.BLUE + "-p 53 " + Style.RESET_ALL)

try:
    target = sys.argv[1]
    wordlist_path = sys.argv[2]
    ports = get_port_list()

    found_subdomains = find_subdomains(target, wordlist_path)

    for port in ports:
        nmap_scan(target, port)

except Exception as e:
    print(Fore.RED + f"An error occurred during the scan: {e}" + Style.RESET_ALL)
    display_usage()
