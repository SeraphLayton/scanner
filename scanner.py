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

"""
This script can perform an automated nmap scan for single domains and find other subdomains. I use this for hackthebox challenges.
It focuses on flexibility and customization as it is not faster than nmap itself. Future implementations will come along.
The goal is to create a good enumeration tool for hackthebox challenges.

Created by: Layton
GitHub: https://github.com/SeraphLayton
Website: https://seraphlayton.github.io/Website
Year: 2023
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
                answers = dns.resolver.resolve(full_domain, 'A')
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

def nmap_scan(target, ports):
    try:
        for port in ports:
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
    except Exception as e:
            print(Fore.RED + f"An error occurred during port scanning: {e}" + Style.RESET_ALL)

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

def get_user_choice():
    print(banner)
    print(Fore.YELLOW + "Select Scan Type:")
    print(Fore.MAGENTA + "1. DNS Scan")
    print("2. Port Scan" + Style.RESET_ALL)
    choice = input("Enter your choice (1/2): ")
    return choice
    
def get_user_input_dns():
    try:
        target = input("Enter the target IP/domain: ")
        wordlist_path = input("Enter the wordlist file path: ")
        return target, wordlist_path
    except KeyboardInterrupt:
        print(Fore.RED + "\nUser interrupted the input process." + Style.RESET_ALL)
        return None, None
        
def get_user_input_port():
    try:
        target = input("Enter the target IP/domain: ")
        port_input = input("Enter port(s) separated by commas or a port range (e.g., 80,443 or 1-1024): ")
        return target, port_input
    except KeyboardInterrupt:
        print(Fore.RED + "\nUser interrupted the input process." + Style.RESET_ALL)
        return None, None

def display_usage():
    print(banner)
    print(Fore.MAGENTA + "Something went wrong")

try:
    choice = get_user_choice()

    if choice == '1':
        target, wordlist_path = get_user_input_dns()
        if target is not None and wordlist_path is not None:
            found_subdomains = find_subdomains(target, wordlist_path)
    elif choice == '2':
        target, port_input = get_user_input_port()
        if target is not None and port_input is not None:
            ports = parse_ports(port_input)
            nmap_scan(target, ports)
    else:
        print(Fore.RED + "Invalid choice! Please select either '1' or '2'." + Style.RESET_ALL)
        display_usage()

except ValueError as ve:
    print(Fore.RED + f"Error: {ve}" + Style.RESET_ALL)
    display_usage()
except Exception as e:
    print(Fore.RED + f"An error occurred: {e}" + Style.RESET_ALL)
    display_usage()
