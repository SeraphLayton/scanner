import sys
import dns.resolver
import nmap
import requests
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

def find_subdomains(target, wordlist_path, save_to_file):
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

        if save_to_file:
            filename = f"results_{target}_dns.txt"
            with open(filename, 'w') as file:
                sys.stdout = file
                for subdomain in found_subdomains:
                    print(f"Found Subdomain: {subdomain}")
            sys.stdout = sys.__stdout__

        return found_subdomains
    except Exception as e:
        print(Fore.RED + f"An error occurred during subdomain enumeration: {e}" + Style.RESET_ALL)
        return []

def nmap_scan(target, ports, save_to_file):
    try:
        output_data = []

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
                                    output_data.append(f"{scanned_port} - State: {state}, {service_info}")
                                if scripts:
                                    output_data.append("Scripts:")
                                    for script_name, script_output in scripts.items():
                                        output_data.append(f"  {script_name}:")
                                        output_data.append(f"    {script_output}")

        if save_to_file:
            filename = f"results_{target}_ports.txt"
            with open(filename, 'w') as file:
                for line in output_data:
                    file.write(line + '\n')

    except Exception as e:
        print(Fore.RED + f"An error occurred during port scanning: {e}" + Style.RESET_ALL)
        
        
def vhost_enumeration(target, wordlist_path, save_to_file):
    try:
        subdomains = load_wordlist(wordlist_path)

        found_vhosts = []

        for subdomain in subdomains:
            headers = {'Host': f"{subdomain}.{target}"}
            url = f"http://{target}"  # Assuming you want to target the base domain

            response = requests.get(url, headers=headers, allow_redirects=False)
            if response.status_code == 200:  # change if needed 
                found_vhosts.append(f"{subdomain}.{target}")
                print(Fore.GREEN + f"Found VHost: {subdomain}.{target} - Response Code: {response.status_code}" + Style.RESET_ALL)
            elif response.status_code == 301 or response.status_code == 302: 
                found_vhosts.append(f"{subdomain}.{target}")
                print(Fore.GREEN + f"Redirect found, possible vhost at: {subdomain}.{target} - Response Code: {response.status_code}" + Style.RESET_ALL)
            #elif response.status_code == 404: 
            #    print(Fore.RED + f"Vhost not found: {subdomain}.{target} - Response Code: {response.status_code}" + Style.RESET_ALL)    # <- More verbose
            elif response.status_code != 404:
                print(Fore.YELLOW + f"Interesting Status code: {subdomain}.{target} - Response Code: {response.status_code}" + Style.RESET_ALL)

        if save_to_file:
            filename = f"results_{target}_vhosts.txt"
            with open(filename, 'w') as file:
                for vhost in found_vhosts:
                    file.write(f"Found VHost: {vhost} - Response Code: {response.status_code}\n")

        return found_vhosts
    except Exception as e:
        print(Fore.RED + f"An error occurred during VHost enumeration: {e}" + Style.RESET_ALL)
        return [] 


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
    print("2. Port Scan")
    print("3. Vhost scan" + Style.RESET_ALL)
    choice = input("Enter your choice (1,2 or 3): ")
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
        port_input = input("Enter port(s) separated by commas or a port range (e.g. 22 or 80,443 or 1-1024): ")
        return target, port_input
    except KeyboardInterrupt:
        print(Fore.RED + "\nUser interrupted the input process." + Style.RESET_ALL)
        return None, None
        
def get_user_input_vhost():
    try:
        target = input("Enter the target domain: ")
        wordlist_path = input("Enter the wordlist file path: ")
        return target, wordlist_path
    except KeyboardInterrupt:
        print(Fore.RED + "\nUser interrupted the input process." + Style.RESET_ALL)
        return None, None
    

def ask_to_save():
    while True:
        save_option = input("Do you want to save the results to a file? (yes/no): ").lower()
        if save_option in ['yes', 'no']:
            return True if save_option == 'yes' else False
        else:
            print(Fore.RED + "Please enter 'yes' or 'no'." + Style.RESET_ALL)

try:
    choice = get_user_choice()

    if choice == '1':
        target, wordlist_path = get_user_input_dns()
        if target is not None and wordlist_path is not None:
            save_to_file = ask_to_save()
            found_subdomains = find_subdomains(target, wordlist_path, save_to_file)
    elif choice == '2':
        target, port_input = get_user_input_port()
        if target is not None and port_input is not None:
            save_to_file = ask_to_save()
            ports = parse_ports(port_input)
            nmap_scan(target, ports, save_to_file)
    elif choice == '3':
        target, wordlist_path = get_user_input_vhost()
        if target is not None and wordlist_path is not None:
            save_to_file = ask_to_save()
            vhost_enumeration(target, wordlist_path, save_to_file)
    else:
        print(Fore.RED + "Invalid choice! Please select either '1' or '2' or '3'." + Style.RESET_ALL)
except ValueError as ve:
    print(Fore.RED + f"Error: {ve}" + Style.RESET_ALL)
except Exception as e:
    print(Fore.RED + f"An error occurred: {e}" + Style.RESET_ALL)
