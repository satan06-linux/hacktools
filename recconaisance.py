import whois
import requests
import socket

def get_domain_info(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        print(f"Error retrieving domain info: {e}")
        return None

def get_ip_info(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        return response.json()
    except Exception as e:
        print(f"Error retrieving IP info: {e}")
        return None

def scan_ports(target, start_port=1, end_port=1024):
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

if __name__ == "__main__":
    print("Automated Reconnaissance-Tool")
    
    # Get domain information
    domain = input("Enter a domain name (e.g., example.com or google.com): ")
    domain_info = get_domain_info(domain)
    if domain_info:
        print("\nDomain Information: ")
        print(domain_info)

    # Get IP information
    ip = input("\nEnter an IP address (or leave blank to use the domain's IP): ")
    if not ip:
        ip = socket.gethostbyname(domain)
    ip_info = get_ip_info(ip)
    if ip_info:
        print("\nIP Information:")
        print(ip_info)

    # Scan ports
    target = input("\nEnter a target IP address to scan for open ports: ")
    open_ports = scan_ports(target)
    print("\nOpen Ports:")
    for port in open_ports:
        print(f"Port {port} is open")
