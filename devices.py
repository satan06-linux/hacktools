from scapy.all import ARP, Ether, srp
import socket

def get_device_info(ip):#it is used scan our surroundings
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "Unknown"
    return hostname

def scan_network(ip_range):#it is ip scan
    # Create an ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the packet and receive the response
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        hostname = get_device_info(ip)
        devices.append({'ip': ip, 'mac': mac, 'hostname': hostname})

    return devices

if __name__ == "__main__":
    # Define the IP range to scan (e.g., "192.168.1.1/24")
    ip_range = "192.168.1.1/24"

    print(f"Scanning network {ip_range}...")
    devices = scan_network(ip_range)

    print("\nFound devices:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}")
