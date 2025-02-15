import nmap

def scan_network(ip_range):
    nm = nmap.PortScanner()
    nm.scan(ip_range, arguments='-sn')  # -sn for ping scan (no port scan)

    devices = []
    for host in nm.all_hosts():
        devices.append({'ip': host, 'state': nm[host].state()})

    return devices

if __name__ == "__main__":
    ip_range = "192.168.1.0/24"  # Change this to your network range
    devices = scan_network(ip_range)

    print("Available devices in the network:")
    for device in devices:
        print(f"IP: {device['ip']}, State: {device['state']}")
        speak(f"IP: {device['ip']}, State: {device['state']}")


        
