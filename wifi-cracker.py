import pywifi # pip install pywifi
from pywifi import const
import time # pip install time

def scan_wifi_networks():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    iface.scan()
    time.sleep(2)  # Wait for the scan to complete
    scan_results = iface.scan_results()
    return scan_results

def display_networks(networks):
    print("Available Wi-Fi networks:")
    for i, network in enumerate(networks):
        print(f"{i}: SSID: {network.ssid}, BSSID: {network.bssid}")

def crack_wifi_password(ssid):
    # This is a placeholder function. In a real scenario, you would use a tool like aircrack-ng.
    print(f"Attempting to crack the password for network: {ssid}")
    # Simulate cracking process
    time.sleep(1)
    file_path = "" # enter the file  path in between the "" you have to enter the txt file which has all types of password
    crack_wifi_password(ssid, file_path)
def main():
    networks = scan_wifi_networks()
    if not networks:
        print("No networks found.")
        return

    display_networks(networks)

    choice = input("Enter the number of the network you want to crack the password for (or 'q' to quit): ")
    if choice.lower() == 'q':## based in input it will crack the wifi that selected by user
        print("Exiting program.")
        return

    try:
        network_index = int(choice)
        if 0 <= network_index < len(networks):
            network = networks[network_index]
            crack_wifi_password(network.ssid)
        else:
            print("Invalid choice.") # exceptional case 
    except ValueError:
        print("Invalid input.")

if __name__ == "__main__":
    main()
