from scapy.all import *
import requests
import threading
import time
import logging
from collections import defaultdict
from socket import socket, AF_INET, SOCK_STREAM
import psutil
import os
import subprocess
from ipaddress import ip_address, ip_network

# Configurazione IP e Logging
my_ip = "192.168.1.150"
monitoring_interval = 60  # Secondi tra i controlli
ddos_threshold = 1000
port_scan_threshold = 1000
network_scan_threshold = 200
brute_force_threshold = 10
malware_signatures = ["malicious", "phishing"]
firewall_blacklist = set()
vpn_ip_ranges = [ip_network("192.168.0.0/24")]

logging.basicConfig(filename='network_security.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Funzione per ottenere la posizione geografica dell'IP
def get_location(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data['status'] == 'success':
            lat = data['lat']
            lon = data['lon']
            city = data['city']
            country = data['country']
            google_maps_url = f"https://www.google.com/maps?q={lat},{lon}"
            return f"{city}, {country}", google_maps_url
        else:
            return "Posizione non disponibile", ""
    except Exception as e:
        logging.error(f"Errore nell'ottenere la posizione per l'IP {ip}: {e}")
        return "Errore nell'ottenere la posizione", ""

# Funzione per rilevare e bloccare IP sospetti
def block_ip(ip):
    if ip in firewall_blacklist:
        return
    firewall_blacklist.add(ip)
    logging.info(f"Blocco dell'IP: {ip}")
    # Esempio di comando iptables (Linux)
    # os.system(f"iptables -A INPUT -s {ip} -j DROP")
    # Per Windows, usa netsh o altra configurazione del firewall

# Funzione per rilevare pacchetti sospetti
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        payload_length = len(packet[IP].payload)
        
        if my_ip in (src_ip, dst_ip):
            logging.info(f"[ALERT] Pacchetto sospetto: {src_ip} --> {dst_ip} | Payload: {payload_length} bytes")
            if src_ip != my_ip:
                location, maps_url = get_location(src_ip)
                logging.info(f"L'IP che ha inviato il pacchetto: {src_ip}")
                logging.info(f"Posizione approssimativa: {location}")
                logging.info(f"Google Maps: {maps_url}")
                block_ip(src_ip)  # Blocca l'IP se sospetto

# Funzione per rilevare ARP Spoofing
def detect_arp_spoofing():
    arp_table = {}
    
    def arp_monitor_callback(pkt):
        if ARP in pkt and pkt[ARP].op in (1, 2):
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip in arp_table and arp_table[ip] != mac:
                logging.warning(f"ARP Spoofing rilevato: IP {ip} associato a MAC {mac} (precedentemente {arp_table[ip]})")
            arp_table[ip] = mac

    sniff(prn=arp_monitor_callback, filter="arp", store=0)

# Funzione per rilevare DHCP Spoofing
def detect_dhcp_spoofing():
    dhcp_table = {}
    
    def dhcp_monitor_callback(pkt):
        if DHCP in pkt and pkt[DHCP].options[0][1] == 1:  # DHCP Offer
            ip = pkt[IP].src
            mac = pkt[Ether].src
            if ip in dhcp_table and dhcp_table[ip] != mac:
                logging.warning(f"DHCP Spoofing rilevato: IP {ip} associato a MAC {mac} (precedentemente {dhcp_table[ip]})")
            dhcp_table[ip] = mac

    sniff(prn=dhcp_monitor_callback, filter="udp port 67 or 68", store=0)

# Funzione per monitorare connessioni sospette
def monitor_connections():
    active_connections = defaultdict(int)

    def monitor_callback(pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            active_connections[src_ip] += 1
            active_connections[dst_ip] += 1

            if active_connections[src_ip] > 100 or active_connections[dst_ip] > 100:
                logging.warning(f"Connessione sospetta: {src_ip} -> {dst_ip} | Pacchetti: {active_connections[src_ip]}")
                block_ip(src_ip)  # Blocca l'IP se sospetto

    sniff(prn=monitor_callback, filter="ip", store=0)

# Funzione per rilevare attacchi DDoS
def detect_ddos():
    packet_count = defaultdict(int)
    
    def ddos_callback(pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            packet_count[src_ip] += 1

            if packet_count[src_ip] > ddos_threshold:
                logging.warning(f"Potenziale attacco DDoS da {src_ip} con {packet_count[src_ip]} pacchetti")
                block_ip(src_ip)  # Blocca l'IP se sospetto

    sniff(prn=ddos_callback, filter="ip", store=0)

# Funzione per scansionare le porte
def scan_ports(ip):
    open_ports = []
    
    def scan_port(port):
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(1)
        try:
            result = s.connect_ex((ip, port))
            return result == 0
        except Exception as e:
            logging.error(f"Errore durante la scansione della porta {port} su {ip}: {e}")
            return False
        finally:
            s.close()

    for port in range(1, 65536):
        if scan_port(port):
            open_ports.append(port)
            if len(open_ports) > port_scan_threshold:
                break

    if open_ports:
        logging.warning(f"Porte aperte: {open_ports}")
        block_ip(ip)  # Blocca l'IP se troppi risultati

# Funzione per rilevare scansioni di rete
def detect_network_scans():
    scanned_ips = defaultdict(int)
    
    def network_scan_callback(pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            scanned_ips[src_ip] += 1

            if scanned_ips[src_ip] > network_scan_threshold:
                logging.warning(f"Scansione di rete da {src_ip} con {scanned_ips[src_ip]} pacchetti")
                block_ip(src_ip)  # Blocca l'IP se troppi pacchetti

    sniff(prn=network_scan_callback, filter="ip", store=0)

# Funzione per rilevare tentativi di brute force
def detect_brute_force():
    failed_attempts = defaultdict(int)
    
    def brute_force_callback(pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            payload = str(pkt[IP].payload)
            
            if any(signature in payload for signature in malware_signatures):
                failed_attempts[src_ip] += 1
                
                if failed_attempts[src_ip] > brute_force_threshold:
                    logging.warning(f"Tentativi di brute force da {src_ip}: {failed_attempts[src_ip]}")
                    block_ip(src_ip)  # Blocca l'IP se troppi tentativi

    sniff(prn=brute_force_callback, filter="ip", store=0)

# Funzione per rilevare malware e phishing
def detect_malware_phishing():
    def malware_phishing_callback(pkt):
        if IP in pkt:
            payload = str(pkt[IP].payload)
            if any(signature in payload for signature in malware_signatures):
                src_ip = pkt[IP].src
                logging.warning(f"Malware o phishing rilevato da {src_ip}: {payload}")

    sniff(prn=malware_phishing_callback, filter="ip", store=0)

# Funzione per monitorare l'uso della banda e delle risorse
def monitor_resources():
    def resource_callback():
        while True:
            try:
                cpu_usage = psutil.cpu_percent(interval=1)
                memory_usage = psutil.virtual_memory().percent
                bandwidth_usage = psutil.net_io_counters().bytes_recv + psutil.net_io_counters().bytes_sent
                
                logging.info(f"Uso CPU: {cpu_usage}% | Uso Memoria: {memory_usage}% | Banda: {bandwidth_usage} bytes")
            except Exception as e:
                logging.error(f"Errore durante il monitoraggio delle risorse: {e}")
            time.sleep(monitoring_interval)

    threading.Thread(target=resource_callback, daemon=True).start()

# Funzione per configurare il firewall
def setup_firewall():
    logging.info("Configurazione firewall in corso...")
    # Esempio di comando iptables (Linux)
    # os.system("iptables -A INPUT -j DROP")
    # Per Windows, usa netsh o altra configurazione del firewall
    # subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=\"Block All\"", "dir=in", "action=block"])

# Funzione per configurare VPN
def setup_vpn():
    logging.info("Configurazione VPN...")
    # Esempio di configurazione VPN: dovresti avere una configurazione VPN e client già impostati
    # subprocess.run(["openvpn", "--config", "/path/to/your/vpn/config.ovpn"])

# Funzione principale per avviare il monitoraggio
def start_monitoring():
    print(f"Monitoraggio del traffico in corso per l'IP: {my_ip}")
    logging.info("Avvio del monitoraggio della rete")

    # Avviare thread per monitoraggio
    threading.Thread(target=lambda: sniff(prn=packet_callback, store=0), daemon=True).start()
    threading.Thread(target=detect_arp_spoofing, daemon=True).start()
    threading.Thread(target=detect_dhcp_spoofing, daemon=True).start()
    threading.Thread(target=monitor_connections, daemon=True).start()
    threading.Thread(target=detect_ddos, daemon=True).start()
    threading.Thread(target=lambda: scan_ports(my_ip), daemon=True).start()
    threading.Thread(target=detect_network_scans, daemon=True).start()
    threading.Thread(target=detect_brute_force, daemon=True).start()
    threading.Thread(target=detect_malware_phishing, daemon=True).start()
    monitor_resources()  # Avvia il monitoraggio delle risorse
    setup_firewall()  # Configura il firewall
    setup_vpn()  # Configura la VPN

    while True:
        try:
            time.sleep(monitoring_interval)
            logging.info("Controllo periodico completato")
        except KeyboardInterrupt:
            logging.info("Monitoraggio interrotto manualmente.")
            break

if __name__ == "__main__":
    start_monitoring()
