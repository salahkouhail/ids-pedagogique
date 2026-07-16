from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import csv
import os
from datetime import datetime

# Configuration
INTERFACE = "VMware Network Adapter VMnet2"
OUTPUT_FILE = "traffic.csv"

# Créer CSV avec headers si existe pas
if not os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'size'])

from scapy.all import sniff, IP, TCP, UDP, ARP

def process_packet(packet):
    # ── ARP ──
    if ARP in packet:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(OUTPUT_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, packet[ARP].psrc, packet[ARP].pdst, 0, 0, 'ARP', len(packet)])
        print(f"[{timestamp}] ARP: {packet[ARP].psrc} → {packet[ARP].pdst}")
        return

def detecter_syn_flood(df):
    alertes = []
    HOST_IP = "192.168.100.1"
    df_syn = df[(df['protocol'] == 'TCP') & (df['src_ip'] != HOST_IP)].copy()
    
    for src_ip in df_syn['src_ip'].unique():
        df_ip = df_syn[df_syn['src_ip'] == src_ip]
        # SYN flood = bzzaf connexions vers port wahd
        port_counts = df_ip['dst_port'].value_counts()
        for port, count in port_counts.items():
            if count >= 100:
                alertes.append({
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'src_ip': src_ip,
                    'type': 'SYN_FLOOD',
                    'niveau': 'HAUT',
                    'details': f'{count} SYN vers port {port}'
                })
    return alertes    
    
    if IP not in packet:
        return
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    size = len(packet)
    
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = "TCP"
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        protocol = "UDP"
    else:
        src_port = 0
        dst_port = 0
        protocol = "OTHER"
    
    # Sauvegarder dans CSV
    with open(OUTPUT_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size])
    
    print(f"[{timestamp}] {src_ip}:{src_port} → {dst_ip}:{dst_port} ({protocol})")

print(f"[*] Capture démarrée sur {INTERFACE}")
print("[*] Ctrl+C pour arrêter\n")

sniff(iface=INTERFACE, prn=process_packet, store=0)