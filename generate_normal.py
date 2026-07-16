import csv
import random
from datetime import datetime, timedelta

# Configuration
OUTPUT_FILE = "traffic_normal.csv"
NB_LIGNES = 500

# IPs normales du réseau
IPS_NORMALES = [
    "192.168.100.1",
    "192.168.100.128",
    "192.168.100.129",
]

# Ports et protocoles normaux
TRAFIC_NORMAL = [
    {"dst_port": 80,  "protocol": "TCP",  "service": "HTTP"},
    {"dst_port": 443, "protocol": "TCP",  "service": "HTTPS"},
    {"dst_port": 53,  "protocol": "UDP",  "service": "DNS"},
    {"dst_port": 22,  "protocol": "TCP",  "service": "SSH"},
    {"dst_port": 25,  "protocol": "TCP",  "service": "SMTP"},
    {"dst_port": 123, "protocol": "UDP",  "service": "NTP"},
]

def generer_trafic_normal():
    lignes = []
    timestamp = datetime.now() - timedelta(hours=1)

    for _ in range(NB_LIGNES):
        # Incrémenter timestamp de façon réaliste
        timestamp += timedelta(seconds=random.uniform(0.5, 5))

        src_ip  = random.choice(IPS_NORMALES)
        dst_ip  = random.choice([ip for ip in IPS_NORMALES if ip != src_ip])
        trafic  = random.choice(TRAFIC_NORMAL)

        lignes.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "src_port":  random.randint(1024, 65535),
            "dst_port":  trafic["dst_port"],
            "protocol":  trafic["protocol"],
            "size":      random.randint(40, 1500)
        })

    return lignes

def main():
    print(f"[*] Génération de {NB_LIGNES} lignes de trafic normal...")

    lignes = generer_trafic_normal()

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "timestamp","src_ip","dst_ip",
            "src_port","dst_port","protocol","size"
        ])
        writer.writeheader()
        writer.writerows(lignes)

    print(f"[✓] {OUTPUT_FILE} créé — {NB_LIGNES} lignes")
    print(f"[✓] Ports utilisés: 80, 443, 53, 22, 25, 123")
    print(f"[✓] Aucune attaque — trafic 100% normal")

if __name__ == "__main__":
    main()