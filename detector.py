import pandas as pd
from datetime import datetime

# Configuration des seuils
SEUILS = {
    'port_scan': 50,      # +50 ports différents f 60s = port scan
    'brute_force': 50,    # +10 tentatives SSH f 30s = brute force
    'ddos': 200,          # +200 paquets f 10s = DDoS
}

def detecter_port_scan(df):
    alertes = []
    # Grouper par IP source + fenêtre de 60s
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df_tcp = df[df['protocol'] == 'TCP'].copy()
    
    for src_ip in df_tcp['src_ip'].unique():
        df_ip = df_tcp[df_tcp['src_ip'] == src_ip]
        
        # Compter ports dst différents
        ports_uniques = df_ip['dst_port'].nunique()
        
        if ports_uniques >= SEUILS['port_scan']:
            alertes.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': src_ip,
                'type': 'PORT_SCAN',
                'niveau': 'HAUT',
                'details': f'{ports_uniques} ports scannés'
            })
    return alertes

def detecter_brute_force(df):
    alertes = []
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df_ssh = df[(df['protocol'] == 'TCP') & (df['dst_port'] == 22)].copy()
    
    for src_ip in df_ssh['src_ip'].unique():
        df_ip = df_ssh[df_ssh['src_ip'] == src_ip]
        tentatives = len(df_ip)
        
        if tentatives >= SEUILS['brute_force']:
            alertes.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': src_ip,
                'type': 'BRUTE_FORCE_SSH',
                'niveau': 'HAUT',
                'details': f'{tentatives} tentatives SSH'
            })
    return alertes

def detecter_ddos(df):
    alertes = []
    HOST_IP = "192.168.100.1"
    df = df[df['src_ip'] != HOST_IP]
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    for src_ip in df['src_ip'].unique():
        df_ip = df[df['src_ip'] == src_ip]
        nb_paquets = len(df_ip)
        
        if nb_paquets >= SEUILS['ddos']:
            alertes.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': src_ip,
                'type': 'DDOS',
                'niveau': 'MOYEN',
                'details': f'{nb_paquets} paquets envoyés'
            })
    return alertes

def detecter_arp_spoofing(df):
    alertes = []
    df_arp = df[df['protocol'] == 'ARP'].copy()
    
    # Khraj IPs suspectes — machi host (192.168.100.1)
    WHITELIST = ["192.168.100.1", "192.168.100.129"]
    df_arp = df_arp[~df_arp['src_ip'].isin(WHITELIST)]
    
    for src_ip in df_arp['src_ip'].unique():
        df_ip = df_arp[df_arp['src_ip'] == src_ip]
        nb_arp = len(df_ip)
        
        if nb_arp >= 5:
            alertes.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': src_ip,
                'type': 'ARP_SPOOFING',
                'niveau': 'HAUT',
                'details': f'{nb_arp} paquets ARP suspects'
            })
    return alertes

def detecter_ping_flood(df):
    alertes = []
    df_icmp = df[df['protocol'] == 'ICMP'].copy()
    HOST_IP = "192.168.100.1"
    df_icmp = df_icmp[df_icmp['src_ip'] != HOST_IP]
    
    for src_ip in df_icmp['src_ip'].unique():
        df_ip = df_icmp[df_icmp['src_ip'] == src_ip]
        nb_icmp = len(df_ip)
        
        if nb_icmp >= 50:
            alertes.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': src_ip,
                'type': 'PING_FLOOD',
                'niveau': 'MOYEN',
                'details': f'{nb_icmp} paquets ICMP suspects'
            })
    return alertes

def main():
    import sys
    fichier = sys.argv[1] if len(sys.argv) > 1 else 'traffic.csv'
    print(f"[*] Lecture de {fichier}...")
    
    try:
        df = pd.read_csv(fichier)
        print(f"[*] {len(df)} lignes chargées")
    except FileNotFoundError:
        print(f"[!] {fichier} introuvable")
        return
    
    # Lancer les détections
    alertes = []
    alertes += detecter_port_scan(df)
    alertes += detecter_brute_force(df)
    alertes += detecter_ddos(df)
    alertes += detecter_arp_spoofing(df)
    alertes += detecter_ping_flood(df)

    
    if not alertes:
        print("[✓] Aucune alerte détectée — trafic normal")
        return
    
    # Sauvegarder alertes
    df_alertes = pd.DataFrame(alertes)
    df_alertes.to_csv('alerts.csv', index=False)
    
    # Afficher résultats
    print(f"\n[!] {len(alertes)} ALERTES DÉTECTÉES:\n")
    for a in alertes:
        couleur = "🔴" if a['niveau'] == 'HAUT' else "🟠"
        print(f"{couleur} [{a['niveau']}] {a['type']} — {a['src_ip']} — {a['details']}")
    
    print(f"\n[*] Alertes sauvegardées dans alerts.csv")

if __name__ == "__main__":
    main()