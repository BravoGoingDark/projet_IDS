import requests
from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        proto = "icmp"
        service = "other"
        flag = "OTH"
        src_bytes = 0
        dst_bytes = 0
        duration = 0  # simplifié
        src_ip = packet[IP].src  # 🔍 Adresse IP source

        if TCP in packet:
            proto = "tcp"
            service = "http" if packet[TCP].dport == 80 else "other"
            
            tcp_flags = packet[TCP].flags
            if tcp_flags == 0x02:       # SYN
                flag = "S0"
            elif tcp_flags == 0x12:     # SYN+ACK
                flag = "S1"
            elif tcp_flags == 0x10:     # ACK
                flag = "SF"
            else:
                flag = "REJ"

            src_bytes = len(packet[TCP].payload)
            dst_bytes = 0

        elif UDP in packet:
            proto = "udp"
            service = "domain_u" if packet[UDP].dport == 53 else "other"
            flag = "SF"
            src_bytes = len(packet[UDP].payload)
            dst_bytes = 0

        sample = {
            "feature_0": duration,
            "feature_1": proto,
            "feature_2": service,
            "feature_3": flag,
            "feature_4": src_bytes,
            "feature_5": dst_bytes,
            "src_ip": src_ip  # ✅ Adresse IP source ajoutée
        }

        for i in range(6, 41):
            sample[f"feature_{i}"] = 0

        try:
            response = requests.post("http://127.0.0.1:5000/predict", json=sample)
            result = response.json()['prediction']
            print(f"📦 Paquet {proto.upper()} ({src_ip}) vers service {service} [{flag}] ➜ 🧠 Prédiction : {result}")
        except Exception as e:
            print(f"Erreur d’envoi à l’API : {e}")

# 🚨 Capture en temps réel
print("🔎 Capture réseau en cours...")
sniff(prn=packet_callback, store=False)
