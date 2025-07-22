import requests
import time
from scapy.all import sniff, IP, TCP, UDP

# Configuration des endpoints
IDS_PREDICT_URL = "http://127.0.0.1:5000/predict"
DASHBOARD_UPDATE_URL = "http://127.0.0.1:5000/update_stats"  # À adapter selon votre configuration
TIMEOUT = 3  # Timeout en secondes pour les requêtes

def send_to_server(url, data, retries=2):
    """Envoie des données à un serveur avec gestion des réessais."""
    for attempt in range(retries):
        try:
            response = requests.post(url, json=data, timeout=TIMEOUT)
            response.raise_for_status()  # Lève une exception pour les codes 4XX/5XX
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"⚠️ Tentative {attempt + 1} échouée pour {url}: {str(e)}")
            if attempt == retries - 1:
                return None
            time.sleep(1)  # Attente avant réessai

def packet_callback(packet):
    if IP not in packet:
        return

    # Extraction des caractéristiques du paquet
    src_ip = packet[IP].src
    proto = "icmp"
    service = "other"
    flag = "OTH"
    src_bytes = dst_bytes = duration = 0

    if TCP in packet:
        proto = "tcp"
        service = "http" if packet[TCP].dport == 80 else "other"
        tcp_flags = packet[TCP].flags
        flag = {
            0x02: "S0",  # SYN
            0x12: "S1",  # SYN-ACK
            0x10: "SF",  # ACK
        }.get(tcp_flags, "REJ")
        src_bytes = len(packet[TCP].payload)

    elif UDP in packet:
        proto = "udp"
        service = "domain_u" if packet[UDP].dport == 53 else "other"
        flag = "SF"
        src_bytes = len(packet[UDP].payload)

    # Construction du sample pour l'IDS
    sample = {"feature_0": duration, "feature_1": proto, "feature_2": service, 
              "feature_3": flag, "feature_4": src_bytes, "feature_5": dst_bytes, 
              "src_ip": src_ip}
    
    # Remplissage des features vides (6 à 40)
    for i in range(6, 41):
        sample[f"feature_{i}"] = 0

    try:
        # 1. Prédiction par l'IDS
        print(f"\n🔍 Analyse du paquet {proto.upper()} {src_ip} → {service} [{flag}]")
        print("📤 Envoi à l'IDS...")
        ids_response = send_to_server(IDS_PREDICT_URL, sample)
        
        if not ids_response:
            print("❌ Échec de la prédiction par l'IDS")
            return

        prediction = ids_response.get("prediction", "inconnu")
        probability = ids_response.get("probability", 0)
        print(f"🧠 Résultat IDS: {prediction.upper()} (confiance: {probability:.2f})")

        # 2. Notification au dashboard
        print("📊 Mise à jour du dashboard...")
        dashboard_data = {
            "src_ip": src_ip,
            "prediction": prediction,
            "service": service,
            "protocol": proto,
            "flag": flag,
            "timestamp": int(time.time())
        }
        dashboard_response = send_to_server(DASHBOARD_UPDATE_URL, dashboard_data)
        
        if dashboard_response:
            print("✅ Dashboard mis à jour avec succès")
        else:
            print("❌ Échec de la mise à jour du dashboard")

    except Exception as e:
        print(f"🔥 Erreur critique dans le traitement: {str(e)}")

if __name__ == "__main__":
    print(""" 
   _____                      __  ___       __               
  / ___/______ ____  ___ ____/  |/  /__    / /  ___ ________ 
 / /__/ __/ _ `/ _ \/ -_) __/ /|_/ / _ \  / /__/ _ `/ __/ -_)
 \___/_/  \_,_/ .__/\__/_/ /_/  /_/\___/ /____/\_,_/_/  \__/ 
             /_/  Real-Time IDS Capture v2.0                  
    """)
    print("🔎 Démarrage de la capture réseau (CTRL+C pour arrêter)...")
    print(f"• Serveur IDS: {IDS_PREDICT_URL}")
    print(f"• Dashboard: {DASHBOARD_UPDATE_URL}\n")

    try:
        sniff(iface="enp0s3", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n🛑 Capture arrêtée par l'utilisateur")
    except Exception as e:
        print(f"💥 Erreur de capture: {str(e)}")
