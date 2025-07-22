from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import joblib
import pandas as pd
import psutil
import time
import threading
from datetime import datetime, timedelta
import json
import os
import smtplib
import socket
import traceback
import subprocess

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
import requests
from config import EMAIL_CONFIG, EMAIL_SETTINGS
from sklearn.preprocessing import LabelEncoder

# Initialisation de l\'application
app = Flask(__name__)
app.config["SECRET_KEY"] = "secret!"
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Variables globales
captured_packets = []
# Assurez-vous que ces fichiers existent dans le dossier 'model/'
label_encoders = joblib.load("model/label_encoders.pkl")
model = joblib.load("model/model_ids.pkl")
scaler = joblib.load("model/scaler.pkl")
features = [f"feature_{i}" for i in range(41)]

# Configuration de capture
CAPTURE_CONFIG = {
    "enabled": False,
    "interface": "any",
    "filter": "",
    "max_packets": 1000,
    "capture_thread": None
}

# Statistiques du serveur
server_stats = {
    "cpu_usage": [],
    "memory_usage": [],
    "disk_usage": [],
    "network_io": [],
    "timestamps": [],
    "predictions_per_minute": [],
    "total_predictions": 0,
    "attack_count": 0,
    "normal_count": 0,
    "uptime": time.time(),
    "capture_mode": "simulated"
}

recent_predictions = []
MAX_RECENT_PREDICTIONS = 1000

# Email tracking
last_email_sent = None
emails_sent_this_hour = 0
email_hour_reset = datetime.now()

# Fichier pour stocker les IPs bloquées
BLOCKED_IPS_FILE = "blocked_ips.json"

def load_blocked_ips():
    """Charger la liste des IPs bloquées depuis le fichier JSON"""
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, 'r') as f:
                return json.load(f)
        return []
    except Exception as e:
        print(f"Erreur lors du chargement des IPs bloquées: {e}")
        return []

def save_blocked_ip(ip, reason="Attaque détectée"):
    """Sauvegarder une IP bloquée dans le fichier JSON"""
    try:
        blocked_ips = load_blocked_ips()
        
        # Vérifier si l'IP n'est pas déjà bloquée
        for blocked_ip in blocked_ips:
            if blocked_ip["ip"] == ip:
                return  # IP déjà bloquée
        
        # Ajouter la nouvelle IP bloquée
        new_blocked_ip = {
            "ip": ip,
            "date": datetime.now().isoformat(),
            "reason": reason,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        blocked_ips.append(new_blocked_ip)
        
        # Sauvegarder dans le fichier
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump(blocked_ips, f, indent=2)
            
        print(f"IP {ip} sauvegardée comme bloquée")
        
    except Exception as e:
        print(f"Erreur lors de la sauvegarde de l'IP bloquée {ip}: {e}")

# Fonctions utilitaires
def encode_features(data):
    for col, le in label_encoders.items():
        if col in data:
            try:
                data[col] = int(le.transform([data[col]])[0])
            except ValueError:
                data[col] = le.transform([le.classes_[0]])[0]
    return {k: v for k, v in data.items() if k in features}

def get_network_interfaces():
    try:
        return get_if_list()
    except Exception:
        return ["any", "lo", "eth0"]

def extract_packet_features(packet):
    try:
        features = {f"feature_{i}": 0 for i in range(41)}
        features.update({
            "src_ip": "unknown",
            "dst_ip": "unknown",
            "feature_0": 0,  # duration
            "feature_1": "other",  # proto
            "feature_2": "other",  # service
            "feature_3": "OTH",  # flag
            "feature_4": 0,  # src_bytes
            "feature_5": 0  # dst_bytes
        })

        if IP in packet:
            features["src_ip"] = packet[IP].src
            features["dst_ip"] = packet[IP].dst

            if TCP in packet:
                features["feature_1"] = "tcp"
                port = packet[TCP].dport
                features["feature_2"] = {
                    80: "http", 443: "https", 21: "ftp", 22: "ssh",
                    23: "telnet", 25: "smtp", 53: "domain", 110: "pop_3"
                }.get(port, "other" )
                features["feature_3"] = {
                    0x02: "S0", 0x12: "S1", 0x10: "SF", 0x04: "REJ", 0x01: "SF"
                }.get(packet[TCP].flags, "OTH")
                features["feature_4"] = len(packet[TCP].payload) if packet[TCP].payload else 0

            elif UDP in packet:
                features["feature_1"] = "udp"
                port = packet[UDP].dport
                features["feature_2"] = {
                    53: "domain_u", 67: "dhcp", 68: "dhcp", 123: "ntp_u"
                }.get(port, "other")
                features["feature_3"] = "SF"
                features["feature_4"] = len(packet[UDP].payload) if packet[UDP].payload else 0

            elif ICMP in packet:
                features["feature_1"] = "icmp"
                features["feature_2"] = "eco_i"
                features["feature_3"] = "SF"
                features["feature_4"] = len(packet) - 20

        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

def packet_callback(packet):
    try:
        features = extract_packet_features(packet)
        if features:
            captured_packets.append(features)
            if len(captured_packets) > 1000:
                captured_packets.pop(0)
            
            response = requests.post("http://127.0.0.1:5000/predict", json=features, timeout=1 )
            if response.status_code == 200:
                result = response.json()
                socketio.emit('packet_processed', {
                    'src_ip': features.get("src_ip"),
                    'proto': features.get("feature_1"),
                    'service': features.get("feature_2"),
                    'flag': features.get("feature_3"),
                    'prediction': result.get("prediction"),
                    'probability': result.get("probability")
                })
    except Exception as e:
        print(f"Packet processing error: {e}")

def start_packet_capture():
    if CAPTURE_CONFIG["enabled"]:
        return

    try:
        CAPTURE_CONFIG["enabled"] = True
        server_stats["capture_mode"] = "real"
        
        def capture_worker():
            try:
                sniff(
                    iface=CAPTURE_CONFIG["interface"],
                    prn=packet_callback,
                    filter=CAPTURE_CONFIG["filter"],
                    store=False,
                    stop_filter=lambda x: not CAPTURE_CONFIG["enabled"]
                )
            except Exception as e:
                print(f"Capture error: {e}")
                CAPTURE_CONFIG["enabled"] = False
                server_stats["capture_mode"] = "simulated"

        CAPTURE_CONFIG["capture_thread"] = threading.Thread(target=capture_worker, daemon=True)
        CAPTURE_CONFIG["capture_thread"].start()
    except Exception as e:
        print(f"Failed to start capture: {e}")
        CAPTURE_CONFIG["enabled"] = False
        server_stats["capture_mode"] = "simulated"
        
@app.route('/update_stats', methods=['POST'])
def update_stats():
    stats = {
        'cpu': psutil.cpu_percent(),
        'memory': psutil.virtual_memory().percent,
        'disk': psutil.disk_usage('/').percent,
        'uptime': get_system_uptime()
    }
    return jsonify(stats)

def get_system_uptime():
    import time
    return round(time.time() - psutil.boot_time())  # uptime en secondes

def stop_packet_capture():
    if not CAPTURE_CONFIG["enabled"]:
        return
        
    CAPTURE_CONFIG["enabled"] = False
    server_stats["capture_mode"] = "simulated"
    time.sleep(1)

def send_attack_email(attack_data):
    global last_email_sent, emails_sent_this_hour, email_hour_reset
    
    if not EMAIL_SETTINGS.get("enabled", False):
        return
        
    current_time = datetime.now()
    if current_time.hour != email_hour_reset.hour:
        emails_sent_this_hour = 0
        email_hour_reset = current_time
        
    if last_email_sent and (current_time - last_email_sent).total_seconds() / 60 < EMAIL_SETTINGS.get("cooldown_minutes", 5):
        return
        
    if emails_sent_this_hour >= EMAIL_SETTINGS.get("max_emails_per_hour", 10):
        return

    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_CONFIG["sender_email"]
        msg["To"] = EMAIL_CONFIG["recipient_email"]
        msg["Subject"] = "🚨 IDS ALERT: Attack Detected!"
        
        body = f"""
INTRUSION DETECTION SYSTEM ALERT

⚠️ ATTACK DETECTED ⚠️

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Source IP: {attack_data.get('src_ip', 'Unknown')}
Protocol: {attack_data.get('proto', 'Unknown').upper()}
Service: {attack_data.get('service', 'Unknown')}
Flag: {attack_data.get('flag', 'Unknown')}
Prediction: {attack_data.get('prediction', 'Unknown').upper()}

System Status:
- Total Attacks Today: {server_stats['attack_count']}
- Total Normal Traffic: {server_stats['normal_count']}
- System Uptime: {time.time() - server_stats['uptime']:.0f} seconds
"""
        msg.attach(MIMEText(body, "plain"))
        
        with smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"]) as server:
            server.starttls()
            server.login(EMAIL_CONFIG["sender_email"], EMAIL_CONFIG["sender_password"])
            server.send_message(msg)
            
        last_email_sent = current_time
        emails_sent_this_hour += 1
    except Exception as e:
        print(f"Email error: {e}")
        

def block_ip_address(ip, reason="Attaque détectée"):
    try:
        if ip == "127.0.0.1" or ip.startswith("192.168.") or ip.startswith("10.") or ip == "unknown":
            return  # éviter de bloquer local ou inconnu
        
        # Bloquer l'IP avec iptables
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"[FIREWALL] IP bloquée : {ip}")
        
        # Sauvegarder l'IP bloquée
        save_blocked_ip(ip, reason)
        
    except subprocess.CalledProcessError as e:
        print(f"Erreur blocage IP {ip} : {e}")

def get_system_stats():
    stats = {
        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory_usage": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage("/").percent,
        "network_bytes_sent": psutil.net_io_counters().bytes_sent,
        "network_bytes_recv": psutil.net_io_counters().bytes_recv,
        "timestamp": datetime.now().isoformat()
    }
    return stats

def monitor_system():
    while True:
        try:
            stats = get_system_stats()
            current_time = datetime.now()
            
            # Mise à jour des stats système
            for metric in ["cpu_usage", "memory_usage", "disk_usage"]:
                server_stats[metric].append(stats[metric])
                if len(server_stats[metric]) > 60:
                    server_stats[metric].pop(0)
                    
            server_stats["timestamps"].append(current_time.isoformat())
            if len(server_stats["timestamps"]) > 60:
                server_stats["timestamps"].pop(0)
                
            # Calcul des prédictions par minute
            one_min_ago = current_time - timedelta(minutes=1)
            recent_preds = len([p for p in recent_predictions if datetime.fromisoformat(p["timestamp"]) > one_min_ago])
            server_stats["predictions_per_minute"].append(recent_preds)
            if len(server_stats["predictions_per_minute"]) > 60:
                server_stats["predictions_per_minute"].pop(0)
                
            # Émission des stats via WebSocket
            socketio.emit("system_stats", {
                "cpu": stats["cpu_usage"],
                "memory": stats["memory_usage"],
                "disk": stats["disk_usage"],
                "predictions_per_minute": recent_preds,
                "uptime": time.time() - server_stats["uptime"],
                "capture_mode": server_stats["capture_mode"],
                "capture_enabled": CAPTURE_CONFIG["enabled"]
            })
            
        except Exception as e:
            print(f"Monitoring error: {e}")
            
        time.sleep(10)

# Démarrer le thread de monitoring
threading.Thread(target=monitor_system, daemon=True).start()

# Routes API
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/predict", methods=['POST'])
def predict():
    try:
        data = request.get_json(force=True)
        encoded_data = encode_features(data.copy())
        df = pd.DataFrame([encoded_data], columns=features)
        df_scaled = scaler.transform(df)
        prediction = model.predict(df_scaled)[0]
        probability = model.predict_proba(df_scaled)[0].max()
        
        # Mise à jour des stats
        server_stats["total_predictions"] += 1
        if prediction == "attaque":
            server_stats["attack_count"] += 1
        else:
            server_stats["normal_count"] += 1

        # Stockage de la prédiction
        recent_pred = {
            "timestamp": datetime.now().isoformat(),
            "prediction": prediction,
            "src_ip": data.get("src_ip", "unknown"),
            "proto": data.get("feature_1", "unknown"),
            "service": data.get("feature_2", "unknown"),
            "flag": data.get("feature_3", "unknown"),
            "probability": float(probability)
        }
        recent_predictions.append(recent_pred)
        if len(recent_predictions) > MAX_RECENT_PREDICTIONS:
            recent_predictions.pop(0)

        # Blocage IP si attaque détectée
        if prediction == "attaque":
            block_ip_address(data.get("src_ip", "unknown"), "Attaque détectée par IDS")
            send_attack_email(data)

        # Notification WebSocket
        socketio.emit("new_prediction", recent_pred)

        return jsonify({
            "prediction": prediction,
            "probability": float(probability)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Nouvelle route pour récupérer les IPs bloquées
@app.route("/api/blocked-ips", methods=['GET'])
def api_get_blocked_ips():
    """Récupérer la liste des IPs bloquées"""
    try:
        blocked_ips = load_blocked_ips()
        return jsonify({
            "blocked_ips": blocked_ips,
            "total": len(blocked_ips)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route pour débloquer une IP
@app.route("/api/unblock-ip", methods=['POST'])
def api_unblock_ip():
    """Débloquer une IP spécifique"""
    try:
        data = request.get_json()
        ip_to_unblock = data.get("ip")
        
        if not ip_to_unblock:
            return jsonify({"error": "IP address required"}), 400
        
        # Supprimer la règle iptables
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip_to_unblock, "-j", "DROP"], check=True)
        except subprocess.CalledProcessError:
            pass  # La règle n'existe peut-être pas
        
        # Supprimer de la liste des IPs bloquées
        blocked_ips = load_blocked_ips()
        blocked_ips = [ip for ip in blocked_ips if ip["ip"] != ip_to_unblock]
        
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump(blocked_ips, f, indent=2)
        
        return jsonify({"message": f"IP {ip_to_unblock} débloquée avec succès"})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/capture/stop", methods=['POST'])
def api_stop_capture():
    try:
        stop_packet_capture()
        return jsonify({"status": "stopped"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/capture/status", methods=['GET'])
def api_capture_status():
    return jsonify({
        "enabled": CAPTURE_CONFIG["enabled"],
        "interface": CAPTURE_CONFIG["interface"],
        "filter": CAPTURE_CONFIG["filter"],
        "capture_mode": server_stats["capture_mode"],
        "available_interfaces": get_network_interfaces()
    })

@app.route("/api/stats", methods=['GET'])
def api_get_stats():
    stats = get_system_stats()
    total = server_stats["total_predictions"]
    attack_rate = (server_stats["attack_count"] / total * 100) if total > 0 else 0
    
    return jsonify({
        "system": {
            "cpu": stats["cpu_usage"],
            "memory": stats["memory_usage"],
            "disk": stats["disk_usage"],
            "network_sent": stats["network_bytes_sent"],
            "network_recv": stats["network_bytes_recv"],
            "uptime": time.time() - server_stats["uptime"],
            "capture_mode": server_stats["capture_mode"]
        },
        "predictions": {
            "total": total,
            "normal": server_stats["normal_count"],
            "attacks": server_stats["attack_count"],
            "attack_rate": attack_rate
        }
    })

@app.route("/api/packets", methods=['GET'])
def api_get_packets():
    return jsonify({"packets": captured_packets[-100:]})

# WebSocket handlers
@socketio.on("connect")
def handle_connect():
    emit("connection_established", {
        "status": "connected",
        "server_time": datetime.now().isoformat()
    })

@socketio.on("disconnect")
def handle_disconnect():
    print("Client disconnected")

# Point d'entrée principal
if __name__ == "__main__":
    print("Starting IDS Monitoring System...")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)

