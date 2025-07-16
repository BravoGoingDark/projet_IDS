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
import subprocess
import socket

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Scapy imports for real packet capture
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, conf
import requests

from config import EMAIL_CONFIG, EMAIL_SETTINGS

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret!"
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Email tracking variables
last_email_sent = None
emails_sent_this_hour = 0
email_hour_reset = datetime.now()

# Load model and encoders
model = joblib.load("model/model_ids.pkl")
label_encoders = joblib.load("model/label_encoders.pkl")
features = [f"feature_{i}" for i in range(41)]

# Real-time capture configuration
CAPTURE_CONFIG = {
    "enabled": False,
    "interface": "any",  # Default to capture on all interfaces
    "filter": "",  # BPF filter (empty = capture all)
    "max_packets": 1000,  # Maximum packets to store
    "capture_thread": None
}

# Server monitoring data
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
    "capture_mode": "simulated"  # "simulated" or "real"
}

# Store recent predictions for analysis
recent_predictions = []
MAX_RECENT_PREDICTIONS = 1000

def get_network_interfaces():
    """Get available network interfaces"""
    try:
        interfaces = get_if_list()
        return interfaces
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        return ["any", "lo", "eth0"]

def extract_packet_features(packet):
    """Extract features from a real network packet for IDS analysis"""
    try:
        # Initialize default values
        features_dict = {f"feature_{i}": 0 for i in range(41)}
        
        # Basic packet info
        src_ip = "unknown"
        dst_ip = "unknown"
        proto = "other"
        service = "other"
        flag = "OTH"
        src_bytes = 0
        dst_bytes = 0
        duration = 0
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Protocol analysis
            if TCP in packet:
                proto = "tcp"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # Service identification based on port
                if dst_port == 80 or src_port == 80:
                    service = "http"
                elif dst_port == 443 or src_port == 443:
                    service = "https"
                elif dst_port == 21 or src_port == 21:
                    service = "ftp"
                elif dst_port == 22 or src_port == 22:
                    service = "ssh"
                elif dst_port == 23 or src_port == 23:
                    service = "telnet"
                elif dst_port == 25 or src_port == 25:
                    service = "smtp"
                elif dst_port == 53 or src_port == 53:
                    service = "domain"
                elif dst_port == 110 or src_port == 110:
                    service = "pop_3"
                else:
                    service = "other"
                
                # TCP flags analysis
                tcp_flags = packet[TCP].flags
                if tcp_flags == 0x02:  # SYN
                    flag = "S0"
                elif tcp_flags == 0x12:  # SYN+ACK
                    flag = "S1"
                elif tcp_flags == 0x10:  # ACK
                    flag = "SF"
                elif tcp_flags == 0x04:  # RST
                    flag = "REJ"
                elif tcp_flags == 0x01:  # FIN
                    flag = "SF"
                else:
                    flag = "OTH"
                
                src_bytes = len(packet[TCP].payload) if packet[TCP].payload else 0
                
            elif UDP in packet:
                proto = "udp"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                
                # UDP service identification
                if dst_port == 53 or src_port == 53:
                    service = "domain_u"
                elif dst_port == 67 or dst_port == 68:
                    service = "dhcp"
                elif dst_port == 123:
                    service = "ntp_u"
                else:
                    service = "other"
                
                flag = "SF"  # UDP is connectionless
                src_bytes = len(packet[UDP].payload) if packet[UDP].payload else 0
                
            elif ICMP in packet:
                proto = "icmp"
                service = "eco_i"
                flag = "SF"
                src_bytes = len(packet) - 20  # IP header is typically 20 bytes
        
        # Map to feature format expected by the model
        features_dict["feature_0"] = duration
        features_dict["feature_1"] = proto
        features_dict["feature_2"] = service
        features_dict["feature_3"] = flag
        features_dict["feature_4"] = src_bytes
        features_dict["feature_5"] = dst_bytes
        
        # Add source IP for tracking
        features_dict["src_ip"] = src_ip
        features_dict["dst_ip"] = dst_ip
        
        return features_dict
        
    except Exception as e:
        print(f"Error extracting packet features: {e}")
        return None

def packet_callback(packet):
    """Callback function for processing captured packets"""
    try:
        features = extract_packet_features(packet)
        if features:
            # Send to prediction endpoint
            response = requests.post(
                "http://127.0.0.1:5000/predict", 
                json=features,
                timeout=1
            )
            
            if response.status_code == 200:
                result = response.json()
                src_ip = features.get("src_ip", "unknown")
                proto = features.get("feature_1", "unknown")
                service = features.get("feature_2", "unknown")
                flag = features.get("feature_3", "unknown")
                prediction = result.get("prediction", "unknown")
                
                print(f"📦 Real packet: {proto.upper()} from {src_ip} to service {service} [{flag}] ➜ 🧠 Prediction: {prediction}")
                
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_packet_capture():
    """Start real-time packet capture"""
    global CAPTURE_CONFIG
    
    if CAPTURE_CONFIG["enabled"]:
        print("Packet capture is already running!")
        return
    
    try:
        interface = CAPTURE_CONFIG["interface"]
        bpf_filter = CAPTURE_CONFIG["filter"]
        
        print(f"🔍 Starting packet capture on interface: {interface}")
        print(f"🔍 Filter: {bpf_filter if bpf_filter else 'None (capturing all traffic)'}")
        
        CAPTURE_CONFIG["enabled"] = True
        server_stats["capture_mode"] = "real"
        
        # Start packet capture in a separate thread
        def capture_worker():
            try:
                if interface == "any":
                    # Capture on all interfaces
                    sniff(prn=packet_callback, filter=bpf_filter, store=False, stop_filter=lambda x: not CAPTURE_CONFIG["enabled"])
                else:
                    # Capture on specific interface
                    sniff(iface=interface, prn=packet_callback, filter=bpf_filter, store=False, stop_filter=lambda x: not CAPTURE_CONFIG["enabled"])
            except Exception as e:
                print(f"❌ Packet capture error: {e}")
                CAPTURE_CONFIG["enabled"] = False
                server_stats["capture_mode"] = "simulated"
        
        capture_thread = threading.Thread(target=capture_worker, daemon=True)
        capture_thread.start()
        CAPTURE_CONFIG["capture_thread"] = capture_thread
        
        print("✅ Real-time packet capture started successfully!")
        
    except Exception as e:
        print(f"❌ Failed to start packet capture: {e}")
        CAPTURE_CONFIG["enabled"] = False
        server_stats["capture_mode"] = "simulated"

def stop_packet_capture():
    """Stop real-time packet capture"""
    global CAPTURE_CONFIG
    
    if not CAPTURE_CONFIG["enabled"]:
        print("Packet capture is not running!")
        return
    
    print("🛑 Stopping packet capture...")
    CAPTURE_CONFIG["enabled"] = False
    server_stats["capture_mode"] = "simulated"
    
    # Wait a moment for the capture thread to stop
    time.sleep(1)
    print("✅ Packet capture stopped successfully!")

def send_attack_email(attack_data):
    """Send email notification when attack is detected"""
    global last_email_sent, emails_sent_this_hour, email_hour_reset
    
    if not EMAIL_SETTINGS.get("enabled", False):
        return
    
    current_time = datetime.now()
    
    if current_time.hour != email_hour_reset.hour:
        emails_sent_this_hour = 0
        email_hour_reset = current_time
    
    if last_email_sent:
        time_since_last = (current_time - last_email_sent).total_seconds() / 60
        if time_since_last < EMAIL_SETTINGS.get('cooldown_minutes', 5):
            print(f"Email cooldown active. {EMAIL_SETTINGS.get('cooldown_minutes', 5) - time_since_last:.1f} minutes remaining.")
            return
    
    if emails_sent_this_hour >= EMAIL_SETTINGS.get('max_emails_per_hour', 10):
        print("Hourly email limit reached. No more emails will be sent this hour.")
        return
    
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_CONFIG["sender_email"]
        msg["To"] = EMAIL_CONFIG["recipient_email"]
        msg["Subject"] = "🚨 IDS ALERT: Attack Detected!"
        
        capture_mode = "Real Network Traffic" if server_stats["capture_mode"] == "real" else "Simulated Traffic"
        src_ip = attack_data.get("src_ip", "Unknown")
        
        body = f"""
INTRUSION DETECTION SYSTEM ALERT

⚠️ ATTACK DETECTED ⚠️

Time: {attack_data.get('timestamp', 'Unknown')}
Source IP: {src_ip}
Protocol: {attack_data.get('proto', 'Unknown').upper()}
Service: {attack_data.get('service', 'Unknown')}
Flag: {attack_data.get('flag', 'Unknown')}
Prediction: {attack_data.get('prediction', 'Unknown').upper()}
Capture Mode: {capture_mode}

System Status:
- Total Attacks Today: {server_stats['attack_count']}
- Total Normal Traffic: {server_stats['normal_count']}
- System Uptime: {time.time() - server_stats['uptime']:.0f} seconds

This is an automated alert from your IDS monitoring system.
Please review your network security immediately.

---
IDS Monitoring Dashboard
Generated at: {current_time.strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        msg.attach(MIMEText(body, "plain"))
        
        server = smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"])
        server.starttls()
        server.login(EMAIL_CONFIG["sender_email"], EMAIL_CONFIG["sender_password"])
        
        text = msg.as_string()
        server.sendmail(EMAIL_CONFIG["sender_email"], EMAIL_CONFIG["recipient_email"], text)
        server.quit()
        
        last_email_sent = current_time
        emails_sent_this_hour += 1
        
        print(f"✅ Attack alert email sent successfully to {EMAIL_CONFIG['recipient_email']}")
        
    except Exception as e:
        print(f"❌ Failed to send email: {str(e)}")

def encode_features(sample):
    """Encode categorical features using fitted label encoders"""
    for col_name, encoder in label_encoders.items():
        if col_name in sample:
            try:
                sample[col_name] = encoder.transform([sample[col_name]])[0]
            except ValueError:
                sample[col_name] = 0
    return sample

def get_system_stats():
    """Get current system statistics"""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    network = psutil.net_io_counters()
    
    return {
        "cpu_usage": cpu_percent,
        "memory_usage": memory.percent,
        "disk_usage": disk.percent,
        "network_bytes_sent": network.bytes_sent,
        "network_bytes_recv": network.bytes_recv,
        "timestamp": datetime.now().isoformat()
    }

def monitor_system():
    """Background thread to monitor system stats"""
    while True:
        try:
            stats = get_system_stats()
            current_time = datetime.now()
            
            server_stats["cpu_usage"].append(stats["cpu_usage"])
            server_stats["memory_usage"].append(stats["memory_usage"])
            server_stats["disk_usage"].append(stats["disk_usage"])
            server_stats["timestamps"].append(current_time.isoformat())
            
            if len(server_stats["cpu_usage"]) > 60:
                server_stats["cpu_usage"].pop(0)
                server_stats["memory_usage"].pop(0)
                server_stats["disk_usage"].pop(0)
                server_stats["timestamps"].pop(0)
            
            one_minute_ago = current_time - timedelta(minutes=1)
            recent_count = len([p for p in recent_predictions 
                              if datetime.fromisoformat(p["timestamp"]) > one_minute_ago])
            
            server_stats["predictions_per_minute"].append(recent_count)
            if len(server_stats["predictions_per_minute"]) > 60:
                server_stats["predictions_per_minute"].pop(0)
            
            socketio.emit("system_stats", {
                "cpu": stats["cpu_usage"],
                "memory": stats["memory_usage"],
                "disk": stats["disk_usage"],
                "predictions_per_minute": recent_count,
                "uptime": time.time() - server_stats["uptime"],
                "timestamp": stats["timestamp"],
                "capture_mode": server_stats["capture_mode"],
                "capture_enabled": CAPTURE_CONFIG["enabled"]
            })
            
        except Exception as e:
            print(f"Error in system monitoring: {e}")
        
        time.sleep(60)

# Start monitoring thread
monitoring_thread = threading.Thread(target=monitor_system, daemon=True)
monitoring_thread.start()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)
        data_encoded = encode_features(data.copy())
        df = pd.DataFrame([data_encoded], columns=features)
        pred = model.predict(df)[0]
        src_ip = data.get("src_ip", "unknown")
        
        prediction_data = {
            "prediction": pred,
            "proto": data.get("feature_1", "unknown"),
            "service": data.get("feature_2", "unknown"),
            "flag": data.get("feature_3", "unknown"),
            "timestamp": datetime.now().isoformat(),
            "raw_data": data,
            "src_ip": src_ip,
            "capture_mode": server_stats["capture_mode"]
        }
        
        recent_predictions.append(prediction_data)
        if len(recent_predictions) > MAX_RECENT_PREDICTIONS:
            recent_predictions.pop(0)
        
        server_stats["total_predictions"] += 1
        if pred == "attaque":
            server_stats["attack_count"] += 1
            send_attack_email(prediction_data)
        else:
            server_stats["normal_count"] += 1
        
        socketio.emit("new_prediction", prediction_data)
        
        return jsonify({"prediction": pred, "timestamp": prediction_data["timestamp"]})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/capture/start", methods=["POST"])
def start_capture():
    """Start real-time packet capture"""
    try:
        data = request.get_json() or {}
        
        # Update capture configuration
        CAPTURE_CONFIG["interface"] = data.get("interface", "any")
        CAPTURE_CONFIG["filter"] = data.get("filter", "")
        
        start_packet_capture()
        
        return jsonify({
            "message": "Packet capture started successfully",
            "interface": CAPTURE_CONFIG["interface"],
            "filter": CAPTURE_CONFIG["filter"],
            "enabled": CAPTURE_CONFIG["enabled"]
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/capture/stop", methods=["POST"])
def stop_capture():
    """Stop real-time packet capture"""
    try:
        stop_packet_capture()
        
        return jsonify({
            "message": "Packet capture stopped successfully",
            "enabled": CAPTURE_CONFIG["enabled"]
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/capture/status", methods=["GET"])
def capture_status():
    """Get current capture status and configuration"""
    return jsonify({
        "enabled": CAPTURE_CONFIG["enabled"],
        "interface": CAPTURE_CONFIG["interface"],
        "filter": CAPTURE_CONFIG["filter"],
        "capture_mode": server_stats["capture_mode"],
        "available_interfaces": get_network_interfaces()
    })

@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Get comprehensive server and prediction statistics"""
    current_stats = get_system_stats()
    
    total_preds = server_stats["total_predictions"]
    attack_rate = (server_stats["attack_count"] / total_preds * 100) if total_preds > 0 else 0
    
    one_hour_ago = datetime.now() - timedelta(hours=1)
    recent_activity = [p for p in recent_predictions 
                      if datetime.fromisoformat(p["timestamp"]) > one_hour_ago]
    
    hourly_attacks = len([p for p in recent_activity if p["prediction"] == "attaque"])
    hourly_normal = len([p for p in recent_activity if p["prediction"] == "normal"])
    
    return jsonify({
        "system": {
            "cpu_usage": current_stats["cpu_usage"],
            "memory_usage": current_stats["memory_usage"],
            "disk_usage": current_stats["disk_usage"],
            "uptime": time.time() - server_stats["uptime"]
        },
        "predictions": {
            "total": server_stats["total_predictions"],
            "attacks": server_stats["attack_count"],
            "normal": server_stats["normal_count"],
            "attack_rate": round(attack_rate, 2),
            "hourly_attacks": hourly_attacks,
            "hourly_normal": hourly_normal
        },
        "capture": {
            "enabled": CAPTURE_CONFIG["enabled"],
            "mode": server_stats["capture_mode"],
            "interface": CAPTURE_CONFIG["interface"]
        },
        "email_status": {
            "enabled": EMAIL_SETTINGS.get("enabled", False),
            "emails_sent_this_hour": emails_sent_this_hour,
            "last_email_sent": last_email_sent.isoformat() if last_email_sent else None
        }
    })

@app.route("/api/recent-predictions", methods=["GET"])
def get_recent_predictions():
    """Get recent predictions with optional filtering"""
    limit = request.args.get("limit", 50, type=int)
    prediction_type = request.args.get("type", None)
    
    filtered_predictions = recent_predictions
    if prediction_type:
        filtered_predictions = [p for p in recent_predictions if p["prediction"] == prediction_type]
    
    return jsonify(filtered_predictions[-limit:])

@app.route("/api/attack-analysis", methods=["GET"])
def get_attack_analysis():
    """Analyze attack patterns and provide insights"""
    attacks = [p for p in recent_predictions if p["prediction"] == "attaque"]
    
    if not attacks:
        return jsonify({"message": "No attacks detected yet"})
    
    proto_counts = {}
    service_counts = {}
    hourly_distribution = {}
    ip_counts = {}
    
    for attack in attacks:
        proto = attack.get("proto", "unknown")
        proto_counts[proto] = proto_counts.get(proto, 0) + 1
        
        service = attack.get("service", "unknown")
        service_counts[service] = service_counts.get(service, 0) + 1
        
        hour = datetime.fromisoformat(attack["timestamp"]).hour
        hourly_distribution[hour] = hourly_distribution.get(hour, 0) + 1
        
        src_ip = attack.get("src_ip", "unknown")
        ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
    
    return jsonify({
        "total_attacks": len(attacks),
        "protocol_distribution": proto_counts,
        "service_distribution": service_counts,
        "hourly_distribution": hourly_distribution,
        "source_ip_distribution": ip_counts,
        "most_targeted_protocol": max(proto_counts.items(), key=lambda x: x[1]) if proto_counts else None,
        "most_targeted_service": max(service_counts.items(), key=lambda x: x[1]) if service_counts else None,
        "peak_attack_hour": max(hourly_distribution.items(), key=lambda x: x[1]) if hourly_distribution else None,
        "top_attacker_ip": max(ip_counts.items(), key=lambda x: x[1]) if ip_counts else None
    })

@socketio.on("connect")
def handle_connect():
    """Handle client connection"""
    emit("connected", {"message": "Connected to IDS monitoring system"})
    
    current_stats = get_system_stats()
    emit("system_stats", {
        "cpu": current_stats["cpu_usage"],
        "memory": current_stats["memory_usage"],
        "disk": current_stats["disk_usage"],
        "uptime": time.time() - server_stats["uptime"],
        "timestamp": current_stats["timestamp"],
        "capture_mode": server_stats["capture_mode"],
        "capture_enabled": CAPTURE_CONFIG["enabled"]
    })

@socketio.on("new_prediction")
def handle_new_prediction(data):
    print(f"[WebSocket] Received new_prediction event: {data}")
    
    server_stats["total_predictions"] += 1

    if data["prediction"] == "attaque":
        server_stats["attack_count"] += 1
        send_attack_email(data)
    else:
        server_stats["normal_count"] += 1

    recent_predictions.append(data)
    if len(recent_predictions) > MAX_RECENT_PREDICTIONS:
        recent_predictions.pop(0)

    emit("new_prediction", data, broadcast=True)

@socketio.on("disconnect")
def handle_disconnect():
    """Handle client disconnection"""
    print("Client disconnected")

if __name__ == "__main__":
    print("🛡️ Starting Enhanced IDS Monitoring System...")
    print("📊 System monitoring active")
    print(f"🔍 Model loaded: {len(features)} features")
    print(f"📧 Email notifications: {'Enabled' if EMAIL_SETTINGS.get('enabled') else 'Disabled'}")
    print(f"🌐 Available network interfaces: {', '.join(get_network_interfaces())}")
    print("🔍 Real-time packet capture: Ready (use /api/capture/start to begin)")
    print("🌐 Server starting on http://0.0.0.0:5000")
    
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)