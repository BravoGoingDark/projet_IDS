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

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from config import EMAIL_CONFIG, EMAIL_SETTINGS  # Import from config.py

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
    "uptime": time.time()
}

# Store recent predictions for analysis
recent_predictions = []
MAX_RECENT_PREDICTIONS = 1000

def send_attack_email(attack_data):
    """Send email notification when attack is detected"""
    global last_email_sent, emails_sent_this_hour, email_hour_reset
    
    # Check if email notifications are enabled
    if not EMAIL_SETTINGS.get("enabled", False):
        return
    
    current_time = datetime.now()
    
    # Reset hourly counter if needed
    if current_time.hour != email_hour_reset.hour:
        emails_sent_this_hour = 0
        email_hour_reset = current_time
    
    # Check cooldown period
    if last_email_sent:
        time_since_last = (current_time - last_email_sent).total_seconds() / 60
        if time_since_last < EMAIL_SETTINGS.get('cooldown_minutes', 5):
            print(f"Email cooldown active. {EMAIL_SETTINGS.get('cooldown_minutes', 5) - time_since_last:.1f} minutes remaining.")
            return
    
    # Check hourly limit
    if emails_sent_this_hour >= EMAIL_SETTINGS.get('max_emails_per_hour', 10):
        print("Hourly email limit reached. No more emails will be sent this hour.")
        return
    
    try:
        # Create email message
        msg = MIMEMultipart()
        msg["From"] = EMAIL_CONFIG["sender_email"]
        msg["To"] = EMAIL_CONFIG["recipient_email"]
        msg["Subject"] = "🚨 IDS ALERT: Attack Detected!"
        
        # Email body
        body = f"""
INTRUSION DETECTION SYSTEM ALERT

⚠️ ATTACK DETECTED ⚠️

Time: {attack_data.get('timestamp', 'Unknown')}
Protocol: {attack_data.get('proto', 'Unknown').upper()}
Service: {attack_data.get('service', 'Unknown')}
Flag: {attack_data.get('flag', 'Unknown')}
Prediction: {attack_data.get('prediction', 'Unknown').upper()}

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
        
        # Connect to server and send email
        server = smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"])
        server.starttls()  # Enable encryption
        server.login(EMAIL_CONFIG["sender_email"], EMAIL_CONFIG["sender_password"])
        
        text = msg.as_string()
        server.sendmail(EMAIL_CONFIG["sender_email"], EMAIL_CONFIG["recipient_email"], text)
        server.quit()
        
        # Update tracking variables
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
                # Handle unseen labels by assigning a default value
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
            
            # Store stats (keep last 60 data points - 1 hour of data)
            server_stats["cpu_usage"].append(stats["cpu_usage"])
            server_stats["memory_usage"].append(stats["memory_usage"])
            server_stats["disk_usage"].append(stats["disk_usage"])
            server_stats["timestamps"].append(current_time.isoformat())
            
            # Keep only last 60 entries (1 hour)
            if len(server_stats["cpu_usage"]) > 60:
                server_stats["cpu_usage"].pop(0)
                server_stats["memory_usage"].pop(0)
                server_stats["disk_usage"].pop(0)
                server_stats["timestamps"].pop(0)
            
            # Calculate predictions per minute
            one_minute_ago = current_time - timedelta(minutes=1)
            recent_count = len([p for p in recent_predictions 
                              if datetime.fromisoformat(p["timestamp"]) > one_minute_ago])
            
            server_stats["predictions_per_minute"].append(recent_count)
            if len(server_stats["predictions_per_minute"]) > 60:
                server_stats["predictions_per_minute"].pop(0)
            
            # Emit real-time stats to connected clients
            socketio.emit("system_stats", {
                "cpu": stats["cpu_usage"],
                "memory": stats["memory_usage"],
                "disk": stats["disk_usage"],
                "predictions_per_minute": recent_count,
                "uptime": time.time() - server_stats["uptime"],
                "timestamp": stats["timestamp"]
            })
            
        except Exception as e:
            print(f"Error in system monitoring: {e}")
        
        time.sleep(60)  # Update every minute

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
        
        # Store prediction
        prediction_data = {
            "prediction": pred,
            "proto": data.get("feature_1", "unknown"),
            "service": data.get("feature_2", "unknown"),
            "flag": data.get("feature_3", "unknown"),
            "timestamp": datetime.now().isoformat(),
            "raw_data": data,
            "src_ip": src_ip,
        }
        
        recent_predictions.append(prediction_data)
        if len(recent_predictions) > MAX_RECENT_PREDICTIONS:
            recent_predictions.pop(0)
        
        # Update counters
        server_stats["total_predictions"] += 1
        if pred == "attaque":
            server_stats["attack_count"] += 1
            # Send email notification for attacks
            send_attack_email(prediction_data)
        else:
            server_stats["normal_count"] += 1
        
        # Emit via WebSocket
        socketio.emit("new_prediction", prediction_data)
        
        return jsonify({"prediction": pred, "timestamp": prediction_data["timestamp"]})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Get comprehensive server and prediction statistics"""
    current_stats = get_system_stats()
    
    # Calculate attack rate
    total_preds = server_stats["total_predictions"]
    attack_rate = (server_stats["attack_count"] / total_preds * 100) if total_preds > 0 else 0
    
    # Get recent activity (last hour)
    one_hour_ago = datetime.now() - timedelta(hours=1)
    recent_activity = [p for p in recent_predictions 
                      if datetime.fromisoformat(p["timestamp"]) > one_hour_ago]
    
    # Calculate hourly stats
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
    prediction_type = request.args.get("type", None)  # "attaque" or "normal"
    
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
    
    # Analyze attack patterns
    proto_counts = {}
    service_counts = {}
    hourly_distribution = {}
    
    for attack in attacks:
        # Protocol analysis
        proto = attack.get("proto", "unknown")
        proto_counts[proto] = proto_counts.get(proto, 0) + 1
        
        # Service analysis
        service = attack.get("service", "unknown")
        service_counts[service] = service_counts.get(service, 0) + 1
        
        # Hourly distribution
        hour = datetime.fromisoformat(attack["timestamp"]).hour
        hourly_distribution[hour] = hourly_distribution.get(hour, 0) + 1
    
    return jsonify({
        "total_attacks": len(attacks),
        "protocol_distribution": proto_counts,
        "service_distribution": service_counts,
        "hourly_distribution": hourly_distribution,
        "most_targeted_protocol": max(proto_counts.items(), key=lambda x: x[1]) if proto_counts else None,
        "most_targeted_service": max(service_counts.items(), key=lambda x: x[1]) if service_counts else None,
        "peak_attack_hour": max(hourly_distribution.items(), key=lambda x: x[1]) if hourly_distribution else None
    })

@app.route("/api/email-config", methods=["GET", "POST"])
def email_config():
    """Get or update email configuration"""
    global EMAIL_CONFIG
    
    if request.method == "GET":
        # Return config without sensitive data
        safe_config = EMAIL_CONFIG.copy()
        safe_config["sender_password"] = "***hidden***" if safe_config.get("sender_password") else ""
        return jsonify(safe_config)
    
    elif request.method == "POST":
        # Update email configuration
        data = request.get_json()
        for key in ["sender_email", "recipient_email", "enabled", "cooldown_minutes", "max_emails_per_hour"]:
            if key in data:
                EMAIL_CONFIG[key] = data[key]
        
        # Only update password if provided
        if "sender_password" in data and data["sender_password"] != "***hidden***":
            EMAIL_CONFIG["sender_password"] = data["sender_password"]
        
        return jsonify({"message": "Email configuration updated successfully"})

@socketio.on("connect")
def handle_connect():
    """Handle client connection"""
    emit("connected", {"message": "Connected to IDS monitoring system"})
    
    # Send current stats to new client
    current_stats = get_system_stats()
    emit("system_stats", {
        "cpu": current_stats["cpu_usage"],
        "memory": current_stats["memory_usage"],
        "disk": current_stats["disk_usage"],
        "uptime": time.time() - server_stats["uptime"],
        "timestamp": current_stats["timestamp"]
    })

@socketio.on("new_prediction")
def handle_new_prediction(data):
    print(f"[WebSocket] Received new_prediction event: {data}")
    
    # Update counters
    total_predictions = server_stats["total_predictions"]
    attack_count = server_stats["attack_count"]
    normal_count = server_stats["normal_count"]

    if data["prediction"] == "attaque":
        attack_count += 1
        # Send email notification for attacks
        send_attack_email(data)
    else:
        normal_count += 1
    
    total_predictions += 1

    server_stats["total_predictions"] = total_predictions
    server_stats["attack_count"] = attack_count
    server_stats["normal_count"] = normal_count

    # Update recent_predictions list
    recent_predictions.append(data)
    if len(recent_predictions) > MAX_RECENT_PREDICTIONS:
        recent_predictions.pop(0)

    # Emit the updated prediction data back to the client
    emit("new_prediction", data, broadcast=True)

@socketio.on("disconnect")
def handle_disconnect():
    """Handle client disconnection"""
    print("Client disconnected")

if __name__ == "__main__":
    print("🛡️ Starting IDS Monitoring System...")
    print("📊 System monitoring active")
    print(f"🔍 Model loaded: {len(features)} features")
    print(f"📧 Email notifications: {'Enabled' if EMAIL_SETTINGS.get('enabled') else 'Disabled'}")
    print("🌐 Server starting on http://0.0.0.0:5000")
    
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)