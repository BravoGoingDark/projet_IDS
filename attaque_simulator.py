from scapy.all import IP, TCP, send
import time

target_ip = "127.0.0.1"  # ou ton IP locale si capture depuis un autre terminal
target_port = 12345      # un port aléatoire (tu n’as pas besoin d’un serveur actif)

def attaque_syn():
    for i in range(10):
        pkt = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
        send(pkt, verbose=False)
        print(f"📦 SYN paquet {i+1} envoyé ➡️ {target_ip}:{target_port}")
        time.sleep(0.5)

if __name__ == "__main__":
    attaque_syn()
