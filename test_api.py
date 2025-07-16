import requests

# URL de ton API
url = "http://127.0.0.1:5000/predict"

# Exemple de connexion réseau simulée (avec 41 features numériques)
data = {
    f"feature_{i}": 0 for i in range(41)
}

# Exemple : simule une attaque en modifiant certains paramètres
data["feature_1"] = 2   # protocole (ex: udp)
data["feature_2"] = 10  # service (ex: telnet)
data["feature_3"] = 5   # flag

# Envoi de la requête POST
response = requests.post(url, json=data)

# Affiche la prédiction
print("🧠 Prédiction IA :", response.json()["prediction"])
