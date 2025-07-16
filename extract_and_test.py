import pandas as pd
import random
import requests

# Dictionnaires d'encodage
protocole_encodage = {'tcp': 0, 'udp': 1, 'icmp': 2}
service_encodage = {
    'http': 0, 'domain_u': 1, 'smtp': 2, 'ftp': 3, 'telnet': 4, 'other': 5,
    # complète selon ton dataset
}
flag_encodage = {'SF': 0, 'S0': 1, 'REJ': 2, 'RSTR': 3, 'RSTO': 4, 'SH': 5}

def main():
    colonnes = [f'feature_{i}' for i in range(41)] + ['label', 'difficulty']
    data = pd.read_csv("NSL_KDD/KDDTest+.txt", names=colonnes)

    index_aleatoire = random.randint(0, len(data) - 1)
    exemple = data.iloc[index_aleatoire]

    features = exemple.drop(['label', 'difficulty'])
    features_dict = features.to_dict()

    # Encoder les variables catégorielles en nombres
    features_dict['feature_1'] = protocole_encodage.get(features_dict['feature_1'], -1)
    features_dict['feature_2'] = service_encodage.get(features_dict['feature_2'], -1)
    features_dict['feature_3'] = flag_encodage.get(features_dict['feature_3'], -1)

    print(f"Exemple index {index_aleatoire} encodé envoyé à l'API:")
    print(features_dict)

    url = "http://127.0.0.1:5000/predict"
    response = requests.post(url, json=features_dict)

    print("Prédiction IA :", response.json()['prediction'])
    print("Label réel   :", exemple['label'])

if __name__ == "__main__":
    main()
