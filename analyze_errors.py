import pandas as pd
import requests
from collections import defaultdict

def label_to_binary(label):
    return 0 if label == "normal" else 1

def main():
    colonnes = [f'feature_{i}' for i in range(41)] + ['label', 'difficulty']
    data = pd.read_csv("NSL_KDD/KDDTest+.txt", names=colonnes)

    protocole_encodage = {'tcp': 0, 'udp': 1, 'icmp': 2}
    service_encodage = {
        'http': 0, 'domain_u': 1, 'smtp': 2, 'ftp': 3, 'telnet': 4, 'other': 5,
    }
    flag_encodage = {'SF': 0, 'S0': 1, 'REJ': 2, 'RSTR': 3, 'RSTO': 4, 'SH': 5}

    n_tests = 1000
    url = "http://127.0.0.1:5000/predict"

    errors = defaultdict(int)

    for i in range(n_tests):
        exemple = data.iloc[i]
        features = exemple.drop(['label', 'difficulty'])
        features_dict = features.to_dict()

        features_dict['feature_1'] = protocole_encodage.get(features_dict['feature_1'], -1)
        features_dict['feature_2'] = service_encodage.get(features_dict['feature_2'], -1)
        features_dict['feature_3'] = flag_encodage.get(features_dict['feature_3'], -1)

        label = exemple['label']
        label_bin = label_to_binary(label)

        response = requests.post(url, json=features_dict)
        pred = response.json()['prediction']
        pred_bin = 0 if pred == "normal" else 1

        # Faux négatif : le modèle a dit "normal" mais c’était une attaque
        if pred_bin == 0 and label_bin == 1:
            errors[label] += 1

    # Afficher les attaques souvent ratées
    print("\n🔍 Attaques souvent ratées (faux négatifs) :")
    if errors:
        for label, count in sorted(errors.items(), key=lambda x: x[1], reverse=True):
            print(f"- {label} : {count} fois")
    else:
        print("✅ Aucune attaque manquée dans ces 1000 exemples.")

if __name__ == "__main__":
    main()
