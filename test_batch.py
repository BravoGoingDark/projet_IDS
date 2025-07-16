import pandas as pd
import requests

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
    correct = 0

    # Variables pour métriques
    TP = 0  # vrais positifs (attaque détectée et attaque réelle)
    FP = 0  # faux positifs (attaque détectée mais c'était normal)
    FN = 0  # faux négatifs (normal détecté mais c'était attaque)
    TN = 0  # vrais négatifs (normal détecté et c'était normal)

    url = "http://127.0.0.1:5000/predict"

    for i in range(n_tests):
        exemple = data.iloc[i]
        features = exemple.drop(['label', 'difficulty'])
        features_dict = features.to_dict()

        features_dict['feature_1'] = protocole_encodage.get(features_dict['feature_1'], -1)
        features_dict['feature_2'] = service_encodage.get(features_dict['feature_2'], -1)
        features_dict['feature_3'] = flag_encodage.get(features_dict['feature_3'], -1)

        response = requests.post(url, json=features_dict)
        pred = response.json()['prediction']

        pred_bin = 0 if pred == 'normal' else 1
        label_bin = label_to_binary(exemple['label'])

        if pred_bin == label_bin:
            correct += 1

        # Calcul des TP, FP, FN, TN
        if pred_bin == 1 and label_bin == 1:
            TP += 1
        elif pred_bin == 1 and label_bin == 0:
            FP += 1
        elif pred_bin == 0 and label_bin == 1:
            FN += 1
        elif pred_bin == 0 and label_bin == 0:
            TN += 1

        if i % 100 == 0:
            print(f"Test {i}: prédiction={pred}, label={exemple['label']}")

    precision_globale = correct / n_tests * 100

    # Calcul Precision, Recall, F1 pour la classe "attaque"
    precision_attaque = TP / (TP + FP) if (TP + FP) > 0 else 0
    rappel_attaque = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1_score = (2 * precision_attaque * rappel_attaque) / (precision_attaque + rappel_attaque) if (precision_attaque + rappel_attaque) > 0 else 0

    print(f"\nPrécision globale (normal vs attaque) : {precision_globale:.2f}%")
    print(f"Précision sur attaques : {precision_attaque:.2f}")
    print(f"Rappel (Recall) sur attaques : {rappel_attaque:.2f}")
    print(f"F1-score sur attaques : {f1_score:.2f}")

if __name__ == "__main__":
    main()
