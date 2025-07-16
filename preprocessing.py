import pandas as pd
from sklearn.preprocessing import LabelEncoder
import os

# Créer dossier data si inexistant
os.makedirs("data", exist_ok=True)

# Charger le fichier d'entraînement
colonnes = [f'feature_{i}' for i in range(41)] + ['label', 'difficulty']
data = pd.read_csv("NSL_KDD/KDDTrain+.txt", names=colonnes)

# Encoder les colonnes catégorielles : protocole, service, flag
for col in ['feature_1', 'feature_2', 'feature_3']:
    le = LabelEncoder()
    data[col] = le.fit_transform(data[col])

# Transformer les labels : "normal" ou "attaque"
data['label'] = data['label'].apply(lambda x: 'normal' if x == 'normal' else 'attaque')

# Séparer X et y
X = data.drop(columns=['label', 'difficulty'])
y = data[['label']]

# Sauvegarder dans le dossier data/
X.to_csv("data/X.csv", index=False)
y.to_csv("data/y.csv", index=False)

print("✅ Prétraitement terminé, fichiers X.csv et y.csv sauvegardés dans /data")
