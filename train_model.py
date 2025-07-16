import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

# Créer dossier model si inexistant
os.makedirs("model", exist_ok=True)

# Charger les données prétraitées
X = pd.read_csv('data/X.csv')
y = pd.read_csv('data/y.csv')

# Diviser en train/test
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42)

# Créer et entraîner le modèle
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train.values.ravel())

# Prédire sur test
y_pred = model.predict(X_test)

# Évaluer
print(classification_report(y_test, y_pred))

# Sauvegarder le modèle
joblib.dump(model, 'model/model_ids.pkl')
print("✅ Modèle entraîné et sauvegardé dans /model")
