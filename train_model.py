import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os

# Create model directory if it doesn't exist
os.makedirs("model", exist_ok=True)

# Load preprocessed data
try:
    X = pd.read_csv('data/X.csv')
    y = pd.read_csv('data/y.csv')
    print("Successfully loaded X.csv and y.csv")
    print("Unique values in feature_1 (X.csv):", X['feature_1'].unique())
except Exception as e:
    print(f"Error loading X.csv or y.csv: {str(e)}")
    exit(1)

# Load original dataset to fit encoders
colonnes = [f'feature_{i}' for i in range(41)] + ['label', 'difficulty']
try:
    data = pd.read_csv("NSL_KDD/KDDTrain+.txt", names=colonnes)
    print("Successfully loaded KDDTrain+.txt")
    print("Unique values in feature_1 (KDDTrain+.txt):", data['feature_1'].unique())
except Exception as e:
    print(f"Error loading KDDTrain+.txt: {str(e)}")
    exit(1)

# Encode categorical columns
label_encoders = {}
for col in ['feature_1', 'feature_2', 'feature_3']:
    le = LabelEncoder()
    data[col] = le.fit_transform(data[col])
    label_encoders[col] = le
    print(f"Saved {col} classes: {le.classes_}")

# Verify no categorical columns in X
categorical_cols = X.select_dtypes(include=['object']).columns.tolist()
print(f"Categorical columns in X.csv: {categorical_cols}")

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42)

# Train scaler
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train_scaled, y_train.values.ravel())

# Evaluate
y_pred = model.predict(X_test_scaled)
print(classification_report(y_test, y_pred))

# Save model, encoders, and scaler
joblib.dump(model, 'model/model_ids.pkl')
joblib.dump(label_encoders, 'model/label_encoders.pkl')
joblib.dump(scaler, 'model/scaler.pkl')

print("✅ Model, encoders, and scaler saved to /model")
joblib.dump(scaler, 'model/scaler.pkl')

print("✅ Modèle, encodeurs et scaler entraînés et sauvegardés dans /model")
