import pandas as pd
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# Load the training data to fit the LabelEncoders
colonnes = [f'feature_{i}' for i in range(41)] + ['label', 'difficulty']
data = pd.read_csv("NSL_KDD/KDDTrain+.txt", names=colonnes)

# Create and fit LabelEncoders for the categorical columns
encoders = {}
for col in ['feature_1', 'feature_2', 'feature_3']:
    le = LabelEncoder()
    data[col] = le.fit_transform(data[col])
    encoders[col] = le

# Save the fitted encoders
joblib.dump(encoders, 'model/label_encoders.pkl')

print("✅ LabelEncoders fitted and saved.")


