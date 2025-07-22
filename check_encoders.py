import joblib
import os

file_path = "/home/vboxuser/projet_IDS/model/label_encoders.pkl"
print(f"Checking if file exists: {os.path.exists(file_path)}")
if not os.path.exists(file_path):
    print(f"Error: {file_path} does not exist")
    exit(1)
try:
    label_encoders = joblib.load(file_path)
    print(f"Loaded label_encoders: {label_encoders}")
    if not label_encoders:
        print("Error: label_encoders is empty")
    for col, le in label_encoders.items():
        print(f"{col} classes: {le.classes_}")
except Exception as e:
    print(f"Error loading or processing {file_path}: {str(e)}")
print("Script execution completed")
