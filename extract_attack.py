import pandas as pd
import json

df = pd.read_csv(r"NSL_KDD\KDDTrain+.txt", header=None)
df.columns = [f"feature_{i}" for i in range(41)] + ["label", "difficulty"]

attaque = df[df["label"] != "normal"].iloc[0]

# Convertir les valeurs en types Python natifs
sample = {}
for i in range(41):
    value = attaque[f"feature_{i}"]
    if pd.isna(value):
        sample[f"feature_{i}"] = None
    else:
        sample[f"feature_{i}"] = value.item() if hasattr(value, 'item') else value

with open("attaque_reelle.json", "w") as f:
    json.dump(sample, f, indent=2)

print("✅ attaque_reelle.json créé avec succès")
