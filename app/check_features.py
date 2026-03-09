import joblib

#This file lists all the features used in the model training. 
# It can be used to verify that the correct features are being extracted from the live data and passed to the model for scoring.
# Make sure to run this file after you have trained the model and saved the artifacts, 
feature_columns = joblib.load("artifacts/feature_columns.pkl")

print("Number of features:", len(feature_columns))
print("\nFeature columns:\n")

for col in feature_columns:
    print(col)