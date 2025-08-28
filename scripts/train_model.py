import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import joblib


# Load your data
df = pd.read_csv("DomainAccurateDataCSVType.csv")

# Drop 'domain' column and separate label
X = df.drop(columns=["domain", "is_phishing"])
y = df["is_phishing"]


# Encode 'tld' 
le = LabelEncoder()
X["tld"] = le.fit_transform(X["tld"])


# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


# Train the model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)


# Evaluate
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))


joblib.dump(model, "phishing_model.pkl")
joblib.dump(le, "label_encoder.pkl")






