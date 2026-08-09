import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)


DATA_FILE = "data/sms_spam_dataset.csv"
MODEL_FILE = "ml/spam_model.pkl"


print("\nLoading dataset...")

data = pd.read_csv(DATA_FILE)
data = data.dropna()

print("Total samples:", len(data))

print("\nClass distribution:")
print(data["label"].value_counts())


X = data["message"].astype(str)
y = data["label"].astype(str)


X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


model = Pipeline([

    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            ngram_range=(1, 2),
            max_features=15000,
            sublinear_tf=True
        )
    ),

    (
        "classifier",
        LogisticRegression(
            max_iter=2000,
            class_weight="balanced"
        )
    )

])


print("\nTraining Digital Guardian ML model...")


model.fit(
    X_train,
    y_train
)


predictions = model.predict(
    X_test
)


accuracy = accuracy_score(
    y_test,
    predictions
)


precision = precision_score(
    y_test,
    predictions,
    pos_label="spam",
    zero_division=0
)


recall = recall_score(
    y_test,
    predictions,
    pos_label="spam",
    zero_division=0
)


f1 = f1_score(
    y_test,
    predictions,
    pos_label="spam",
    zero_division=0
)


print("\n=====================================")
print(" DIGITAL GUARDIAN ML MODEL REPORT")
print("=====================================")

print(f"\nAccuracy : {accuracy * 100:.2f}%")
print(f"Precision: {precision * 100:.2f}%")
print(f"Recall   : {recall * 100:.2f}%")
print(f"F1 Score : {f1 * 100:.2f}%")


print("\nConfusion Matrix:")

print(
    confusion_matrix(
        y_test,
        predictions
    )
)


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        zero_division=0
    )
)


joblib.dump(
    model,
    MODEL_FILE
)


print("\nModel saved successfully:")
print(MODEL_FILE)
