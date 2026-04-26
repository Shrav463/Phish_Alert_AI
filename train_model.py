import argparse
import csv
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATA_PATH = BASE_DIR / "data" / "emails.csv"
DEFAULT_MODEL_PATH = BASE_DIR / "model" / "scam_detector.joblib"


def clean(value: object) -> str:
    return str(value or "").replace("\x00", " ").strip()


def combine_email_text(row: dict[str, str]) -> str:
    sender = clean(row.get("sender") or row.get("Sender"))
    subject = clean(row.get("subject") or row.get("Subject"))
    body = clean(row.get("body") or row.get("Body"))
    urls = clean(row.get("urls") or row.get("URL") or row.get("url"))

    return "\n".join(
        [
            f"Sender: {sender}",
            f"Subject: {subject}",
            f"URLs: {urls}",
            "",
            body,
        ]
    ).strip()


def load_dataset(path: Path, limit: int | None = None) -> tuple[list[str], list[int]]:
    texts: list[str] = []
    labels: list[int] = []
    skipped = 0

    with path.open(encoding="utf-8", errors="replace", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            label = clean(row.get("label") or row.get("Label")).lower()
            if label not in {"0", "1"}:
                skipped += 1
                continue

            text = combine_email_text(row)
            if len(text) < 20:
                skipped += 1
                continue

            texts.append(text)
            labels.append(int(label))

            if limit and len(labels) >= limit:
                break

    print(f"Loaded {len(labels):,} valid labeled rows from {path}")
    print(f"Skipped {skipped:,} rows with blank/invalid labels or too little text")
    return texts, labels


def train(data_path: Path, model_path: Path, limit: int | None) -> None:
    texts, labels = load_dataset(data_path, limit=limit)
    if len(set(labels)) < 2:
        raise ValueError("Dataset must contain both label 0 and label 1 rows.")

    x_train, x_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    stop_words="english",
                    ngram_range=(1, 2),
                    max_features=120_000,
                    min_df=2,
                    max_df=0.95,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=1000,
                    solver="liblinear",
                ),
            ),
        ]
    )

    print("Training TF-IDF + Logistic Regression model...")
    pipeline.fit(x_train, y_train)

    predictions = pipeline.predict(x_test)
    probabilities = pipeline.predict_proba(x_test)[:, 1]

    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print(f"ROC AUC: {roc_auc_score(y_test, probabilities):.4f}")
    print(classification_report(y_test, predictions, target_names=["legitimate", "spam/phishing"]))

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "pipeline": pipeline,
            "model_type": "tfidf_logistic_regression",
            "label_map": {"0": "legitimate", "1": "spam/phishing"},
        },
        model_path,
    )
    print(f"Saved model to {model_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Gmail Scam Detector ML model.")
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA_PATH)
    parser.add_argument("--out", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--limit", type=int, default=None, help="Optional max valid rows for quick tests.")
    args = parser.parse_args()

    train(args.data, args.out, args.limit)


if __name__ == "__main__":
    main()
