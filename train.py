
import csv
import json
import random
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split

FEATURES = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "count",
    "srv_count",
    "serror_rate",
    "rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "dst_host_count",
    "failed_logins",
    "num_compromised",
]

LABELS = ["normal", "dos", "probe", "brute_force"]
LABEL_TO_ID = {label: i for i, label in enumerate(LABELS)}

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
TRAIN_PATH = DATA_DIR / "KDDTrain+.txt"
TEST_PATH = DATA_DIR / "KDDTest+.txt"
MODEL_PATH = BASE_DIR / "model.joblib"
METRICS_PATH = BASE_DIR / "metrics.json"

DOS_ATTACKS = {
    "neptune", "smurf", "back", "teardrop", "pod", "land",
    "apache2", "udpstorm", "processtable", "mailbomb",
}
PROBE_ATTACKS = {
    "portsweep", "ipsweep", "nmap", "satan", "mscan", "saint",
}


def map_label(raw_label):
    """Map NSL-KDD labels into the project's four existing classes."""
    attack = raw_label.strip().lower().rstrip(".")

    if attack == "normal":
        return "normal"
    if attack in DOS_ATTACKS:
        return "dos"
    if attack in PROBE_ATTACKS:
        return "probe"

    # Project-compatible fallback grouping, not a true attack taxonomy.
    return "brute_force"


def read_nsl_kdd(path):
    """Read NSL-KDD records and select the project's 12 numeric features."""
    X, y = [], []

    with path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.reader(file)

        for line_number, row in enumerate(reader, start=1):
            if len(row) < 43:
                raise ValueError(
                    f"{path.name}, line {line_number}: "
                    f"expected 43 columns, found {len(row)}"
                )

            try:
                # NSL-KDD columns are zero-indexed.
                values = [
                    float(row[0]),   # duration
                    float(row[4]),   # src_bytes
                    float(row[5]),   # dst_bytes
                    float(row[22]),  # count
                    float(row[23]),  # srv_count
                    float(row[24]),  # serror_rate
                    float(row[26]),  # rerror_rate
                    float(row[28]),  # same_srv_rate
                    float(row[29]),  # diff_srv_rate
                    float(row[31]),  # dst_host_count
                    float(row[10]),  # failed_logins
                    float(row[12]),  # num_compromised
                ]
            except ValueError as exc:
                raise ValueError(
                    f"{path.name}, line {line_number}: "
                    "a required feature is not numeric"
                ) from exc

            X.append(values)
            y.append(map_label(row[41]))

    if not X:
        raise ValueError(f"No records found in {path}")

    return np.asarray(X, dtype=float), np.asarray(y)


def gen_sample(label):
    """Generate one synthetic sample for fallback training."""

    if label == "normal":
        values = [
            np.random.exponential(5), np.random.lognormal(6, 1),
            np.random.lognormal(7, 1), random.randint(1, 25),
            random.randint(1, 25), random.uniform(0, 0.08),
            random.uniform(0, 0.08), random.uniform(0.75, 1),
            random.uniform(0, 0.15), random.randint(1, 120), 0, 0,
        ]
    elif label == "dos":
        values = [
            random.uniform(0, 0.5), random.uniform(0, 150), 0,
            random.randint(180, 500), random.randint(180, 500),
            random.uniform(0.75, 1), random.uniform(0, 0.1),
            random.uniform(0.9, 1), random.uniform(0, 0.06),
            random.randint(200, 255), 0, 0,
        ]
    elif label == "probe":
        values = [
            random.uniform(0, 2), random.uniform(0, 120),
            random.uniform(0, 200), random.randint(5, 70),
            random.randint(1, 6), random.uniform(0, 0.35),
            random.uniform(0.45, 1), random.uniform(0, 0.3),
            random.uniform(0.5, 1), random.randint(100, 255), 0, 0,
        ]
    else:
        values = [
            random.uniform(1, 10), random.uniform(100, 350),
            random.uniform(100, 450), random.randint(3, 35),
            random.randint(3, 35), random.uniform(0, 0.12),
            random.uniform(0, 0.25), random.uniform(0.9, 1),
            0, random.randint(1, 25), random.randint(3, 15),
            random.randint(0, 3),
        ]

    integer_features = {
        "count", "srv_count", "dst_host_count",
        "failed_logins", "num_compromised",
    }

    return [
        int(value) if name in integer_features else round(float(value), 4)
        for name, value in zip(FEATURES, values)
    ]


def get_synthetic_data():
    """Create reproducible synthetic training and test samples."""
    random.seed(42)
    np.random.seed(42)

    X, y = [], []
    for label in LABELS:
        for _ in range(2500):
            X.append(gen_sample(label))
            y.append(label)

    return train_test_split(
        np.asarray(X, dtype=float),
        np.asarray(y),
        test_size=0.2,
        random_state=42,
        stratify=y,
    )


def train():
    """Train on NSL-KDD when available; otherwise use synthetic fallback."""
    random.seed(42)
    np.random.seed(42)

    source = "synthetic_fallback"

    if TRAIN_PATH.is_file() and TEST_PATH.is_file():
        try:
            X_train, y_train = read_nsl_kdd(TRAIN_PATH)
            X_test, y_test = read_nsl_kdd(TEST_PATH)
            source = "NSL-KDD"
            print("Dataset: real NSL-KDD train/test files")
        except (OSError, ValueError) as exc:
            print(f"Could not load NSL-KDD dataset: {exc}")
            print("Falling back to synthetic training data.")
            X_train, X_test, y_train, y_test = get_synthetic_data()
    else:
        print("NSL-KDD files not found; using synthetic fallback.")
        X_train, X_test, y_train, y_test = get_synthetic_data()

    # Numeric IDs keep predict_proba() columns aligned with LABELS in app.py.
    y_train_ids = np.asarray([LABEL_TO_ID[label] for label in y_train])
    y_test_ids = np.asarray([LABEL_TO_ID[label] for label in y_test])

    model = RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    model.fit(X_train, y_train_ids)

    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test_ids, predictions)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test_ids,
        predictions,
        labels=list(range(len(LABELS))),
        zero_division=0,
    )

    print("\nClassification Report")
    print(
        classification_report(
            y_test_ids,
            predictions,
            labels=list(range(len(LABELS))),
            target_names=LABELS,
            zero_division=0,
        )
    )
    print("Confusion matrix (rows=actual, columns=predicted):")
    print(confusion_matrix(y_test_ids, predictions, labels=list(range(len(LABELS)))))
    print(f"Accuracy: {accuracy * 100:.2f}%")
    print(f"Training samples: {len(X_train)}")
    print(f"Test samples: {len(X_test)}")
    print(f"Training source: {source}")

    joblib.dump(model, MODEL_PATH)

    importance = sorted(
        zip(FEATURES, model.feature_importances_),
        key=lambda item: item[1],
        reverse=True,
    )

    metrics = {
        "source": source,
        "accuracy": round(float(accuracy * 100), 2),
        "samples": int(len(X_train) + len(X_test)),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "labels": LABELS,
        "precision": {
            label: round(float(precision[i]) * 100, 2)
            for i, label in enumerate(LABELS)
        },
        "recall": {
            label: round(float(recall[i]) * 100, 2)
            for i, label in enumerate(LABELS)
        },
        "f1": {
            label: round(float(f1[i]) * 100, 2)
            for i, label in enumerate(LABELS)
        },
        "importance": [
            [name, round(float(value), 6)]
            for name, value in importance[:6]
        ],
    }

    with METRICS_PATH.open("w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=4)

    print(f"\nModel saved to: {MODEL_PATH}")
    print(f"Metrics saved to: {METRICS_PATH}")


if __name__ == "__main__":
    train()
