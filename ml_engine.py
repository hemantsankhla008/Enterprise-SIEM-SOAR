import numpy as np
import math
from sklearn.ensemble import IsolationForest

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum([p * math.log2(p) for p in prob])

def extract_features(payload: str) -> list:
    length = len(payload)
    num_digits = sum(c.isdigit() for c in payload)
    num_special = sum(not c.isalnum() and not c.isspace() for c in payload)
    entropy = calculate_entropy(payload)
    return [length, num_digits, num_special, entropy]

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.15, random_state=42)
        
        baseline_payloads = [
            "GET /index.html HTTP/1.1 200 OK",
            "GET /about-us HTTP/1.1 200 OK",
            "POST /login HTTP/1.1 200 OK",
            "GET /static/css/style.css HTTP/1.1 200 OK",
            "GET /api/v1/health HTTP/1.1 200 OK",
            "User logged in successfully",
            "Session refreshed for active user"
        ]
        
        X_train = np.array([extract_features(p) for p in baseline_payloads])
        self.model.fit(X_train)

    def is_anomaly(self, payload: str) -> bool:
        features = np.array([extract_features(payload)])
        prediction = self.model.predict(features)
        return prediction[0] == -1

anomaly_detector = AnomalyDetector()