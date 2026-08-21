import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = [
    'write_count','delete_count','create_count','rename_count',
    'write_entropy','ext_diversity','sensitive_path_access','read_write_ratio'
]

class ActivityML:
    """Unsupervised ML baseline for real-time file-activity anomaly detection.

    This model learns a baseline from low-risk activity windows observed on the
    monitored PC. It reports anomalies; it does NOT claim that an anomaly is
    proof of malware. Confirmed malware remains a separate scan classification.
    """
    def __init__(self, model_path):
        self.model_path = model_path
        self.scaler = StandardScaler()
        self.model = None
        self.samples = []
        self.ready = False
        self.max_samples = 40
        self._load()

    def _load(self):
        if not os.path.isfile(self.model_path):
            return
        try:
            obj = joblib.load(self.model_path)
            self.scaler = obj['scaler']
            self.model = obj['model']
            self.ready = True
        except Exception:
            self.model = None
            self.ready = False

    def _vector(self, features):
        return [float(features.get(k, 0) or 0) for k in FEATURES]

    def observe(self, features):
        """Learn from low-risk windows until baseline is ready, then score anomalies."""
        vector = self._vector(features)
        heuristic_score = float(features.get('score', 0) or 0)

        # Only use low-risk windows as baseline examples.
        if not self.ready and heuristic_score < 40:
            self.samples.append(vector)
            if len(self.samples) >= 12:
                X = np.asarray(self.samples[-self.max_samples:], dtype=float)
                self.scaler.fit(X)
                Xs = self.scaler.transform(X)
                self.model = IsolationForest(
                    n_estimators=100,
                    contamination=0.10,
                    random_state=42,
                    n_jobs=-1
                )
                self.model.fit(Xs)
                self.ready = True
                try:
                    joblib.dump({'scaler': self.scaler, 'model': self.model}, self.model_path)
                except Exception:
                    pass

        if not self.ready:
            return {
                'ml_ready': False,
                'ml_status': 'LEARNING BASELINE',
                'ml_anomaly_score': None,
                'ml_method': 'Isolation Forest anomaly detection',
                'ml_note': f'Collecting low-risk activity windows ({len(self.samples)}/12).'
            }

        X = self.scaler.transform([vector])
        prediction = int(self.model.predict(X)[0])
        decision = float(self.model.decision_function(X)[0])
        # Convert decision function into an easy-to-read anomaly score.
        anomaly_score = round(max(0.0, min(100.0, 50.0 - decision * 100.0)), 2)
        status = 'ANOMALY' if prediction == -1 else 'NORMAL'
        return {
            'ml_ready': True,
            'ml_status': status,
            'ml_anomaly_score': anomaly_score,
            'ml_method': 'Isolation Forest anomaly detection',
            'ml_note': 'Anomaly means unusual activity compared with the learned baseline; it is not proof of malware.'
        }
