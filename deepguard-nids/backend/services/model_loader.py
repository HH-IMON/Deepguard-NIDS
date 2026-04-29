"""
DeepGuard NIDS - ML Model Engine
Handles both simulated (rule-based) and real (trained) ML models.
"""

import random
import math
import hashlib
import os
import json
import joblib


class ModelEngine:
    """
    Manages detection models. Switches between real-trained models and 
    sophisticated mock simulations as needed.
    """

    # --- Pre-computed evaluation metrics (Mocks) ---
    EVALUATION_METRICS = {
        "random_forest": {
            "accuracy": 0.9724, "precision": 0.9681, "recall": 0.9589,
            "f1_score": 0.9635, "false_positive_rate": 0.0218,
            "confusion_matrix": [[4521, 98], [167, 3914]],
            "training_time": "12.4s", "inference_time": "0.8ms",
            "description": "Ensemble of decision trees using bagging.",
            "hyperparameters": {"n_estimators": 200, "max_depth": 25}
        },
        "xgboost": {
            "accuracy": 0.9812, "precision": 0.9793, "recall": 0.9701,
            "f1_score": 0.9747, "false_positive_rate": 0.0156,
            "confusion_matrix": [[4563, 56], [121, 3960]],
            "training_time": "18.7s", "inference_time": "0.5ms",
            "description": "Gradient boosted trees with regularization.",
            "hyperparameters": {"n_estimators": 300, "learning_rate": 0.1}
        },
        "lstm": {
            "accuracy": 0.9687, "precision": 0.9612, "recall": 0.9723,
            "f1_score": 0.9667, "false_positive_rate": 0.0289,
            "confusion_matrix": [[4486, 133], [113, 3968]],
            "training_time": "245.3s", "inference_time": "3.2ms",
            "description": "Long Short-Term Memory network capturing temporal patterns.",
            "hyperparameters": {"units": 128, "layers": 2}
        },
        "cnn_1d": {
            "accuracy": 0.9751, "precision": 0.9718, "recall": 0.9654,
            "f1_score": 0.9686, "false_positive_rate": 0.0201,
            "confusion_matrix": [[4532, 87], [129, 3952]],
            "training_time": "156.8s", "inference_time": "2.1ms",
            "description": "1D Convolutional Neural Network extracting spatial features.",
            "hyperparameters": {"filters": [64, 128], "kernel_size": 3}
        },
        "autoencoder": {
            "accuracy": 0.9534, "precision": 0.9389, "recall": 0.9812,
            "f1_score": 0.9596, "false_positive_rate": 0.0423,
            "confusion_matrix": [[4424, 195], [76, 4005]],
            "training_time": "189.2s", "inference_time": "1.8ms",
            "description": "Unsupervised anomaly detector. High reconstruction error = attack.",
            "hyperparameters": {"encoding_dim": 32}
        }
    }

    # --- Feature importance weights (Mocks) ---
    FEATURE_IMPORTANCE = {
        "random_forest": {"dst_port": 0.25, "packet_size": 0.20, "protocol": 0.15, "src_port": 0.10, "flow_duration": 0.30},
        "xgboost": {"dst_port": 0.28, "packet_size": 0.22, "protocol": 0.12, "src_port": 0.08, "flow_duration": 0.30},
        "lstm": {"flow_duration": 0.35, "packet_size": 0.20, "dst_port": 0.15, "protocol": 0.15, "src_port": 0.15},
        "cnn_1d": {"packet_size": 0.30, "dst_port": 0.20, "protocol": 0.15, "src_port": 0.15, "flow_duration": 0.20},
        "autoencoder": {"packet_size": 0.25, "flow_duration": 0.25, "dst_port": 0.20, "protocol": 0.15, "src_port": 0.15}
    }

    def __init__(self):
        self.active_model = "random_forest"
        self._ip_history = {}
        self.real_models = {}
        self._load_real_models()

    def _load_real_models(self):
        try:
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
            # Map of internal file names to dashboard IDs
            mapping = {
                "rf": "random_forest",
                "xgb": "xgboost",
                "lstm": "lstm",
                "cnn_1d": "cnn_1d",
                "ae": "autoencoder"
            }
            for m_key, d_id in mapping.items():
                model_path = os.path.join(base_dir, f"{m_key}_model.joblib")
                metrics_path = os.path.join(base_dir, f"{m_key}_metrics.json")
                if os.path.exists(model_path) and os.path.exists(metrics_path):
                    self.real_models[d_id] = joblib.load(model_path)
                    with open(metrics_path, "r") as f:
                        metrics = json.load(f)
                        self.EVALUATION_METRICS[d_id] = metrics
                        if "feature_importance" in metrics:
                            self.FEATURE_IMPORTANCE[d_id] = metrics["feature_importance"]
                    print(f"[ModelEngine] Loaded REAL {d_id} model and metrics.")
        except Exception as e:
            print(f"[ModelEngine] Error loading real models: {e}")

    def set_active_model(self, model_id):
        if model_id in self.EVALUATION_METRICS:
            self.active_model = model_id
            return True
        return False

    def predict(self, packet_features):
        src_ip = packet_features.get("source_ip", "0.0.0.0")
        dst_port = packet_features.get("dst_port", 0)
        packet_size = packet_features.get("packet_size", 64)
        
        # IP History
        if src_ip not in self._ip_history:
            self._ip_history[src_ip] = {"count": 0}
        self._ip_history[src_ip]["count"] += 1
        hist_count = self._ip_history[src_ip]["count"]

        # --- Use Real Model if available ---
        real_model = self.real_models.get(self.active_model)
        if real_model:
            # Prepare features
            if "real_features" in packet_features:
                rf = packet_features["real_features"]
                x = [[rf["protocol"], rf["src_bytes"], rf["dst_bytes"], rf["duration"], rf["count"], rf["srv_count"]]]
            else:
                proto_map = {"TCP": 0, "UDP": 1, "ICMP": 2}
                x = [[proto_map.get(packet_features.get("protocol", "TCP"), 0), packet_size, 0, 0, hist_count, hist_count]]

            # Prediction
            try:
                # Autoencoder / IsolationForest special handling
                if self.active_model == "autoencoder":
                    pred_raw = real_model.predict(x)[0]
                    pred_label = "Normal" if pred_raw == 1 else "DoS"
                    confidence = 0.95
                else:
                    pred_raw = real_model.predict(x)[0]
                    # If encoded labels were used, we need the classes
                    metrics = self.EVALUATION_METRICS[self.active_model]
                    classes = metrics.get("classes", ["Normal", "DoS"])
                    
                    if isinstance(pred_raw, (int, np.integer)) and len(classes) > pred_raw:
                        pred_label = classes[pred_raw]
                    else:
                        pred_label = pred_raw
                        
                    probas = real_model.predict_proba(x)[0]
                    confidence = float(max(probas))

                severity_map = {
                    "Normal": "none", "DoS": "high", "DDoS": "critical",
                    "Brute Force": "medium", "Port Scan": "low",
                    "Botnet": "critical", "Web Attack": "high", "Infiltration": "critical"
                }

                return {
                    "prediction": pred_label,
                    "confidence": round(confidence, 4),
                    "is_attack": pred_label != "Normal",
                    "severity": severity_map.get(pred_label, "medium"),
                    "model_used": f"{self.active_model} (REAL)"
                }
            except Exception as e:
                print(f"[ModelEngine] Real prediction failed: {e}")

        # --- Fallback to Mock Simulation ---
        is_attack = random.random() < 0.15
        prediction = random.choice(["DoS", "DDoS", "Brute Force"]) if is_attack else "Normal"
        return {
            "prediction": prediction,
            "confidence": 0.85,
            "is_attack": is_attack,
            "severity": "high" if is_attack else "none",
            "model_used": f"{self.active_model} (SIM)"
        }

    def get_evaluation(self, model_id=None):
        return self.EVALUATION_METRICS.get(model_id or self.active_model, {})

    def get_all_evaluations(self):
        return self.EVALUATION_METRICS

    def get_feature_importance(self, model_id=None):
        return self.FEATURE_IMPORTANCE.get(model_id or self.active_model, {})


_model_engine = None
def get_model_engine():
    global _model_engine
    if _model_engine is None:
        _model_engine = ModelEngine()
    return _model_engine
