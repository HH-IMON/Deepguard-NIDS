"""
DeepGuard NIDS - Configuration Settings
Central configuration for all system components.
"""

import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# --- Database Configuration ---
# Try XAMPP MySQL first, fallback to SQLite
DATABASE = {
    "mysql": {
        "uri": "mysql+pymysql://root:@localhost:3306/deepguard_db",
        "echo": False
    },
    "sqlite": {
        "uri": f"sqlite:///{os.path.join(BASE_DIR, 'data', 'deepguard.db')}",
        "echo": False
    }
}

# Default to MySQL (XAMPP). Set env var DB_TYPE=sqlite to use SQLite.
DB_TYPE = os.getenv("DB_TYPE", "mysql")

# --- Server Configuration ---
SERVER = {
    "host": "0.0.0.0",
    "port": 5000,
    "debug": True
}

# --- Model Configuration ---
AVAILABLE_MODELS = [
    {"id": "random_forest", "name": "Random Forest", "type": "traditional_ml"},
    {"id": "xgboost", "name": "XGBoost", "type": "traditional_ml"},
    {"id": "lstm", "name": "LSTM (Deep Learning)", "type": "deep_learning"},
    {"id": "cnn_1d", "name": "1D CNN (Deep Learning)", "type": "deep_learning"},
    {"id": "autoencoder", "name": "Autoencoder (Anomaly)", "type": "anomaly_detection"},
]

DEFAULT_MODEL = "random_forest"

# --- Attack Types ---
ATTACK_TYPES = [
    "Normal", "DoS", "DDoS", "Brute Force", "Port Scan",
    "Botnet", "Web Attack", "Infiltration"
]

SEVERITY_LEVELS = {
    "Normal": "none",
    "DoS": "high",
    "DDoS": "critical",
    "Brute Force": "medium",
    "Port Scan": "low",
    "Botnet": "critical",
    "Web Attack": "high",
    "Infiltration": "critical"
}

# --- Simulation Configuration ---
SIMULATION = {
    "interval_ms": 800,          # Time between simulated packets
    "attack_probability": 0.30,  # 30% chance of attack traffic
    "max_events_stored": 10000,  # Max events in DB
}

# --- Logging ---
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
