"""
DeepGuard NIDS - Main Flask API Server
Serves the REST API and static frontend files.
All endpoints return JSON. Frontend is served from /frontend directory.
"""

import sys
import os
import json
import datetime
import threading
import time
import traceback

# Fix imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
from sqlalchemy import func, desc

from config.settings import SERVER, AVAILABLE_MODELS, DEFAULT_MODEL
from backend.database.models import (
    get_session, get_engine, init_db, Base, remove_session,
    Attack, Alert, TrafficLog, BlockedIP
)
from backend.services.model_loader import get_model_engine
from backend.defense.defense_engine import get_defense
from backend.realtime.detection_engine import TrafficSimulator

# ─────────────────────────────────────────────
# APP INITIALIZATION
# ─────────────────────────────────────────────
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend"))

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)

@app.teardown_appcontext
def shutdown_session(exception=None):
    remove_session()

# Initialize components
model_engine = get_model_engine()
defense = get_defense()

# Event buffer for real-time feed
_event_buffer = []
_event_lock = threading.Lock()
_MAX_BUFFER = 200

# Initialize database
try:
    init_db()
    print("[APP] Database initialized successfully.")
except Exception as e:
    print(f"[APP] Database init error: {e}")


# ─────────────────────────────────────────────
# EVENT CALLBACK (from simulation engine)
# ─────────────────────────────────────────────
def on_traffic_event(event):
    """Called for each simulated traffic event."""
    try:
        session = get_session()

        # Run defense assessment
        threat = defense.assess_threat(event)

        # Store traffic log
        log = TrafficLog(
            source_ip=event["source_ip"],
            destination_ip=event["destination_ip"],
            protocol=event["protocol"],
            packet_size=event["packet_size"],
            source_port=event["src_port"],
            destination_port=event["dst_port"],
            prediction=event["prediction"],
            confidence=event["confidence"],
            model_used=event["model_used"],
            is_attack=event["is_attack"]
        )
        session.add(log)

        # If attack detected, store attack record and alert
        if event["is_attack"]:
            attack = Attack(
                source_ip=event["source_ip"],
                destination_ip=event["destination_ip"],
                attack_type=event["prediction"],
                severity=event["severity"],
                protocol=event["protocol"],
                confidence=event["confidence"],
                model_used=event["model_used"],
                packet_size=event["packet_size"],
                source_port=event["src_port"],
                destination_port=event["dst_port"]
            )
            session.add(attack)
            session.flush()

            if threat["alert"]:
                alert = Alert(
                    message=threat["alert"]["message"],
                    severity=threat["alert"]["severity"],
                    status="new",
                    attack_id=attack.id
                )
                session.add(alert)

        session.commit()

        # Add to real-time buffer
        with _event_lock:
            event["threat_action"] = threat["action"]
            event["recommendation"] = threat.get("recommendation")
            _event_buffer.append(event)
            if len(_event_buffer) > _MAX_BUFFER:
                del _event_buffer[:len(_event_buffer) - _MAX_BUFFER]

    except Exception as e:
        print(f"[EVENT] Error processing event: {e}")
        traceback.print_exc()
        try:
            session.rollback()
        except:
            pass


# Create simulator
simulator = TrafficSimulator(model_engine, on_event_callback=on_traffic_event)


# ─────────────────────────────────────────────
# FRONTEND ROUTES
# ─────────────────────────────────────────────
@app.route("/")
def serve_index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory(FRONTEND_DIR, path)


# ─────────────────────────────────────────────
# API: DASHBOARD STATS
# ─────────────────────────────────────────────
@app.route("/api/stats")
def get_stats():
    """Get dashboard overview statistics."""
    try:
        session = get_session()
        total_traffic = session.query(func.count(TrafficLog.id)).scalar() or 0
        total_attacks = session.query(func.count(Attack.id)).scalar() or 0
        total_blocked = session.query(func.count(BlockedIP.id)).scalar() or 0
        total_alerts = session.query(func.count(Alert.id)).filter(Alert.status == "new").scalar() or 0

        # Attack type breakdown
        attack_breakdown = session.query(
            Attack.attack_type, func.count(Attack.id)
        ).group_by(Attack.attack_type).all()

        # Protocol breakdown
        protocol_breakdown = session.query(
            TrafficLog.protocol, func.count(TrafficLog.id)
        ).group_by(TrafficLog.protocol).all()

        # Recent attack rate (last 60 seconds worth of data)
        threat_info = defense.get_overall_threat_level()
        sim_stats = simulator.get_stats()

        return jsonify({
            "total_traffic": total_traffic,
            "total_attacks": total_attacks,
            "total_blocked": total_blocked,
            "pending_alerts": total_alerts,
            "attack_breakdown": {row[0]: row[1] for row in attack_breakdown},
            "protocol_breakdown": {row[0]: row[1] for row in protocol_breakdown},
            "threat_level": threat_info,
            "simulation": sim_stats,
            "active_model": model_engine.active_model,
            "detection_rate": round(total_attacks / max(total_traffic, 1) * 100, 1)
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# API: ALERTS
# ─────────────────────────────────────────────
@app.route("/api/alerts")
def get_alerts():
    """Get recent alerts."""
    try:
        session = get_session()
        limit = request.args.get("limit", 50, type=int)
        status_filter = request.args.get("status", None)

        query = session.query(Alert).order_by(desc(Alert.timestamp))
        if status_filter:
            query = query.filter(Alert.status == status_filter)
        alerts = query.limit(limit).all()

        return jsonify({"alerts": [a.to_dict() for a in alerts]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
def acknowledge_alert(alert_id):
    """Acknowledge an alert."""
    try:
        session = get_session()
        alert = session.query(Alert).get(alert_id)
        if not alert:
            return jsonify({"error": "Alert not found"}), 404
        alert.status = "acknowledged"
        session.commit()
        return jsonify({"success": True, "alert": alert.to_dict()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# API: TRAFFIC LOGS
# ─────────────────────────────────────────────
@app.route("/api/traffic")
def get_traffic():
    """Get recent traffic logs."""
    try:
        session = get_session()
        limit = request.args.get("limit", 100, type=int)
        attack_only = request.args.get("attack_only", "false") == "true"

        query = session.query(TrafficLog).order_by(desc(TrafficLog.timestamp))
        if attack_only:
            query = query.filter(TrafficLog.is_attack == True)
        logs = query.limit(limit).all()

        return jsonify({"traffic": [l.to_dict() for l in logs]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# API: ATTACKS
# ─────────────────────────────────────────────
@app.route("/api/attacks")
def get_attacks():
    """Get detected attacks."""
    try:
        session = get_session()
        limit = request.args.get("limit", 100, type=int)
        attacks = session.query(Attack).order_by(desc(Attack.timestamp)).limit(limit).all()
        return jsonify({"attacks": [a.to_dict() for a in attacks]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# API: BLOCKED IPS (Manual Only)
# ─────────────────────────────────────────────
@app.route("/api/blocked-ips")
def get_blocked_ips():
    """Get all blocked IPs."""
    try:
        session = get_session()
        blocked = session.query(BlockedIP).order_by(desc(BlockedIP.blocked_at)).all()
        return jsonify({"blocked_ips": [b.to_dict() for b in blocked]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/block-ip", methods=["POST"])
def block_ip():
    """Manually block an IP address."""
    try:
        data = request.get_json()
        ip = data.get("ip_address")
        reason = data.get("reason", "Manually blocked by administrator")

        if not ip:
            return jsonify({"error": "ip_address is required"}), 400

        session = get_session()
        existing = session.query(BlockedIP).filter_by(ip_address=ip).first()
        if existing:
            return jsonify({"error": f"IP {ip} is already blocked"}), 409

        blocked = BlockedIP(ip_address=ip, reason=reason)
        session.add(blocked)
        session.commit()

        return jsonify({"success": True, "blocked": blocked.to_dict()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/block-ip/<int:block_id>", methods=["DELETE"])
def unblock_ip(block_id):
    """Unblock an IP address."""
    try:
        session = get_session()
        blocked = session.query(BlockedIP).get(block_id)
        if not blocked:
            return jsonify({"error": "Blocked IP not found"}), 404
        ip = blocked.ip_address
        session.delete(blocked)
        session.commit()
        return jsonify({"success": True, "unblocked_ip": ip})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# API: MODELS
# ─────────────────────────────────────────────
@app.route("/api/models")
def get_models():
    """Get available models."""
    return jsonify({
        "models": AVAILABLE_MODELS,
        "active_model": model_engine.active_model
    })


@app.route("/api/models/switch", methods=["POST"])
def switch_model():
    """Switch the active detection model."""
    try:
        data = request.get_json()
        model_id = data.get("model_id")
        if model_engine.set_active_model(model_id):
            return jsonify({"success": True, "active_model": model_id})
        return jsonify({"error": f"Unknown model: {model_id}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# API: MODEL EVALUATION
# ─────────────────────────────────────────────
@app.route("/api/evaluation")
def get_evaluation():
    """Get evaluation metrics for all models."""
    try:
        model_id = request.args.get("model_id", None)
        if model_id:
            metrics = model_engine.get_evaluation(model_id)
            return jsonify({"model_id": model_id, "metrics": metrics})
        return jsonify({"evaluations": model_engine.get_all_evaluations()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# API: FEATURE IMPORTANCE / EXPLAINABILITY
# ─────────────────────────────────────────────
@app.route("/api/feature-importance")
def get_feature_importance():
    """Get feature importance for the active or specified model."""
    try:
        model_id = request.args.get("model_id", None)
        importance = model_engine.get_feature_importance(model_id)
        return jsonify({"model_id": model_id or model_engine.active_model, "features": importance})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# API: THREAT INTELLIGENCE
# ─────────────────────────────────────────────
@app.route("/api/threats")
def get_threats():
    """Get threat intelligence data."""
    try:
        threats = defense.get_all_threats()
        overall = defense.get_overall_threat_level()
        return jsonify({"threats": threats, "overall": overall})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# API: REAL-TIME FEED
# ─────────────────────────────────────────────
@app.route("/api/live-feed")
def live_feed():
    """Get recent events from the buffer."""
    try:
        since = request.args.get("since", 0, type=int)
        with _event_lock:
            events = _event_buffer[since:] if since < len(_event_buffer) else []
            current_index = len(_event_buffer)
        return jsonify({"events": events, "index": current_index})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# API: SIMULATION CONTROL
# ─────────────────────────────────────────────
@app.route("/api/simulation/start", methods=["POST"])
def start_simulation():
    """Start the traffic simulation."""
    simulator.start()
    return jsonify({"success": True, "status": "running"})


@app.route("/api/simulation/stop", methods=["POST"])
def stop_simulation():
    """Stop the traffic simulation."""
    simulator.stop()
    return jsonify({"success": True, "status": "stopped"})


@app.route("/api/simulation/status")
def simulation_status():
    """Get simulation status."""
    return jsonify(simulator.get_stats())


# ─────────────────────────────────────────────
# API: PREDICT (manual single packet)
# ─────────────────────────────────────────────
@app.route("/api/predict", methods=["POST"])
def predict():
    """Run prediction on a manually submitted packet."""
    try:
        data = request.get_json()
        result = model_engine.predict(data)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# API: HISTORY / ANALYTICS
# ─────────────────────────────────────────────
@app.route("/api/history")
def get_history():
    """Get attack history aggregated by type and time."""
    try:
        session = get_session()

        # Attack count by type
        by_type = session.query(
            Attack.attack_type, func.count(Attack.id)
        ).group_by(Attack.attack_type).all()

        # Attack count by severity
        by_severity = session.query(
            Attack.severity, func.count(Attack.id)
        ).group_by(Attack.severity).all()

        # Attack count by model
        by_model = session.query(
            Attack.model_used, func.count(Attack.id)
        ).group_by(Attack.model_used).all()

        # Top attacker IPs
        top_ips = session.query(
            Attack.source_ip, func.count(Attack.id).label("count")
        ).group_by(Attack.source_ip).order_by(desc("count")).limit(10).all()

        return jsonify({
            "by_type": {r[0]: r[1] for r in by_type},
            "by_severity": {r[0]: r[1] for r in by_severity},
            "by_model": {r[0]: r[1] for r in by_model},
            "top_attackers": [{"ip": r[0], "count": r[1]} for r in top_ips]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# API: RESET (for testing)
# ─────────────────────────────────────────────
@app.route("/api/reset", methods=["POST"])
def reset_system():
    """Reset all data (for testing purposes)."""
    try:
        session = get_session()
        session.query(Alert).delete()
        session.query(Attack).delete()
        session.query(TrafficLog).delete()
        session.query(BlockedIP).delete()
        session.commit()
        defense.reset()
        with _event_lock:
            _event_buffer.clear()
        return jsonify({"success": True, "message": "System reset complete"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  DeepGuard NIDS - AI Network Intrusion Detection System")
    print("  Dashboard: http://localhost:5000")
    print("=" * 60)
    app.run(
        host=SERVER["host"],
        port=SERVER["port"],
        debug=False,
        threaded=True
    )
