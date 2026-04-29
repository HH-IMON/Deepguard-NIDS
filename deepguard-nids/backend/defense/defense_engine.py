"""
DeepGuard NIDS - Defense Engine (IPS Module)
Handles threat assessment, alert generation, and manual IP blocking support.
NOTE: IP blocking is MANUAL only - the user decides which IPs to block via the dashboard.
"""

import datetime


class DefenseEngine:
    """
    Intrusion Prevention System (IPS) logic.
    - Tracks IP strike counts
    - Generates alerts for detected attacks
    - Supports manual-only IP blocking (no auto-block)
    - Rate limiting and false-positive protection
    """

    SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(self):
        self._ip_strikes = {}       # ip -> {"count": int, "last_seen": datetime, "types": set}
        self._recent_alerts = []     # Last 100 alerts in memory for fast access

    def assess_threat(self, event):
        """
        Assess an event and return threat info + alert if warranted.
        Does NOT auto-block. Returns recommendation only.
        """
        if not event.get("is_attack"):
            return {
                "action": "allow",
                "severity": "none",
                "alert": None,
                "recommendation": None
            }

        src_ip = event.get("source_ip", "unknown")
        attack_type = event.get("prediction", "Unknown")
        confidence = event.get("confidence", 0.0)
        severity = event.get("severity", "medium")

        # Track strikes
        if src_ip not in self._ip_strikes:
            self._ip_strikes[src_ip] = {"count": 0, "last_seen": None, "types": set()}

        strike = self._ip_strikes[src_ip]
        strike["count"] += 1
        strike["last_seen"] = datetime.datetime.utcnow()
        strike["types"].add(attack_type)

        # Build alert message
        alert_msg = (
            f"🚨 {attack_type} detected from {src_ip} | "
            f"Confidence: {confidence:.1%} | Severity: {severity.upper()} | "
            f"Strike #{strike['count']}"
        )

        # Determine recommendation (but don't auto-block)
        recommendation = None
        if strike["count"] >= 10 or severity == "critical":
            recommendation = f"RECOMMEND BLOCK: {src_ip} has {strike['count']} strikes with {', '.join(strike['types'])}"
        elif strike["count"] >= 5:
            recommendation = f"MONITOR: {src_ip} has {strike['count']} strikes - consider blocking"

        alert_data = {
            "message": alert_msg,
            "severity": severity,
            "source_ip": src_ip,
            "attack_type": attack_type,
            "confidence": confidence,
            "strike_count": strike["count"]
        }

        # Keep in memory cache
        self._recent_alerts.append(alert_data)
        if len(self._recent_alerts) > 100:
            self._recent_alerts = self._recent_alerts[-100:]

        return {
            "action": "alert",
            "severity": severity,
            "alert": alert_data,
            "recommendation": recommendation
        }

    def get_ip_threat_level(self, ip_address):
        """Get threat assessment for a specific IP."""
        strike = self._ip_strikes.get(ip_address)
        if not strike:
            return {"threat_level": "none", "strikes": 0, "attack_types": []}

        count = strike["count"]
        if count >= 15:
            level = "critical"
        elif count >= 10:
            level = "high"
        elif count >= 5:
            level = "medium"
        elif count >= 2:
            level = "low"
        else:
            level = "minimal"

        return {
            "threat_level": level,
            "strikes": count,
            "attack_types": list(strike["types"]),
            "last_seen": strike["last_seen"].isoformat() if strike["last_seen"] else None
        }

    def get_all_threats(self):
        """Get summary of all tracked IPs with threat info."""
        threats = []
        for ip, strike in self._ip_strikes.items():
            threats.append({
                "ip": ip,
                "strikes": strike["count"],
                "types": list(strike["types"]),
                "last_seen": strike["last_seen"].isoformat() if strike["last_seen"] else None
            })
        threats.sort(key=lambda x: x["strikes"], reverse=True)
        return threats

    def get_overall_threat_level(self):
        """Calculate system-wide threat level."""
        if not self._ip_strikes:
            return {"level": "safe", "score": 0, "active_threats": 0}

        total_strikes = sum(s["count"] for s in self._ip_strikes.values())
        critical_ips = sum(1 for s in self._ip_strikes.values() if s["count"] >= 10)
        active_ips = sum(1 for s in self._ip_strikes.values() if s["count"] >= 2)

        if critical_ips >= 3 or total_strikes >= 100:
            level, score = "critical", 95
        elif critical_ips >= 1 or total_strikes >= 50:
            level, score = "high", 75
        elif active_ips >= 3 or total_strikes >= 20:
            level, score = "elevated", 55
        elif active_ips >= 1 or total_strikes >= 5:
            level, score = "guarded", 35
        else:
            level, score = "safe", 10

        return {
            "level": level,
            "score": score,
            "active_threats": active_ips,
            "critical_threats": critical_ips,
            "total_strikes": total_strikes
        }

    def reset(self):
        """Reset all tracking data."""
        self._ip_strikes.clear()
        self._recent_alerts.clear()


# Singleton
_defense = None

def get_defense():
    global _defense
    if _defense is None:
        _defense = DefenseEngine()
    return _defense
