#TODO: ALERT SYSTEM

from datetime import datetime
from typing import Dict, List
import json


class AlertSystem:
    def __init__(self):
        self.alerts = []
        self.alert_history = []

    def check_alerts(self, port_status: Dict, api_status: Dict) -> List:
        """Check monitoring data for alert conditions"""
        new_alerts = []

        # Check port alerts
        unauthorized_attempts = port_status.get('unauthorized_attempts', [])
        if len(unauthorized_attempts) > 0:
            alert = {
                'type': 'UNAUTHORIZED_PORT_ACCESS',
                'severity': 'HIGH',
                'message': f"Unauthorized access attempt on port 4481 from {unauthorized_attempts[-1]['ip']}",
                'timestamp': datetime.now().isoformat(),
                'details': unauthorized_attempts
            }
            new_alerts.append(alert)
            self.alerts.append(alert)

        # Check API key alerts
        suspicious_count = api_status.get('suspicious_count', 0)
        if suspicious_count > 0:
            alert = {
                'type': 'SUSPICIOUS_API_USAGE',
                'severity': 'MEDIUM',
                'message': f"Detected {suspicious_count} suspicious API key activities",
                'timestamp': datetime.now().isoformat(),
                'details': api_status.get('key_activities', [])
            }
            new_alerts.append(alert)
            self.alerts.append(alert)

        # Archive alerts older than 24 hours
        self._cleanup_alerts()

        return new_alerts

    def get_active_alerts(self) -> str:
        """Get formatted active alerts"""
        if not self.alerts:
            return "✅ No active alerts"

        alert_text = ""
        for alert in self.alerts[-5]:  # Last 5 alerts
            alert_text += f"⚠️ {alert['severity']}: {alert['message']}\n"

        return alert_text

    def _cleanup_alerts(self):
        """Remove old alerts"""
        current_time = datetime.now()
        self.alerts = [
            alert for alert in self.alerts
            if (current_time - datetime.fromisoformat(alert['timestamp'])).days < 1
        ]
