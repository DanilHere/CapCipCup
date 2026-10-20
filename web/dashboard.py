from flask import Flask, jsonify, render_template, request

from modules.ids import (
    DETECTION_THRESHOLD,
    get_alert_count,
    get_alert_history,
    get_alert_trend,
    get_alerts_since,
    get_last_alert,
    get_packet_count,
    get_scan_tracker,
    get_severity,
    get_udp_scan_tracker,
)

app = Flask(__name__, template_folder="templates")


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/status")
def status():
    threats = []

    for proto, tracker in (
        ("TCP", get_scan_tracker()),
        ("UDP", get_udp_scan_tracker()),
    ):
        for src_ip, ports in tracker.items():
            port_count = len(ports)

            if port_count > DETECTION_THRESHOLD:
                threats.append(
                    {
                        "source_ip": src_ip,
                        "protocol": proto,
                        "unique_ports": port_count,
                        "severity": get_severity(port_count),
                    }
                )

    return jsonify(
        {
            "packets_processed": get_packet_count(),
            "alerts_detected": get_alert_count(),
            "threats": threats,
            "last_alert": get_last_alert(),
            "alert_trend": get_alert_trend(),
            "alert_history": get_alert_history(),
        }
    )


@app.get("/api/alerts")
def alerts():
    """Return alerts newer than `since` (ISO timestamp query param)."""
    since = request.args.get("since")
    if since:
        return jsonify(get_alerts_since(since))
    return jsonify(get_alert_history())


def run_web_dashboard(stop_event):
    """
    Start the dashboard on all LAN interfaces.

    Flask's development server is acceptable for this local portfolio
    dashboard. Do not expose this service directly to the internet.
    """

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False,
        threaded=True,
    )
