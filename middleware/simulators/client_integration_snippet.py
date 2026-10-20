# --- 1. Main Flask API Server (Python `requests`) ---
import time, requests

def send_security_log(ip: str, event: str, resource: str, status: int, severity: int, payload: dict):
    requests.post("http://localhost:8000/ingest", json={
        "timestamp": round(time.time(), 3), "client_ip": ip, "event_type": event,
        "target_resource": resource, "status_code": status, "severity": severity, "raw_payload": payload
    }, timeout=1.5)

# --- 2. ESP32 IoT Control Board (MicroPython `urequests`) ---
import urequests, utime

def log_iot_event(attacker_ip, pin_target, cmd):
    res = urequests.post("http://192.168.1.100:8000/ingest", json={
        "timestamp": utime.time() + 946684800.0, "client_ip": attacker_ip, "event_type": "IOT_CONTROL",
        "target_resource": pin_target, "status_code": 200, "severity": 1, "raw_payload": {"cmd": cmd}
    })
    res.close()
