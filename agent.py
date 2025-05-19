import socket
import uuid
import os
import subprocess
import platform
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

def scan_ports(ip):
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
        3389: "RDP"
    }
    open_ports = []
    for port, service in common_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append(f"{port} ({service})")
        except Exception as e:
            print(f"[Port Scan Error for {ip}:{port}] {e}")
    return open_ports

def assess_risk(open_ports):
    high_risk_ports = ["21", "23", "139", "445", "3389"]
    if any(port.split()[0] in high_risk_ports for port in open_ports):
        return "High"
    elif open_ports:
        return "Low"
    return "Unknown"

def get_mac(ip):
    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output(f"arp -a {ip}", shell=True).decode()
        else:
            output = subprocess.check_output(["arp", "-n", ip]).decode()
        for line in output.splitlines():
            if ip in line:
                parts = line.split()
                for part in parts:
                    if "-" in part or ":" in part:
                        return part
    except Exception as e:
        print(f"[MAC Error for {ip}] {e}")
    return "Unavailable"

def get_own_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def scan_network():
    devices = []
    base_ip = ".".join(get_own_ip().split('.')[:3])
    param = "-n" if platform.system().lower() == "windows" else "-c"

    for i in range(1, 255):
        ip = f"{base_ip}.{i}"
        try:
            subprocess.check_output(["ping", param, "1", ip], stderr=subprocess.DEVNULL)
            open_ports = scan_ports(ip)
            mac = get_mac(ip)
            risk = assess_risk(open_ports)
            devices.append({
                "ip": ip,
                "status": "online",
                "ports": open_ports if open_ports else ["None"],
                "mac": mac,
                "risk": risk,
                "warning": "⚠️ High Risk Ports Detected!" if risk == "High" else ""
            })
        except subprocess.CalledProcessError:
            continue
    return devices

def get_current_ip_info():
    try:
        ip_address = get_own_ip()
        subnet = ".".join(ip_address.split('.')[:3]) + ".x"
        hostname = socket.gethostname()
        return {
            "hostname": hostname,
            "ip_address": ip_address,
            "subnet": subnet
        }
    except Exception as e:
        return {"error": str(e)}

@app.route("/network-info")
def network_info():
    return jsonify(get_current_ip_info())

@app.route("/devices")
def get_devices():
    return jsonify(scan_network())

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
