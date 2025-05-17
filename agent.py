import subprocess
import platform
import socket
import uuid
import os
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # ✅ Enable CORS globally

# ------------------------------ Port Scanner ------------------------------
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
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.3)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(f"{port} ({service})")
        except Exception:
            pass
    return open_ports

# ------------------------------ Get Own IP ------------------------------
def get_own_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

# ------------------------------ Risk Assessment ------------------------------
def assess_risk(open_ports):
    high_risk_ports = ["21", "23", "445", "3389"]  # FTP, Telnet, SMB, RDP
    if any(port.split()[0] in high_risk_ports for port in open_ports):
        return "High"
    elif open_ports:
        return "Low"
    return "Unknown"

# ------------------------------ Get Own MAC ------------------------------
def get_own_mac():
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff)
                    for i in range(40, -1, -8)])
    return mac

# ------------------------------ Network Scan ------------------------------
def scan_network():
    devices = []
    ip = get_own_ip()

    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        subprocess.check_output(["ping", param, "1", ip], stderr=subprocess.DEVNULL)

        open_ports = scan_ports(ip)
        risk = assess_risk(open_ports)

        devices.append({
            "ip": ip,
            "status": "online",
            "ports": open_ports if open_ports else ["None"],
            "mac": get_own_mac(),
            "risk": risk
        })

    except subprocess.CalledProcessError:
        pass

    return devices

# ------------------------------ Current Network Info ------------------------------
def get_current_ip_info():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        subnet_parts = ip_address.split('.')
        subnet = ".".join(subnet_parts[:3]) + ".x"

        return {
            "hostname": hostname,
            "ip_address": ip_address,
            "subnet": subnet
        }
    except Exception as e:
        return {"error": str(e)}

# ------------------------------ Flask Routes ------------------------------
@app.route("/network-info")
def network_info():
    return jsonify(get_current_ip_info())

@app.route("/devices")
def get_devices():
    return jsonify(scan_network())

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
