"""
app.py — Advanced Automotive Cybersecurity Cellular Attack Simulation Lab
Interactive Terminal Edition
"""
from flask import Flask, jsonify, request, render_template
from vehicle_sim import (
    vehicle_state, can_log, attack_log, gateway_log, ecu_event_log, ids_alerts,
    ecu_status, attack_stage, defenses, STAGES,
    inject_can, set_attack_stage, reset_all, simulate_cellular_latency,
    log_attack, log_gateway, log_ids, state_lock
)
import hashlib

app = Flask(__name__, template_folder='templates')
app.secret_key = "cellular_adv_sim_2026"

# ────────────────────────────────────────────────────────────────────────────
# TELEMATICS / TCU ENDPOINTS
# ────────────────────────────────────────────────────────────────────────────
@app.route("/api/status", methods=["GET"])
def tcu_status():
    return jsonify({
        "service":          "Uconnect TCU v2.5.1",
        "model":            "Jeep Cherokee Telematics Module",
        "firmware":         "2.5.1-RELEASE",
        "vehicle_id":       "VIN-JC7-DEMO-2026",
        "cellular_ip":      "100.72.18.44",
        "internal_ip":      "192.168.100.5",
        "port":             8080,
        "auth_required":    False,
        "uptime_hours":     1243,
        "endpoints": ["/api/status", "/api/firmware/update",
                      "/api/commands", "/api/diagnostics"],
        "warning":          "⚠  No authentication on this endpoint!"
    })

@app.route("/api/diagnostics", methods=["GET"])
def tcu_diagnostics():
    with state_lock:
        return jsonify({
            "can_interface":  "can0",
            "can_bitrate":    500000,
            "gateway_ip":     "192.168.100.1",
            "ecu_count":      5,
            "dtc_codes":      ["P0420", "U0100"],
            "os":             "Linux 4.14.0-telematics",
        })

@app.route("/api/firmware/update", methods=["POST"])
def firmware_update():
    fw   = request.files.get("firmware")
    name = fw.filename if fw else "payload.bin"
    md5  = hashlib.md5(fw.read()).hexdigest() if fw else "none"

    if defenses["firmware_verification"]:
        sig = request.headers.get("X-Firmware-Signature", "")
        if not sig.startswith("RSA2048:VALID:"):
            log_gateway("BLOCKED: Unsigned firmware rejected by verification policy", "BLOCK")
            return jsonify({
                "status": "REJECTED",
                "reason": "RSA-2048 signature check failed — unsigned firmware blocked.",
            }), 403

    log_gateway(f"WARNING: Unsigned firmware '{name}' accepted — no verification!", "WARN")
    return jsonify({
        "status":  "INSTALLED",
        "message": "⚠  Firmware installed without signature verification.",
        "file":    name,
        "md5":     md5,
    })

@app.route("/api/commands", methods=["POST"])
def remote_commands():
    if defenses["api_auth"]:
        token = request.headers.get("Authorization", "")
        if not token.startswith("Bearer "):
            log_gateway("BLOCKED: Unauthenticated command attempt rejected", "BLOCK")
            return jsonify({"error": "401 Unauthorized — Bearer token required."}), 401

    if defenses["ids_enabled"]:
        log_ids("Command injection attempt detected on /api/commands", "CRITICAL")

    body = request.get_json(force=True, silent=True) or {}
    cmd  = body.get("cmd", "")
    SHELL = {
        "id":                    "uid=0(root) gid=0(root) groups=0(root)",
        "whoami":                "root",
        "sudo -l":               "(ALL) NOPASSWD: ALL",
        "cat /etc/passwd":       "root:x:0:0:root:/root:/bin/bash\ntcu:x:1000:1000::/home/tcu:/bin/sh",
        "ifconfig":              "eth0: 192.168.100.5/24\ncan0: CAN interface UP bitrate=500000",
        "ls /dev/can*":          "/dev/can0  /dev/can1",
        "cansend can0 7FF#DEADBEEF": "Frame sent to CAN bus",
        "chmod +s /bin/bash":    "SUID set — root shell available via /bin/bash -p",
    }
    out = SHELL.get(cmd, f"[root@tcu-uconnect ~]# {cmd}\n(simulated shell output)")
    return jsonify({"prompt": "[root@tcu-uconnect ~]#", "cmd": cmd, "output": out, "uid": 0})

# ────────────────────────────────────────────────────────────────────────────
# 7-STAGE ATTACK CHAIN
# ────────────────────────────────────────────────────────────────────────────
STAGE_INFO = {
    1: {
        "title": "Reconnaissance",
        "mission": "Scan the internet and discover the telematics unit.",
        "hint": "nmap -p 8080 100.72.18.0/24",
        "expected_cmds": ["nmap", "scan", "stage 1", "1"],
        "plain": "Attacker scanned internet IP range 100.72.0.0/16 and found open port 8080 responding as 'Uconnect TCU v2.5.1'.",
        "technical": (
            "Starting Nmap 7.94 ( https://nmap.org )\n"
            "Scanning 100.72.18.0/24 [256 hosts]...\n\n"
            "Nmap scan report for 100.72.18.44\n"
            "Host is up (0.048s latency).\n"
            "PORT STATE SERVICE\n"
            "8080/tcp open http-proxy Uconnect TCU v2.5.1\n\n"
            "⚠ Vehicle telematics unit found at 100.72.18.44:8080\n"
            "→ Service banner: Jeep Cherokee Uconnect v2.5.1"
        ),
        "defense": None,
        "blocked_plain": None,
    },
    2: {
        "title": "Cellular Access",
        "mission": "Connect to the telematics API and map the internal network.",
        "hint": "curl http://100.72.18.44:8080/api/diagnostics",
        "expected_cmds": ["curl", "connect", "stage 2", "2"],
        "plain": "Attacker established TCP connection over LTE to the TCU and retrieved the internal network topology.",
        "technical": (
            "GET http://100.72.18.44:8080/api/diagnostics\n"
            "HTTP/1.1 200 OK\n\n"
            "{\"can_bitrate\":500000,\"can_interface\":\"can0\",\n"
            " \"ecu_count\":5,\"gateway_ip\":\"192.168.100.1\",\n"
            " \"os\":\"Linux 4.14.0-telematics\"}\n\n"
            "→ LTE Connection established (Latency: {latency}ms)\n"
            "→ Gateway IP identified: 192.168.100.1\n"
            "→ Target CAN interface identified: can0"
        ),
        "defense": None,
        "blocked_plain": None,
    },
    3: {
        "title": "Firmware Exploit",
        "mission": "Upload a malicious firmware payload to the telematics endpoint.",
        "hint": "curl -X POST http://100.72.18.44:8080/api/firmware/update -F 'firmware=@payload.bin'",
        "expected_cmds": ["upload", "firmware", "post", "stage 3", "3"],
        "plain": "Attacker uploaded malicious firmware containing a CAN injection payload to the telematics unit.",
        "technical": (
            "Uploading payload.bin (2.3MB)...\n"
            "POST /api/firmware/update HTTP/1.1\n\n"
            "HTTP/1.1 200 OK\n"
            "{\"status\":\"INSTALLED\",\"message\":\"⚠ Firmware installed without signature verification.\"}\n\n"
            "→ SUCCESS: Malicious firmware accepted!\n"
            "→ No RSA-2048 signature requested by TCU.\n"
            "→ Payload CAN forwarder successfully embedded in OS."
        ),
        "defense": "firmware_verification",
        "blocked_plain": (
            "🔒 BLOCKED — Firmware Signature Verification Active\n"
            "The car checked the firmware update's digital signature. The fake signature "
            "failed verification and the malicious firmware was REJECTED.\n\n"
            "→ RSA-2048 signature mismatch — firmware rejected\n"
            "→ Attack stopped at Stage 3 — attacker cannot proceed"
        ),
    },
    4: {
        "title": "Privilege Escalation",
        "mission": "Exploit the command endpoint to gain root access on the telematics OS.",
        "hint": "curl -X POST http://100.72.18.44:8080/api/commands -d '{\"cmd\":\"sudo -l\"}'",
        "expected_cmds": ["sudo", "privesc", "cmd", "stage 4", "4"],
        "plain": "Attacker used command injection to escalate to root privileges on the telematics OS.",
        "technical": (
            "POST /api/commands\n"
            "Payload: {\"cmd\":\"sudo -l\"}\n\n"
            "HTTP/1.1 200 OK\n"
            "{\"output\":\"(ALL) NOPASSWD: ALL\"}\n\n"
            "→ Vulnerability confirmed: Passwordless sudo available.\n"
            "→ Executing: sudo chmod +s /bin/bash\n"
            "→ Privilege Escalation Successful: uid=0(root) gid=0(root)\n"
            "[root@tcu-uconnect ~]#"
        ),
        "defense": "api_auth",
        "blocked_plain": (
            "🔒 BLOCKED — API Authentication Active\n"
            "The command endpoint now requires a valid Bearer token. "
            "The attacker's request was denied.\n\n"
            "→ 401 Unauthorized — Bearer token required\n"
            "→ Command execution denied — escalation stopped"
        ),
    },
    5: {
        "title": "Gateway Pivot",
        "mission": "Pivot from the telematics unit to the internal CAN bus via the gateway.",
        "hint": "ip route add 10.0.0.0/8 via 192.168.100.1",
        "expected_cmds": ["ip route", "pivot", "ifconfig", "stage 5", "5"],
        "plain": "Attacker pivoted through the unsegmented vehicle gateway to reach the internal CAN bus.",
        "technical": (
            "[root@tcu-uconnect ~]# ip route add 10.0.0.0/8 via 192.168.100.1\n"
            "Routing table updated.\n\n"
            "[root@tcu-uconnect ~]# ping -c 1 10.0.0.100 (Engine ECU)\n"
            "64 bytes from 10.0.0.100: icmp_seq=1 ttl=64 time=1.2 ms\n\n"
            "→ Gateway Pivot Successful!\n"
            "→ Gateway ACL: ALLOW ALL (No segmentation detected)\n"
            "→ Internal vehicle network is fully routable from internet."
        ),
        "defense": "network_segmentation",
        "blocked_plain": (
            "🔒 BLOCKED — Network Segmentation Active\n"
            "The safety-critical CAN segments are completely isolated from "
            "the telematics zone. The attacker cannot reach the ECUs.\n\n"
            "→ Safety-critical CAN segments ISOLATED\n"
            "→ Gateway pivot failed — safety ECUs unreachable"
        ),
    },
    6: {
        "title": "CAN Bus Injection",
        "mission": "Inject malicious CAN frames into the bus to manipulate ECUs.",
        "hint": "cansend can0 102#0000 && cansend can0 104#00",
        "expected_cmds": ["cansend", "inject", "102#", "104#", "stage 6", "6"],
        "plain": "Attacker started broadcasting fake CAN frames, bypassing component access controls.",
        "technical": (
            "Initializing CAN injector script on can0...\n\n"
            "[root@tcu-uconnect ~]# cansend can0 103#00       (Target: ECU4 Doors)\n"
            "[root@tcu-uconnect ~]# cansend can0 102#0000     (Target: ECU2 Brakes)\n"
            "[root@tcu-uconnect ~]# cansend can0 104#00       (Target: ECU1 Engine)\n"
            "[root@tcu-uconnect ~]# cansend can0 100#FFFF     (Target: ECU3 Steering)\n\n"
            "→ Frames broadcasted onto CAN bus.\n"
            "→ No message authentication codes (MAC) required by ECUs."
        ),
        "defense": "gateway_filtering",
        "blocked_plain": (
            "🔒 BLOCKED — Gateway CAN Filtering Active\n"
            "The gateway identified the CAN frames originating from an unauthorized source "
            "(the telematics unit) and dropped them.\n\n"
            "→ All attacker CAN frames blocked at gateway\n"
            "→ ECUs received ZERO malicious commands"
        ),
    },
    7: {
        "title": "Vehicle Compromise",
        "mission": "Complete the attack sequence to take full control of the vehicle.",
        "hint": "cansend can0 000#DEADBEEF (Execute final payload)",
        "expected_cmds": ["cansend", "compromise", "kill", "stage 7", "7", "execute"],
        "plain": "Vehicle systems responded to malicious commands, granting full remote control to the attacker.",
        "technical": (
            "🚨 VEHICLE FULLY COMPROMISED 🚨\n\n"
            "Attack sequence completed successfully:\n"
            "1. ECU4 Body    → Doors Unlocked\n"
            "2. ECU2 Brakes  → Brakes Disabled (0% pressure limit)\n"
            "3. ECU1 Engine  → Engine Killed (ignition OFF state)\n"
            "4. ECU3 Steer   → Hard right turn engaged\n\n"
            "→ Remote attacker has persistent control over vehicle safety systems.\n"
            "→ Connection remains open via cellular LTE.\n"
            "→ Warning: Physical vehicle behavior manipulated."
        ),
        "defense": "gateway_filtering",
        "blocked_plain": (
            "🛡️ ATTACK MITIGATED — Defenses Stopped the Chain\n"
            "Active defenses prevented the attacker from achieving their goal. "
            "This is what a properly secured vehicle looks like.\n\n"
            "→ Vehicle systems are SECURE"
        ),
    },
}

@app.route("/api/terminal", methods=["POST"])
def run_terminal_command():
    body = request.get_json(force=True, silent=True) or {}
    cmd = body.get("cmd", "").strip().lower()
    
    current = attack_stage["stage"]
    target = current + 1
    
    # Generic commands
    if cmd in ["clear", "cls"]:
        return jsonify({"action": "clear"})
    
    if cmd == "reset":
        api_reset()
        return jsonify({"output": "Lab reset successfully. Ready for new attack session.", "advance": True, "action": "reset", "stage": 0})
    
    if target > 7:
        return jsonify({"output": "All stages completed. Type 'reset' to restart the lab.", "advance": False})

    # Expected commands for the next stage
    info = STAGE_INFO[target]
    expected = info.get("expected_cmds", [])
    
    is_match = False
    for exp in expected:
        if exp in cmd:
            is_match = True
            break
            
    if is_match:
        # Run the attack stage!
        return _execute_stage(target)
    
    # Easter eggs or generic responses
    if "sudo" in cmd or "rm -rf" in cmd:
        return jsonify({"output": "Permission denied. (Are you trying to crash the lab instead of the target?)", "advance": False})
    
    hint = info.get("hint")
    return jsonify({
        "output": f"bash: {cmd}: command not found or not effective for Stage {target}.\n→ Hint: {hint}\n→ (Or simply type 'stage {target}' to advance automatically)",
        "advance": False
    })

def _execute_stage(stage):
    info    = STAGE_INFO[stage]
    defense = info.get("defense")
    blocked = bool(defense and defenses.get(defense))

    if defenses["ids_enabled"] and stage in (5, 6, 7):
        log_ids(f"ATTACK DETECTED: Stage {stage} — {info['title']}", "CRITICAL")

    set_attack_stage(stage)
    latency = simulate_cellular_latency() if stage >= 2 else 0

    plain = info["plain"].replace("{latency}", str(latency))
    tech  = info.get("technical", "").replace("{latency}", str(latency))

    if stage == 6 and not blocked:
        with state_lock:
            vehicle_state["compromised"] = True
        inject_can(0x103, [0x00])             # unlock
        inject_can(0x102, [0x00, 0x00])        # brakes
        inject_can(0x104, [0x00])              # engine off
        inject_can(0x100, [0xFF, 0xFF])        # steer right
        inject_can(0x105, [0x01])              # lights on
    elif stage == 6 and blocked:
        inject_can(0x103, [0x00]); inject_can(0x102, [0x00, 0x00])
        inject_can(0x104, [0x00]); inject_can(0x100, [0xFF, 0xFF])
        inject_can(0x105, [0x01])
    elif stage == 7 and not blocked:
        with state_lock:
            vehicle_state["compromised"] = True
    elif stage == 5:
        inject_can(0x7FF, [0xDE, 0xAD, 0xBE, 0xEF])

    log_attack(stage, info["title"], info.get("blocked_plain","") if blocked else plain, blocked)
    if blocked:
        log_gateway(f"Defense blocked Stage {stage}: {info['title']}", "BLOCK")

    res_output = info["blocked_plain"] if blocked else tech
    if blocked:
        # Wrap blocked msg in a clear format so terminal renders it nicely
        res_output = f"\n{res_output}\n"

    return jsonify({
        "stage":     stage,
        "label":     info["title"],
        "blocked":   blocked,
        "output":    res_output,
        "latency_ms": latency,
        "advance":   True,
        # Send next stage intent for the UI to update its "Current Mission" immediately
        "next_mission": STAGE_INFO.get(stage+1, {}).get("mission", "All stages complete!"),
        "next_hint": STAGE_INFO.get(stage+1, {}).get("hint", "")
    })

# ────────────────────────────────────────────────────────────────────────────
# DEFENSE TOGGLE
# ────────────────────────────────────────────────────────────────────────────
@app.route("/api/defend/<feature>", methods=["POST"])
def toggle_defense(feature: str):
    if feature not in defenses:
        return jsonify({"error": "Unknown feature"}), 400
    defenses[feature] = not defenses[feature]
    state = "ENABLED" if defenses[feature] else "DISABLED"
    log_gateway(f"Defense '{feature}' {state}", "INFO")
    if feature == "ids_enabled" and defenses[feature]:
        log_ids("IDS System Online — monitoring for anomalies", "INFO")
    return jsonify({"feature": feature, "active": defenses[feature]})

# ────────────────────────────────────────────────────────────────────────────
# RESET
# ────────────────────────────────────────────────────────────────────────────
@app.route("/api/reset", methods=["POST"])
def api_reset():
    reset_all()
    return jsonify({"status": "reset"})

# ────────────────────────────────────────────────────────────────────────────
# STATE APIs
# ────────────────────────────────────────────────────────────────────────────
@app.route("/api/state")
def get_state():
    with state_lock:
        return jsonify({
            "vehicle":  dict(vehicle_state),
            "attack":   dict(attack_stage),
            "defenses": dict(defenses),
            "ecus":     {k: dict(v) for k, v in ecu_status.items()},
        })

@app.route("/api/can_log")
def get_can_log():
    with state_lock:
        return jsonify(can_log[:50])

@app.route("/api/logs")
def get_all_logs():
    with state_lock:
        return jsonify({
            "attack":  attack_log[:20],
            "gateway": gateway_log[:20],
            "ids":     ids_alerts[:20],
            "ecu":     ecu_event_log[:20],
        })

@app.route("/api/mission")
def get_mission():
    curr = attack_stage["stage"]
    nxt = curr + 1
    if nxt <= 7:
        return jsonify({
            "mission": STAGE_INFO[nxt]["mission"],
            "hint": STAGE_INFO[nxt]["hint"]
        })
    return jsonify({"mission": "Attack simulation complete. Reset lab to start over.", "hint": "Type 'reset'"})

# ────────────────────────────────────────────────────────────────────────────
# DASHBOARD
# ────────────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("dashboard.html")

import os
from vehicle_sim import start_simulation

# Automatically spawn simulation threads on import (required for gunicorn/production)
start_simulation()

if __name__ == "__main__":
    print("\n" + "="*62)
    print("  Automotive Cybersecurity Simulation Lab - TERMINAL EDITION")
    print("  SIMULATION ONLY — No real vehicles or networks involved")
    print("  Dashboard → http://localhost:5000")
    print("="*62 + "\n")
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port, use_reloader=False)
