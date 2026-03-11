"""
vehicle_sim.py — Advanced Automotive Cybersecurity Simulation Engine
7 Attack Stages | 5 ECUs | 7 CAN IDs | Cellular Layer | IDS | 5 Defenses
"""
import threading, time, random, struct, collections
from datetime import datetime

# ── CAN ID MASTER TABLE ─────────────────────────────────────────────────────
CAN_INFO = {
    # Control (command) frames
    0x100: ("ECU3", "Steering Control"),
    0x101: ("ECU1", "Throttle Control"),
    0x102: ("ECU2", "Brake Control"),
    0x103: ("ECU4", "Door Lock/Unlock"),
    0x104: ("ECU1", "Engine Start/Stop"),
    0x105: ("ECU4", "Lights Control"),
    0x106: ("ECU4", "Wiper Control"),
    # Telemetry / broadcast frames  (ECU → bus)
    0x201: ("ECU1", "Engine Telemetry"),
    0x202: ("ECU2", "Brake Telemetry"),
    0x203: ("ECU3", "Steering Telemetry"),
    0x204: ("ECU4", "Body Telemetry"),
    0x205: ("ECU5", "Infotainment Telemetry"),
    0x7FF: ("???",  "Probe / Unknown"),
}

# ── SHARED VEHICLE STATE ────────────────────────────────────────────────────
state_lock = threading.Lock()

vehicle_state = {
    "engine_status":    "ON",
    "engine_rpm":       2500,
    "throttle_percent": 25,
    "speed_kmh":        65.0,
    "brake_force":      0,
    "steering_angle":   0.0,
    "doors_locked":     True,
    "lights_on":        False,
    "wipers_mode":      "OFF",
    "climate_temp":     22,
    "climate_fan":      0,
    "infotainment":     "IDLE",
    "compromised":      False,
    "gateway_blocked":  False,
}

# ── ECU HEALTH TABLE ─────────────────────────────────────────────────────────
ecu_status = {
    "ECU1": {"name": "Engine Control Unit",  "icon": "🔧", "status": "NOMINAL", "can_ids": "0x101, 0x104", "last_msg": None},
    "ECU2": {"name": "Brake Control Unit",   "icon": "🛑", "status": "NOMINAL", "can_ids": "0x102",        "last_msg": None},
    "ECU3": {"name": "Steering Control Unit","icon": "🛞", "status": "NOMINAL", "can_ids": "0x100",        "last_msg": None},
    "ECU4": {"name": "Body Control Module",  "icon": "🚗", "status": "NOMINAL", "can_ids": "0x103-0x106",  "last_msg": None},
    "ECU5": {"name": "Infotainment Unit",    "icon": "📱", "status": "NOMINAL", "can_ids": "0x205",        "last_msg": None},
}

# ── LOGS ─────────────────────────────────────────────────────────────────────
can_log        = []     # CAN bus frames
attack_log     = []     # attack stage events
gateway_log    = []     # gateway security events
ecu_event_log  = []     # per-ECU events
ids_alerts     = []     # IDS alert queue
LOG_MAX        = 120

# ── ATTACK STATE ─────────────────────────────────────────────────────────────
attack_stage = {"stage": 0, "label": "Idle", "cellular_latency_ms": 0}

STAGES = [
    (0, "Idle"),
    (1, "Reconnaissance"),
    (2, "Cellular Access"),
    (3, "Firmware Exploit"),
    (4, "Privilege Escalation"),
    (5, "Gateway Pivot"),
    (6, "CAN Bus Injection"),
    (7, "Vehicle Compromise"),
]

# ── DEFENSE FLAGS ─────────────────────────────────────────────────────────────
defenses = {
    "gateway_filtering":     False,
    "firmware_verification": False,
    "api_auth":              False,
    "network_segmentation":  False,
    "ids_enabled":           False,
}

# ── LOG HELPERS ───────────────────────────────────────────────────────────────
def _ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def _append(lst, entry):
    lst.insert(0, entry)
    if len(lst) > LOG_MAX:
        lst.pop()

def log_can(arb_id: int, data: list, source: str = "ECU", blocked: bool = False):
    info   = CAN_INFO.get(arb_id, ("???", "Unknown"))
    entry  = {
        "ts":      _ts(),
        "id":      f"0x{arb_id:03X}",
        "data":    " ".join(f"{b:02X}" for b in data),
        "source":  source,
        "target":  info[0],
        "desc":    info[1],
        "blocked": blocked,
    }
    with state_lock:
        _append(can_log, entry)
        if info[0] in ecu_status and not blocked:
            ecu_status[info[0]]["last_msg"] = entry["ts"]

def log_attack(stage: int, label: str, detail: str, blocked: bool = False):
    with state_lock:
        _append(attack_log, {
            "ts": _ts(), "stage": stage, "label": label,
            "detail": detail, "blocked": blocked,
        })

def log_gateway(msg: str, level: str = "INFO"):
    with state_lock:
        _append(gateway_log, {"ts": _ts(), "level": level, "msg": msg})

def log_ecu(ecu: str, event: str):
    with state_lock:
        _append(ecu_event_log, {"ts": _ts(), "ecu": ecu, "event": event})

def log_ids(alert: str, severity: str = "HIGH"):
    with state_lock:
        _append(ids_alerts, {"ts": _ts(), "alert": alert, "severity": severity})

# ── CAN MESSAGE APPLICATION ───────────────────────────────────────────────────
def _apply_can(arb_id: int, data: list):
    with state_lock:
        if arb_id == 0x100 and len(data) >= 2:
            raw = (data[0] << 8) | data[1]
            vehicle_state["steering_angle"] = round(-180 + (raw / 65535) * 360, 1)
            ecu_status["ECU3"]["status"] = "ACTIVE"
        elif arb_id == 0x101 and len(data) >= 1:
            vehicle_state["throttle_percent"] = min(100, data[0])
            ecu_status["ECU1"]["status"] = "ACTIVE"
        elif arb_id == 0x102 and len(data) >= 2:
            raw = (data[0] << 8) | data[1]
            vehicle_state["brake_force"] = round((raw / 65535) * 100)
            ecu_status["ECU2"]["status"] = "ACTIVE"
        elif arb_id == 0x103 and len(data) >= 1:
            vehicle_state["doors_locked"] = (data[0] == 0x01)
            ecu_status["ECU4"]["status"] = "ACTIVE"
        elif arb_id == 0x104 and len(data) >= 1:
            st = {0x00: "OFF", 0x01: "ON", 0x02: "CRANKING"}.get(data[0], "OFF")
            vehicle_state["engine_status"] = st
            ecu_status["ECU1"]["status"] = "ACTIVE"
        elif arb_id == 0x105 and len(data) >= 1:
            vehicle_state["lights_on"] = bool(data[0])
            ecu_status["ECU4"]["status"] = "ACTIVE"
        elif arb_id == 0x106 and len(data) >= 1:
            modes = ["OFF", "LOW", "MEDIUM", "HIGH"]
            vehicle_state["wipers_mode"] = modes[data[0] % 4]
            ecu_status["ECU4"]["status"] = "ACTIVE"

def inject_can(arb_id: int, data: list, source: str = "ATTACKER") -> bool:
    """Returns True if frame was delivered, False if blocked."""
    blocked = False

    if defenses["gateway_filtering"] and source == "ATTACKER":
        blocked = True
        log_gateway(f"BLOCKED: CAN frame {hex(arb_id)} from {source} rejected by gateway filter", "BLOCK")

    if defenses["ids_enabled"] and source == "ATTACKER":
        log_ids(f"Anomalous CAN frame detected: ID={hex(arb_id)} source={source}", "CRITICAL")

    if defenses["network_segmentation"] and source == "ATTACKER":
        if arb_id in (0x102, 0x104):  # Safety-critical blocked by segmentation
            blocked = True
            log_gateway(f"SEGMENTATION: Safety CAN {hex(arb_id)} isolated — cannot reach ECU", "BLOCK")

    log_can(arb_id, data, source=source, blocked=blocked)

    if not blocked:
        _apply_can(arb_id, data)
        info = CAN_INFO.get(arb_id, ("???",""))
        if info[0] in ecu_status:
            log_ecu(info[0], f"Received frame {hex(arb_id)} [{' '.join(f'{b:02X}' for b in data)}]")

    with state_lock:
        vehicle_state["gateway_blocked"] = blocked
    return not blocked

# ── CELLULAR LATENCY SIMULATION ───────────────────────────────────────────────
def simulate_cellular_latency():
    """Simulate ~50-200ms LTE round-trip latency."""
    latency = random.randint(48, 210)
    attack_stage["cellular_latency_ms"] = latency
    time.sleep(latency / 1000.0)
    return latency

# ── ATTACK & RESET HELPERS ────────────────────────────────────────────────────
def set_attack_stage(idx: int):
    attack_stage["stage"] = idx
    attack_stage["label"] = STAGES[idx][1]

def reset_all():
    with state_lock:
        vehicle_state.update({
            "engine_status":"ON","engine_rpm":2500,"throttle_percent":25,
            "speed_kmh":65.0,"brake_force":0,"steering_angle":0.0,
            "doors_locked":True,"lights_on":False,"wipers_mode":"OFF",
            "climate_temp":22,"climate_fan":0,"infotainment":"IDLE",
            "compromised":False,"gateway_blocked":False,
        })
        for k in defenses: defenses[k] = False
        for e in ecu_status.values():
            e["status"] = "NOMINAL"
            e["last_msg"] = None
        can_log.clear(); attack_log.clear()
        gateway_log.clear(); ecu_event_log.clear(); ids_alerts.clear()
    set_attack_stage(0)
    attack_stage["cellular_latency_ms"] = 0

# ── ECU BROADCAST THREADS ─────────────────────────────────────────────────────
def _ecu_engine():
    while True:
        with state_lock:
            st = vehicle_state["engine_status"]
            if st == "ON":
                tgt = 800 + vehicle_state["throttle_percent"] * 55
                vehicle_state["engine_rpm"] = int(
                    vehicle_state["engine_rpm"] + (tgt - vehicle_state["engine_rpm"]) * 0.15)
                vehicle_state["speed_kmh"] = round(vehicle_state["throttle_percent"] * 1.8, 1)
            elif st == "CRANKING":
                vehicle_state["engine_rpm"] = random.randint(150, 650)
            else:
                vehicle_state["engine_rpm"] = max(0, vehicle_state["engine_rpm"] - 90)
                vehicle_state["speed_kmh"]  = max(0.0, vehicle_state["speed_kmh"] - 3.0)
            rpm = vehicle_state["engine_rpm"]
            s   = {"OFF":0,"ON":1,"CRANKING":2}.get(st, 0)
            thr = vehicle_state["throttle_percent"]
        log_can(0x201, [s, thr, (rpm>>8)&0xFF, rpm&0xFF], source="ECU1")
        time.sleep(1)

def _ecu_brake():
    while True:
        with state_lock:
            bf = int((vehicle_state["brake_force"]/100)*65535)
        log_can(0x202, [(bf>>8)&0xFF, bf&0xFF], source="ECU2")
        time.sleep(1.5)

def _ecu_steering():
    while True:
        with state_lock:
            ang = vehicle_state["steering_angle"]
        raw = int(((ang+180)/360)*65535)
        log_can(0x203, [(raw>>8)&0xFF, raw&0xFF], source="ECU3")
        time.sleep(2)

def _ecu_body():
    while True:
        with state_lock:
            d = 0x01 if vehicle_state["doors_locked"] else 0x00
            w = ["OFF","LOW","MEDIUM","HIGH"].index(vehicle_state["wipers_mode"])
            l = 0x01 if vehicle_state["lights_on"] else 0x00
        log_can(0x204, [d, w, vehicle_state["climate_temp"], l], source="ECU4")
        time.sleep(2)

def _ecu_infotainment():
    modes = ["IDLE","MAPS","MUSIC","PHONE","RADIO"]
    i = 0
    while True:
        with state_lock:
            vehicle_state["infotainment"] = modes[i % len(modes)]
            st = i % len(modes)
        log_can(0x205, [st, 0x00, 0x00], source="ECU5")
        i += 1
        time.sleep(3)

_sim_started = False
def start_simulation():
    global _sim_started
    if _sim_started: return
    _sim_started = True
    for fn in [_ecu_engine, _ecu_brake, _ecu_steering, _ecu_body, _ecu_infotainment]:
        threading.Thread(target=fn, daemon=True).start()
    log_gateway("Gateway initialized. All traffic permitted (default policy).", "INFO")
    log_gateway("IDS: Offline (disabled)", "INFO")
