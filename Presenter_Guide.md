# Presenter Guide: Automotive Cellular Attack Simulation

This guide is designed for the presenter demonstrating the Automotive Cybersecurity Lab. It provides the exact commands to type in the interactive terminal and the talking points to explain what is happening at each stage of the attack chain.

---

### Introduction (Before you start)
**Presenter Script:**
> *"Welcome to our Automotive Cybersecurity Simulation Lab. This dashboard models a modern connected vehicle, specifically inspired by the 2015 Jeep Cherokee hack. On the left, we have an attacker's Kali Linux terminal. In the center, we see the live state of the vehicle's engine, brakes, steering, and doors, alongside the virtual ECUs. On the right, we have a live CAN Bus monitor and our defensive security controls. Let's walk through how a remote attacker can compromise a vehicle and how we can stop it."*

---

### Stage 1: Reconnaissance
**Goal:** Discover the vehicle on the cellular network.
**What to type in terminal:**
```bash
nmap -p 8080 100.72.18.0/24
```
*(Or simply type `1` and press enter)*

**Talking Points:**
- *"First, the attacker scans the cellular IP ranges used by the telecom provider."*
- *"They are looking for open ports. In this case, `nmap` discovers port 8080 is open and identifies the service as a 'Uconnect Telematics Module'."*
- *"The attacker has now found a target connected to the internet."*

---

### Stage 2: Cellular Access
**Goal:** Connect to the Telematics Control Unit (TCU) and map the internal network.
**What to type in terminal:**
```bash
curl http://100.72.18.44:8080/api/diagnostics
```
*(Or simply type `2` and press enter)*

**Talking Points:**
- *"Now that the attacker found the vehicle, they query its public-facing API."*
- *"Look at the terminal output: the TCU responds with internal details like the Gateway IP (`192.168.100.1`) and the CAN interface (`can0`)."*
- *"The attacker has mapped the internal architecture of the car over an LTE connection."*

---

### Stage 3: Firmware Exploit
**Goal:** Upload a malicious payload to the telematics endpoint.
**What to type in terminal:**
```bash
upload payload.bin
```
*(Or simply type `3` and press enter)*

**Talking Points:**
- *"The attacker leverages a vulnerability in the firmware update process. They upload a malicious file (`payload.bin`)."*
- *"Because the system lacks **Firmware Signature Verification**, the car accepts the malicious file blindly."*
- *"The attacker's custom code is now embedded in the telematics operating system."*

---

### Stage 4: Privilege Escalation
**Goal:** Gain Root access on the OS.
**What to type in terminal:**
```bash
sudo -l
```
*(Or simply type `4` and press enter)*

**Talking Points:**
- *"The attacker checks what privileges they have using `sudo -l`."*
- *"Because of poor API security, they find they have passwordless sudo access."*
- *"They escalate their privileges to `root`. They now own the telematics unit completely."*

---

### Stage 5: Gateway Pivot
**Goal:** Pivot from the internet-connected unit to the isolated internal CAN bus.
**What to type in terminal:**
```bash
ip route add 10.0.0.0/8 via 192.168.100.1
```
*(Or simply type `5` and press enter)*

**Talking Points:**
- *"The telematics unit isn't the final target; the attacker wants the physical vehicle controls."*
- *"They adjust the routing table to pivot through the internal Gateway to reach the safety-critical ECUs."*
- *"Notice that because the network lacks **Segmentation**, the ping to the Engine ECU succeeds. The attacker has bridged the gap from the internet to the internal car network."*

---

### Stage 6: CAN Bus Injection
**Goal:** Inject malicious physical commands into the CAN bus.
**What to type in terminal:**
```bash
cansend can0 102#0000
```
*(Or simply type `6` and press enter)*

**Talking Points:**
- *"The attacker begins injecting fake Control Area Network (CAN) frames directly onto the bus."*
- *"If you look at the CAN Monitor on the right, you can see these red `ATTACKER` frames flying across the network."*
- *"Because there is no **Gateway Filtering** to verify the source of these frames, the vehicle treats these malicious commands as legitimate."*

---

### Stage 7: Vehicle Compromise
**Goal:** Execute the final payload and take physical control.
**What to type in terminal:**
```bash
execute current payload
```
*(Or simply type `7` and press enter)*

**Talking Points:**
- *"This is the final stage. The attacker executes the full payload sequence."*
- *(Point to the center dashboard)* *"Notice how the state physically changes based on the injected CAN frames:"*
  - *"The engine is KILLED."*
  - *"The brakes are DISABLED (0%)."*
  - *"The doors are UNLOCKED."*
  - *"The steering wheel is violently turned!"*
- *"The remote attacker has successfully moved from a cellular internet connection to full physical control of the vehicle."*

---

### Demonstrating Defenses (The 'Reset' and Try Again)

**Goal:** Show how security controls mitigate the attack.
**What to do:**
1. Click the **🔄 RESET LAB** button in the top right.
2. In the bottom center, enable **Gateway Filtering** or **API Authentication**.
3. Re-run the attack by typing `stage 5` or `stage 6` in the terminal.

**Talking Points:**
- *"Now let's see what happens if the manufacturer built the car securely."*
- *"I've reset the lab and enabled **Gateway Filtering**."*
- *"When the attacker tries to inject CAN frames (Stage 6), the Gateway recognizes they are coming from an unauthorized source (the telematics unit) and completely **BLOCKS** them."*
- *"By implementing fundamental defense-in-depth, we prevent the attacker from ever reaching the physical safety controls."*
