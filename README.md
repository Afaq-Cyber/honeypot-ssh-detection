# 🍯 Real-Time Dynamic Honeypot — Intrusion Detection & Monitoring

**Final Year Project | University of Agriculture Peshawar | August 2024**
**Authors:** Afaq Ali · Yawar Hassan | **Supervisor:** Mr. Nisar Ali, Lecturer ICS/IT

---

## What This Project Does

A two-component honeypot system that monitors SSH, HTTP, and Telnet traffic in real time:

- **Detects connection attempts** the moment they happen — no delay
- **Captures attacker IP, MAC address, and timestamp** on first contact
- **Logs full HTTP request headers** including browser, OS, and encoding preferences
- **Sends custom deception messages** to mislead the attacker on Telnet
- **Denies access** via both browser GUI and terminal CLI
- **Reverse scans the attacker** using Nmap to profile their open ports and services
- **Records the full packet exchange** in Wireshark for forensic analysis

Everything shown below is from a live test between two virtual machines.

---

## System Architecture

```
┌─────────────────────────────────────┐     ┌────────────────────────────────────┐
│   Ubuntu 64-bit — Victim/Honeypot   │     │   Kali Linux 2024.2 — Attacker     │
│   IP: 192.168.20.129                │◄────│   IP: 192.168.20.128               │
│                                     │     │                                    │
│   Component 1: FYP.py (Python)      │     │   Tools used to attack:            │
│   └─ Monitors SSH (port 22)         │     │   - Firefox browser                │
│   └─ PyShark live packet capture    │     │   - http CLI                       │
│   └─ Scapy ARP MAC resolution       │     │   - Telnet                         │
│   └─ Threading (non-blocking)       │     │   - Nmap                           │
│                                     │     │                                    │
│   Component 2: PentBox 1.8 (Ruby)   │     │                                    │
│   └─ Monitors HTTP (port 80)        │     │                                    │
│   └─ Monitors Telnet (port 23)      │     │                                    │
│   └─ Logs intrusions to file        │     │                                    │
└─────────────────────────────────────┘     └────────────────────────────────────┘
                    │
                    └──► Both VMs on the same VMware virtual network (isolated)
```

---

## Two-Component Design

| Component | Protocol | Technology | Role |
|---|---|---|---|
| **FYP.py** | SSH — Port 22 | Python · PyShark · Scapy · Threading | Custom-built packet sniffer. Captures live SSH traffic, ARP-resolves attacker MAC, prints real-time alert |
| **PentBox 1.8** | HTTP — Port 80, Telnet — Port 23 | Ruby honeypot framework | Activates fake services, logs full request headers, sends deception messages |

---

## Component 1 — Python SSH Detector (`FYP.py`)

### How It Works

```
Network interface ens33
         │
         ▼
  PyShark LiveCapture          ← BPF filter: tcp port 22 (SSH only)
         │
         ▼
  packet_callback()            ← Called for every matching packet
         │
         ├─ Is there an IP layer?         → No  → skip
         ├─ Is destination port == 22?    → No  → skip
         │                               → Yes → proceed
         ▼
  get_mac(attacker_ip)         ← Scapy ARP broadcast → resolves MAC address
         │
         ▼
  get_current_datetime()       ← Timestamp of detection
         │
         ▼
  print_banner(ip, mac, time)  ← Formatted alert printed to terminal
```

### The Code

```python
import threading
import pyshark
from scapy.all import ARP, Ether, srp
from datetime import datetime


def get_mac(ip):
    """Resolve IP to MAC address via ARP broadcast."""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None


def get_current_datetime():
    """Return formatted timestamp: YYYY-MM-DD HH:MM:SS"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def print_banner(ip, mac, timestamp):
    """Print formatted intrusion alert."""
    print(f"""
    *********************************************
    *         Yawar & Afaq Cyber Security       *
    *         SSH Access Attempt Detected       *
    *********************************************
    * Attacker IP   : {ip}
    * Attacker MAC  : {mac}
    * Time & Date   : {timestamp}
    *********************************************
    """)


def packet_callback(packet):
    """Triggered for every captured packet. Fires alert on SSH detection."""
    if 'IP' in packet:
        ip_src = packet.ip.src
        if 'TCP' in packet and packet.tcp.dstport == '22':
            print_banner(ip_src, get_mac(ip_src), get_current_datetime())


def start_packet_capture():
    """Start live capture on ens33, filtered to TCP port 22 only."""
    capture = pyshark.LiveCapture(interface='ens33', bpf_filter='tcp port 22')
    capture.apply_on_packets(packet_callback)


if __name__ == "__main__":
    capture_thread = threading.Thread(target=start_packet_capture)
    capture_thread.daemon = True
    capture_thread.start()
    print("Honeypot is Activated — Monitoring SSH Access Attempts")
    capture_thread.join()
```

### Why PyShark + Scapy Together?

**PyShark** handles the heavy lifting of live capture — it wraps `tshark` (Wireshark's CLI engine) and applies a BPF filter so only SSH packets (TCP port 22) are processed. This is efficient: the kernel drops everything else before Python even sees it.

**Scapy** handles a different job: taking the attacker's IP and sending out an ARP broadcast to resolve it to a MAC address. ARP operates at Layer 2 and requires raw socket access — which is why the script needs root (`sudo`). This gives you both the logical identifier (IP) and the physical identifier (MAC) of the attacker on the local network.

**Threading** ensures the packet capture loop runs in the background without blocking the main process. The main thread stays alive with `join()` so the program doesn't exit immediately.

### Run It

```bash
# Install dependencies
pip install pyshark scapy
sudo apt install tshark        # Required by PyShark

# Run (root required for raw packet capture)
sudo python3 FYP.py
```

> **Note:** `ens33` is the VMware virtual NIC name used in this project.
> Change to `eth0`, `wlan0`, or your active interface before running.

---

## Component 2 — PentBox HTTP & Telnet Honeypot

PentBox 1.8 provides the HTTP and Telnet honeypot services.
Navigate into the `pentbox-1.8/` directory and run:

```bash
sudo ruby pentbox.rb
# → Network tools → Honeypot → Select port and configuration
```

---

## Live Demonstration

---

### Step 1 — Honeypot Activated (Port 80)

PentBox is configured and the HTTP honeypot goes live:

![Honeypot Activated](<img width="697" height="91" alt="honeypot_activated_port80 jpg" src="https://github.com/user-attachments/assets/70c6519b-7448-45ec-b763-8c726c68140d" />
)

```
HONEYPOT ACTIVATED ON PORT 80 (2024-08-09 22:26:19 +0500)
```

---

### Step 2 — Attacker Connects via Browser

Kali browser navigates to `http://192.168.20.129`:

![Access Denied Browser](screenshots/access_denied_browser.jpg)

```
Access denied
IP Address login failed
2024-08-09 22:26:19 +0500
```

---

### Step 3 — Attacker Tries via Terminal

```bash
http 192.168.20.129
```

![Access Denied CLI](screenshots/access_denied_cli.jpg)

```
ConnectionError: ('Connection aborted.', BadStatusLine('<HEAD>\n'))
```

---

### Step 4 — What the Honeypot Captured

The honeypot silently logged everything:

![Intrusion Log HTTP](screenshots/intrusion_detected_http.jpg)

```
INTRUSION ATTEMPT DETECTED! from 192.168.20.128:47920  (2024-08-09 22:26:43 +0500)
─────────────────────────────────────────────────────
GET / HTTP/1.1
Host: 192.168.20.129
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive

INTRUSION ATTEMPT DETECTED! from 192.168.20.128:47936  (2024-08-09 22:26:46 +0500)
─────────────────────────────────────────────────────
GET /favicon.ico HTTP/1.1
...
```

From a single browser visit, the honeypot extracted: attacker IP and port, operating system (Linux x86_64), browser and exact version (Firefox 115), accepted content types, encoding preferences — all logged passively without the attacker knowing.

---

### Step 5 — Telnet Honeypot with Deception Message

PentBox is reconfigured manually for Telnet (port 23):

![Manual Config](screenshots/manual_config_port23.jpg)

```
Port: 23
Deception message: "Don't try to hack me, Because i can see you!!!"
Save log: yes
HONEYPOT ACTIVATED ON PORT 23 (2024-08-09 22:34:59 +0500)
```

Attacker connects via Telnet:

![Telnet Deception](screenshots/telnet_deception.jpg)

```bash
telnet 192.168.20.129 23
# → Connected to 192.168.20.129.
# → Don't try to hack me, Because i can see you!!!
# → Connection closed by foreign host.
```

Both Telnet attempts are logged:

![Telnet Log](screenshots/telnet_intrusion_log.jpg)

```
INTRUSION ATTEMPT DETECTED! from 192.168.20.128:39982  (2024-08-09 22:35:15 +0500)
INTRUSION ATTEMPT DETECTED! from 192.168.20.128:38502  (2024-08-09 23:06:38 +0500)
```

---

### Step 6 — Reverse Scanning the Attacker

Using the attacker IP from the honeypot logs, the victim machine scans back:

**Top 1000 ports:**

![Reverse Scan 1000](screenshots/reverse_scan_1000.jpg)

```bash
nmap 192.168.20.128
# → All 1000 scanned ports are in ignored states (0.0014s latency)
```

**All 65,535 ports:**

![Reverse Scan Full](screenshots/reverse_scan_full.jpg)

```bash
nmap -p- 192.168.20.128
# → All 65535 closed tcp ports (conn-refused)
```

Host is confirmed up. No services exposed — typical for an attacker machine.

**Checking honeypot stealth:**

![Port 80 Closed](screenshots/port80_closed_external.jpg)

```bash
nmap -p 80 192.168.20.129
# → 80/tcp   closed   http
```

Port 80 appears **closed** to an external Nmap scan even while the honeypot is actively running — the honeypot intercepts at the connection layer before Nmap's SYN scan can observe the port as open.

---

### Step 7 — Wireshark Traffic Analysis

Full packet capture of the session (2036 packets, 2008 displayed):

![Wireshark Full](screenshots/wireshark_full.jpg)

Filtered to `ip.addr == 192.168.20.129`:

![Wireshark Filtered](screenshots/wireshark_filtered.jpg)

| Packet Type | Direction | Meaning |
|---|---|---|
| SYN | `.129 → .128` | Victim's reverse Nmap scan probing attacker ports |
| RST, ACK | `.128 → .129` | Attacker ports closed — all rejecting connections |
| DNS (PTR) | `.129 → .2` | Victim performing reverse DNS lookup on attacker IP |
| TCP (port 80) | `.128 → .129` | Original attacker HTTP connection to honeypot |

The `.pcapng` file provides a complete forensic record — every packet, timestamp, and header of the full attack session.

---

## Results

| Test | Result |
|---|---|
| Python script start (SSH monitoring) | ✅ Live capture active on ens33, port 22 |
| HTTP honeypot activation (port 80) | ✅ Activated immediately |
| Browser intrusion detected | ✅ IP, port, timestamp, full HTTP headers logged |
| CLI intrusion detected | ✅ Connection aborted, attempt logged |
| Attacker deceived via Telnet | ✅ Deception message delivered, connection closed |
| Telnet intrusions logged | ✅ Two attempts with timestamps and raw bytes |
| Reverse scan completed | ✅ Attacker host confirmed up (0.0014s latency) |
| Honeypot stealth from Nmap | ✅ Port 80 reports closed externally |
| Wireshark capture | ✅ 2036 packets, full session recorded |

---

## Key Observations

**Passive fingerprinting from one HTTP request**
A single browser visit exposed: OS (Linux x86_64), browser (Firefox 115), accepted content types, and encoding — without the attacker doing anything unusual.

**The stealth gap**
Port 80 shows as `closed` to an external Nmap SYN scan even while the honeypot accepts connections. The honeypot intercepts at the application layer, making it invisible to standard port scanners.

**Attacker machine hardening**
All 65,535 ports on the Kali machine were closed — zero exposed services. The reverse scan confirmed host presence and measured 0.0014s latency, but returned no exploitable service information.

**Threading matters**
Running packet capture in a daemon thread means the SSH detector stays responsive even under high packet volume. The main thread joins and waits rather than spinning — a deliberate design choice.

---

## Repository Structure

```
honeypot-ssh-detection/
├── README.md                    ← This file
├── FYP.py                       ← Python SSH intrusion detector
├── requirements.txt             ← Python dependencies
├── thesis/
│   └── FYP_Final_Thesis.pdf     ← Full project report (46 pages)
└── screenshots/                 ← Live demonstration evidence
    ├── honeypot_activated_port80.jpg
    ├── access_denied_browser.jpg
    ├── access_denied_cli.jpg
    ├── intrusion_detected_http.jpg
    ├── manual_config_port23.jpg
    ├── telnet_deception.jpg
    ├── telnet_intrusion_log.jpg
    ├── reverse_scan_1000.jpg
    ├── reverse_scan_full.jpg
    ├── port80_closed_external.jpg
    ├── wireshark_full.jpg
    └── wireshark_filtered.jpg
```

---

## Ethical Note

Built and tested entirely within an isolated VMware virtual network.
No external systems were targeted or monitored at any point.
Deploy only on networks you own or have explicit written permission to monitor.

---

## Authors

**Afaq Ali** — NOC Agent & IT Support Technician, Evamp & Saanga
BS Computer Science, University of Agriculture Peshawar (2024)
[linkedin.com/in/afaq-ali-cyber](https://linkedin.com/in/afaq-ali-cyber)

**Yawar Hassan** — BS Computer Science, University of Agriculture Peshawar (2024)

**Supervisor:** Mr. Nisar Ali, Lecturer, ICS/IT, University of Agriculture Peshawar
