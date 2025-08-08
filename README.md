# 🛡️ GitHub Project: Intrusion Detection on VirtualBox

---
> A project demonstrating how to install, configure, and use an Intrusion Detection System (IDS) such as **Snort** or **Suricata** on a **Linux VM** in **VirtualBox** to monitor and detect suspicious activity in a lab environment.

---

## 📂 Folder Structure

```
ids-virtualbox-lab/
├── README.md
├── images/
│   ├── snort-capture.png
│   ├── alert-log.png
│   └── network-setup.png
├── IDS_Setup_Guide.md
├── Skills_Learned.md
├── Example_Alerts.md
├── IDS_Rule_Creation.md
├── Troubleshooting.md
└── LICENSE
```

---

## 📄 `README.md`

```md
# 🛡️ Intrusion Detection System on VirtualBox VM

This project walks through setting up and running a **host-based intrusion detection system (HIDS)** or **network-based IDS (NIDS)** using **Snort** or **Suricata** on a **Linux virtual machine** in **VirtualBox**. It covers installation, rule creation, traffic generation, and alert analysis.

---

## 🎯 Project Goals

- Install and configure an IDS in a virtual environment
- Monitor network traffic for malicious behavior
- Learn how IDS rules work and how alerts are triggered
- Analyze alert logs and create custom rules

---

## 🛠 Tools Used

- **VirtualBox** – Virtualization platform
- **Ubuntu/Kali Linux** – OS for VM
- **Snort** or **Suricata** – IDS engine
- **Scapy / Nmap / hping3** – Tools for simulating attacks

---

## 🧱 Prerequisites

- VirtualBox installed with a Linux VM
- Bridged or Host-Only network mode for monitoring
- Root or sudo access on the VM
- Internet access to install packages

---

## 📘 Documentation

- 🧰 [IDS Setup Guide](IDS_Setup_Guide.md)
- ✍️ [Example Alerts](Example_Alerts.md)
- 🔧 [IDS Rule Creation](IDS_Rule_Creation.md)
- 💡 [Skills Learned](Skills_Learned.md)
- 🚑 [Troubleshooting](Troubleshooting.md)

---

## 🧠 Skills Learned

- IDS installation and configuration
- Creating and customizing detection rules
- Understanding alert logs and responses
- Basic threat simulation and penetration testing
- Network protocol analysis (TCP, UDP, ICMP)

---

## 🧠 `Skills_Learned.md`

```md
# 🧠 Skills Learned from IDS VirtualBox Project

## 🛡️ Cybersecurity Concepts

- **Intrusion Detection vs. Prevention**
- **Host-Based vs. Network-Based IDS**
- Understanding Snort/Suricata alert formats
- Analyzing real-time traffic and logs

## 💻 Technical Skills

- Installing and configuring IDS tools (Snort, Suricata)
- Editing rule sets and creating custom rules
- Parsing PCAPs and log files
- Using traffic simulation tools like `nmap`, `hping3`, and `scapy`
- Configuring VirtualBox networking (Bridged, Host-Only)

## 🧪 Lab/Testing Experience

- Designing a safe test environment for IDS
- Launching scans and malicious traffic for detection
- Monitoring system resource usage with IDS running

## 🧠 Soft Skills

- Problem-solving and research
- Troubleshooting installation and networking issues
- Documenting configuration steps
- Interpreting error messages and alerts
```

---

## 🔧 `IDS_Setup_Guide.md`

````md
# 🔧 IDS Setup Guide (Snort on Ubuntu)

## ✅ Step 1: VM Setup in VirtualBox

- Create or import a Linux VM (Ubuntu recommended)
- Set network adapter to `Bridged` or `Host-Only`
- Update system packages:
  ```bash
  sudo apt update && sudo apt upgrade
````

---

## 🔽 Step 2: Install Snort (Example)

```bash
sudo apt install snort -y
```

If using Suricata:

```bash
sudo apt install suricata -y
```

---

## ⚙️ Step 3: Configure the IDS

* Edit the configuration file:

  ```bash
  sudo nano /etc/snort/snort.conf
  ```
* Set correct interface, rule paths, and output logs

---

## 📝 Step 4: Create a Custom Rule

Example rule to detect ICMP ping:

```bash
echo 'alert icmp any any -> any any (msg:"ICMP Packet Detected"; sid:1000001; rev:1;)' | sudo tee /etc/snort/rules/local.rules
```

Ensure `local.rules` is included in `snort.conf`

---

## ▶️ Step 5: Run Snort

```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

---

## 🧪 Step 6: Generate Test Traffic

```bash
ping -c 4 8.8.8.8
nmap -sS 192.168.x.x
```

Snort should trigger alerts visible in console or log files.

---

## 📂 Step 7: Check Logs

```bash
cat /var/log/snort/alert
```

````

---

## ✍️ `Example_Alerts.md`

```md
# ✍️ Example IDS Alerts

## 🛑 Alert 1: ICMP Packet

````

\[**] \[1:1000001:1] ICMP Packet Detected \[**]
\[Priority: 0]
08/07-18:35:22.135634 192.168.1.5 -> 8.8.8.8
ICMP TTL:64 TOS:0x0 ID:54321 IpLen:20 DgmLen:84
Type:8  Code:0  ID:1   Seq:1  ECHO

```

---

## 🛑 Alert 2: Nmap SYN Scan

```

\[**] \[1:1000002:1] Nmap SYN Scan Detected \[**]
\[Priority: 2]
08/07-18:36:44.441900 192.168.1.5 -> 192.168.1.1
TCP TTL:64 TOS:0x0 ID:0 IpLen:20 DgmLen:40
\*\*\*\*\**S* Seq: 0x0  Ack: 0x0  Win: 0x4000

```

---

## 🛑 Alert 3: HTTP Access

```

\[**] \[1:1000003:1] HTTP GET Detected \[**]
\[Priority: 1]
08/07-18:40:10.111001 192.168.1.5 -> 93.184.216.34
TCP Dst Port: 80

```
```

---

## 🧪 `IDS_Rule_Creation.md`

```md
# 🧪 Writing Custom Snort Rules

## 📌 Rule Format

```

action protocol src\_ip src\_port -> dest\_ip dest\_port (options)

```

## 📝 Example 1: Detect ICMP

```

alert icmp any any -> any any (msg:"ICMP Detected"; sid:1000001; rev:1;)

```

## 📝 Example 2: Detect SYN Scan

```

alert tcp any any -> any any (flags\:S; msg:"SYN Scan"; sid:1000002; rev:1;)

```

## 📝 Example 3: HTTP Detection

```

alert tcp any any -> any 80 (msg:"HTTP Access"; sid:1000003; rev:1;)

```

## ➕ Notes

- `sid` must be unique
- Always increment `rev` on rule changes
- Restart Snort after rule changes
```

---

## 🚑 `Troubleshooting.md`

````md
# 🚑 IDS Troubleshooting Tips

## ❌ Snort Not Logging Alerts

- Ensure `output alert_fast` is enabled in `snort.conf`
- Verify the interface (e.g., `eth0`, `enp0s3`) is correct
- Run in verbose mode for debugging:
  ```bash
  sudo snort -A console -i eth0 -c /etc/snort/snort.conf
````

## ❌ No Rules Loaded

* Make sure `local.rules` is referenced in `snort.conf`
* Check for syntax errors in custom rules

## ❌ Permissions Issues

* Run with `sudo`
* Confirm `snort` has access to `/var/log/snort`

## ❌ Traffic Not Detected

* Switch VM network mode to `Bridged`
* Try `nmap`, `ping`, or `curl` to generate traffic

```

Let me know if you'd like the project zipped or turned into a GitHub-ready repo!
```
