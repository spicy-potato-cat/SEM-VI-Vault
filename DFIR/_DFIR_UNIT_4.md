# Unit 4: Network Forensics

> **Course**: Digital Forensics and Incident Response (DFIR)
> **Unit**: 4 - Network Forensics
> **Book Reference**: *Guide to Computer Forensics and Investigations*, 5th Edition — Ch. 10 & 11
> **Additional Reference**: NIST SP 800-86 — *Guide to Integrating Forensic Techniques into Incident Response* (2006)

---

## Table of Contents

[[#1. Overview of Network Forensics]]
[[#2. Analyzing Network Traffic]]
[[#3. Network-Based Evidence]]
[[#4. Investigating Routers]]

---

## 1. Overview of Network Forensics

### 1.1 Definition and Goals

> **Definition**: **Network Forensics** is the process of collecting and analyzing raw network data and systematically tracking network traffic to ascertain how an attack was carried out or how an event occurred on a network.

Because network attacks are on the rise, the demand for skilled network forensics specialists is growing rapidly. Labor forecasts predicted a shortfall of 50,000 network forensics specialists across law enforcement, legal firms, companies, and universities.

**Core Goals**:

| # | Goal | Description |
|---|------|-------------|
| 1 | Collect | Capture raw network traffic and logs |
| 2 | Analyze | Identify anomalies, attack patterns, intrusion indicators |
| 3 | Track | Reconstruct the sequence of events on a network |
| 4 | Report | Document findings in a legally admissible manner |

---

### 1.2 Why Network Forensics Matters

- **Intrusion evidence** exists primarily on the network — packet captures, connection logs, firewall records
- Being able to **spot variations in network traffic** can help you track intrusions; knowing your network's *typical* traffic patterns is essential
- Example: if peak usage is 6 a.m.–6 p.m., a usage spike during the night is a red flag
- Network forensics can **distinguish a real attack** from an admin error (e.g., an untested patch causing anomalous traffic)
- When intruders break into a network, they **leave a trail** — logs, artifacts in memory, altered files

---

### 1.3 The Need for Established Procedures

Network forensics examiners must establish **standard procedures** before an incident occurs. Key considerations:

- Network administrators want to find compromised machines, get them offline, and restore quickly
- However, taking time to **follow standard procedures** is essential to find all compromised systems and understand the attack method
- Procedures must be based on an organization's needs and complement the network infrastructure

**Key frameworks and references**:

| Source | Publication |
|--------|------------|
| NIST | SP 800-86 — *Guide to Integrating Forensic Techniques into Incident Response* |
| Adeyemi, Razak & Azhan (2012) | *Identifying Critical Features for Network Forensics Investigation Perspectives* |
| General framework | www.ijcaonline.org (2010) — Military, law enforcement, industry perspectives |

---

### 1.4 Securing a Network (Defense in Depth)

Network forensics is used to determine *how* a breach occurred, but networks must be **hardened** before breaches happen.

> **Definition**: **Defense in Depth (DiD)** is the NSA's approach to implementing a layered network defense strategy. It focuses on three modes of protection: **People, Technology, and Operations**.

```
┌──────────────────────────────────────────────────────────────────┐
│              DEFENSE IN DEPTH (DiD) — NSA FRAMEWORK             │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌────────────────────────────────────────────────────────┐    │
│   │  PEOPLE                                                │    │
│   │  Hire qualified staff; adequate security training      │    │
│   │  Physical & personnel security measures                │    │
│   └────────────────────────────────────────────────────────┘    │
│                          ▼                                       │
│   ┌────────────────────────────────────────────────────────┐    │
│   │  TECHNOLOGY                                            │    │
│   │  Strong network architecture; IDSs; firewalls          │    │
│   │  Regular penetration testing + risk assessment         │    │
│   └────────────────────────────────────────────────────────┘    │
│                          ▼                                       │
│   ┌────────────────────────────────────────────────────────┐    │
│   │  OPERATIONS                                            │    │
│   │  Daily patch updates; antivirus; disaster recovery     │    │
│   │  Assessment & monitoring procedures                    │    │
│   └────────────────────────────────────────────────────────┘    │
│                                                                  │
│  KEY: If one mode fails, the others can still thwart the attack  │
└──────────────────────────────────────────────────────────────────┘
```

**Layered Network Defense Strategy**: Sets up layers of protection so that the most valuable data is at the innermost layer. The deeper an attacker gets, the more difficult access becomes.

**Internal vs. External Threats**:
- In the early/mid-1990s: ~70% of attacks were caused by **internal employees**
- Today: internal and external threats are approximately **50-50** due to increased Internet use
- Contract employees often have same network privileges as full-time employees — a significant risk factor

---

### 1.5 Standard Network Forensics Procedure

```
┌───────────────────────────────────────────────────────────────────┐
│           STANDARD NETWORK FORENSICS PROCEDURE                    │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  STEP 1: STANDARD BASELINE IMAGE                                  │
│  Always use a standard installation image for all network         │
│  systems — with MD5/SHA-1 hash values of all application/OS files │
│                          │                                        │
│                          ▼                                        │
│  STEP 2: FIX THE VULNERABILITY                                    │
│  When an intrusion occurs, patch the vulnerability first          │
│  Prevent further exploitation of the same opening                 │
│                          │                                        │
│                          ▼                                        │
│  STEP 3: LIVE ACQUISITION                                         │
│  Retrieve volatile data — RAM, running processes                  │
│  Do BEFORE turning the system off                                 │
│                          │                                        │
│                          ▼                                        │
│  STEP 4: FORENSIC IMAGING                                         │
│  Acquire the compromised drive and create a forensic image        │
│                          │                                        │
│                          ▼                                        │
│  STEP 5: COMPARISON & ANALYSIS                                    │
│  Compare image with original installation image                   │
│  Compare hash values of common files (Win.exe, DLLs)             │
│  Check for rootkits, Trojans, modified files                      │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

> **Rootkit**: A collection of tools that attackers install on a compromised system to perform reconnaissance (using `ls`, `netstat`), keylogging, and other actions while hiding their presence.

---

## 2. Analyzing Network Traffic

### 2.1 Order of Volatility (OOV)

> **Definition**: The **Order of Volatility (OOV)** determines how long a piece of information lasts on a system. Data such as RAM and running processes might exist for only milliseconds; files stored on a hard drive might last for years.

| Priority | Data Type | Volatility |
|---------|-----------|-----------|
| 1st (capture first) | RAM / running processes | Lost on power-off |
| 2nd | Network connections, routing tables | Lost on shutdown |
| 3rd | Temporary files, swap space | May be overwritten |
| 4th | Hard drive (NAND Flash) | Persistent; survives power loss |
| 5th | Remote logs, monitoring data | May be overwritten by rotation |
| 6th | Archival media | Stable |

---

### 2.2 Reading Network Logs

Network logs record all traffic in and out of a network. Network servers, routers, firewalls, and other devices log the activities and events that move through them.

**tcpdump** — The most common command-line tool for examining network traffic. Can produce hundreds or thousands of records.

**tcpdump Output Format**:
```
time ; protocol ; interface ; size ; source_IP:port → destination_IP:port
```

**Sample tcpdump Output**:
```
TCP log from 2015-12-16:15:06:33 to 2015-12-16:15:06:34.
Tue Dec 16 15:06:33 2015; TCP; eth0; 1296 bytes; from
204.146.114.10:1916 to 156.26.62.201:126
Tue Dec 16 15:06:33 2015; TCP; eth0; 625 bytes; from
192.168.114.30:289 to 188.226.173.122:13
Tue Dec 16 15:06:33 2015; TCP; eth0; 2401 bytes; from
192.168.5.41:529 to 188.226.173.122:31; first packet
```

**Reading a tcpdump line**:
- `Tue Dec 16 15:06:33 2015` — Timestamp
- `TCP` — Protocol used
- `eth0` — Network interface (Ethernet 0)
- `1296 bytes` — Packet size
- `204.146.114.10:1916` — Source IP:Port
- `156.26.62.201:126` — Destination IP:Port

**Forensic clues in port numbers**:
- A receiving port **above 1024** should raise a flag
- Check IANA (www.iana.org/assignments/port-numbers) for a list of assigned port numbers
- Unusual or high-numbered destination ports may indicate unauthorized access or C2 traffic

---

### 2.3 Packet Analyzers

> **Definition**: **Packet analyzers** (also called sniffers) are devices or software placed on a network to monitor and capture traffic. They operate at **Layer 2 or Layer 3 of the OSI model**.

**Types**:
- Some analyzers perform **packet capture only**
- Some are used for **analysis only**
- Some handle **both capture and analysis**

**Pcap Format**:
- Most tools can read the **Pcap (Packet Capture)** format
- **Libpcap** — Linux version
- **WinPcap** — Windows version
- Programs such as `tcpdump` and `Wireshark` use Pcap format

```
┌──────────────────────────────────────────────────────────────┐
│              OSI MODEL — WHERE PACKET ANALYZERS WORK         │
├──────────────────────────────────────────────────────────────┤
│  Layer 7 — Application                                       │
│  Layer 6 — Presentation                                      │
│  Layer 5 — Session                                           │
│  Layer 4 — Transport          ← TCP header analysis          │
│  Layer 3 — Network  ◄─ Packet analyzers work here           │
│  Layer 2 — Data Link ◄─ and here                            │
│  Layer 1 — Physical                                          │
└──────────────────────────────────────────────────────────────┘
```

---

### 2.4 Network Traffic Analysis Tools

| Tool | Type | Key Features |
|------|------|-------------|
| **Wireshark** | GUI packet analyzer | Real-time capture; reads Pcap files; "Follow TCP Stream" to rebuild sessions; filter by protocol/IP/port; most widely used |
| **tcpdump** | CLI packet capture | Lightweight; scriptable; SYN flood detection; outputs Pcap format; runs on Linux/Windows |
| **Tcpslice** | CLI | Extracts specific time frames from large Libpcap files; can combine files |
| **Tcpreplay** | CLI | Replays recorded Libpcap traffic; used to test IDSs, switches, routers |
| **Tcpdstat** | CLI | Real-time Libpcap statistics; breaks packets down by protocol; shows avg/max transfer rates |
| **Ngrep** | CLI | Examine email headers or chat logs; identifies worm/virus network communication; similar to tcpdump with grep |
| **Etherape** | GUI | Graphical network traffic visualization |
| **Netdude** | GUI | Easy interface for inspecting large tcpdump files (multi-GB) |
| **Argus** | CLI/daemon | Session data probe, collector, and analysis tool; real-time flow monitor for security, accounting, and network management |
| **Tripwire** | Automated | Audit control program that detects traffic anomalies and sends automatic alerts |

**Wireshark — Follow TCP Stream**:
- Right-click a frame in the upper pane → *Follow TCP Stream*
- Traces all packets associated with an exploit or session
- Reconstructs the full conversation between client and server

**SYN Flood Detection with tcpdump**:
- In a **SYN flood attack**, the attacker repeatedly sends SYN packets to exhaust server connection state
- tcpdump can be programmed to examine TCP headers for the **SYN flag**
- The Flags area of a TCP header contains: SYN (S), ACK (A), FIN (F), RST (R), PSH (P), URG (U)

---

### 2.5 Sysinternals / PsTools (Windows Network Tools)

**Sysinternals** — A collection of free tools for examining Windows products (by Mark Russinovich, acquired by Microsoft):

| Tool | Function |
|------|---------|
| RegMon | Shows all Registry data in real time |
| Process Explorer | Shows what files, Registry keys, and DLLs are loaded at a specific time |
| Handle | Shows what files are open and which processes are using them |
| FileMon | Shows file system activity |

**PsTools Suite** — Remote management and monitoring:

| Tool | Function |
|------|---------|
| PsExec | Runs processes remotely |
| PsGetSid | Displays the Security Identifier (SID) of a computer or user |
| PsKill | Kills processes by name or process ID |
| PsList | Lists detailed process information |
| PsLoggedOn | Displays who is logged on locally |
| PsPasswd | Allows changing account passwords |
| PsService | Views and controls services |
| PsShutdown | Shuts down and optionally restarts a computer |
| PsSuspend | Suspends processes |

> **Security Warning**: If an attacker gains administrative rights to a network, these same tools can be weaponized. Example: a student used `PsShutdown` to remotely shut down another machine because no password was set for the default admin account.

---

## 3. Network-Based Evidence

### 3.1 Types of Network Evidence

```
┌──────────────────────────────────────────────────────────────────┐
│              NETWORK-BASED EVIDENCE TYPES                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Volatile Evidence (capture immediately)                         │
│  ──────────────────────────────────────                          │
│  • RAM contents — active processes, decryption keys             │
│  • Running network connections and open sockets                  │
│  • Routing tables, ARP cache                                     │
│  • Active user sessions, logged-on users                        │
│                                                                  │
│  Network Log Evidence                                            │
│  ──────────────────────────────────────                          │
│  • Router logs — traffic in/out, ACL hits                       │
│  • Firewall logs — allowed/denied connections                   │
│  • IDS/IPS logs — alert signatures, blocked attacks             │
│  • DHCP logs — IP address assignments over time                 │
│  • DNS logs — domain resolution requests                        │
│                                                                  │
│  Packet Capture Evidence                                         │
│  ──────────────────────────────────────                          │
│  • Full packet captures (Pcap files)                            │
│  • Protocol-specific captures (HTTP, FTP, SMTP)                 │
│  • Reconstructed sessions (TCP streams)                         │
│                                                                  │
│  Application Evidence                                            │
│  ──────────────────────────────────────                          │
│  • Web server access/error logs                                 │
│  • Email server logs (SMTP headers, message-IDs)               │
│  • Authentication logs (failed logins, brute force)             │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

### 3.2 Live Acquisition for Network Evidence

Live acquisitions are especially useful when:
- Dealing with **active network intrusions** or ongoing attacks
- Investigating employees accessing network areas they shouldn't
- **Malware that disappears after a reboot** — some threats exist only in RAM
- Taking the system offline would adversely affect business operations

**Live Acquisition Steps**:

```
1. Create/download a bootable forensic CD or USB drive; test before use
2. Keep a log of all actions — document everything and the reasons for it
3. Use a network drive (preferred) or external drive to collect data
4. Copy physical memory (RAM) using tools like:
   - Mandiant Memoryze — lists open network sockets including rootkit-hidden ones
   - Belkasoft RamCapturer — 32-bit/64-bit; runs from USB
   - FTK Imager
   - OSForensics
5. Check for rootkits (e.g., RootKitRevealer); examine firmware; create network image
6. Get a forensically sound hash (MD5/SHA-1) of all recovered files
```

> **Important**: After a live acquisition, information on the system has changed because your actions affect RAM and running processes. Therefore, live acquisitions **do not follow typical forensics procedures** and results cannot be exactly reproduced.

---

### 3.3 Network Log Analysis

**Generating Top-N Reports** (using Wireshark or similar):

**Top 10 External Sites Visited**:
```
4897  188.226.173.122
2592  156.26.62.201
4897  110.150.70.190
4897  132.130.65.172
```
*(bytes transferred listed first, then IP address)*

**Top 10 Internal Users by Traffic Volume**:
```
4897  192.168.5.119
4897  192.168.5.41
4897  192.168.5.44
4897  192.168.5.5
```

These logs reveal patterns such as:
- An employee repeatedly transmitting data to a specific external IP → possible data exfiltration
- Unusual high-volume traffic to shopping/streaming sites
- Access at unexpected hours → possible unauthorized access

**Evidence Preservation Note**:
- Your investigation might uncover **other compromised companies**
- Do not reveal information discovered about other organizations publicly
- Contact affected companies and enlist their help in tracking the intruder
- Report to federal authorities when appropriate

---

### 3.4 The Honeynet Project

> **Definition**: A **Honeypot** is a computer set up to look like any other machine on a network; its purpose is to lure attackers but it contains no information of real value.

> **Definition**: **Honeywalls** are computers set up to monitor what is happening to honeypots on your network and record attacker activity.

**The Honeynet Project** (https://www.honeynet.org):
- Worldwide collaborative project designed to make information available to thwart Internet and network attackers
- Three objectives: **Awareness**, **Information**, **Tools**

**Major Threats Studied**:

| Threat | Description |
|--------|------------|
| **DDoS Attacks** | Distributed Denial-of-Service; uses hundreds/thousands of **zombie** machines (compromised without owners' knowledge); high monetary and time cost |
| **Zero-Day Attacks** | Launched before vendors are aware of vulnerabilities; no patch exists; penetration testers seek to find these before attackers do |

> **Honeypot use**: You can take a honeypot offline to analyze it without affecting the running network. Honeypots and honeywalls are used to study attacker behavior, tools, and tactics.

---

### 3.5 Evidence Preservation in Network Investigations

| Priority | Action |
|---------|--------|
| Volatile first | Capture RAM before shutdown |
| Document continuously | Log every action, tool version, timestamp |
| Hash everything | MD5 + SHA-1/SHA-256 of all acquired files |
| Protect other organizations' data | Redact or secure data about uninvolved parties |
| Warrant for third-party data | ISP logs, email records, and cloud data require legal process |

---

## 4. Investigating Routers

### 4.1 Role of Routers in Network Forensics

Routers are critical sources of evidence in network investigations. They:
- Route packets between network segments
- Maintain **Access Control Lists (ACLs)** to allow or deny traffic based on source/destination IP address
- Record logs of **all traffic flowing through their ports**
- Act as the gateway through which all network data passes

> **Key Forensic Value**: A router's log can reveal the **complete path** a packet or email took across the network, and can confirm or deny that specific traffic occurred.

---

### 4.2 Router Logs

**Network administrators maintain logs of inbound and outbound traffic** that routers handle.

**What Router Logs Record**:

| Log Entry Type | Information Captured |
|---------------|---------------------|
| Traffic flow | Source IP, destination IP, port, protocol, bytes |
| ACL hits | Matched allow/deny rules, timestamps |
| Interface activity | Traffic per port/interface |
| Connection state | Established, dropped, rejected connections |

**Using Router Logs in Investigation**:
- **Email tracing**: Review router logs to find the path a transmitted email took; look for the unique message ID number
- **IP mapping**: Cross-reference log IPs with ARIN (www.arin.net) or InterNIC (www.internic.com) to map IP addresses to domain names and find point-of-contact
- **Verification**: Verify email header claims by checking network e-mail logs

**Requesting Router Logs**:
- The network administrator who manages routers can supply log files
- In a criminal investigation, a **warrant or subpoena** may be required
- Build a working relationship with network administrators — they are essential to network forensics

---

### 4.3 Firewall Logs

Firewalls filter Internet traffic and maintain log files that track traffic destined for other networks or the protected network.

**Firewall Log Analysis**:
- Opened in a text editor (Notepad on Windows, `vim` on Linux)
- Some firewalls require **special programs** to read their proprietary log format
- Logs confirm whether a specific email or packet **passed through the firewall**
- Cross-reference with router logs for a complete traffic picture

**Typical Firewall Log Fields**:

```
Date | Time | Action | Protocol | Source IP | Dest IP | Source Port | Dest Port | Size
```

---

### 4.4 Investigating Router-Based Evidence: Step-by-Step

```
┌───────────────────────────────────────────────────────────────────┐
│           ROUTER INVESTIGATION PROCEDURE                          │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  STEP 1: CONTACT NETWORK ADMINISTRATOR                            │
│  Request router and firewall log files                            │
│  Obtain access credentials if authorized                          │
│                          │                                        │
│                          ▼                                        │
│  STEP 2: IDENTIFY RELEVANT TIME WINDOW                            │
│  Determine timeframe of incident from initial evidence            │
│  Use Tcpslice or similar to extract that time window from logs   │
│                          │                                        │
│                          ▼                                        │
│  STEP 3: REVIEW ACCESS CONTROL LISTS (ACLs)                      │
│  Document current ACL rules                                       │
│  Identify rules that may have been added/modified by attacker    │
│                          │                                        │
│                          ▼                                        │
│  STEP 4: TRACE TRAFFIC PATH                                       │
│  Use router logs to reconstruct the path of suspect traffic      │
│  Map IPs using ARIN / InterNIC                                    │
│                          │                                        │
│                          ▼                                        │
│  STEP 5: CORRELATE WITH OTHER LOGS                                │
│  Cross-reference router logs with firewall, IDS, DHCP, DNS logs  │
│  Build a complete timeline of network activity                    │
│                          │                                        │
│                          ▼                                        │
│  STEP 6: DOCUMENT AND HASH                                        │
│  Hash all log files (MD5/SHA-1) immediately                       │
│  Document chain of custody for all obtained records              │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

---

### 4.5 IP Address Mapping Resources

When investigating router logs, the source/destination IPs must be mapped to organizations:

| Resource | URL | Use |
|----------|-----|-----|
| **ARIN** | www.arin.net | American Registry for Internet Numbers; maps IP address to domain name and finds point of contact |
| **InterNIC** | www.internic.com | Finds a domain's IP address and point of contact |
| **IANA Port Registry** | www.iana.org/assignments/port-numbers | List of assigned well-known port numbers |
| **Google / search engines** | www.google.com | Look for additional postings and information about suspect addresses |

> **Warning**: A suspect may have posted **false registration information**. Always verify findings by checking network email logs against email addresses and cross-referencing multiple sources.

---

### 4.6 Key Network Forensics Tools Summary

```
┌───────────────────────────────────────────────────────────────────┐
│              NETWORK FORENSICS TOOL SELECTION GUIDE               │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Need real-time packet capture?                                   │
│  ─────────────────────────────────────────────────────────────►  │
│           Wireshark (GUI) or tcpdump (CLI)                        │
│                                                                   │
│  Need to analyze a large existing Pcap file?                     │
│  ─────────────────────────────────────────────────────────────►  │
│           Wireshark, Netdude, or Tcpstat                          │
│                                                                   │
│  Need to extract a time window from a capture?                   │
│  ─────────────────────────────────────────────────────────────►  │
│           Tcpslice                                                │
│                                                                   │
│  Need to test IDSs/routers/switches with captured traffic?       │
│  ─────────────────────────────────────────────────────────────►  │
│           Tcpreplay                                               │
│                                                                   │
│  Need to analyze email/chat headers in network traffic?          │
│  ─────────────────────────────────────────────────────────────►  │
│           Ngrep                                                   │
│                                                                   │
│  Need anomaly-based alerting on live traffic?                    │
│  ─────────────────────────────────────────────────────────────►  │
│           Tripwire (automated audit control)                      │
│                                                                   │
│  Need to capture live RAM from a suspect machine?                │
│  ─────────────────────────────────────────────────────────────►  │
│           Mandiant Memoryze / Belkasoft RamCapturer / FTK Imager │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

---

## Key Terms

| Term | Definition |
|------|-----------|
| **Network Forensics** | The process of collecting and analyzing raw network data and systematically tracking network traffic to determine how security incidents occur |
| **Defense in Depth (DiD)** | The NSA's approach to implementing a layered network defense strategy, focusing on People, Technology, and Operations |
| **Order of Volatility (OOV)** | A term indicating how long an item on a network lasts; RAM and running processes last milliseconds, hard drive data lasts years |
| **Packet Analyzers** | Devices and software used to examine network traffic; operate at Layers 2 and 3 of the OSI model |
| **tcpdump** | A command-line packet capture and analysis tool that produces output in Pcap format |
| **Wireshark** | A GUI-based packet capture and analysis tool that can rebuild TCP sessions |
| **Pcap** | Packet Capture format; standard format for network captures; Libpcap (Linux) and WinPcap (Windows) |
| **Honeypot** | A computer or network set up to lure an attacker; contains no real data of value |
| **Honeywall** | An intrusion prevention and monitoring system that tracks what attackers do on honeypots |
| **Layered Network Defense Strategy** | An approach to network hardening that sets up several network layers to place the most valuable data at the innermost part |
| **Distributed Denial-of-Service (DDoS)** | A type of DoS attack in which other online machines are used, without the owners' knowledge, to launch an attack |
| **Zero-Day Attack** | An attack launched before a patch is available; before the vendor is aware of the vulnerability |
| **Zombie** | A computer used without the owner's knowledge in a DDoS attack |
| **ACL (Access Control List)** | A set of rules on a router that allows or denies traffic based on source/destination IP address |
| **Rootkit** | A collection of tools that attackers install on a compromised system to hide their presence and maintain access |
| **Live Acquisition** | Acquisition of volatile data (RAM, running processes) from a system while it is still running |

---

## Sources

- Nelson, B., Phillips, A., & Steuart, C. (2016). *Guide to Computer Forensics and Investigations* (5th ed.). Cengage Learning. — Chapter 10: Virtual Machine Forensics, Live Acquisitions, and Network Forensics; Chapter 11: E-mail and Social Media Investigations (Network E-mail Logs section)
- NIST Special Publication 800-86 — *Guide to Integrating Forensic Techniques into Incident Response* (2006)
- The Honeynet Project — https://www.honeynet.org
- ARIN — https://www.arin.net
- IANA Port Registry — https://www.iana.org/assignments/port-numbers
- Adeyemi, I.R., Razak, S.A., & Azhan, N. (2012). *Identifying Critical Features for Network Forensics Investigation Perspectives*. arXiv:1210.1645
