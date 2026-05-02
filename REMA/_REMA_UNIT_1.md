# Unit 1: Introduction to Reverse Engineering and Malware Analysis

> **Course**: Reverse Engineering and Malware Analysis (REMA)
> **Unit**: 1 — Introduction to Reverse Engineering and Malware Analysis
> **Syllabus Duration**: 4 Hours
> **Reference Book**: Monnappa K A, *Learning Malware Analysis*, Packt Publishing, 2018

---

## Table of Contents

[[#1. Need for Reverse Engineering and Malware Analysis]]
[[#2. Malware Analysis Techniques]]
[[#3. Steps in Reverse Engineering]]
[[#4. Creating a Lab Environment for Malware Analysis]]

---

## 1. Need for Reverse Engineering and Malware Analysis

### 1.1 Why Malware Analysis Matters

> **Definition**: **Malware** (malicious software) is any software intentionally designed to cause damage, steal data, gain unauthorized access, or disrupt normal operation of a computer system.

Malware intrusion is the **leading type of cyberattack** on systems and computers worldwide. Categories include:

| Malware Type | Description |
|-------------|-------------|
| **Virus** | Self-replicating code that attaches to legitimate programs |
| **Worm** | Self-propagates across networks without host program |
| **Trojan** | Disguised as legitimate software; opens backdoor |
| **Ransomware** | Encrypts files and demands payment for decryption key |
| **Spyware** | Secretly monitors user activity and exfiltrates data |
| **Adware** | Delivers unwanted advertisements; may track browsing |
| **Rootkit** | Hides malware by modifying OS internals |
| **Botnet Agent** | Turns infected machine into remotely controlled bot |
| **Keylogger** | Records keystrokes to steal credentials and sensitive data |
| **Fileless Malware** | Runs in memory without writing files to disk; evades AV |

### 1.2 Goals of Malware Analysis

> **Definition**: **Malware Analysis** is the process of studying malware samples to understand their behavior, purpose, origin, and impact on the target environment.

**Why organizations invest in malware analysis:**
- Understand the **nature and scope** of a compromise
- Identify **Indicators of Compromise (IoCs)** for detection
- Determine the **attacker's intent** (espionage, financial, disruption)
- Understand **what data was compromised**
- Build **defenses and detection rules** (YARA, Snort signatures)
- Support **incident response and legal/forensic actions**
- Attribute attacks to **threat actors or nation-states**

### 1.3 Reverse Engineering Defined

> **Definition**: **Reverse engineering** is the process of deconstructing a system or artifact to understand its design, functionality, and operation — without access to the original source code or documentation.

In malware analysis, reverse engineering is applied to:
- **Executables** (PE files: `.exe`, `.dll`)
- **Scripts** (JavaScript, PowerShell, VBScript)
- **Documents** (PDF, Office, RTF with embedded malicious code)
- **Network protocols** (C2 communication)

### 1.4 Industry Relevance

Malware analysis and RE skills are in demand across:

| Industry | Use Case |
|----------|----------|
| Cybersecurity firms | Threat intelligence, detection engineering |
| Financial / Banking | Protecting against banking trojans, fraud |
| Healthcare | Protecting patient records from ransomware |
| Government / Law Enforcement | Attribution, investigation, cyber warfare |
| Telecom | Protecting infrastructure from advanced persistent threats |
| Software Development | Protecting applications from license bypass and tampering |

---

## 2. Malware Analysis Techniques

> Malware analysts choose from three complementary approaches based on available time, required depth, and analyst expertise.

```
┌──────────────────────────────────────────────────────────────────┐
│               MALWARE ANALYSIS APPROACHES                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  STATIC ANALYSIS                                                 │
│  ├── Examine without executing                                  │
│  ├── File metadata, strings, imports, disassembly               │
│  └── Safe; no risk of infection                                 │
│                                                                  │
│  DYNAMIC ANALYSIS                                               │
│  ├── Execute in controlled environment                          │
│  ├── Observe real-time behavior                                 │
│  └── Requires isolated sandbox/VM                              │
│                                                                  │
│  BEHAVIORAL ANALYSIS                                            │
│  ├── Subset of dynamic analysis                                 │
│  ├── Focus on observable actions (files, registry, network)     │
│  └── Uses automated sandbox tools                              │
└──────────────────────────────────────────────────────────────────┘
```

### 2.1 Static Analysis

> **Definition**: **Static analysis** (also called **code analysis**) examines a malware sample **without executing** it. The analyst inspects file properties, strings, imports, code structure, and disassembly.

#### 2.1.1 Basic Static Analysis

Performed first; fast and safe:

| Technique | Purpose | Tools |
|-----------|---------|-------|
| **File Hashing** | Unique fingerprint; lookup on VirusTotal | CertUtil, sha256sum, HashCalc |
| **AV Scanning** | Multi-engine detection check | VirusTotal, Windows Defender |
| **File Identification** | Determine true file type (beyond extension) | PEiD, ExeinfoPE, `file` command |
| **String Extraction** | Find hardcoded URLs, IPs, registry keys, passwords | Strings (Sysinternals), FLOSS |
| **PE Header Analysis** | Inspect imports, exports, sections, compilation timestamp | PEview, PE-bear, CFF Explorer |
| **Import Analysis** | Understand what Windows API calls the malware makes | Dependency Walker, PEview |

**Suspicious string categories to look for:**

| Category | Examples |
|----------|---------|
| Network indicators | IP addresses, domain names, URLs |
| Host indicators | Registry paths, file system paths |
| Persistence mechanisms | `HKEY_RUN`, Scheduled Tasks references |
| Encoding artifacts | Base64 strings, XOR keys |
| System commands | `cmd.exe`, `powershell.exe`, `regsvr32` |

#### 2.1.2 Advanced Static Analysis — Disassembly

Converts binary machine code back into assembly instructions:

| Tool | Description |
|------|-------------|
| **IDA Pro** | Industry-standard interactive disassembler |
| **Ghidra** | Free, open-source by NSA; includes decompiler |
| **Radare2** | Open-source reverse engineering framework |
| **Binary Ninja** | Modern disassembler/decompiler with scripting |
| **x64dbg** | Debugger with built-in disassembly view |

### 2.2 Dynamic Analysis

> **Definition**: **Dynamic analysis** executes the malware sample in a **controlled, isolated environment** and observes its real-time behavior — file operations, registry changes, network communications, and process activity.

#### 2.2.1 Why Dynamic Analysis?

Static analysis has limitations:
- Packed or encrypted malware cannot be disassembled before decryption
- Polymorphic malware changes structure each run
- Dynamic analysis reveals **actual run-time behavior**

#### 2.2.2 Dynamic Analysis Tools

| Category | Tool | What It Monitors |
|----------|------|-----------------|
| **Process Monitoring** | Process Monitor (ProcMon) | File, registry, network, process events |
| **Process Listing** | Process Hacker, Process Explorer | Running processes, loaded DLLs, memory |
| **Network Monitoring** | Wireshark, FakeNet-NG | Network traffic, DNS, HTTP, C2 connections |
| **Registry Monitoring** | RegShot | Before/after comparison of registry changes |
| **API Monitoring** | API Monitor | Windows API calls made by the sample |
| **Sandbox** | Cuckoo Sandbox, Any.Run | Automated behavioral report generation |

#### 2.2.3 Indicators from Dynamic Analysis

| Indicator Type | Examples |
|---------------|---------|
| **File Operations** | Created/modified/deleted files; dropped payloads |
| **Registry Changes** | Persistence keys (Run, RunOnce); configuration storage |
| **Network Activity** | C2 beaconing, DNS queries, data exfiltration |
| **Process Activity** | Spawned child processes; process injection |
| **Service/Driver** | Installation of malicious services or drivers |

### 2.3 Behavioral Analysis

> **Definition**: **Behavioral analysis** is a form of dynamic analysis that focuses on the **observable actions** of malware — what it does to the system, network, and user data — rather than its code structure.

**Key difference from deeper dynamic analysis**: Behavioral analysis answers *"what does it do?"* while code-level dynamic analysis with a debugger answers *"how does it do it?"*

**Automated behavioral sandboxes:**
- **Cuckoo Sandbox** — Open-source; generates reports on file/registry/network activity
- **Any.Run** — Interactive online sandbox with real-time behavioral reports
- **Joe Sandbox** — Commercial; deep static + dynamic combined analysis
- **VirusTotal** — Multi-engine scan plus limited behavioral analysis

**Comparison of all three techniques:**

| Aspect | Static | Dynamic | Behavioral |
|--------|--------|---------|------------|
| Execution required? | No | Yes | Yes |
| Infection risk? | None | Low (isolated) | Low (isolated) |
| Can defeat packing? | No | Yes | Yes |
| Speed | Fast | Moderate | Fast (automated) |
| Depth of analysis | Code level | Real-time runtime | Observable actions |
| Best for | Quick triage | Deep investigation | Initial profiling |

---

## 3. Steps in Reverse Engineering

### 3.1 The RE Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                   REVERSE ENGINEERING STEPS                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STEP 1: TRIAGE (Basic Static Analysis)                        │
│  ├── Compute hash; check VirusTotal                            │
│  ├── Identify file type; check for packing                     │
│  └── Extract strings; note interesting artifacts               │
│              │                                                  │
│              ▼                                                  │
│  STEP 2: BEHAVIORAL ANALYSIS (Basic Dynamic)                   │
│  ├── Execute in sandbox / monitored VM                         │
│  ├── Record file, registry, network activity                   │
│  └── Document IoCs (IPs, domains, mutexes, files)              │
│              │                                                  │
│              ▼                                                  │
│  STEP 3: ADVANCED STATIC ANALYSIS (Disassembly)                │
│  ├── Load in IDA Pro / Ghidra                                  │
│  ├── Identify key functions (WinMain, DllMain, exports)        │
│  └── Analyze code logic, obfuscation, encryption routines      │
│              │                                                  │
│              ▼                                                  │
│  STEP 4: ADVANCED DYNAMIC ANALYSIS (Debugging)                 │
│  ├── Load in debugger (x64dbg, WinDbg)                        │
│  ├── Set breakpoints on interesting API calls                  │
│  ├── Step through execution to understand control flow         │
│  └── Dump decrypted payloads from memory                       │
│              │                                                  │
│              ▼                                                  │
│  STEP 5: REPORT AND SIGNATURES                                 │
│  ├── Document findings (TTPs, IoCs)                            │
│  ├── Write YARA rules for detection                            │
│  └── Map to MITRE ATT&CK framework                            │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Understanding PE (Portable Executable) Format

> **Definition**: The **Portable Executable (PE)** format is the file format for executables, object code, DLLs, FON font files, and other object code on Windows.

**Key PE Header Sections:**

| Section | Description |
|---------|-------------|
| `.text` | Executable code |
| `.data` | Initialized global/static variables |
| `.rdata` | Read-only data (strings, constants) |
| `.rsrc` | Resources (icons, dialogs, version info) |
| `.idata` | Import table — lists DLLs and functions used |
| `.edata` | Export table — functions the DLL exposes |

**Useful PE header fields for malware analysts:**

| Field | Significance |
|-------|-------------|
| **TimeDateStamp** | Compilation timestamp (can be forged) |
| **Subsystem** | GUI (0x2) vs Console (0x3) |
| **Import Address Table** | Which DLLs/functions are used |
| **Section entropy** | High entropy (>7.0) suggests packing/encryption |

### 3.3 Key Windows APIs in Malware

Malware commonly uses specific Windows API categories:

| Category | Suspicious APIs |
|----------|----------------|
| **Process** | `CreateProcess`, `VirtualAlloc`, `WriteProcessMemory` |
| **Network** | `WSAStartup`, `connect`, `send`, `recv`, `InternetOpen` |
| **Registry** | `RegOpenKey`, `RegSetValueEx`, `RegCreateKey` |
| **File** | `CreateFile`, `WriteFile`, `CopyFile`, `DeleteFile` |
| **Crypto** | `CryptAcquireContext`, `CryptEncrypt`, `CryptDecrypt` |
| **Privilege** | `AdjustTokenPrivileges`, `OpenProcessToken` |

---

## 4. Creating a Lab Environment for Malware Analysis

> **Critical Principle**: Malware analysis **must always be performed in an isolated environment**. Executing malware on a production machine can cause real damage, data loss, or network propagation.

### 4.1 Lab Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                MALWARE ANALYSIS LAB SETUP                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  HOST MACHINE (Physical or trusted VM)                         │
│  └── Hypervisor: VMware Workstation / VirtualBox               │
│         │                                                       │
│         ├── WINDOWS ANALYSIS VM (primary)                      │
│         │    ├── Windows 7/10 (32-bit for legacy malware)      │
│         │    ├── Analysis tools installed                      │
│         │    ├── Isolated network adapter (Host-Only)          │
│         │    └── Snapshot taken BEFORE each analysis           │
│         │                                                       │
│         └── LINUX VM (optional)                                │
│              ├── REMnux (malware analysis distro)              │
│              └── FakeNet-NG / INetSim (simulate internet)      │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Network Isolation Options

| Network Mode | Description | Use Case |
|-------------|-------------|---------|
| **Host-Only** | VM can only talk to host; no real internet | Full isolation; safest |
| **NAT** | VM gets internet through host | Observe real C2 traffic (risky) |
| **Internal Network** | Multiple VMs talk to each other; no host/internet | Multi-VM analysis scenarios |
| **Simulated Internet** | INetSim or FakeNet-NG provides fake DNS, HTTP, SMTP | Trick malware into thinking it has internet |

### 4.3 Essential Analysis Tools

**Windows Analysis VM Tools:**

| Category | Tool |
|----------|------|
| **Disassemblers** | IDA Pro (free), Ghidra, Binary Ninja |
| **Debuggers** | x64dbg, WinDbg, OllyDbg (legacy) |
| **PE Analysis** | PEview, PE-bear, CFF Explorer, Detect-It-Easy (DIE) |
| **String Extraction** | Strings (Sysinternals), FLOSS (FireEye) |
| **Process Monitoring** | Process Monitor (ProcMon), Process Hacker |
| **Network Monitoring** | Wireshark, TCPView, FakeNet-NG |
| **Registry** | RegShot (before/after snapshot) |
| **Sandbox** | Cuckoo Sandbox |
| **Hex Editors** | HxD, 010 Editor |
| **Script Analysis** | Node.js (JS deobfuscation), PDF-parser (PDF) |

**REMnux (Linux-based malware analysis distribution):**
- Pre-installed tools for file analysis, network analysis, and memory forensics
- Tools: `peframe`, `volatility`, `yara`, `radare2`, `pdf-parser`, `oledump`

### 4.4 Safe Analysis Practices

| Practice | Reason |
|----------|--------|
| **Always use snapshots** | Restore VM to clean state after each analysis |
| **Disable VM Tools clipboard sharing** | Prevent accidental cross-VM data transfer |
| **Use Host-Only networking** | Prevent malware from reaching real internet |
| **Rename analysis tools** | Some malware checks for tool names (ProcMon.exe, wireshark.exe) |
| **Use a dedicated analysis machine** | Keep analysis completely separate from daily use |
| **Document everything** | Screenshots, tool output, timestamps — needed for reports |
| **Hash samples before analysis** | Ensure sample integrity; enable VirusTotal lookup |

### 4.5 REMnux and Flare VM

| Distribution | Platform | Description |
|-------------|----------|-------------|
| **REMnux** | Linux (Ubuntu) | Linux-based distro with pre-installed malware analysis tools; ideal for script/document analysis |
| **Flare VM** | Windows (VM overlay) | Windows 10 VM with all RE tools auto-installed via Chocolatey; developed by Mandiant/Google |
| **SANS SIFT Workstation** | Linux | Broader forensics + malware analysis toolset |

> **Flare VM** is particularly useful because it provides a pre-configured Windows analysis environment — the same OS most malware targets — with tools like x64dbg, Ghidra, FLOSS, PE-bear, and ProcMon pre-installed.
