# Unit 6: Dark Web Forensics and Anti-Forensics Techniques

> **Course**: Digital Forensics and Incident Response (DFIR)
> **Unit**: 6 - Dark Web Forensics and Anti-Forensics Techniques
> **Book Reference**: *Guide to Computer Forensics and Investigations*, 5th Edition — Ch. 8, Ch. 9
> **Additional Reference**: Evers, B. et al., *Thirteen Years of Tor Attacks* (Attacks-on-Tor/Attacks-on-Tor, GitHub)

---

## Table of Contents

[[#1. Dark Web Forensics]]
[[#2. Anti-Forensics Techniques]]

---

## 1. Dark Web Forensics

### 1.1 The Web Layered Model

> **Definition**: The **Internet** is commonly divided into three distinct layers based on accessibility and indexing by search engines.

The three layers form a conceptual stack from publicly visible content to intentionally hidden services:

```
┌─────────────────────────────────────────────────────────────┐
│                  THE WEB LAYERS MODEL                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────────────────────────────────────────────────────┐   │
│   │              SURFACE WEB (~4%)                      │   │
│   │   Indexed by Google, Bing, Yahoo                    │   │
│   │   News sites, e-commerce, social media              │   │
│   └─────────────────────────────────────────────────────┘   │
│                         ▼                                    │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                DEEP WEB (~96%)                      │   │
│   │   Not indexed — requires login or direct URL        │   │
│   │   Banking portals, medical records, private DBs     │   │
│   └─────────────────────────────────────────────────────┘   │
│                         ▼                                    │
│   ┌─────────────────────────────────────────────────────┐   │
│   │              DARK WEB (subset of Deep Web)          │   │
│   │   Requires special software (Tor, I2P, Freenet)     │   │
│   │   .onion domains, hidden services, anonymised comms │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

| Layer | Accessibility | Indexing | Examples |
|-------|--------------|----------|----------|
| Surface Web | Open browser | Yes | Wikipedia, news sites |
| Deep Web | Direct URL / auth | No | Online banking, academic DBs |
| Dark Web | Tor / I2P / Freenet | No | .onion sites, hidden services |

---

### 1.2 The Tor Network Architecture

> **Definition**: **Tor (The Onion Router)** is a low-latency, anonymity network based on **onion routing**, where data is wrapped in multiple layers of encryption and forwarded through a randomly selected chain of volunteer-operated relay nodes, ensuring no single node knows both the sender and the receiver.

Tor was originally developed by the U.S. Naval Research Laboratory for protecting government communications. It is now an open-source project. More than 7,000 distinct relay nodes carry terabytes of traffic each day for hundreds of thousands of users.

#### 1.2.1 Onion Routing — How it Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                  ONION ROUTING — DATA FLOW                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   Client                                                  Server    │
│   ┌─────┐  Enc(Enc(Enc(data)))   ┌───────┐               ┌──────┐  │
│   │     │ ─────────────────────▶ │ Guard │               │      │  │
│   │ OP  │                        │ Node  │               │      │  │
│   │     │                        │(Entry)│               │      │  │
│   └─────┘                        └───┬───┘               └──────┘  │
│                                      │ Enc(Enc(data))               │
│                                      ▼                              │
│                                  ┌───────┐                          │
│                                  │ Middle│                          │
│                                  │ Relay │                          │
│                                  └───┬───┘                          │
│                                      │ Enc(data)                    │
│                                      ▼                              │
│                                  ┌───────┐                          │
│                                  │  Exit │──────────────▶ Server   │
│                                  │  Node │  Raw data               │
│                                  └───────┘                          │
│                                                                      │
│   Each relay decrypts ONE layer — knows only prev/next hop          │
└─────────────────────────────────────────────────────────────────────┘
```

**Key Components**:
- **Onion Proxy (OP)**: Local software on the user's machine; accepts SOCKS connections and builds circuits
- **Entry/Guard Node**: First relay; knows the client's real IP but not the destination
- **Middle Relay**: Intermediate node; knows only the nodes before and after it
- **Exit Node**: Final relay; forwards traffic to the open Internet; knows the destination but not the origin
- **Directory Servers**: Authoritative servers that list all known relays and their metadata
- **Bridges**: Unlisted relays used to bypass censorship; not published in directory servers

**Session Key Negotiation**: Each relay negotiates a separate session key with the client using a **Diffie-Hellman handshake**. Messages are encrypted incrementally — the client wraps the data with exit node key first, then middle relay key, then entry node key. Each relay peels off one encryption layer.

A **circuit** typically consists of **three relays**. Multiple TCP streams are **multiplexed** over a single circuit.

---

#### 1.2.2 Hidden Services (.onion Addresses)

> **Definition**: A **Hidden Service** (now called an **Onion Service**) is a network service — web server, chat server, etc. — whose real IP address and location is concealed by the Tor network. It is reachable only via a `.onion` address.

**How a Hidden Service Connection is Established**:

```
┌─────────────────────────────────────────────────────────────────────┐
│              HIDDEN SERVICE CONNECTION SETUP                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   STEP 1: Hidden Server selects Introduction Points (IPs)           │
│           and registers them with HSDir (Hidden Service Dirs)       │
│                                                                      │
│   STEP 2: Client fetches HS descriptor (incl. IP list) from HSDir   │
│                                                                      │
│   STEP 3: Client selects a Rendezvous Point (RP), sends             │
│           one-time secret to RP                                      │
│                                                                      │
│   STEP 4: Client sends "connect" request to Introduction Point,     │
│           including RP address + one-time secret                    │
│                                                                      │
│   STEP 5: Hidden Server connects to RP using the one-time secret    │
│                                                                      │
│   STEP 6: RP bridges the two circuits → Anonymous end-to-end        │
│           communication established                                  │
│                                                                      │
│   RESULT: Client doesn't know HS server location                    │
│           HS server doesn't know client location                    │
│           RP knows neither client identity nor HS identity          │
└─────────────────────────────────────────────────────────────────────┘
```

**Properties of Hidden Service Communication**:
- Neither client nor server reveals its IP address to the other
- The Rendezvous Point does not know the content being transmitted
- At least **two or more** anonymizing relays exist between each endpoint and the RP
- `.onion` addresses are derived from the SHA-1 hash of the hidden service's public key (v2) or SHA-3/ed25519 (v3 — current standard)

---

### 1.3 Dark Web Criminal Landscape

The same properties that protect journalists and activists under repressive regimes also attract criminal exploitation. Research shows approximately **44% of websites** hosted as hidden services are of criminal intent (Biryukov et al., 2014).

**Categories of Dark Web Criminal Activity**:

| Category | Examples |
|----------|----------|
| Drug Markets | Silk Road (shut 2013), AlphaBay, Hansa Market |
| Weapons | Firearms, ammunition trade |
| Financial Fraud | Stolen credit cards, fake identities, money laundering |
| Malware / Hacking | Exploit kits for sale, RaaS (Ransomware-as-a-Service) |
| Child Exploitation | CSAM — FBI's "Playpen" case (2015) |
| Terrorist Content | ISIS propaganda (.onion sites discovered 2015) |
| Counterfeit Documents | Fake passports, licenses |

> **Case Study: Silk Road (2011–2013)**: Silk Road was the most notorious dark web marketplace for illegal drugs and other contraband. It was operated by Ross Ulbricht under the pseudonym "Dread Pirate Roberts." The FBI located the Silk Road servers in Iceland — attributed to a CAPTCHA misconfiguration that leaked the real server IP — and shut it down in 2013. Ulbricht was arrested and sentenced to life in prison.

---

### 1.4 Dark Web Forensics Investigation Challenges

Dark web investigations are substantially harder than conventional digital forensics due to by-design anonymity protections.

```
┌─────────────────────────────────────────────────────────────────────┐
│              DARK WEB FORENSICS — KEY CHALLENGES                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  1. ANONYMITY     Tor hides IP of users and hidden services   │  │
│  │  2. ENCRYPTION    End-to-end encryption at multiple layers    │  │
│  │  3. JURISDICTION  Servers may span multiple countries         │  │
│  │  4. VOLATILITY    Hidden services go offline frequently       │  │
│  │  5. NO INDEXING   Content not searchable via normal engines   │  │
│  │  6. CRYPTO        Payments in Bitcoin / Monero (pseudonymous) │  │
│  │  7. ATTRIBUTION   Linking pseudonym to real identity is hard  │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

**Additional Challenges**:
- **Opsec failures** by suspects are often the only entry point for investigators
- **Legal authority**: Requires warrants that may extend internationally
- **Evidence admissibility**: Must prove the suspect was the operator of a hidden service, not merely a relay
- **Fourth Amendment considerations**: US courts debated whether hacking Tor users (without knowing server location) is constitutionally permissible

---

### 1.5 De-anonymization Attack Techniques

The security community and law enforcement use a variety of methods to de-anonymize Tor users and hidden services. These attacks are categorized based on their method and goal:

#### 1.5.1 Correlation (Traffic Confirmation) Attacks

> **Definition**: **Correlation attacks** aim to confirm that two network endpoints are communicating through Tor by finding statistical correlation between traffic entering and leaving the Tor circuit.

The attacker controls or observes both the **entry node** and the **exit node** of a circuit:

```
┌─────────────────────────────────────────────────────────┐
│              CORRELATION ATTACK MODEL                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Client ──▶ [Entry Node*] ──▶ [Relay] ──▶ [Exit Node*]  │
│                │                              │          │
│                └───── Traffic Comparison ─────┘          │
│                                                          │
│  * = attacker-controlled or attacker-observed nodes      │
│  Matching traffic patterns → client identity confirmed   │
└─────────────────────────────────────────────────────────┘
```

**Notable Correlation Attack Variants**:

| Attack | Description |
|--------|-------------|
| **Relay Early Traffic Confirmation** | Malicious HSDir + entry guard encode hidden service name in relay-cell pattern; used against Silk Road |
| **Replay Attack** | Duplicate a relay cell at entry node; decryption failure at exit node confirms the circuit |
| **Cell Counter Attack** | Embed signal in traffic by manipulating the number of relay cells flushed per interval |
| **RAPTOR Attack** | Uses BGP hijacking / BGP interception plus asymmetric traffic analysis to correlate via malicious Autonomous Systems |
| **Congestion Attack** | Send probe traffic through a suspected relay to detect latency changes; confirms the node is on the circuit |

---

#### 1.5.2 Traffic Analysis and Fingerprinting

> **Definition**: **Traffic fingerprinting** exploits distinctive characteristics of encrypted network traffic — packet sizes, timing patterns, cell counts — to identify which website or hidden service a client is accessing, without decrypting content.

**Types of Fingerprinting**:

| Type | Technique |
|------|-----------|
| **Website Fingerprinting** | Record packet size distribution of known sites; compare against observed Tor traffic |
| **Circuit Fingerprinting** | Tor's hidden service setup exhibits unique cell-count patterns; identifies HS-bound traffic |
| **Throughput Fingerprinting** | Bottleneck relay creates a throughput "fingerprint"; concurrent connections sharing a relay correlate |

**Tor's Defenses** (and their limitations):
- Fixed 512-byte cell sizes obscure file sizes — but packet counting can still distinguish content
- Multiplexing all streams over one connection — but inter-packet timing still leaks info
- Packet padding countermeasures exist but degrade performance

---

#### 1.5.3 Sybil Attack

> **Definition**: A **Sybil attack** on Tor involves an adversary operating a large number of malicious relay nodes to gain disproportionate influence over the network — increasing the probability that a circuit's entry and/or exit node is attacker-controlled.

- In June 2010, hundreds of Tor relays were added from PlanetLab machines as a Sybil attack
- The Relay Early Traffic Confirmation attack relied on a Sybil attack to place malicious guard nodes and HSDir nodes simultaneously
- Detection heuristics: Sybil relays tend to join/leave simultaneously, share configuration parameters, and change identity fingerprints often

---

#### 1.5.4 Hidden Service De-anonymization

**Clock Skew Attack**: Sending a large number of requests to a hidden service causes the server's CPU temperature to rise, which slightly alters the hardware clock skew. The skew is observable in TCP timestamps and can be matched to a list of candidate servers.

**First Node Attack**: Attacker runs many Tor relays hoping to become the first hop from the hidden server's circuit. If successful, the attacker's relay directly knows the HS server's IP address.

**HSDir Enumeration**: HSDirs (Hidden Service Directory servers) store HS descriptors that include Introduction Point addresses. An attacker controlling HSDir nodes can enumerate and track hidden services.

---

### 1.6 Forensic Investigation of Dark Web Users

#### 1.6.1 Tor Browser Artifacts

The **Tor Browser** is the standard client for accessing the dark web. It is based on Firefox ESR with enhanced privacy settings. On the **suspect's machine**, investigators look for:

```
┌─────────────────────────────────────────────────────────────────────┐
│              TOR BROWSER FORENSIC ARTIFACTS                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  FILESYSTEM ARTIFACTS:                                               │
│  ├── Tor Browser installation directory (portable or installed)      │
│  ├── Profile folder: Browser\TorBrowser\Data\Browser\profile.default │
│  │   ├── places.sqlite  → browsing history (may be cleared)         │
│  │   ├── cookies.sqlite → session cookies                           │
│  │   ├── formhistory.sqlite → form data                             │
│  │   └── logins.json   → saved passwords                            │
│  ├── Cached files (Tor Browser limits caching significantly)         │
│  └── Tor process logs: Data\Tor\tor.log                             │
│                                                                      │
│  REGISTRY ARTIFACTS (Windows):                                       │
│  ├── HKCU\Software\Tor Browser → installation evidence              │
│  ├── MRU lists showing Tor Browser was recently run                 │
│  └── Prefetch / AppCompatCache → execution evidence                 │
│                                                                      │
│  MEMORY ARTIFACTS:                                                   │
│  ├── Live RAM may contain .onion URLs and decrypted content          │
│  └── SOCKS proxy config, circuit state, session keys                │
└─────────────────────────────────────────────────────────────────────┘
```

**Important Notes**:
- Tor Browser by default does not retain browsing history, cookies, or cache after the session ends
- However, **RAM acquisition** during an active session can yield .onion URLs, plaintext content, and session data
- Examination of **Windows Volume Shadow Copies** or **hibernation file (`hiberfil.sys`)** may contain residual Tor session data
- **Prefetch files** (.pf) confirm Tor Browser execution even if history is wiped

---

#### 1.6.2 Network-Level Investigation

At the **network layer**, investigators and law enforcement use:

| Technique | Description |
|-----------|-------------|
| **Exit Node Monitoring** | Monitor exit nodes for credential sniffing or MitM attacks; tools like *exitmap* and *HoneyConnector* detect malicious relays |
| **Traffic Correlation** | ISP-level traffic correlation to match timing patterns of Tor entry traffic with known server traffic |
| **IP Identification** | Tor directory servers list all known entry guards; if a suspect's entry guard is compromised, source IP may be revealed |
| **BGP-level Analysis** | RAPTOR-style analysis using Autonomous System traffic records |
| **Blockchain Analysis** | Cryptocurrency transactions (Bitcoin) used on dark web markets are traceable via blockchain analysis tools (Chainalysis, CipherTrace) |
| **Honeypot Operations** | Law enforcement operated Playpen for two weeks after seizure to identify 1,500 users via NIT (Network Investigative Technique) |

---

#### 1.6.3 Hidden Service Investigation

When investigating a **dark web marketplace or service** (from the server side):

1. **Identify the .onion address**: Through criminal complaint, tipoff, or HSDir enumeration
2. **Mirror the site**: Use Tor-capable web archiving tools to capture site content, usernames, transaction records
3. **Opsec errors**: Look for real-IP leaks in:
   - CAPTCHA service configurations (Silk Road case — CAPTCHA not routed through Tor)
   - `PHPMyAdmin` configuration files
   - Error messages containing server paths or IP addresses
   - Metadata in uploaded files (EXIF data in images)
4. **Server seizure**: Once physical location is identified (via error, informant, or traffic analysis), seize the server with proper warrant
5. **Database forensics**: Dark web markets run databases (MySQL, PostgreSQL) containing user registrations, transaction logs, Bitcoin wallet addresses — all valuable evidence

---

### 1.7 Legal and Ethical Considerations in Dark Web Forensics

**Fourth Amendment (USA) / Right to Privacy Tensions**:
- US courts have ruled that FBI hacking of Tor users (to identify them) is permissible if the server location cannot be determined otherwise
- Proposed amendments to "Rule 41" of the Federal Rules of Criminal Procedure would allow warrants to hack systems using anonymization tools without specifying the exact location
- In India: IT Act S.69 allows lawful interception of information transmitted through computer resources

**International Cooperation**:
- Silk Road servers were in Iceland — requiring FBI to work across jurisdictions
- MLAT (Mutual Legal Assistance Treaty) used for cross-border server seizures
- Europol's Operation Bayonet (2017) seized AlphaBay and Hansa simultaneously, with Hansa monitored for 27 days before shutdown

**Ethical Issues**:
- About 44% of HS sites are criminal in intent; ~56% serve legitimate purposes (privacy, journalism, whistleblowing)
- Government operations can compromise the anonymity of innocent users
- Investigator operations (e.g., running a child exploitation site for 2 weeks) raise significant ethical debate

---

### 1.8 Tools for Dark Web Forensics

| Tool | Purpose |
|------|---------|
| **Tor Browser** | Access .onion sites; collect screenshots and site content |
| **OSINT Framework** | Mapping dark web services to real-world identities |
| **Maltego** | Graph-based intelligence linking .onion addresses, Bitcoin addresses, email |
| **Chainalysis / CipherTrace** | Cryptocurrency transaction tracing |
| **exitmap** | Detect malicious Tor exit relays (MitM, certificate tampering) |
| **OnionScan** | Enumerate hidden services; detect IP leaks and opsec failures |
| **Volatility** | Memory forensics; extract Tor session data from RAM |
| **Wireshark** | Capture and analyse Tor traffic at network level |
| **HTTrack / wget** | Mirror dark web site content for evidence preservation |

---

## 2. Anti-Forensics Techniques

### 2.1 Overview of Anti-Forensics

> **Definition**: **Anti-forensics** refers to any technique, tool, or action used by a suspect (or malicious actor) to **obstruct, confuse, or prevent** a digital forensic investigation by destroying, hiding, altering, or obfuscating digital evidence.

> *"Anti-forensics is the attempt to negatively affect the existence, amount, and/or quality of evidence from a crime scene, or make the analysis and examination of evidence difficult or impossible to conduct."*
> — Ryan Harris, "Arriving at an Anti-Forensics Consensus" (2006)

**Goals of Anti-Forensics**:
- Prevent discovery of incriminating evidence
- Destroy evidence before seizure
- Conceal the nature of activities
- Create doubt about evidence integrity
- Slow down or resource-exhaust investigators

**Classification Framework**:

```
┌─────────────────────────────────────────────────────────────────────┐
│              ANTI-FORENSICS TAXONOMY                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────────────┐   ┌──────────────────┐   ┌────────────────┐  │
│   │   DATA HIDING    │   │  DATA DESTRUCTION│   │ TRAIL COVERING │  │
│   │                  │   │                  │   │                │  │
│   │ • Steganography  │   │ • Secure deletion│   │ • Log clearing │  │
│   │ • ADS            │   │ • Disk wiping    │   │ • Timestomping │  │
│   │ • Hidden partns  │   │ • File shredding │   │ • Anti-carving │  │
│   │ • Bit-shifting   │   │ • Degaussing     │   │ • Rootkits     │  │
│   └──────────────────┘   └──────────────────┘   └────────────────┘  │
│                                                                      │
│   ┌──────────────────┐   ┌──────────────────────────────────────┐   │
│   │   OBFUSCATION    │   │           ENCRYPTION                 │   │
│   │                  │   │                                      │   │
│   │ • File renaming  │   │ • Full disk encryption (VeraCrypt)   │   │
│   │ • Fake headers   │   │ • PGP / GPG file encryption          │   │
│   │ • Packers        │   │ • Password protection                │   │
│   └──────────────────┘   └──────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

### 2.2 Data Hiding Techniques

#### 2.2.1 Steganography

> **Definition**: **Steganography** is the practice of concealing a secret message within an ordinary, non-secret file or message (the "cover" or "host") so that the existence of the secret is not apparent to a casual observer.

The word derives from the Greek *steganos* (covered/concealed) + *graphia* (writing).

**Historical Note**: Greek rulers sent covert messages by tattooing them on messengers' shaved heads and waiting for hair to grow back before dispatching them.

**Two Fundamental Steganographic Methods**:

| Method | Description | Example |
|--------|-------------|---------|
| **Insertion** | Places hidden data inside the host file's structure without replacing existing data | Appending data after image EOF marker; hidden HTML comments |
| **Substitution (LSB)** | Replaces the least significant bits of host file data with secret message bits | LSB substitution in BMP/PNG/WAV files |

**LSB (Least Significant Bit) Substitution** — Detailed:

```
┌─────────────────────────────────────────────────────────────────┐
│              LSB STEGANOGRAPHY — BIT LEVEL                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  8-bit pixel colour value:  1 0 1 0 1 1 0 0                    │
│                             ↑           ↑↑                      │
│                            MSB    Replacing last 2 LSBs         │
│                                                                  │
│  Secret message: 01 10 11 00 (broken into 2-bit groups)         │
│                                                                  │
│  Original → Altered:                                            │
│  1010 1010  →  1010 10|01    (last 2 bits replaced with "01")   │
│  1001 1101  →  1001 11|10                                       │
│  1111 0000  →  1111 00|11                                       │
│  0011 1111  →  0011 11|00                                       │
│                                                                  │
│  Human eye can distinguish ~6 bits of colour → 2 LSBs invisible │
└─────────────────────────────────────────────────────────────────┘
```

**Detection**: Human eye cannot detect 2-LSB changes. Tools like **StegDetect**, **StegBreak**, and **Steg Suite (WetStone)** perform steganalysis.

**Steganalysis Attack Types** (from Johnson & Jajodia, 1998):

| Attack | When Used | How |
|--------|-----------|-----|
| Stego-only | Only stego-file available | Statistical analysis of file structure |
| Known cover | Original + stego file available | Compare files; find pattern deviations |
| Known message | Hidden message later revealed | Comparative analysis to learn encoding method |
| Chosen stego | Known tool + stego-file | Password recovery on known algorithm |
| Chosen message | Analyst creates test stego-media | Reverse-engineer encoding configuration |

**Forensic Detection Clues**:
- Duplicate image files with **different hash values** (indicates one may have been altered)
- Presence of known steganography tools (S-Tools, OpenStego, Invisible Secrets)
- File sizes inconsistent with expected dimensions × bit depth
- Statistical anomalies in pixel colour distributions (Chi-square test)

---

#### 2.2.2 NTFS Alternate Data Streams (ADS)

> **Definition**: **Alternate Data Streams (ADS)** are a feature of the NTFS file system that allow multiple data streams to be attached to a single file. The primary data stream holds the visible file content; additional streams are invisible in File Explorer but accessible via command line.

ADS was originally designed for compatibility with Macintosh HFS file systems (to store resource forks). It can be misused to hide data undetected by normal file-browsing tools.

**ADS Structure**:

```
┌─────────────────────────────────────────────────────────────────────┐
│              NTFS ALTERNATE DATA STREAMS                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Normal file:   document.txt                                        │
│  └── :$DATA (primary stream) → "Hello World"  [visible, 11 bytes]  │
│                                                                      │
│  With ADS:      document.txt                                        │
│  ├── :$DATA (primary stream) → "Hello World"  [visible, 11 bytes]  │
│  └── :hidden_data (alternate stream) → [malware.exe, invisible!]   │
│                                                                      │
│  Command to create ADS:                                             │
│     echo secret > document.txt:hiddenfile.txt                      │
│                                                                      │
│  Command to execute ADS:                                            │
│     wscript document.txt:script.vbs                                │
│                                                                      │
│  File Explorer shows:  document.txt  (11 bytes) — NO size change   │
│  The ADS payload is completely invisible to Windows Explorer        │
└─────────────────────────────────────────────────────────────────────┘
```

**Forensic Detection of ADS**:
- `dir /r` command — lists all streams for each file
- `streams.exe` (Sysinternals) — scans for ADS
- Digital forensics tools (EnCase, FTK, Autopsy) — detect and display ADS
- Hash mismatch: If file hash differs from what the visible size implies, ADS may be present
- Monitoring total volume disk usage — if unaccounted space exists beyond known files

---

#### 2.2.3 Hiding Partitions

A suspect can use **diskpart** or third-party tools (Partition Magic, GRUB) to **remove the drive letter** from a partition, making it invisible in File Explorer while the data remains intact on disk.

**Detection**:
- Account for **all disk space** — gaps between partitions larger than 128 bytes (Windows Vista+) are suspicious
- Digital forensics tools assign drive letters to hidden partitions (e.g., ProDiscover assigns the highest available letter)
- Use hexadecimal editors to access unassigned disk regions

---

#### 2.2.4 Marking Bad Clusters (FAT)

On FAT-formatted drives, the FAT table entry for a cluster can be manually changed to `B` (bad) using tools like Norton DiskEdit. The OS considers these clusters unusable and skips them, but the data remains physically present.

```
FAT Table: Cluster 42 = B (bad) → OS skips, data present
Investigator: Must manually change bad→good to access data
```

**Detection**: Compare volume free space vs actual unallocated space; examine all clusters marked bad with a hex editor.

---

#### 2.2.5 Bit-Shifting

> **Definition**: **Bit-shifting** rearranges bits in each byte of a file by shifting them left or right, changing readable content into what appears to be random binary data.

- Originally used by home programmers using assembly-language macros
- A right-shifted file looks like binary executable code — confusing investigators
- Advanced malware uses bit-shifting to hide malicious code from antivirus tools; malware shifts bits back at runtime before executing

**Tools**: WinHex and Hex Workshop have built-in bit-shift functions.

**Detection**: Use WinHex to attempt bit-shift reversal; hash comparison before/after shift confirms identity.

---

### 2.3 Data Destruction Techniques

> **Definition**: **Data destruction** as anti-forensics involves **permanently removing** digital evidence so that it cannot be recovered by investigators, even using advanced forensic recovery tools.

#### 2.3.1 Secure File Deletion

Standard file deletion in Windows only removes the directory entry — the file's data clusters remain intact and are recoverable with forensic tools. **Secure deletion** overwrites those clusters with random or fixed data patterns before removing the directory entry.

```
┌─────────────────────────────────────────────────────────────────┐
│              SECURE DELETION — OVERWRITE PATTERNS               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  DoD 5220.22-M (3-pass):                                        │
│    Pass 1: Overwrite with 0x00 (all zeros)                      │
│    Pass 2: Overwrite with 0xFF (all ones)                       │
│    Pass 3: Overwrite with random data + verification            │
│                                                                  │
│  Gutmann Method (35-pass):                                       │
│    Applies specific bit-patterns based on drive encoding        │
│    (largely obsolete for modern drives)                          │
│                                                                  │
│  Single Pass (NIST 800-88):                                     │
│    Recommended for modern drives: single overwrite is           │
│    sufficient due to high areal density making magnetic         │
│    remnance recovery impractical                                │
└─────────────────────────────────────────────────────────────────┘
```

**Tools**: Eraser, BleachBit, BCWipe, SDelete (Sysinternals), Secure Empty Trash (macOS).

**Forensic Detection**:
- File system metadata (MFT entries, directory entries) may show the file existed even after secure deletion
- The `$LogFile` and `$MFT` in NTFS may retain file name / metadata
- Volume shadow copies may contain the file if created before deletion

---

#### 2.3.2 Disk Wiping

**Disk wiping** overwrites the **entire storage device** — including all partitions, slack space, unallocated space, and MBR — with repeated passes of data.

**Tools**: DBAN (Darik's Boot and Nuke), HDShredder, Blancco, `dd` with `/dev/urandom`.

**Detection**: A completely wiped drive will have uniform bit patterns (all 0s or random) with no file system structure visible in a hex editor — itself a form of evidence.

---

#### 2.3.3 Physical Destruction and Degaussing

- **Degaussing**: Exposing a hard drive to a strong magnetic field that scrambles the magnetic domains; destroys data on HDDs completely (ineffective on SSDs)
- **Physical destruction**: Shredding, melting, or drilling through the drive platters
- **NAND flash / SSD**: Requires device-level secure erase commands (ATA Secure Erase or crypto-erase if self-encrypting)

**Forensic implication**: Physically destroyed drives are largely unrecoverable; investigator must rely on cloud backups, remote logs, or network traffic.

---

#### 2.3.4 Anti-Carving Techniques

**File carving** recovers files from unallocated space by searching for file headers and footers. Anti-carving targets this by:
- Overwriting only file headers and footers (minimal but effective against carving)
- Using tools that fragment files so that no contiguous carved segment forms a complete file
- Corrupting file signatures while leaving data intact (confuses forensic tools)

---

### 2.4 Trail Covering — Log Manipulation and Timestomping

#### 2.4.1 Log Tampering

System and application logs are critical forensic artifacts. Anti-forensics techniques to defeat log analysis:

| Technique | Method |
|-----------|--------|
| **Log clearing** | `wevtutil cl System` (Windows); `echo "" > /var/log/auth.log` (Linux) |
| **Log disabling** | Stopping syslog, Windows Event Log service |
| **Selective deletion** | Removing specific log entries using hex editors |
| **Log injection** | Inserting false entries to create misleading timelines |
| **Remote log tampering** | Modifying logs on a compromised remote system before investigators arrive |

**Forensic countermeasures**:
- SIEM (Security Information and Event Management) systems that forward logs in real time to a remote, append-only store
- Windows Security Event Log has its own hash chain (protected by Windows)
- Log entries stored across multiple sources (firewall logs, IDS logs, endpoint logs) are hard to clear consistently
- Memory forensics may recover log entries cleared from disk

---

#### 2.4.2 Timestomping

> **Definition**: **Timestomping** is the deliberate modification of file system timestamps (creation time, modification time, access time, MFT change time — **MACE** values) to mislead investigators about when a file was created or accessed.

```
┌─────────────────────────────────────────────────────────────────┐
│              NTFS TIMESTAMP ATTRIBUTES (MACE)                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  NTFS stores two copies of timestamps:                          │
│  1. $STANDARD_INFORMATION attribute — easily modifiable         │
│  2. $FILE_NAME attribute — NOT updated by most tools             │
│                                                                  │
│  Timestomping tools (Metasploit timestomp, SetMACE) modify      │
│  only $STANDARD_INFORMATION                                     │
│                                                                  │
│  Forensic Detection:                                            │
│  Compare $STANDARD_INFORMATION vs $FILE_NAME timestamps         │
│  If $SI timestamps are earlier than $FN timestamps → ANOMALY    │
│  (A file cannot be modified before it was created per $FN)      │
└─────────────────────────────────────────────────────────────────┘
```

**Tools**: Metasploit `timestomp` module, Antiforensics toolkit, custom PowerShell scripts.

---

### 2.5 Encryption as Anti-Forensics

> **Definition**: **Encryption** as anti-forensics is the use of cryptographic algorithms to render file contents unreadable without the correct key or passphrase, making evidence inaccessible even after physical seizure.

**Types Used**:

| Type | Tool | Notes |
|------|------|-------|
| Full Disk Encryption (FDE) | VeraCrypt, BitLocker, LUKS | Entire drive encrypted; useless without key |
| File/Volume Encryption | VeraCrypt, PGP/GPG, 7-Zip AES-256 | Individual containers or files |
| Plausible Deniability | VeraCrypt hidden volumes | Outer + inner volume; only inner volume is truly incriminating |
| Encrypted Communications | Signal, ProtonMail | Evidence of communication exists; content does not |

**VeraCrypt Hidden Volumes**: An outer volume and an inner "hidden" volume share the same container. Providing the outer volume password reveals only decoy content; the inner volume password reveals incriminating content. Forensics tools cannot distinguish the encrypted space of the hidden volume from random data.

**Forensic Approaches**:

```
┌─────────────────────────────────────────────────────────────────────┐
│              FORENSIC APPROACHES TO ENCRYPTION                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. KEY / PASSPHRASE RECOVERY                                       │
│     ├── Brute-force attack: All keyboard combinations               │
│     ├── Dictionary attack: Common words (John the Ripper)           │
│     ├── Hybrid attack: Dictionary + numeric suffixes                │
│     ├── Rainbow tables: Pre-computed hash lookups                   │
│     └── Social engineering / suspect cooperation                    │
│                                                                      │
│  2. COLD BOOT ATTACK                                                │
│     └── RAM retains data for seconds–minutes after power off       │
│         Freeze RAM → remove and read → extract in-memory keys       │
│                                                                      │
│  3. KEY ESCROW                                                      │
│     └── Some commercial products provide key recovery               │
│         infrastructure for lawful access                            │
│                                                                      │
│  4. LEGAL COMPULSION                                                │
│     └── Court order requiring the suspect to provide passphrase     │
│         (5th Amendment self-incrimination issues in the US)         │
└─────────────────────────────────────────────────────────────────────┘
```

**Password Cracking Tools**:

| Tool | Method | Notes |
|------|--------|-------|
| John the Ripper | Dictionary + brute force | Open source, widely used |
| Hashcat | GPU-accelerated brute force | Fastest for hash cracking |
| AccessData PRTK | Hybrid + dictionary | Integrates with FTK |
| ophcrack | Rainbow tables | Windows NTLM hashes |
| Passware Kit Forensic | Full disk analysis + GPU | Supports VeraCrypt, BitLocker |

**Salted Passwords**: Modern systems add a unique salt (random bits) to the password before hashing. Salting defeats rainbow table attacks because no precomputed table can cover salted values.

---

### 2.6 Obfuscation Techniques

#### 2.6.1 File Extension Manipulation

Changing a file extension is the simplest obfuscation technique — renaming `evidence.xlsx` to `photo.jpg` to mislead casual inspection.

**Forensic countermeasure**: All modern forensic tools (FTK, EnCase, Autopsy) compare **file signatures** (magic bytes in the file header) against the declared extension. A mismatch is flagged for manual review.

**Common Magic Bytes**:

| Format | Hex Signature | ASCII |
|--------|---------------|-------|
| JPEG | `FF D8 FF` | `ÿØÿ` |
| PNG | `89 50 4E 47` | `.PNG` |
| PDF | `25 50 44 46` | `%PDF` |
| ZIP/DOCX | `50 4B 03 04` | `PK..` |
| EXE | `4D 5A` | `MZ` |

---

#### 2.6.2 Executable Packers and Obfuscators

- **Packers** (UPX, ASPack): Compress and encrypt the executable code; the packer stub unpacks it at runtime. Used by malware to evade static AV analysis.
- **Obfuscators**: Rename variables, insert junk code, flatten control flow — source code level
- **Virtualisers**: Convert instructions to a custom VM bytecode (Themida, VMProtect) — extremely hard to reverse

---

#### 2.6.3 Rootkits

> **Definition**: A **rootkit** is malicious software designed to provide continued privileged access to a computer while actively hiding its presence from users and security tools.

**Types**:

| Type | Hiding Level | Example |
|------|-------------|---------|
| User-mode | Userspace API hooks | Hacker Defender |
| Kernel-mode | OS kernel hooks | Azazel, Alureon |
| Bootkit | MBR/UEFI | Mebroot, Uefi Rootkit |
| Hypervisor | Below OS | Blue Pill |
| Firmware | CPU/NIC/HDD firmware | Equation Group implants |

**Forensic Detection**:
- Boot from trusted external media to bypass user/kernel-mode rootkits
- Compare kernel object lists from two different methods (cross-view analysis)
- Check SSDT (System Service Descriptor Table) for hooks
- Memory forensics with Volatility: `pslist` vs `psscan` discrepancies reveal hidden processes

---

### 2.7 Anonymization Techniques (Beyond Tor)

Suspects use additional anonymity tools alongside or instead of Tor:

| Tool | Mechanism | Forensic Notes |
|------|-----------|----------------|
| **VPN** | Routes traffic through encrypted tunnel to VPN server | Provider logs (if retained) can link IP; kill-switch failures can leak real IP |
| **I2P** (Invisible Internet Project) | Garlic routing (similar to onion routing but fully internal) | Less studied; used for internal .i2p sites |
| **Freenet** | Decentralised, censorship-resistant file storage | Files distributed across nodes; harder to attribute |
| **Proxy Chains** | Multiple open proxies chained in sequence | Speed sacrifice; any single unprotected hop compromises anonymity |
| **Public Wi-Fi** | Uses MAC address of AP, not suspect's home | CCTV at venue, DHCP lease logs, and access point logs remain |

**Forensic implication**: Even with anonymizing tools, investigators pursue:
- Opsec failures (posting personal details on dark web forums)
- Cryptocurrency trail (Bitcoin addresses reused or connected to KYC exchanges)
- Device fingerprinting (browser fingerprint, canvas fingerprint)
- Timing correlation (login times matching suspect's known activity)

---

### 2.8 Anti-Forensics Detection and Countermeasures

As an investigator, detection of anti-forensics activity is itself a skill:

```
┌──────────────────────────────────────────────────────────────────────┐
│           ANTI-FORENSICS DETECTION CHECKLIST                         │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Steganography:                                                       │
│  □ Run steganalysis tools (StegDetect, stegexpose)                   │
│  □ Look for duplicate images with different hash values              │
│  □ Look for steganography programs in installed software list        │
│                                                                       │
│  ADS:                                                                 │
│  □ Run dir /r or streams.exe on all NTFS volumes                     │
│  □ Check for ADS on directory objects as well as files               │
│                                                                       │
│  Partition Hiding:                                                    │
│  □ Account for all disk space — gaps indicate hidden partitions      │
│  □ Use forensic tools that enumerate partitions independently        │
│                                                                       │
│  Secure Deletion / Wiping:                                            │
│  □ Check MFT entries for traces of deleted file metadata             │
│  □ Examine Volume Shadow Copies                                      │
│  □ Uniform disk regions (all-zero or random) indicate wiping         │
│  □ Recover from cloud backups, email servers, third-party sources    │
│                                                                       │
│  Timestomping:                                                        │
│  □ Compare $STANDARD_INFORMATION vs $FILE_NAME timestamps            │
│  □ Impossible timestamps flag = timestomping occurred                │
│                                                                       │
│  Encryption:                                                          │
│  □ Attempt key recovery via RAM/hibernation file analysis            │
│  □ Use password cracking tools (Hashcat, PRTK)                       │
│  □ Check for key escrow or backup mechanisms                         │
│                                                                       │
│  Logs:                                                                │
│  □ Cross-reference multiple log sources (FW, IDS, endpoint)         │
│  □ Check SIEM for forwarded logs before clearing occurred            │
│  □ Examine Windows Event Log integrity markers                       │
│                                                                       │
│  Rootkits:                                                            │
│  □ Boot from trusted external OS for clean examination               │
│  □ Volatility cross-view analysis for hidden processes               │
└──────────────────────────────────────────────────────────────────────┘
```

**Investigator Principle**: The presence of anti-forensics activity is itself evidence of consciousness of guilt. The systematic use of multiple techniques — disk wiping + Tor + cryptocurrency + steganography — strongly suggests deliberate evidence concealment and can be presented as such in court.

---

### 2.9 Anti-Forensics Tools Reference

| Tool | Category | Description |
|------|----------|-------------|
| **S-Tools** | Steganography | Hides data in BMP, GIF, WAV files |
| **OpenStego** | Steganography | Open-source LSB steganography |
| **DBAN** | Disk wiping | Boot-time full disk overwrite |
| **Eraser** | Secure deletion | Windows file-level secure delete |
| **SDelete** | Secure deletion | Sysinternals, command-line |
| **VeraCrypt** | Encryption / hidden volumes | Open-source FDE + hidden volumes |
| **BleachBit** | Trail covering | Privacy cleaner; wipes logs, temp files |
| **Metasploit timestomp** | Timestomping | Modifies MACE timestamps |
| **UPX** | Packing | Compresses executables |

---

## Sources

- Nelson, B., Phillips, A., & Steuart, C. (2016). *Guide to Computer Forensics and Investigations*, 5th Edition. Cengage Learning.
  - Ch. 8: "Recovering Graphics Files" — Steganography (pp. 344–347)
  - Ch. 9: "Digital Forensics Analysis and Validation" — Data Hiding Techniques (pp. 372–378)
- Evers, B., Schouten, H., et al. (2016). *Thirteen Years of Tor Attacks*. GitHub: Attacks-on-Tor/Attacks-on-Tor. [https://github.com/Attacks-on-Tor/Attacks-on-Tor](https://github.com/Attacks-on-Tor/Attacks-on-Tor)
- Dingledine, R., Mathewson, N., & Syverson, P. (2004). *Tor: The Second Generation Onion Router*. USENIX Security Symposium.
- Biryukov, A. et al. (2014). *Content and popularity analysis of Tor hidden services*. IEEE ICDCS Workshops.
- Harris, R. (2006). *Arriving at an Anti-Forensics Consensus*. Digital Investigation.
- NIST SP 800-88 Rev. 1 (2014). *Guidelines for Media Sanitization*.
- Johnson, N.F. & Jajodia, S. (1998). *Steganalysis of Images Created Using Current Steganography Software*.
