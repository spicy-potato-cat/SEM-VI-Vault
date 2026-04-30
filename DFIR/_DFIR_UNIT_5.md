# Unit 5: Mobile Device Forensics

> **Course**: Digital Forensics and Incident Response (DFIR)
> **Unit**: 5 - Mobile Device Forensics
> **Book Reference**: *Guide to Computer Forensics and Investigations*, 5th Edition — Ch. 12
> **Additional Reference**: NIST SP 800-101 Rev. 1 — *Guidelines on Mobile Device Forensics* (May 2014)

---

## Table of Contents

[[#1. Introduction to Mobile Device Forensics]]
[[#2. Mobile Phone Basics]]
[[#3. Inside Mobile Devices]]
[[#4. Acquisition Procedure for Mobile Devices]]
[[#5. Mobile Forensics Tools]]

---

## 1. Introduction to Mobile Device Forensics

### 1.1 Definition and Goals

> **Definition**: **Mobile Device Forensics** is the science of recovering digital evidence from a mobile device under forensically sound conditions, using accepted methods, in order to preserve, identify, extract, and document digital evidence.

Mobile devices now carry more personal data per byte — location history, communications, health data, financial transactions — than traditional computers. Because of this density, they are a primary source of evidence in modern investigations.

**Four Core Goals of Mobile Forensics**:

| # | Goal | Description |
|---|------|-------------|
| 1 | Identify & Extract | Locate and recover digital evidence from the device |
| 2 | Preserve Integrity | Ensure data is not modified during the process |
| 3 | Analyze Activity | Reconstruct user behavior and communications |
| 4 | Present Legally | Report findings in a court-admissible manner |

---

### 1.2 Key Challenges

> **Importance**: Mobile devices "contain more probative information per byte examined than traditional computers" — Lessard & Kessler, *Android Forensics: Simplifying Cell Phone Examinations*, 2010.

**Three Major Challenges**:

- **Rapidly evolving hardware and OS versions** — New phone models release approximately every six months. Cables, software, and accessories for forensic acquisition can become obsolete quickly, and no single standard exists for how phones store messages.
- **Security features** — Passcodes, biometrics (Face ID, fingerprint), full-disk encryption (e.g., iOS Secure Enclave), and SIM PIN locks all impede access to evidence.
- **Volatile and remote data** — Volatile memory (RAM) is lost on power-off. Cloud syncing can overwrite local data; remote wiping can destroy all evidence on a stolen or seized device.

**Legal Context** — In *Riley v. California* (2014), the U.S. Supreme Court ruled unanimously that a search warrant is required before an officer can examine the contents of a seized phone. Any private information not related to the case must be redacted from the public record.

---

### 1.3 Types of Evidence Found on Mobile Devices

```
┌────────────────────────────────────────────────────────┐
│            FORENSIC VALUE — MOBILE DEVICE DATA         │
├────────────────────────────────────────────────────────┤
│                                                        │
│  Communications          Multimedia                    │
│  ─────────────────        ─────────────────            │
│  • Call logs (in/out/    • Photos & videos             │
│    missed)               • Voice recordings            │
│  • SMS / MMS messages    • Music files                 │
│  • Emails                                              │
│  • Instant messaging     Activity & Location           │
│    logs                  ─────────────────             │
│                          • GPS / location history      │
│  App Data                • Browser history             │
│  ─────────────────        • Calendar & address book    │
│  • WhatsApp, Telegram    • Social media accounts       │
│  • Instagram, Facebook   • Bank login / transactions   │
│  • App databases                                       │
│                                                        │
└────────────────────────────────────────────────────────┘
```

---

## 2. Mobile Phone Basics

### 2.1 Network Generations

Mobile phone technology has advanced through successive generations, each adding new capabilities:

| Generation | Era | Key Feature |
|-----------|-----|-------------|
| 1G (Analog) | 1980s | Voice only; no digital security |
| 2G (Digital PCS) | 1990s | GSM/CDMA digital voice; SMS introduced |
| 3G | ~2000s | Mobile data; download while moving (EDGE, UMTS) |
| 4G LTE | 2009+ | High-speed broadband; OFDM-based; Sprint launched first U.S. 4G in 2009 |
| 5G | 2019+ | Ultra-low latency; mmWave; network slicing |

---

### 2.2 Digital Network Standards

Multiple competing digital network standards are used in the mobile industry. Understanding which standard a phone uses is critical — it determines whether a SIM card is present and which forensic tools apply.

| Standard | Full Name | Key Facts | Forensic Relevance |
|----------|-----------|-----------|-------------------|
| **CDMA** | Code Division Multiple Access | Patented by Qualcomm (WWII origin); IS-95/CDMAOne → CDMA2000; used by Verizon, Sprint | Older CDMA phones have **no SIM card** — subscriber data is embedded in the handset |
| **GSM** | Global System for Mobile Communications | Uses TDMA technique; standard in Europe, Asia; AT&T, T-Mobile (US) | **SIM card present** — stores IMSI, ICCID, contacts, SMS |
| **TDMA** | Time Division Multiple Access | Divides radio frequency into time slots; IS-136 standard; introduced sleep mode | Also refers to IS-136; SIM cards present in newer TDMA phones |
| **iDEN** | Integrated Digital Enhanced Network | Motorola protocol; combines voice/data | Niche; used in Nextel push-to-talk networks |
| **EDGE** | Enhanced Data GSM Environment | Faster GSM variant designed for data delivery | Common in 2G/3G era devices |
| **LTE** | Long Term Evolution | Designed for GSM/UMTS; 45–144 Mbps; commonly called "4G LTE" | Modern devices — uses nano/eSIM |

> **Key forensic note**: GSM carriers must accept any GSM phone, while CDMA carriers lock phones to prevent users from switching. For GSM devices, when the SIM card is switched, all subscriber data follows it.

---

### 2.3 SIM Cards

> **Definition**: A **SIM (Subscriber Identity Module)** card is a microprocessor-and-memory module found primarily in GSM devices. GSM divides a mobile station into two parts: the **SIM card** and the **Mobile Equipment (ME)**.

**SIM Card Functions**:
- Identifies the subscriber to the network (via IMSI)
- Stores service-related information
- Can be used to back up device data

**Data Recoverable from a SIM Card**:

| Category | Examples |
|----------|---------|
| Service-related | IMSI (International Mobile Subscriber Identity), ICCID (SIM serial number) |
| Call data | Last numbers dialed |
| Message data | Stored SMS messages (including deleted) |
| Location data | Last cell tower used (LAI — Location Area Identity) |

**SIM File Structure (Hierarchical)**:

```
        MF (Master File / Root)
        ├── DF_GSM (GSM network data)
        │    └── EF files (elementary files: network freq data)
        ├── DF_DCS1800 (DCS1800 band data)
        │    └── EF files
        └── DF_Telecom (service-related data)
             └── EF files (contacts, SMS, phonebook)
```

**SIM Access Notes**:
- SIM cards now come in standard, micro, and nano sizes
- Three attempts allowed before PIN locks the card — then a **PUK (PIN Unlock Key)** is required from the carrier
- Common default PINs to try: `1111`, `1234`
- Older CDMA phones incorporate SIM functions directly into the handset with no removable card

---

### 2.4 External Memory Cards

PDAs and smartphones frequently use peripheral memory cards for additional storage:

| Card Type | Description | Forensic Notes |
|-----------|-------------|----------------|
| Compact Flash (CF) | Early PDA storage; similar to PCMCIA | Legacy; rarely seen now |
| MultiMediaCard (MMC) | Originally for mobile phones | Provides separate storage area |
| Secure Digital (SD) | Most common today; 16 GB–64 GB+ | Contains photos, files; treat as separate evidence item; write-block before imaging |

---

## 3. Inside Mobile Devices

### 3.1 Core Hardware Components

Understanding internal components is essential for determining which forensic method to apply and where evidence may reside.

| Component | Role | Forensic Significance |
|-----------|------|-----------------------|
| **CPU (Processor)** | Executes instructions; the "brain" of the device | Location: center of motherboard under large shield cover; largest IC |
| **RAM** | Volatile memory for active processes | Lost on power-off; may contain decryption keys, running apps, call state |
| **ROM / Flash (NAND)** | Non-volatile storage for OS and user data | Primary evidence target; survives power loss; physical acquisition copies this |
| **SIM Card** | Subscriber identity + service data (GSM) | Stores IMSI/ICCID; contacts; deleted SMS recoverable |
| **Battery** | Power supply | Critical for evidence preservation — device must not die during acquisition |

**Storage Types**:
- **Internal Storage** — Contains OS, installed apps, and user data (photos, messages, databases). Stored in NAND Flash.
- **External Storage** — SD card (photos, downloads, media files). Must be separately imaged with a write-blocker.

---

### 3.2 Hardware Architecture

> **Definition**: A **Microprocessor** is the central processing unit of a mobile device (e.g., Apple A-series chips, Qualcomm Snapdragon). It is the largest IC on the motherboard, located under a large shield cover.

**Memory Hierarchy**:

```
┌──────────────────────────────────────────────────────────────┐
│                 MOBILE DEVICE MEMORY HIERARCHY               │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌────────────────────────────────────────────────────┐    │
│   │  ROM (Read-Only Memory)                            │    │
│   │  Stores firmware and OS image                      │    │
│   │  Non-volatile; cannot be modified by user          │    │
│   └────────────────────────────────────────────────────┘    │
│                          ▼                                   │
│   ┌────────────────────────────────────────────────────┐    │
│   │  NAND Flash Memory                                 │    │
│   │  Non-volatile; stores user data (photos/messages)  │    │
│   │  Primary target of physical/chip-off acquisition   │    │
│   └────────────────────────────────────────────────────┘    │
│                          ▼                                   │
│   ┌────────────────────────────────────────────────────┐    │
│   │  RAM (Random Access Memory)                        │    │
│   │  Volatile; active processes, decryption keys       │    │
│   │  Lost when device loses power                      │    │
│   └────────────────────────────────────────────────────┘    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**Radio Baseband Processor**:
- A separate, independent processor that manages all cellular functions (calls, SMS, data)
- Runs its **own OS**, independent of the main OS (Android/iOS)
- Can transmit/receive even when the main OS is suspended
- Forensically significant: may contain call metadata and network state independently

---

### 3.3 Motherboard Layout

The mobile motherboard is divided into two main sections. Understanding this layout is relevant for hardware-level forensic techniques (JTAG, Chip-Off).

```
┌─────────────────────────────────────────────────────────────────┐
│                  MOBILE MOTHERBOARD LAYOUT                      │
├───────────────────────────┬─────────────────────────────────────┤
│    LEFT SIDE              │    RIGHT SIDE                       │
├───────────────────────────┼─────────────────────────────────────┤
│  NETWORK SECTION          │  • Antenna Point                    │
│  ─────────────────────    │  • On/OFF Switch                    │
│  • PFO / PA               │  • Antenna Switch                   │
│    (= Antenna Switch +    │  • RX Filter                        │
│     PFO component)        │  • Network IC                       │
│  • BSI                    │  • Audio IC                         │
│  • VCO                    │  • RAM (×2 chips)                   │
│                           │  • UI Module / Logic IC             │
│  POWER SECTION            │  • Buzzer Interface                 │
│  ─────────────────────    │                                     │
│  • Power IC               │                                     │
│  • RTC (Real-Time Clock)  │  KEY NOTES:                         │
│  • Charging IC            │  ─────────────────────────          │
│  • CPU                    │  UEM = Logic IC + Charging IC       │
│  • R22                    │       + Audio IC + Power IC         │
│  • MIC Interface          │  Flash IC = RAM + Flash chip        │
└───────────────────────────┴─────────────────────────────────────┘
```

**Component Quick Reference**:

| Component | Function | Note |
|-----------|----------|------|
| PFO/PA | Power amplifier + antenna switch | Part of Network Section |
| BSI | Battery Status Indicator | Monitors battery level |
| VCO | Voltage-Controlled Oscillator | Generates carrier frequency for radio |
| RTC | Real-Time Clock | Maintains date/time; forensically relevant for timestamping |
| UEM | Unified Endpoint Management IC | Combines Logic + Charging + Audio + Power ICs into one chip |
| Network IC | Baseband processor chip | Manages cellular communication independently |

---

### 3.4 Mobile Operating Systems

The two dominant mobile OSes differ significantly in their security architecture, file system, and forensic accessibility.

| Feature | Android | iOS |
|---------|---------|-----|
| **Kernel** | Linux kernel | Darwin (Unix-like / XNU) |
| **File System** | EXT4 or F2FS | APFS (Apple File System) |
| **Source** | Open-source; multiple vendors | Closed-source; Apple only |
| **Security Model** | Varies by manufacturer/vendor ROM | Uniform; hardware-based Secure Enclave |
| **Encryption** | AES-256; full-disk encryption since Android 6.0 | Hardware-enforced; keys tied to Secure Enclave |
| **Backup** | Google Cloud / local ADB backup | iCloud / iTunes encrypted backup |
| **Physical Acquisition** | Easier (ADB, rooting) | Harder; requires exploit or Cellebrite-level tools |
| **App Data Location** | `/data/data/<package>/` | Sandboxed app containers; SQLite databases |

> **iOS Secure Enclave**: A dedicated hardware security module (co-processor) that stores encryption keys. Even Apple cannot extract keys from it without the user's passcode. This makes brute-forcing the only viable approach once logical acquisition fails.

> **Android open-source nature**: Allows for varied security implementations across manufacturers (Samsung Knox, Google Pixel Titan M chip), making a universal acquisition approach impossible.

---

## 4. Acquisition Procedure for Mobile Devices

### 4.1 Pre-Acquisition Concerns

Before any extraction begins, three critical risks must be managed:

```
┌──────────────────────────────────────────────────────────────────┐
│               PRE-ACQUISITION RISK MATRIX                        │
├──────────────────────┬───────────────────────────────────────────┤
│ Risk                 │ Mitigation                                │
├──────────────────────┼───────────────────────────────────────────┤
│ Power loss           │ Check battery level; attach charger ASAP  │
│                      │ If OFF: leave OFF, find charger            │
│                      │ If ON: note charge level in log            │
├──────────────────────┼───────────────────────────────────────────┤
│ Cloud synchronization│ Immediately disconnect USB cable from      │
│                      │ any connected PC/tablet                    │
│                      │ Prevents automatic sync overwriting data   │
├──────────────────────┼───────────────────────────────────────────┤
│ Remote wiping        │ Isolate device from all networks           │
│                      │ Faraday bag / Airplane Mode / paint can    │
│                      │ Drawback: roaming mode drains battery      │
└──────────────────────┴───────────────────────────────────────────┘
```

**Isolation Options (in order of preference)**:
1. **Faraday Bag** (e.g., Paraben Wireless StrongHold Bag) — Blocks all RF signals; conforms to Faraday wire cage standards
2. **Airplane Mode** — Disables cellular, Wi-Fi, Bluetooth; fastest to apply if screen is accessible
3. **Paint Can** — RF-shielded metal container (previously contained radio wave–blocking paint)
4. **Power Off** — Last resort; removes volatile RAM data

> **Legal note**: If the device is seized based on a warrant, document the time and date the device was isolated, as post-seizure messages received may or may not be admissible. A warrant or subpoena is required to access voicemail and cloud backups stored with third-party providers.

---

### 4.2 The Five-Step Acquisition Procedure

```
┌───────────────────────────────────────────────────────────────────┐
│           MOBILE EVIDENCE ACQUISITION — STEP BY STEP             │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  STEP 1: ISOLATION                                                │
│  ─────────────────────────────────────────────────────────────   │
│  Place device in Faraday Bag or enable Airplane Mode             │
│  Prevents remote wiping, cloud sync, incoming signals            │
│                          │                                        │
│                          ▼                                        │
│  STEP 2: IDENTIFICATION                                           │
│  ─────────────────────────────────────────────────────────────   │
│  Record: Make, Model, IMEI number, OS version, physical state    │
│  Photograph device before handling                               │
│                          │                                        │
│                          ▼                                        │
│  STEP 3: BYPASS SECURITY                                          │
│  ─────────────────────────────────────────────────────────────   │
│  Attempt known passcodes, biometric bypass, exploit methods      │
│  Check scene for written PINs, phone manual, PUK codes           │
│                          │                                        │
│                          ▼                                        │
│  STEP 4: EXTRACTION                                               │
│  ─────────────────────────────────────────────────────────────   │
│  Select appropriate acquisition method:                          │
│  Manual → Logical → File System → Physical                       │
│  Connect power supply; attach correct cable/SIM reader           │
│                          │                                        │
│                          ▼                                        │
│  STEP 5: DOCUMENTATION                                            │
│  ─────────────────────────────────────────────────────────────   │
│  Maintain chain of custody throughout                            │
│  Log every action, tool used, hash values, timestamps            │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

---

### 4.3 Acquisition Methods Compared

The NIST SP 800-101 guidelines identify six methods of mobile forensic acquisition, ordered from least invasive to most invasive:

| Method | How It Works | Data Obtained | Recovers Deleted? | Invasiveness |
|--------|-------------|---------------|-------------------|--------------|
| **Manual Extraction** | Navigate device UI; photograph each screen | Visible content only | No | Minimal |
| **Logical Acquisition** | Connect via USB/Bluetooth; use OS API | Call logs, SMS, contacts, emails | No | Low |
| **File System Acquisition** | Extract full directory structure | All files + hidden app databases | Partial | Medium |
| **Hex Dumping / JTAG** | Modified boot loader accesses RAM; JTAG connects to processor test points | Flash memory, RAM contents | Yes | High |
| **Chip-Off** | Physically remove NAND flash chip; read at binary level | All raw binary data | Yes | Very High (destructive) |
| **Micro Read** | Electron microscope examines logic gates | Even overwritten data | Yes | Extreme (national security only) |

**Method Details**:

**Manual Extraction**
- Investigator navigates device menus and photographs each screen
- Used as a **last resort** when no other method works
- Not forensically ideal — no hash verification; risk of changing data by navigation
- Useful for documenting visually displayed content

**Logical Acquisition**
- Device connected to forensic workstation via USB cable or Bluetooth
- Forensic software requests data through the OS API
- Retrieves: call logs, SMS/MMS, contacts, calendar, emails
- **Does not recover deleted data** — only what the OS exposes
- Example tool: Cellebrite UFED, ADB (Android)

**File System Acquisition**
- Extracts the complete directory and file structure
- Accesses hidden application databases (e.g., WhatsApp's `msgstore.db`, Facebook SQLite DBs)
- Better than logical — includes app caches, thumbnails, deleted-but-not-overwritten files
- Example: connecting Android via ADB with USB debugging enabled

**Physical Acquisition**
- Bit-for-bit copy of the entire NAND flash memory
- Most complete method; allows recovery of deleted files and data remnants
- Requires device to be unlocked, rooted (Android), or jailbroken (iOS)
- Produces a raw binary image that can be analyzed with tools like Autopsy or FTK

**JTAG (Joint Test Action Group)**
- Connects directly to the processor's **test access port (TAP)** on the motherboard
- Reads flash memory and RAM contents at a hardware level
- Useful when screen is broken or device is otherwise inaccessible
- Requires specialized equipment and knowledge of the specific chipset

**Chip-Off**
- Physical removal of the NAND flash memory chip from the PCB
- Chip is read using a specialized chip reader
- Used in extreme cases when all other methods fail
- Risk of destroying the chip if done incorrectly — irreversible

---

### 4.4 Data Locations to Check

When back in the forensics lab, evidence should be sought in all of the following locations:

```
┌──────────────────────────────────────────────────────┐
│             EVIDENCE STORAGE LOCATIONS               │
├──────────────────────────────────────────────────────┤
│  1. Internal Memory (NAND Flash)                     │
│     OS files, apps, user data, databases             │
│                                                      │
│  2. SIM Card                                         │
│     IMSI, ICCID, contacts, SMS, location data        │
│                                                      │
│  3. External Memory Card (SD Card)                   │
│     Photos, videos, downloaded files                 │
│                                                      │
│  4. Network Provider (requires warrant/subpoena)     │
│     Voicemail, call records, cell tower triangulation│
│     Cloud backups (iCloud, Google Drive, carrier)    │
└──────────────────────────────────────────────────────┘
```

> **Cloud Backups**: Because of growing mobile theft problems, service providers now offer remote wiping. A warrant or subpoena is required to access provider-held voicemail, call records, or cloud backups. GPS data can usually be retrieved directly from the device if it is in hand.

---

### 4.5 Memory Types and Volatility

| Memory Type | Volatile? | Contents | Priority |
|-------------|-----------|----------|---------|
| RAM | Yes (lost on power-off) | Active processes, decryption keys, missed calls, active sessions | Capture first — cannot be recovered after power loss |
| NAND Flash (internal) | No | OS, app data, user files, SQLite DBs | Primary evidence target |
| SIM Card (EEPROM) | No | IMSI, ICCID, SMS, contacts, LAI | Secondary; remove and image separately |
| SD Card | No | Photos, videos, downloads | Tertiary; treat as separate storage medium |

---

### 4.6 Chain of Custody

Chain of custody must be documented continuously from the moment the device is seized:

- **Photograph** the device before touching it (screen state, physical condition)
- **Record** the time and date of seizure, isolation, and every action taken
- **Log** every tool used, its version, and whether it is forensically sound
- **Hash** all extracted images (MD5 + SHA-1/SHA-256) immediately after acquisition
- **Package** the device in an anti-static, RF-shielded bag with a tamper-evident seal
- Every person who handles the device must sign the custody log

---

## 5. Mobile Forensics Tools

### 5.1 Commercial Software Tools

| Tool | Vendor | Key Capabilities |
|------|--------|-----------------|
| **Cellebrite UFED** | Cellebrite | Industry leader; supports thousands of phone models; unlocking + extraction; hundreds of cables included; multi-language support; widely used by law enforcement |
| **Magnet AXIOM Cyber** | Magnet Forensics | Excellent for parsing app artifacts (social media, messaging); visual timeline reconstruction; cloud evidence support |
| **MSAB XRY** | MSAB | High-speed extraction; broad support for legacy and current devices; GPS/tablet/music player support; used by government agencies |
| **Oxygen Forensics** | Oxygen Forensics | Specialized in cloud data integration; social media artifact analysis; extracts Facebook friends, Twitter data, Instagram |
| **Paraben Device Seizure** | Paraben | Acquires data from a variety of phone models; includes Device Seizure Toolbox (cables, SIM reader) |
| **MOBILedit Forensic** | Compelson | Built-in write-blocker; connects via Bluetooth, irDA, or cable; reads SIM cards; user-friendly |
| **SIMcon** | SIMcon | Specialized SIM card tool; recovers deleted SMS; generates MD5/SHA-1 hashed reports; exports to spreadsheet |

> **Limitation**: Cellebrite can analyze app data from only a few hundred of the 500,000+ available mobile apps. Always validate any tool before use with rigorous testing.

---

### 5.2 Open-Source Tools

| Tool | Platform | Use |
|------|----------|-----|
| **Autopsy / Sleuth Kit** | Windows/Linux/Mac | Open-source digital forensics platform; analyzes mobile disk images; parses SQLite databases, file systems |
| **ADB (Android Debug Bridge)** | Android | Command-line tool for logical extraction; requires USB Debugging enabled on device; part of Android SDK |

**ADB — Common Forensic Commands**:

```bash
# List connected devices
adb devices

# Pull entire file system (requires root)
adb pull /data/data/ ./output/

# Backup application data
adb backup -apk -shared -all -f backup.ab

# Pull SMS database
adb pull /data/data/com.android.providers.telephony/databases/mmssms.db
```

---

### 5.3 Hardware Forensic Tools

| Tool | Type | Method | Use Case |
|------|------|--------|----------|
| **JTAG** | Hardware | Connect to processor test points (TAP) on PCB | Device with broken screen, locked bootloader, or inaccessible via software |
| **Chip-Off** | Hardware | Physically remove NAND flash chip; read with chip reader | Device that is completely unresponsive; last resort before destruction |
| **SIM Card Reader** | Hardware/Software | Remove SIM; insert into USB reader connected to forensic workstation | Extract SIM data independently; works on all GSM/LTE devices |

**SIM Card Reader Procedure**:

```
1. Remove back panel of device
2. Remove battery
3. Remove SIM card from its holder
4. Insert SIM card into card reader
5. Plug reader into forensic workstation USB port
6. Run SIM forensics software (e.g., SIMcon)
7. Document unread messages BEFORE viewing
   (viewing marks them as "read" — alters state)
```

> **Anti-static precaution**: SIM card removal and chip-off operations must be performed in an ESD-safe (electrostatic discharge) environment with antistatic wrist straps and mats. Biological evidence (fingerprints) may be present inside the device — consult the lead investigator before opening.

---

### 5.4 Tool Selection Guide

```
┌───────────────────────────────────────────────────────────────────┐
│               TOOL SELECTION DECISION FLOW                        │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Device accessible & unlocked?                                    │
│       YES ──────────────────────────────────────────────────────► │
│                  Try Logical first (Cellebrite UFED / ADB)        │
│                  Then File System (ADB / AXIOM)                   │
│                  Then Physical (Cellebrite / AXIOM Physical)      │
│                                                                   │
│       NO  ──────────────────────────────────────────────────────► │
│                  Bypass security (known PIN / exploit)            │
│                  If iOS locked: JTAG or Cellebrite exploit        │
│                  If Android locked: JTAG + boot loader bypass     │
│                                                                   │
│  Device completely unresponsive?                                  │
│       ──────────────────────────────────────────────────────────► │
│                  Chip-Off (last resort; destructive)              │
│                                                                   │
│  SIM data needed independently?                                   │
│       ──────────────────────────────────────────────────────────► │
│                  SIM Card Reader + SIMcon                         │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

---

## Sources

- Nelson, B., Phillips, A., & Steuart, C. (2016). *Guide to Computer Forensics and Investigations* (5th ed.). Cengage Learning. — Chapter 12: Mobile Device Forensics
- NIST Special Publication 800-101 Revision 1 — *Guidelines on Mobile Device Forensics* (May 2014)
- Lessard, J. & Kessler, G. (2010). *Android Forensics: Simplifying Cell Phone Examinations*. Small Scale Digital Device Forensics Journal.
- Al Mutawa, N. et al. (2012). *Forensic analysis of social networking applications on mobile devices*. Digital Investigation 9.
- *Riley v. California*, 573 U.S. 373 (2014) — U.S. Supreme Court ruling on mobile device search warrants
