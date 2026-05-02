# Unit 5: Mobile Application Security and Testing

> **Course**: Application Security Testing (AST)
> **Unit**: 5 — Mobile Application Security and Testing
> **Syllabus Duration**: 6 Hours
> **PPT Reference**: *AST_5_Mobile Application Security*
> **Reference Book**: Vijay Kumar Velu, *Mobile Application Penetration Testing*, Packt Publications, 2016

---

## Table of Contents

[[#1. Types of Mobile Applications]]
[[#2. Challenges in Mobile Security Testing]]
[[#3. OWASP Mobile Top 10]]
[[#4. Anatomy of a Mobile Attack]]
[[#5. Mobile Platform Vulnerabilities and Risks]]
[[#6. Mobile Attack Countermeasures]]

---

## 1. Types of Mobile Applications

| Type | Description | Examples |
|------|-------------|---------|
| **Native Apps** | Built specifically for one platform (Android/iOS) using platform-native SDKs | Gmail (Android/iOS native) |
| **Web Apps** | Mobile-optimized websites accessed via mobile browsers; no installation required | m.twitter.com |
| **Hybrid Apps** | Combination of native and web; web code wrapped in native container (e.g., Cordova) | Ionic-based apps |
| **Progressive Web Apps (PWA)** | Web apps with native-like features (offline, push notifications) via Service Workers | Twitter Lite, Instagram PWA |

### 1.1 Security Implications by App Type

| App Type | Security Concern |
|----------|-----------------|
| Native | Access to device APIs, local data storage, potential over-permissioning |
| Web | XSS, CSRF, insecure data caching in browser |
| Hybrid | Both web and native attack surfaces; insecure WebView configurations |
| PWA | Service Worker vulnerabilities, cache poisoning |

---

## 2. Challenges in Mobile Security Testing

> Mobile devices have become the **preferred devices** for accessing the Internet, managing communications, and business operations — making them increasingly attractive targets for cybercriminals.

### 2.1 Key Challenges

| Challenge | Description |
|-----------|-------------|
| **Diverse Platforms** | Android and iOS have different architectures, SDKs, and security models |
| **Multiple Attack Surfaces** | Device, network, application, and backend/cloud |
| **Rapid Release Cycles** | Frequent app updates; security testing must keep pace |
| **Third-Party Libraries** | Heavy reliance on SDKs with potentially undiscovered vulnerabilities |
| **Jailbreaking/Rooting** | Breaks platform security model; difficult to test on stock devices |
| **Network Diversity** | Apps used on Wi-Fi, mobile data, and untrusted public networks |
| **Hardware Diversity** | Thousands of Android device models with different firmware |
| **Cryptographic Misuse** | Incorrect use of cryptographic APIs common in mobile development |
| **Local Data Storage** | Sensitive data stored insecurely on device |

---

## 3. OWASP Mobile Top 10

> The **OWASP Mobile Top 10** documents the most critical mobile application security risks:

| Risk | Name | Description |
|------|------|-------------|
| **M1** | Improper Platform Usage | Misuse of platform features (permissions, Keychain, TouchID) or failure to use platform security controls |
| **M2** | Insecure Data Storage | Storing sensitive data insecurely on the device |
| **M3** | Insecure Communication | Transmitting data insecurely (no TLS, weak cipher suites, certificate not validated) |
| **M4** | Insecure Authentication | Weak login/authentication mechanisms |
| **M5** | Insufficient Cryptography | Weak or flawed encryption implementation |
| **M6** | Insecure Authorization | Poor access control; app fails to properly authorize actions |
| **M7** | Client Code Quality | Code-level implementation vulnerabilities (buffer overflow, format string vulnerabilities) |
| **M8** | Code Tampering** | Binary patching, resource modification, method hooking/swizzling |
| **M9** | Reverse Engineering | Analysis of app binary to reveal source code, libraries, algorithms, and secrets |
| **M10** | Extraneous Functionality | Hidden backdoor functionality or development controls left in production apps |

### M1: Improper Platform Usage

> Misuse of platform-provided features (e.g., iOS Keychain, Android Permissions, TouchID/FaceID), or failure to use platform security controls properly.

**Examples**:
- Requesting excessive permissions that are not needed for app function
- Storing sensitive data in publicly accessible locations (external storage)
- Using WebViews insecurely (enabling JavaScript, file access)

### M2: Insecure Data Storage

> Sensitive data stored in **unprotected locations** on the device that can be accessed by other apps or attackers with physical/logical access.

**Vulnerable Storage Locations**:
- SQLite databases (unencrypted)
- Log files (containing sensitive data)
- Shared preferences / property list files
- Cloud synchronization (iCloud, Google Drive)
- Cookie stores
- SD card / external storage

### M3: Insecure Communication

> Transmitting sensitive data **without proper encryption** or with improperly configured TLS.

**Issues**:
- Using HTTP instead of HTTPS
- Accepting invalid or self-signed SSL certificates
- Improper SSL validation (certificate pinning bypass)
- Using weak cipher suites (e.g., RC4, null ciphers)
- Transmitting sensitive data in plaintext over Wi-Fi

### M4: Insecure Authentication

> Mobile applications often don't implement **proper authentication** — relying on device-based authentication or insecure client-side checks.

**Examples**:
- Authentication performed on the client side (easily bypassed)
- Storing credentials locally in plaintext
- Lack of multi-factor authentication for sensitive actions
- Biometric authentication without proper fallback security

### M5: Insufficient Cryptography

> Flawed or insufficient encryption of data at rest or in transit — allowing attackers to **decrypt or brute-force** protected data.

**Issues**:
- Using outdated/weak algorithms (MD5, SHA-1 for passwords, DES/RC4 for encryption)
- Hardcoded encryption keys in source code
- Improper key management (keys stored in predictable locations)
- Insufficient random number generation for cryptographic keys

### M6: Insecure Authorization

> App fails to properly **verify what an authenticated user is allowed to do** — allowing access to other users' data or privileged functions.

- Similar to Broken Access Control (IDOR) in web apps
- Server should enforce authorization; never trust client-side checks

### M7: Client Code Quality

> Implementation-level code vulnerabilities in **client-side code** — buffer overflows, format string vulnerabilities, injection attacks in local components.

**Real-World Case**:
- WhatsApp vulnerability patched in 2019 — attackers could install **Pegasus Spyware** simply by placing a WhatsApp audio call on targeted phones, exploiting a buffer overflow in the VoIP stack. No user interaction required.

### M8: Code Tampering

> Attackers **modify app code** after it's distributed — through binary patching, resource modification, method hooking (Frida/Xposed), or method swizzling.

**Methods**:
- **Binary patching** — directly modify the compiled binary
- **Method hooking** — intercept and modify function calls at runtime (Frida framework)
- **Method swizzling** — iOS-specific runtime method replacement
- **Counterfeit apps** — modified versions published on third-party app stores

**Attack vectors**:
1. Attacker obtains APK/IPA from app store
2. Decompiles and modifies the binary (removes license checks, adds malicious code)
3. Repacks and redistributes via phishing or third-party stores
4. Users install the modified app

### M9: Reverse Engineering

> Attackers **analyze the app binary** using tools like IDA Pro, Hopper, otool, jadx, apktool to understand internal operations, extract secrets, and discover backend vulnerabilities.

**What attackers can find**:
- **Backend server URLs** and internal API endpoints
- **Hardcoded credentials** and API keys
- **Cryptographic constants** and algorithms
- **Business logic** and proprietary algorithms

**Tools used**: IDA Pro, Hopper, Ghidra, apktool, jadx (Android), otool, class-dump (iOS)

**Real-World Case**:
- Pokémon Go was reverse engineered to reveal the vicinity of Pokémon — users caught Pokémon in minutes without physically visiting locations.

### M10: Extraneous Functionality

> Development or testing functionality **accidentally left in production** builds — creating unnecessary attack surface.

**Examples**:
- Debug backdoor URLs (e.g., `/admin/debug`) accessible in production
- Hardcoded credentials used during development left in comments
- Disabled two-factor authentication toggle left in code
- Logging statements that output sensitive data

**Real-World Case**:
- WiFi File Transfer app opened a port on Android allowing connections from computers **without authentication** — anyone on the same network could access the device fully.

### Summary Table

| Risk | Simple Meaning |
|------|---------------|
| M1 | Not using platform security properly |
| M2 | Storing data unsafely on device |
| M3 | Sending data insecurely over network |
| M4 | Weak login / authentication system |
| M5 | Weak or flawed encryption |
| M6 | No proper access control |
| M7 | Poor client-side code quality |
| M8 | App can be modified by attacker |
| M9 | App secrets can be extracted |
| M10 | Unnecessary features left open in production |

---

## 4. Anatomy of a Mobile Attack

Mobile attacks target three points:

```
┌─────────────────────────────────────────────────────────────────────┐
│                   ANATOMY OF A MOBILE ATTACK                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   POINT 1: THE DEVICE                                               │
│   ├── Browsing-based attacks                                       │
│   ├── Phone/SMS-based attacks                                      │
│   └── Application-based attacks                                    │
│              │                                                      │
│              ▼                                                      │
│   POINT 2: THE NETWORK                                              │
│   ├── Wi-Fi attacks (rogue AP, packet sniffing)                    │
│   ├── Bluetooth attacks                                            │
│   └── SS7 protocol vulnerabilities                                 │
│              │                                                      │
│              ▼                                                      │
│   POINT 3: THE DATA CENTRE / CLOUD                                  │
│   ├── Web-server-based attacks                                     │
│   └── Database attacks                                             │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.1 Point 1 — The Device

**Browsing-based attacks**:

| Attack | Description |
|--------|-------------|
| **Phishing** | Emails/pop-ups redirect users to fake web pages mimicking trusted sites |
| **Framing** | Web page integrated into another using HTML iFrames |
| **Clickjacking** | Trick users into clicking elements different from what they think |
| **Man-in-the-Mobile (MitMo)** | Malicious code implanted on device to steal OTPs sent via SMS |
| **Buffer Overflow** | Program writes beyond buffer bounds, corrupts adjacent memory |
| **Data Caching** | Exploit cached data stored by mobile browsers and apps |

**Phone/SMS-based attacks**:

| Attack | Description |
|--------|-------------|
| **Baseband Attacks** | Exploit vulnerabilities in the phone's GSM/3GPP baseband processor |
| **SMiShing (SMS Phishing)** | Bogus SMS messages containing malicious links or phone numbers to lure victims |

**Application-based attacks**:

| Attack | Description |
|--------|-------------|
| **Sensitive Data Storage** | Exploit weak database architecture of apps |
| **No/Weak Encryption** | Session hijacking over unencrypted data |
| **Improper SSL Validation** | Accept invalid certificates, enabling MITM |
| **Configuration Manipulation** | Apps using external config files/libraries with weak protections |
| **Dynamic Runtime Injection** | Inject code at runtime (Frida) |
| **Escalated Privileges** | Exploit design flaws or bugs to gain root/admin access |

**System-level attacks**:

| Attack | Description |
|--------|-------------|
| **iOS Jailbreaking** | Removing Apple's security restrictions to allow unsigned code |
| **Android Rooting** | Gaining privileged control (root) within Android subsystem |
| **OS Data Caching** | Extract sensitive data from OS cache stored temporarily on disk |
| **Carrier-loaded Software** | Exploit vulnerabilities in pre-installed software |

### 4.2 Point 2 — The Network

| Attack | Description |
|--------|-------------|
| **Wi-Fi (Weak/No Encryption)** | Intercept data on poorly encrypted or open wireless connections |
| **Rogue Access Points** | Attacker installs illicit wireless AP to hijack connections |
| **Packet Sniffing** | Analyze data packets in network traffic |
| **MITM (Man-in-the-Middle)** | Eavesdrop on existing network connection between two systems |
| **Session Hijacking** | Steal valid session IDs from network traffic |
| **DNS Poisoning** | Substitute false IP addresses at the DNS level |
| **SSLStrip** | Downgrade HTTPS connections to HTTP invisibly |
| **Fake SSL Certificates** | Issue fake certificates to intercept HTTPS connections |

**SS7 (Signaling System 7) Vulnerability**:

> SS7 is a communication protocol allowing mobile users to exchange communication through another cellular network (especially when roaming). It operates on **mutual trust between operators without authentication verification**.

**SS7 Attack Capabilities**:
- Eavesdrop on calls and SMS messages
- Intercept bank OTPs and two-factor authentication codes
- **Bypass 2FA** — intercept SMS-based OTPs
- Locate users (expose subscriber identity and network identity)
- Perform DoS attacks

### 4.3 Point 3 — The Data Centre / Cloud

**Web-server-based attacks**:

| Attack | Description |
|--------|-------------|
| **Platform Vulnerabilities** | Exploit OS, server software, or application module vulnerabilities |
| **Server Misconfiguration** | Exploit misconfigured web servers |
| **XSS** | Inject malicious scripts into invalidated input rendered in user's browser |
| **CSRF** | Victim's active session used to make unauthorized requests to trusted site |
| **Weak Input Validation** | Bypass server validation to perform unauthorized actions |
| **Brute-Force Attacks** | Trial and error to guess credentials when attempts aren't restricted |

**Database attacks**:

| Attack | Description |
|--------|-------------|
| **SQL Injection** | Execute SQL commands on backend database for unauthorized access |
| **Privilege Escalation** | Gain high-level database access to steal sensitive records |
| **Data Dumping** | Force database to dump sensitive records |
| **OS Command Execution** | Use database vulnerabilities to gain system-level access |

### 4.4 SMiShing (SMS Phishing)

> **Definition**: SMS phishing (SMiShing) is a type of phishing fraud using SMS messages containing deceptive links or phone numbers to acquire personal/financial information or install malware.

**Why SMiShing is Effective**:
- Most consumers access Internet through mobile devices
- Easy to set up a mobile phishing campaign
- Mobile users not conditioned to receiving SMS spam
- No mainstream mechanism for filtering spam SMS
- Most mobile antivirus tools don't check SMS

**Attack Flow**:
1. Attacker buys prepaid SMS card with fake identity
2. Sends attractive/urgent SMS (lottery, gift voucher, account suspension alert) with malicious link
3. Victim clicks link → redirected to phishing site
4. Victim enters personal information (name, DOB, credit card, PIN, CVV)
5. Attacker uses information for identity theft, online purchases

---

## 5. Mobile Platform Vulnerabilities and Risks

### 5.1 App Sandboxing

> **Definition**: App sandboxing is a security mechanism that **limits the resources** an app can access to its intended functionality — isolating apps from each other and from system resources.

- Provides each app with a **separate execution environment**
- Prevents apps from accessing other apps' data and system resources
- Securely executes untested code or untrusted programs

**Sandboxing Risks**:
- A **vulnerable sandbox** allows malicious apps to exploit vulnerabilities and breach the sandbox
- Sophisticated malware may perform sandbox **escape** through privilege escalation

### 5.2 Mobile Spam

> Also known as **SMS spam, text spam, m-spam** — unsolicited messages sent in bulk to target mobile phones.

**Typical Spam Message Types**:
- Messages with advertisements or malicious links
- Commercial messages advertising products/services
- "Prize won" messages with premium-rate call numbers
- Phishing messages requesting personal/financial data

**Consequences**: Financial loss, malware injection, corporate data breaches.

---

## 6. Mobile Attack Countermeasures

### 6.1 General Device Guidelines

| Category | Guidelines |
|----------|-----------|
| **Application Management** | Install only from trusted app stores (Google Play, App Store); avoid sideloading |
| **Data Management** | Securely wipe data when disposing of device; limit data in GPS-enabled apps |
| **Wireless Management** | Disable Wi-Fi and Bluetooth when not in use; never connect both simultaneously |
| **Security Assessment** | Perform security assessment of application architecture; maintain configuration control |

### 6.2 Passcode and Authentication

- Use a **strong passcode** (at least 8-character complex passcode)
- Set idle **timeout to automatically lock** the phone
- Enable **lockout/wipe feature** after a set number of failed attempts
- Enable **erase data** after multiple wrong attempts (thwart guessing attacks)
- Consider **biometric authentication** as additional factor

### 6.3 Updates and Patch Management

- **Regularly update OS and apps** to latest versions
- Apply software updates immediately when new security releases are available
- Perform regular software maintenance cycles
- **Do not allow rooting/jailbreaking** — violates the security model

### 6.4 Enterprise Mobile Device Management (MDM)

- Use **MDM software** to: secure, monitor, manage, and support mobile devices across the organization
- MDM can:
  - Enforce device encryption and passcode policies
  - Detect/prevent rooting or jailbreaking
  - Enforce remote wipe capabilities
  - Control app installation

### 6.5 Remote Wipe and Recovery

- Use **remote wipe services**:
  - Android: **Find My Device**
  - iOS: **Find My iPhone / Find My**
- Report lost/stolen devices to IT immediately so certificates and access methods can be disabled

### 6.6 Encryption and Backup

- **Encrypt device storage** using hardware encryption if supported
- Use **secure over-the-air backup** tools
- Control the location of backups
- Encrypt backups
- Limit sensitive enterprise data on shared mobile devices

### 6.7 Developer Countermeasures

| Area | Countermeasure |
|------|----------------|
| **Data Storage** | Use encrypted storage; avoid external storage for sensitive data |
| **Communication** | Enforce TLS; implement certificate pinning |
| **Authentication** | Implement strong server-side authentication; use biometrics as 2FA only |
| **Cryptography** | Use strong, approved algorithms (AES-256, RSA-2048); never hardcode keys |
| **Reverse Engineering Protection** | Code obfuscation (ProGuard for Android); anti-tampering checks |
| **Code Tamper Detection** | Integrity checking; verify app signature at runtime |
| **Extraneous Functionality** | Remove all debug code, backdoors, and development credentials before release |

### 6.8 Security Issues from App Stores

- **Counterfeit apps** — attackers publish modified versions of popular apps on third-party stores
- **Malicious apps** — apps that look legitimate but contain malware (spyware, adware, ransomware)
- **Permissions abuse** — apps requesting far more permissions than needed

**Mitigations**:
- Install only from official app stores
- Review app permissions before installation
- Verify publisher identity and reviews
- Use mobile security solutions that scan apps for malicious behavior
