# Unit 1: Introduction to Application Security Testing

> **Course**: Application Security Testing (AST)
> **Unit**: 1 — Introduction
> **Syllabus Duration**: 4 Hours
> **PPT Reference**: *AST_1_Essentials of Ethical Hacking*
> **Text Book**: Richa Gupta, *Hands-on Penetration Testing for Web Applications*, BPB Publications, 2021

---

## Table of Contents

[[#1. Information Security]]
[[#2. Application Security]]
[[#3. Application Architecture]]
[[#4. Types of Application Security Testing (Box Testing)]]
[[#5. Application Security Tools and Solutions]]
[[#6. SAST — Static Application Security Testing]]
[[#7. DAST — Dynamic Application Security Testing]]
[[#8. IAST — Interactive Application Security Testing]]

---

## 1. Information Security

> **Definition**: Information Security is a state of well-being of information and infrastructure in which the possibility of theft, tampering, and disruption of information and services is **low or tolerable**. It refers to the protection of information systems from unauthorized access, disclosure, alteration, and destruction.

### 1.1 Why Information Security is Needed

- Evolution of technology leading to ease of use
- Increased reliance on computers for accessing, providing, and storing information
- Increased network environments and network-based applications
- Direct impact of security breach on corporate assets and goodwill
- Increased complexity of computer infrastructure administration

### 1.2 CIA Triad

| Property | Description |
|----------|-------------|
| **Confidentiality** | Ensuring information is accessible only to those authorized |
| **Integrity** | Safeguarding accuracy and completeness of information |
| **Availability** | Ensuring authorized users have access to information when needed |

### 1.3 Information Security Attack Vectors

Attack vectors through which an attacker can gain access to a computer or network:

- **Malware** — Viruses, worms, trojans, ransomware
- **Social Engineering** — Phishing, pretexting, baiting
- **Network Attacks** — MITM, packet sniffing, DoS
- **Application Vulnerabilities** — SQL injection, XSS, buffer overflow
- **Physical Access** — Unauthorized physical entry to systems
- **Insider Threats** — Employees or contractors misusing access
- **Supply Chain Attacks** — Compromising third-party software/hardware

### 1.4 Skills Required for Ethical Hacking

- **Programming** — Automate tasks, identify and exploit programming errors
- **Networking** — Understanding TCP/IP, protocols, and network configurations
- **SQL** — Knowledge of databases and query languages
- **OS Knowledge** — Basic commands of Linux, Windows, and macOS
- **Hacking Tools** — Familiarity with tools to identify and exploit weaknesses

---

## 2. Application Security

> **Definition**: Application security aims to protect software application code and data against cyber threats. It should be applied during **all phases of development**, including design, development, and deployment.

### 2.1 How to Promote Application Security

- Introduce security standards and tools during **design and development phases** (e.g., vulnerability scanning)
- Implement security procedures to protect applications in **production** (e.g., continuous security testing)
- Implement **strong authentication** for sensitive applications
- Use security systems: **WAF**, **IPS**, **Firewalls**

### 2.2 Types of Applications to Secure

| Type | Description |
|------|-------------|
| **Web Application Security** | Protect against OWASP Top 10, injection, XSS, CSRF |
| **API Security** | Secure REST/SOAP APIs from unauthorized access and abuse |
| **Cloud Native Security** | Protect containerized applications, microservices, serverless functions |
| **Mobile Application Security** | Secure Android/iOS apps from local and remote threats |

---

## 3. Application Architecture

> **Definition**: Application Architecture is a system that provides a guide to how software applications are assembled and how each application interacts with others to meet client needs. It comprises software modules, their components, systems, and interactions.

### 3.1 MVC (Model-View-Controller)

> A design pattern that separates application logic into three distinct parts.

```
┌─────────────────────────────────────────────────────────┐
│                  MVC ARCHITECTURE                       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│   User Request                                          │
│       │                                                 │
│       ▼                                                 │
│  ┌──────────┐   sends command   ┌──────────┐           │
│  │          │ ───────────────►  │          │           │
│  │   VIEW   │                   │CONTROLLER│           │
│  │          │ ◄───────────────  │          │           │
│  └──────────┘   updates view    └──────────┘           │
│                                       │                 │
│                                  updates/queries        │
│                                       │                 │
│                                       ▼                 │
│                                 ┌──────────┐           │
│                                 │  MODEL   │           │
│                                 │(Database)│           │
│                                 └──────────┘           │
└─────────────────────────────────────────────────────────┘
```

| Component | Role |
|-----------|------|
| **Model** | Manages data — retrieves raw information from the database, organizes it |
| **View** | Handles display — presents data recovered by the model to the user |
| **Controller** | Manages logic — processes user requests from View, calls Model, decides next View |

### 3.2 Microservices Architecture

> A refinement of Service-Oriented Architecture (SOA) where a large application is built as **small, autonomous, monofunctional modules**.

**Key Characteristics**:
- Each microservice is **autonomous** — independently deployable
- Microservices **do not share a data layer** — each has its own database and load balancer
- Changes to one service do not require redeploying the entire application
- Better **scalability** — individual services can be scaled independently

**Example**: An e-commerce application may have separate microservices for: payments, inventory, notifications, user profiles, and shipping.

### 3.3 Serverless Architecture

> An architecture where organizations rely on a **trusted third-party** to manage physical infrastructure. Developers write code without managing servers.

**Two Perspectives**:

| Model | Description |
|-------|-------------|
| **FaaS** (Function as a Service) | Run individual functions on demand without managing backend infrastructure (e.g., AWS Lambda) |
| **BaaS** (Backend as a Service) | Entire backend (database, storage, auth) is outsourced to third-party for management |

**Advantages**: No server maintenance, auto-scaling, pay-per-execution billing.

### 3.4 Single Page Applications (SPAs)

> A web application where a **single HTML page** is loaded once, and content is dynamically rewritten using JavaScript, without reloading the entire page.

- On first request: server sends an HTML file
- On subsequent requests: server sends **JSON data** instead of HTML
- Examples: Trello, Gmail, Facebook, Twitter

```
Traditional Web App:
  User Action → Full page reload from server (new HTML)

SPA:
  User Action → JavaScript updates only changed part (JSON from server)
```

### 3.5 Evolution of Web Application Architecture

| Phase | Technology | Description |
|-------|-----------|-------------|
| Early | Server-side scripts + HTML | All logic in single files |
| MVC Era | MVC pattern | Separated concerns, improved organization |
| Microservices | Microservices | Reduced server burden, scalable independent services |
| Modern | SPA + Microservices | Feature-rich, responsive, partial DOM updates |

---

## 4. Types of Application Security Testing (Box Testing)

### 4.1 Black Box Testing

> **Definition**: Black box security testing examines an application **from the outside** without access to source code. It simulates an external attacker's perspective.

- Tester has **no knowledge** of internal code, architecture, or infrastructure
- Tests the application through its **user interface** and external interfaces
- Equivalent to **DAST** in application security
- Finds vulnerabilities an external attacker would find

### 4.2 White Box Testing

> **Definition**: White box testing assesses an application's **internal working structure** and potential design loopholes with **full disclosure** of source code, IP addresses, network diagrams, and protocols.

Also called: **glass box**, **code-based**, **transparent box**, **open box**, **clear box** testing.

- Tester has **complete internal knowledge** — source code, architecture, DB schemas
- Developer's perspective
- Equivalent to **SAST** in application security
- Finds vulnerabilities in logic, code paths, and design

### 4.3 Gray Box Testing

> **Definition**: Gray box testing is a **blend of black box and white box** testing. The tester has partial knowledge of internal workings.

- Combines code-targeted approach (white box) with functional testing (black box)
- Tester assesses both **internal workings** and **user interface**
- Good for finding bugs due to incorrect code structure or incorrect use of applications

| Testing Type | Knowledge | Perspective | Equivalent |
|--------------|-----------|-------------|------------|
| Black Box | None | External/Attacker | DAST |
| White Box | Full | Internal/Developer | SAST |
| Gray Box | Partial | Mixed | IAST |

---

## 5. Application Security Tools and Solutions

| Tool | Full Form | Purpose |
|------|-----------|---------|
| **WAF** | Web Application Firewall | Monitors/filters HTTP traffic between app and Internet |
| **RASP** | Runtime Application Self-Protection | Detects/prevents threats at runtime from within the app |
| **SCA** | Software Composition Analysis | Inventories third-party components, finds known CVEs |
| **SAST** | Static Application Security Testing | Scans source code at rest ("white-box") |
| **DAST** | Dynamic Application Security Testing | Tests running application ("black-box") |
| **IAST** | Interactive Application Security Testing | Tests from within running app using agents/sensors |
| **MAST** | Mobile Application Security Testing | Tests mobile apps using static, dynamic, and forensic analysis |
| **CNAPP** | Cloud-Native Application Protection Platform | Centralized protection for cloud-native apps |

### 5.1 WAF (Web Application Firewall)

- Monitors and filters **HTTP traffic** between web application and the Internet
- Operates at **OSI Layer 7** (Application Layer)
- Protects against: **XSS**, **CSRF**, **SQL injection**, file inclusion
- Unlike a regular proxy (protects client), a WAF is a **reverse proxy** (protects the server)

### 5.2 RASP (Runtime Application Self-Protection)

- Analyzes user behavior and application traffic **at runtime**
- Achieves visibility into application source code
- Can **identify and terminate** already-exploited sessions
- Issues real-time alerts

### 5.3 SCA (Software Composition Analysis)

- Creates an **inventory of third-party open-source and commercial components**
- Identifies components and versions actively in use
- Finds **known CVEs** in dependencies
- Used to manage open-source risk

---

## 6. SAST — Static Application Security Testing

> **Definition**: SAST is a **"white-box"** testing method that tests source code and related dependencies **statically** (without running the application), early in the SDLC, to identify security flaws.

### 6.1 How SAST Works

```
┌─────────────────────────────────────────────────────────────┐
│                   SAST WORKFLOW                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Source Code / Binary                                       │
│       │                                                     │
│       ▼                                                     │
│  Scan with Predetermined Rules                              │
│  (without executing the code)                               │
│       │                                                     │
│       ▼                                                     │
│  Detects: SQL injection, input validation errors,           │
│           stack buffer overflows, etc.                      │
│       │                                                     │
│       ▼                                                     │
│  Report → Developer fixes vulnerabilities                   │
└─────────────────────────────────────────────────────────────┘
```

- **When**: At coding and testing stages, integrated into CI/CD and IDEs
- **Access**: Full access to source code
- **Advantage**: Early detection (shift-left security)
- **Compliance**: Helps comply with PCI/DSS, HIPAA, etc.

---

## 7. DAST — Dynamic Application Security Testing

> **Definition**: DAST is a **"black-box"** testing method that tests the application **while it is running**, without access to source code. It identifies runtime issues and weaknesses.

### 7.1 How DAST Works

- Implements **automated scans** that simulate malicious external attacks
- Injects malicious data to uncover injection flaws
- Tests **all HTTP and HTML access points**
- Emulates random user behaviors to find vulnerabilities
- Performed **later in the SDLC**, when the application is working

| SAST | DAST |
|------|------|
| Static analysis (code at rest) | Dynamic analysis (code running) |
| White-box testing | Black-box testing |
| Early SDLC | Later SDLC |
| Needs source code | Needs running application |
| Developer's perspective | Attacker's perspective |
| No false runtime negatives | Can find runtime-only issues |

---

## 8. IAST — Interactive Application Security Testing

> **Definition**: IAST is an AST tool designed for modern web and mobile applications that **works from within** an application to detect and report issues while the application is running. It operates from within the application server to inspect compiled source code.

### 8.1 How IAST Works

- Deployed by deploying **agents and sensors** in the application post-build
- The agent **observes application operation** and analyzes traffic flow
- Maps **external signatures/patterns to source code**
- Identifies more **complex vulnerabilities** by combining static and dynamic approaches
- Results reported in **real time** via browser/dashboard

```
┌──────────────────────────────────────────────────────────┐
│              IAST DEPLOYMENT MODEL                       │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │           Running Application                    │   │
│  │                                                  │   │
│  │   ┌──────────┐    ┌──────────────────────────┐  │   │
│  │   │ Business │    │  IAST Agent / Sensor     │  │   │
│  │   │  Logic   │◄──►│  - Observes execution   │  │   │
│  │   └──────────┘    │  - Analyzes traffic flow │  │   │
│  │                   │  - Maps patterns to code │  │   │
│  └───────────────────┴──────────────────────────┘  │   │
│                              │                          │
│                              ▼                          │
│                    Real-time Report / Dashboard          │
└──────────────────────────────────────────────────────────┘
```

### 8.2 MAST (Mobile Application Security Testing)

- Uses **static and dynamic analysis** and forensic data collection
- Tests for mobile-specific issues: jailbreaking, data leakage, malicious WiFi

### 8.3 CNAPP (Cloud-Native Application Protection Platform)

- Provides **centralized control panel** for cloud-native application protection
- Unifies **CWPP** (Cloud Workload Protection Platform) and **CSPM** (Cloud Security Posture Management)
- Incorporates identity entitlement management, API discovery, and Kubernetes security
