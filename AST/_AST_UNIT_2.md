# Unit 2: Secure Software Lifecycle

> **Course**: Application Security Testing (AST)
> **Unit**: 2 — Secure Software Lifecycle
> **Syllabus Duration**: 5 Hours
> **PPT Reference**: *AST_3_Secure Software Security*
> **Reference**: CyBOK, Chapter 16 — *Secure Software Lifecycle*

---

## Table of Contents

[[#1. Need for a Secure Software Lifecycle]]
[[#2. Secure Software Lifecycle Processes]]
[[#3. Microsoft SDL (12 Practices)]]
[[#4. Touchpoints (7 Practices)]]
[[#5. SAFECode (8 Practices)]]
[[#6. Adaptations of SecSDL]]
[[#7. Assessing the Secure Software Lifecycle]]

---

## 1. Need for a Secure Software Lifecycle

### 1.1 The Historic Reactive Approach (Problem)

Traditionally, security was assessed only when software was **"complete" or "deployed"** — vulnerabilities were discovered after the fact and then patched. This approach has major shortcomings:

| Shortcoming | Explanation |
|------------|-------------|
| **Breaches are costly** | Loss of reputation from a breach is difficult to quantify financially |
| **Attackers exploit silently** | Once a vulnerability is publicly known, attackers develop exploits before organizations patch |
| **Patches introduce new bugs** | Urgent patches are rushed out, potentially introducing new vulnerabilities |
| **Patches go unapplied** | Users and system administrators are often reluctant to apply security patches |

### 1.2 The Proactive Approach

> **Goal**: Integrate security into **every phase** of the software development process — design, development, testing, and deployment — rather than treating it as an afterthought.

- **Building Secure Software** (McGraw & Viega, 2002) — landmark work on integrating security into SDLC
- Security violations occur because of **errors in software design and coding** — fixing these requires proactive analysis

### 1.3 Purpose of a Secure Software Lifecycle

- Provide an overview of development processes for implementing **secure software from design to operation**
- Covers new coding **as well as** incorporation of third-party libraries and components
- Organizations **customize** their own lifecycle rather than taking a prescriptive approach
- Successful adoption requires **cultural change** in addition to technical practices

---

## 2. Secure Software Lifecycle Processes

Three major frameworks define SecSDL processes:

| Framework | Practices | Focus |
|-----------|-----------|-------|
| **Microsoft SDL** | 12 Practices | Enterprise security in software development |
| **Touchpoints** | 7 Practices | Best practices integrated into SDLC (Gary McGraw) |
| **SAFECode** | 8 Practices | Software assurance for secure code |

---

## 3. Microsoft SDL (12 Practices)

> **Definition**: The Microsoft Security Development Lifecycle (SDL) is a set of 12 security practices integrated throughout the software development process to reduce the number and severity of vulnerabilities.

```
┌─────────────────────────────────────────────────────────────────────┐
│              MICROSOFT SDL — 12 PRACTICES OVERVIEW                  │
├────────────────────────┬────────────────────────────────────────────┤
│ Practice               │ Phase                                      │
├────────────────────────┼────────────────────────────────────────────┤
│ 1. Training            │ Pre-Development                            │
│ 2. Security Req.       │ Requirements                               │
│ 3. Metrics & Compliance│ Requirements                               │
│ 4. Threat Modeling     │ Design                                     │
│ 5. Design Requirements │ Design                                     │
│ 6. Cryptography Std.   │ Implementation                             │
│ 7. 3rd Party Risk      │ Implementation                             │
│ 8. Approved Tools      │ Implementation                             │
│ 9. SAST                │ Verification                               │
│ 10. DAST               │ Verification                               │
│ 11. Penetration Testing│ Verification                               │
│ 12. Incident Response  │ Release/Response                           │
└────────────────────────┴────────────────────────────────────────────┘
```

### Practice 1: Providing Training

- Developers and architects must understand **technical approaches** for preventing and detecting vulnerabilities
- The entire development organization should understand the **attacker's perspective**, goals, and techniques
- Establish training criteria: secure design, development, test, and privacy topics
- Minimum training frequency set — attackers are a moving target
- **e.g.** 80% of technical personnel trained annually

### Practice 2: Security Requirements

- Security requirements must be defined during **initial design and planning phases**
- Factors influencing requirements: functional requirements, legal/industry compliance, internal/external standards, previous security incidents, known threats
- Security requirements must be **continuously updated** as the threat landscape changes
- Techniques: **SQUARE**, abuse cases, i* and KAOS frameworks

### Practice 3: Define Metrics and Compliance Reporting

- Define and document a **bug bar** for security (what constitutes moderate, important, critical issues)
- Bug classification is used to set priority for fixing and determining if the product can ship
- Ensure bug reporting tools can **track security issues** and support dynamic querying

### Practice 4: Perform Threat Modeling

> **Definition**: Threat modeling is a process to understand (potential) security threats to a system, determine risks from those threats, and establish appropriate mitigations.

**STRIDE Threat Model** — enumerate threats for each system component:

| Letter | Threat | Description |
|--------|--------|-------------|
| **S** | Spoofing Identity | Attacker poses as another user or server |
| **T** | Tampering with Data | Malicious modification of data |
| **R** | Repudiation | User denies performing an action with no proof otherwise |
| **I** | Information Disclosure | Exposure of data to unauthorized individuals |
| **D** | Denial of Service | Making the system unavailable or unusable |
| **E** | Elevation of Privilege | Gaining more permissions than authorized |

**Approach**: Consider (1) malicious/benevolent interactors, (2) system design and components, (3) trust boundaries, and (4) data flow within and across trust boundaries.

### Practice 5: Establish Design Requirements

Design principles to follow:

| Principle | Description |
|-----------|-------------|
| **Economy of Mechanism** | Keep design as simple and small as possible |
| **Fail-Safe Defaults** | On failure, default to denying access |
| **Complete Mediation** | Every access must be checked for authorization |
| **Open Design** | Security should not rely on obscurity; rely on keys/passwords |
| **Separation of Privilege** | Require multiple conditions before granting access |
| **Least Privilege** | Users/programs operate with minimum necessary privileges |
| **Least Common Mechanism** | Minimize shared mechanisms between users |
| **Psychological Acceptability** | Security interface should be easy for users to use correctly |
| **Defense in Depth** | Multiple layers of security controls for redundancy |
| **Design for Updating** | Software must support future security patches |

### Practice 6: Define and Use Cryptography Standards

- Proper use of cryptography: protect **confidentiality** of data, protect data from **unauthorized modification**, and **authenticate** data sources
- Use approved cryptographic algorithms and implementations
- Avoid custom/home-grown crypto

### Practice 7: Manage Risk of Third-Party Components

- Maintain an **accurate inventory** of all third-party components
- Continuously use tools to **scan for known CVEs** in components
- Have a plan to respond when new vulnerabilities are discovered in dependencies

### Practice 8: Use Approved Tools

- Specify approved build tools: compilers, static/dynamic analysis tools, debuggers, IDEs
- Ensure security settings are correctly configured
- Update tools regularly — security tools evolve with the threat landscape

### Practice 9: Perform SAST

- Static analysis at coding and testing stages
- Integrated into CI/CD pipeline and IDEs

### Practice 10: Perform DAST

- **Runtime verification** of compiled/packaged software
- Checks functionality only apparent when all components are integrated and running
- Detects: memory corruption, user privilege issues, injection attacks, and other critical security problems

### Practice 11: Perform Penetration Testing

- **Manual black-box testing** of a running system simulating attacker actions
- Performed by skilled security professionals (internal or external consultants)
- Objective: uncover vulnerabilities from implementation bugs to major design flaws
- Sources: coding errors, system configuration faults, design flaws, operational deployment weaknesses

### Practice 12: Establish Incident Response Practice

- Create a clearly defined **support policy** and **Cyber Security Incident Response Plan (CSIRP)**
- Identify contacts for Cyber Security Council
- Provide 24x7x365 contact information for engineering, marketing, and management
- Ensure ability to issue all code "emergency" releases and third-party licensed code patches

---

## 4. Touchpoints (7 Practices)

> **Definition**: Touchpoints (by Gary McGraw) are a set of **best practices integrated into the SDLC** to improve software security through specific security activities at appropriate phases.

| # | Practice | Description |
|---|----------|-------------|
| 1 | **Code Review (Static Analysis)** | Analyze source code to find vulnerabilities (buffer overflow, injection flaws) |
| 2 | **Architectural Risk Analysis** | Evaluate system architecture for security weaknesses; identify design-level vulnerabilities early |
| 3 | **Penetration Testing** | Simulate real-world attacks; uncover exploitable vulnerabilities |
| 4 | **Risk-Based Security Testing** | Focus testing on high-risk areas; prioritize critical components |
| 5 | **Abuse Cases** | Identify how attackers might misuse the system; design security controls |
| 6 | **Security Requirements** | Define security needs during requirements phase (authentication, authorization, data protection) |
| 7 | **Security Operations** | Monitor and respond to security incidents post-deployment; includes patching and vulnerability management |

---

## 5. SAFECode (8 Practices)

> **Definition**: SAFECode (Software Assurance Forum for Excellence in Code) defines best practices to ensure **security is integrated throughout** the software development lifecycle.

| # | Practice | Key Activities |
|---|----------|----------------|
| 1 | **Define Security Requirements** | Identify security needs early; include compliance, privacy, risk requirements |
| 2 | **Secure Design (Threat Modeling)** | Analyze threats using STRIDE; design architecture to mitigate risks before coding |
| 3 | **Secure Coding Practices** | Follow coding standards; prevent buffer overflow, injection attacks |
| 4 | **Use Approved Tools and Libraries** | Use trusted, updated components; avoid vulnerable third-party libraries |
| 5 | **Code Review and Static Analysis** | Perform manual code reviews; use static analysis tools to detect flaws early |
| 6 | **Security Testing (Dynamic Testing)** | Conduct penetration testing, fuzz testing, and runtime analysis |
| 7 | **Secure Build and Release Management** | Ensure secure configuration before deployment; final security review with no critical vulnerabilities |
| 8 | **Incident Response and Patch Management** | Monitor vulnerabilities after release; provide timely patches and updates |

---

## 6. Adaptations of SecSDL

### 6.1 Agile / DevOps

- Agile is highly iterative — new functionality delivered frequently (multiple times/day to every 2–4 weeks)
- Security must be embedded in each sprint/iteration
- **SAFECode Security User Stories** help express security as user stories
- **Microsoft Secure DevOps** practices:
  - Provide Training
  - Define Requirements
  - Define Metrics and Compliance Reporting
  - Use Software Composition Analysis (SCA)
  - Perform Threat Modeling
  - Use Tools and Automation
  - Keeping credentials safe
  - Continuous learning and monitoring

### 6.2 Mobile

- Security concerns for mobile differ from desktop: **local data storage**, **inter-app communication**, **cryptographic API use**, **secure network communication**
- **OWASP Mobile Security Project** resources:
  - OWASP Mobile Application Security Verification Standard (MASVS)
  - Mobile Security Testing Guide (MSTG)
  - Mobile App Security Checklist
  - Mobile Threat Model

### 6.3 Cloud Computing

- Key threats and practices:
  - **Threat: Multitenancy** — data from multiple tenants on shared infrastructure
  - Tokenization of sensitive data
  - Trusted Compute Pools
  - Data Encryption and Key Management
  - Authentication and Identity Management
  - Shared-Domain Issues

### 6.4 Internet of Things (IoT)

NIST recommends four practices for secure IoT development:

| # | Practice | Description |
|---|----------|-------------|
| 1 | **RFID Tags** | Unique identifiers prevent counterfeits; mitigate data tampering |
| 2 | **No Default Passwords** | Require password changes; randomize passwords per device |
| 3 | **MUD Specification** | Manufacturer Usage Description restricts device communications to intended patterns |
| 4 | **Secure Upgrade Process** | Authenticate the source of patches; implement secure firmware update architecture |

### 6.5 Road Vehicles (Automotive)

- Follow a **systems-engineering approach** to designing cyber-physical systems free of cyber threats
- Documented process for responding to incidents, vulnerabilities, and exploits
- Key security requirements for automotive:
  - Limit developer/debugging access (no open debugging ports in production)
  - Protect cryptographic keys — keys must not provide access to multiple vehicles
  - Restrict diagnostic features to specific operating modes (e.g., speed limits)
  - Use encryption for firmware; implement code signing
  - Maintain immutable logs for forensic analysis

### 6.6 eCommerce / Payment Card Industry (PCI)

> PCI DSS (Payment Card Industry Data Security Standard) — 12 requirements for protecting credit card data:

| # | Requirement |
|---|-------------|
| 1 | Install and maintain a firewall to protect cardholder data |
| 2 | Do not use vendor-supplied defaults for system passwords |
| 3 | Protect stored cardholder data |
| 4 | Encrypt transmission of cardholder data across open, public networks |
| 5 | Use and regularly update antivirus software |
| 6 | Develop and maintain secure systems and applications |
| 7 | Restrict access to cardholder data by business need-to-know |
| 8 | Assign a unique ID to each person with computer access |
| 9 | Restrict physical access to cardholder data |
| 10 | Track and monitor all access to network resources and cardholder data |
| 11 | Regularly test security systems and processes |
| 12 | Maintain a policy that addresses information security |

---

## 7. Assessing the Secure Software Lifecycle

### 7.1 SAMM (Software Assurance Maturity Model)

> **Definition**: SAMM is an **open framework** to help organizations formulate and implement a strategy for software security tailored to their specific risks.

**SAMM enables an organization to**:
1. Define and measure security-related activities
2. Evaluate existing software security practices
3. Build a balanced software security program in well-defined iterations
4. Demonstrate improvements in a security assurance program

**Business Functions and Security Practices**:

| Business Function | Security Practices |
|-------------------|--------------------|
| **Governance** | (a) Strategy & Metrics, (b) Policy & Compliance, (c) Education & Guidance |
| **Construction** | (a) Threat Assessment, (b) Security Requirements, (c) Secure Architecture |
| **Verification** | (a) Design Review, (b) Code Review, (c) Security Testing |
| **Deployment** | (a) Vulnerability Management, (b) Environment Hardening, (c) Operational Enablement |

**SAMM Maturity Levels**:

| Level | Description |
|-------|-------------|
| **0** | Implicit starting point — activities in the Practice unfulfilled |
| **1** | Initial understanding and ad hoc provision of the Security Practice |
| **2** | Increased efficiency and/or effectiveness of the Security Practice |
| **3** | Comprehensive mastery of the Security Practice at scale |

### 7.2 BSIMM (Building Security In Maturity Model)

> **Definition**: BSIMM is a **data-driven model** based on observations of real software security initiatives. Unlike SAMM, BSIMM describes what organizations are **actually doing** (not prescribing).

**Domains and Practices**:

| Domain | Practices |
|--------|-----------|
| **Governance** | (a) Strategy & Metrics, (b) Compliance & Policy, (c) Training |
| **Intelligence** | (a) Attack Models, (b) Security Features & Design, (c) Standards & Requirements |
| **SSDL Touchpoints** | (a) Architecture Analysis, (b) Code Review, (c) Security Testing |
| **Deployment** | (a) Penetration Testing, (b) Software Environment, (c) Configuration & Vulnerability Management |

| | SAMM | BSIMM |
|-|------|-------|
| **Type** | Prescriptive framework | Descriptive/observational model |
| **Focus** | What you *should* do | What organizations *actually* do |
| **Basis** | Open framework | Empirical data from real companies |

### 7.3 Common Criteria

> A framework for specifying and evaluating security properties of IT products, enabling comparison across independent evaluations.

**Objectives**:
- Permits **comparability** between results of independent security evaluations using a common set of requirements
- Establishes **level of confidence** in the security functionality of IT products
- Helps consumers determine whether an IT product **fulfils their security needs**
