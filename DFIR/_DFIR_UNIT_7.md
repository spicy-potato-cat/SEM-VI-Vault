# Unit 7: Incident Response and Digital Forensics Integration

> **Course**: Digital Forensics and Incident Response (DFIR)
> **Unit**: 7 - Incident Response and Digital Forensics Integration
> **Book Reference**: *Guide to Computer Forensics and Investigations*, 5th Edition — Ch. 1, Ch. 4

---

## Table of Contents

[[#1. Stages in Incident Response]]
[[#2. IR Charter and CSIRT]]
[[#3. IR Plan and Playbook]]
[[#4. Indicators of Compromise (IoC)]]
[[#5. Integrating Digital Forensics and Incident Response]]

---

## 1. Stages in Incident Response

### 1.1 What is Incident Response?

> **Definition**: **Incident Response (IR)** is an organized approach to addressing and managing the aftermath of a security breach or cyberattack. The goal is to handle the situation in a way that limits damage, reduces recovery time and costs, and ensures the collection of evidence for legal or remediation purposes.

The NIST Special Publication 800-61 (Computer Security Incident Handling Guide) defines a **security incident** as "a violation or imminent threat of violation of computer security policies, acceptable use policies, or standard security practices."

**Why Incident Response Matters**:
- Minimizes business disruption and financial impact
- Ensures evidence integrity for possible legal action
- Helps organizations learn from incidents to prevent recurrence
- Meets regulatory and compliance requirements
- Preserves reputation and customer trust

---

### 1.2 The NIST Incident Response Lifecycle

The NIST model defines **four phases** of incident response:

```
┌─────────────────────────────────────────────────────────────────┐
│              NIST INCIDENT RESPONSE LIFECYCLE                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│   │    Phase 1   │───▶│    Phase 2   │───▶│    Phase 3   │      │
│   │ PREPARATION  │    │  DETECTION & │    │ CONTAINMENT, │      │
│   │              │    │  ANALYSIS    │    │ ERADICATION  │      │
│   │              │    │              │    │  & RECOVERY  │      │
│   └──────────────┘    └──────────────┘    └──────┬───────┘      │
│                                                   │              │
│                       ┌──────────────┐            │              │
│                       │    Phase 4   │◀───────────┘              │
│                       │  POST-INCIDENT│                          │
│                       │   ACTIVITY   │                           │
│                       └──────────────┘                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 1.3 Detailed Stages of Incident Response

A more granular view uses the **six-stage SANS/PICERL model**:

```
┌────────────────────────────────────────────────────────────────┐
│                 SIX STAGES OF INCIDENT RESPONSE                 │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Stage 1: PREPARATION                                           │
│     └── Develop IR policies, procedures, and playbooks         │
│     └── Build and train the CSIRT                               │
│     └── Acquire and configure IR tools and hardware            │
│     └── Conduct security awareness training                    │
│                                                                 │
│  Stage 2: IDENTIFICATION                                        │
│     └── Detect anomalies through logs, alerts, user reports    │
│     └── Determine if an event is a true incident               │
│     └── Assign severity levels (P1/P2/P3 etc.)                 │
│     └── Begin documentation immediately                        │
│                                                                 │
│  Stage 3: CONTAINMENT                                           │
│     └── Short-term: Isolate affected systems immediately       │
│     └── Long-term: Apply temporary fixes while preserving      │
│         evidence                                                │
│     └── Avoid destroying forensic artifacts                    │
│                                                                 │
│  Stage 4: ERADICATION                                           │
│     └── Identify root cause of the incident                    │
│     └── Remove malware, unauthorized accounts, backdoors       │
│     └── Apply patches and harden configurations                │
│                                                                 │
│  Stage 5: RECOVERY                                              │
│     └── Restore systems from clean backups                     │
│     └── Validate that systems are fully functional             │
│     └── Monitor restored systems for re-infection              │
│                                                                 │
│  Stage 6: LESSONS LEARNED                                       │
│     └── Conduct post-incident review meeting                   │
│     └── Document what happened, how it was handled             │
│     └── Update IR plan and playbooks accordingly               │
│     └── Share threat intelligence with relevant parties        │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

---

### 1.4 Stage 1: Preparation

> **Definition**: The **Preparation** phase involves establishing the policies, tools, and trained personnel needed to handle incidents before they occur.

**Key Preparation Activities**:

| Activity | Description |
|---|---|
| **Policy Development** | Define what constitutes an incident, response procedures, escalation paths |
| **Team Formation** | Establish a CSIRT with clearly defined roles |
| **Tool Acquisition** | Forensic workstations, disk imagers, network analyzers, SIEM |
| **Communication Plans** | Define internal/external communication during an incident |
| **Training & Drills** | Tabletop exercises and simulated incident drills |
| **Legal Considerations** | Work with legal counsel on evidence handling and reporting obligations |

From the book (Ch. 1, p. 22):
> *"Taking a Systematic Approach — By approaching each case methodically, you can evaluate the evidence thoroughly and document the chain of evidence, or chain of custody."*

---

### 1.5 Stage 2: Identification (Detection & Analysis)

> **Definition**: **Identification** is the process of detecting events that may represent security incidents and determining which require a response.

**Detection Sources**:
```
┌──────────────────────────────────────────────────────────┐
│              INCIDENT DETECTION SOURCES                   │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  AUTOMATED SOURCES          HUMAN SOURCES                │
│  ┌───────────────────┐     ┌───────────────────────┐    │
│  │ SIEM Alerts       │     │ Employee Reports       │    │
│  │ IDS/IPS Alerts    │     │ Help Desk Tickets      │    │
│  │ AV/EDR Detections │     │ External Reports       │    │
│  │ Log Anomalies     │     │ Law Enforcement Notif. │    │
│  │ Firewall Alerts   │     │ Security Researchers   │    │
│  └───────────────────┘     └───────────────────────┘    │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

**Incident Classification and Prioritization**:

| Severity | Description | Example |
|---|---|---|
| **Critical (P1)** | Immediate threat to operations | Ransomware actively encrypting |
| **High (P2)** | Significant potential impact | Confirmed data exfiltration |
| **Medium (P3)** | Limited impact, needs attention | Policy violation, phishing attempt |
| **Low (P4)** | Minimal impact | Single user account lockout |

**Key Documentation at Identification Stage**:
- Date/time of detection
- Who detected it and how
- Systems and data potentially affected
- Initial assessment of scope

---

### 1.6 Stage 3: Containment

> **Definition**: **Containment** involves stopping the incident from spreading to other systems while preserving evidence integrity.

**Two Types of Containment**:

```
┌────────────────────────────────────────────────────────┐
│               TYPES OF CONTAINMENT                      │
├────────────────────────────────────────────────────────┤
│                                                        │
│  SHORT-TERM CONTAINMENT                                │
│  Goal: Stop immediate damage                           │
│  Actions:                                              │
│    ├── Network isolation (VLAN segmentation)           │
│    ├── Disabling compromised user accounts             │
│    ├── Blocking malicious IP addresses at firewall     │
│    └── Taking affected systems offline                 │
│                                                        │
│  LONG-TERM CONTAINMENT                                 │
│  Goal: Maintain operations while eradicating threat    │
│  Actions:                                              │
│    ├── Apply temporary patches                         │
│    ├── Rebuild compromised systems from clean images   │
│    ├── Increase monitoring on adjacent systems         │
│    └── Preserve forensic copies of affected systems   │
│                                                        │
└────────────────────────────────────────────────────────┘
```

**Critical Forensics Consideration**: Before taking any containment action, **capture volatile evidence** (RAM, running processes, network connections). As the book states (Ch. 4, p. 135): *"You must handle digital evidence systematically so that you don't inadvertently alter or lose data."*

---

### 1.7 Stage 4: Eradication

> **Definition**: **Eradication** is the process of removing all traces of the incident from the environment, including malware, unauthorized accounts, and vulnerabilities exploited.

**Eradication Activities**:
- Remove malware and all persistence mechanisms (registry keys, scheduled tasks, startup entries)
- Disable/delete unauthorized user accounts
- Identify and patch exploited vulnerabilities
- Review and remove backdoors, web shells, rogue tools
- Apply updated AV signatures and security configurations
- Rebuild compromised systems if necessary

**Root Cause Analysis** must be completed before eradication to ensure all attack vectors are addressed.

---

### 1.8 Stage 5: Recovery

> **Definition**: **Recovery** is the phase of restoring affected systems to normal operations and verifying they are clean.

**Recovery Steps**:
1. Restore from known-good backups or rebuild systems
2. Implement additional monitoring on restored systems
3. Validate system integrity (hash comparison, file system checks)
4. Gradually return systems to production with increased logging
5. Confirm no residual threat remains

**Recovery Criteria**:

| Criteria | Verification Method |
|---|---|
| Malware removed | AV scan, EDR clean report |
| Vulnerabilities patched | Vulnerability scan |
| Normal operations restored | System/application testing |
| No signs of re-infection | 24–72 hours of enhanced monitoring |

---

### 1.9 Stage 6: Post-Incident Activity (Lessons Learned)

> **Definition**: The **Post-Incident** phase involves reviewing the incident response, documenting findings, and updating procedures to improve future responses.

**Lessons Learned Meeting** should include:
- Timeline reconstruction of the incident
- Assessment of what worked and what did not
- Identification of gaps in detection or response capabilities
- Recommended changes to IR plans, playbooks, or security controls
- Training needs identified

From the book (Ch. 1, p. 29):
> *"Critique the Case — Self-evaluation and peer review are essential parts of professional growth. After you complete a case, review it to identify successful decisions and actions and determine how you could have improved your performance."*

---

## 2. IR Charter and CSIRT

### 2.1 What is a CSIRT?

> **Definition**: A **Computer Security Incident Response Team (CSIRT)** is a group of people responsible for coordinating and supporting the response to a computer security incident. It may also be referred to as a CERT (Computer Emergency Response Team) or CIRT (Computer Incident Response Team).

**Historical Context**: The first CERT was established at Carnegie Mellon University in 1988 after the Morris Worm incident. CERT/CC (CERT Coordination Center) was created to coordinate response to internet security incidents.

**Types of CSIRTs**:

```
┌─────────────────────────────────────────────────────────────┐
│                     TYPES OF CSIRTs                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  INTERNAL CSIRT                                             │
│    └── Serves a single organization                         │
│    └── Full-time or part-time staff                         │
│    └── Example: Enterprise security teams                   │
│                                                             │
│  NATIONAL CSIRT                                             │
│    └── Serves an entire country                             │
│    └── Coordinates with government and critical sectors     │
│    └── Example: CERT-In (India), US-CERT (USA)              │
│                                                             │
│  SECTOR-BASED CSIRT                                         │
│    └── Serves a specific industry sector                    │
│    └── Example: Financial sector CSIRT, Healthcare ISAC     │
│                                                             │
│  VENDOR CSIRT                                               │
│    └── Responds to vulnerabilities in own products         │
│    └── Example: Microsoft MSRC, Cisco PSIRT                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

### 2.2 CSIRT Core Functions

| Function | Description |
|---|---|
| **Detection & Analysis** | Monitor for incidents; analyze threats and indicators |
| **Coordination** | Coordinate response across teams, departments, and external parties |
| **Technical Response** | Contain, eradicate, and recover from incidents |
| **Communication** | Notify stakeholders, law enforcement, regulators as required |
| **Forensics** | Conduct or coordinate digital forensic investigations |
| **Post-Incident Review** | Lead lessons-learned processes and update procedures |
| **Threat Intelligence** | Share and consume threat intelligence with external parties |

---

### 2.3 CSIRT Organizational Structure

**Key Roles within a CSIRT**:

```
┌──────────────────────────────────────────────────────────┐
│                  CSIRT ORGANIZATIONAL ROLES               │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  CSIRT Manager / IR Manager                              │
│    └── Overall responsibility for IR capability         │
│    └── Coordinates with senior management               │
│                                                          │
│  Incident Handler / Analyst                              │
│    └── Leads individual incident investigations         │
│    └── Performs containment, eradication, recovery      │
│                                                          │
│  Digital Forensics Investigator                          │
│    └── Collects and analyzes digital evidence           │
│    └── Maintains chain of custody                       │
│                                                          │
│  Threat Intelligence Analyst                             │
│    └── Tracks threat actors, TTPs, IoCs                 │
│    └── Provides context to ongoing incidents            │
│                                                          │
│  Legal / Compliance Representative                       │
│    └── Advises on legal obligations                     │
│    └── Manages law enforcement interaction              │
│                                                          │
│  Communications Officer                                  │
│    └── Handles internal and external communications     │
│    └── Manages public relations during major incidents  │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

### 2.4 The IR Charter

> **Definition**: An **IR Charter** (also called Incident Response Charter) is a formal document that establishes the CSIRT's authority, purpose, scope, and operating guidelines. It provides the legal and organizational mandate for the team to operate.

**Components of an IR Charter**:

| Component | Description |
|---|---|
| **Mission Statement** | Defines the purpose and goals of the CSIRT |
| **Scope of Authority** | What systems, incidents, and actions the CSIRT is authorized to handle |
| **Constituency** | Defines who the CSIRT serves (employees, systems, business units) |
| **Services Provided** | Reactive (incident handling) and proactive (threat intelligence, training) services |
| **Organizational Placement** | Where the CSIRT sits in the organization hierarchy |
| **Funding and Resources** | Budget allocation and resource commitments |
| **Communication and Escalation** | Procedures for reporting to management, legal, law enforcement |
| **Metrics and Reporting** | How the CSIRT's performance is measured and reported |

**Why a Charter Matters**:
- Provides legal authority to access systems and data during investigations
- Defines accountability and oversight mechanisms
- Ensures consistent response across the organization
- Enables coordination with law enforcement and external parties

---

### 2.5 CERT-In: India's National CSIRT

> **Definition**: **CERT-In (Indian Computer Emergency Response Team)** is the national nodal agency for responding to cybersecurity incidents in India. It operates under the Ministry of Electronics and Information Technology (MeitY).

**Key CERT-In Functions**:
- Collection, analysis, and dissemination of information on cyber incidents
- Forecast and alerts on cybersecurity incidents
- Emergency measures for handling cybersecurity incidents
- Coordination of cyber incident response activities
- Issuing guidelines and vulnerability notes
- Training and capacity building

**Mandate Under IT Act 2000 (Section 70B)**:
CERT-In was established under Section 70B of the Information Technology Act, 2000, which was added through the IT (Amendment) Act, 2008.

---

## 3. IR Plan and Playbook

### 3.1 What is an Incident Response Plan?

> **Definition**: An **Incident Response Plan (IRP)** is a documented, structured approach to preparing for, detecting, containing, eradicating, and recovering from security incidents. It provides the organizational framework and operational guidance for the CSIRT.

**Difference Between IR Plan and Playbook**:

```
┌─────────────────────────────────────────────────────────────┐
│           IR PLAN vs. PLAYBOOK COMPARISON                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  IR PLAN                        IR PLAYBOOK                 │
│  ─────────────────────          ─────────────────────────   │
│  High-level strategic           Tactical, step-by-step      │
│  document                       operational guide           │
│                                                             │
│  Covers all incident            Specific to one incident    │
│  types generically              type (e.g., ransomware)     │
│                                                             │
│  Defines roles, authority,      Defines exact commands,     │
│  and communication paths        tools, and actions          │
│                                                             │
│  Updated annually               Updated per threat landscape │
│                                                             │
│  Audience: Management,          Audience: Technical IR team │
│  legal, HR                                                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

### 3.2 Components of an IR Plan

An effective Incident Response Plan includes the following sections:

| Section | Content |
|---|---|
| **Executive Summary** | Purpose, scope, and objectives of the IR plan |
| **Roles and Responsibilities** | CSIRT structure, individual roles, escalation paths |
| **Incident Definition** | What constitutes an incident; categories and severity levels |
| **Detection and Reporting** | How incidents are detected and reported internally |
| **Response Procedures** | Step-by-step actions for each incident phase |
| **Communication Plan** | Internal escalation, external notification (regulators, customers, law enforcement) |
| **Evidence Handling** | Chain of custody procedures, forensic documentation standards |
| **Recovery Procedures** | System restoration and validation steps |
| **Post-Incident Activities** | Lessons learned, documentation, report creation |
| **Plan Maintenance** | Review cycle, testing procedures (tabletop exercises, simulations) |

---

### 3.3 Incident Response Playbooks

> **Definition**: An **IR Playbook** is a pre-defined, tactical checklist of actions to take in response to a specific type of incident. It operationalizes the IR plan for specific threat scenarios.

**Common Playbook Types**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    COMMON IR PLAYBOOKS                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  RANSOMWARE PLAYBOOK                                            │
│    ├── Detect: Honeypot triggered, AV alert, user complaint    │
│    ├── Contain: Isolate affected system from network           │
│    ├── Identify: Determine ransomware family, spread scope     │
│    ├── Eradicate: Remove malware, recover decryption key       │
│    └── Recover: Restore from backup, monitor for recurrence   │
│                                                                 │
│  PHISHING PLAYBOOK                                              │
│    ├── Detect: Email gateway alert, user report                │
│    ├── Contain: Block sender, remove emails from all mailboxes │
│    ├── Analyze: Examine email headers, links, attachments      │
│    ├── Assess: Determine if users clicked links/entered creds  │
│    └── Remediate: Reset credentials, scan systems              │
│                                                                 │
│  DATA BREACH PLAYBOOK                                           │
│    ├── Detect: DLP alert, anomalous outbound traffic           │
│    ├── Contain: Block exfiltration path                        │
│    ├── Identify: Determine data scope and sensitivity          │
│    ├── Legal: Notify legal team, assess notification           │
│    │         requirements (GDPR, IT Act, etc.)                 │
│    └── Notify: Report to regulators, affected individuals      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

### 3.4 Systematic Approach to Investigation

From the book (Ch. 1, p. 22–23), a systematic approach to digital investigation includes:

1. **Assess the case** — Identify the nature and scope of the investigation
2. **Determine required resources** — List tools, expertise, and hardware needed
3. **Obtain and copy evidence** — Create forensic copies before analysis
4. **Identify risks** — Perform a standard risk assessment
5. **Mitigate risks** — Minimize potential for evidence loss or destruction
6. **Test the design** — Verify copies using hash validation
7. **Analyze and recover evidence** — Apply tools systematically
8. **Investigate recovered data** — Review existing files, deleted files, emails, web history
9. **Complete the case report** — Document all findings thoroughly
10. **Critique the case** — Self-evaluate and conduct peer review

---

### 3.5 Private-Sector Investigation Procedures

From the book (Ch. 1, p. 29), procedures for private-sector investigations include:

```assembly
; Investigation Workflow (Private Sector)
Step 1:  Acquire evidence from IT/HR/Legal
Step 2:  Complete evidence custody form (chain of custody)
Step 3:  Transport evidence to digital forensics lab
Step 4:  Place evidence in approved secure container
Step 5:  Prepare forensic workstation
Step 6:  Retrieve evidence from secure container
Step 7:  Create forensic copy of evidence drive (bit-for-bit image)
Step 8:  Return original evidence to secure container
Step 9:  Process copied evidence with forensic tools
Step 10: Document all findings in case report
```

---

## 4. Indicators of Compromise (IoC)

### 4.1 What are Indicators of Compromise?

> **Definition**: **Indicators of Compromise (IoCs)** are pieces of digital forensic evidence that suggest a computer network or system has been breached. IoCs serve as forensic evidence of potential intrusion, malware infection, or other malicious activity.

IoCs help analysts identify **what happened**, **when it happened**, **which systems were affected**, and **what threat actor may be responsible**.

---

### 4.2 Types of Indicators of Compromise

IoCs can be classified into several categories:

```
┌──────────────────────────────────────────────────────────────┐
│                  CATEGORIES OF IoCs                           │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  NETWORK IoCs                  HOST-BASED IoCs               │
│  ─────────────────             ──────────────────────        │
│  Malicious IP addresses        Malicious file hashes (MD5,   │
│  Malicious domains/URLs        SHA-1, SHA-256)               │
│  Suspicious DNS queries        Registry key modifications    │
│  Unusual port usage            Unexpected processes running  │
│  C2 communication patterns     New/unknown user accounts     │
│  Data exfiltration traffic     Suspicious scheduled tasks    │
│  Lateral movement traffic      Unauthorized file changes     │
│                                                              │
│  EMAIL IoCs                    BEHAVIORAL IoCs               │
│  ─────────────────             ──────────────────────        │
│  Phishing sender domains       Anomalous login times         │
│  Malicious attachment hashes   Unusual data access patterns  │
│  Malicious embedded URLs       Privilege escalation attempts  │
│  Spoofed sender headers        Abnormal system calls         │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

### 4.3 The Pyramid of Pain

The **Pyramid of Pain** (David Bianco, 2013) classifies IoCs by how difficult they are for an attacker to change and therefore how much "pain" detecting and blocking them causes the attacker:

```
┌─────────────────────────────────────────────────────┐
│               PYRAMID OF PAIN                        │
├─────────────────────────────────────────────────────┤
│                                                     │
│            ▲  TTPs (Tactics, Techniques,            │
│           ▲▲  Procedures)          ← Tough          │
│          ▲▲▲  Tools (Attack Tooling)                │
│         ▲▲▲▲  Network/Host Artifacts                │
│        ▲▲▲▲▲  Domain Names                         │
│       ▲▲▲▲▲▲  IP Addresses                         │
│      ▲▲▲▲▲▲▲  Hash Values             ← Trivial    │
│                                                     │
│  Bottom (Trivial) = Easy for attacker to change     │
│  Top (Tough) = Hard for attacker to change          │
│                                                     │
└─────────────────────────────────────────────────────┘
```

**Implication**: Defenders should prioritize detecting and responding to **higher-level IoCs** (TTPs and tools) because these are harder for attackers to change.

---

### 4.4 IoC Lifecycle: Collection to Action

```
┌──────────────────────────────────────────────────────────────┐
│                    IoC LIFECYCLE                              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. COLLECTION                                               │
│     └── SIEM logs, EDR telemetry, threat intelligence feeds  │
│     └── Manual analysis during incident investigation        │
│                                                              │
│  2. ANALYSIS                                                 │
│     └── Correlate IoCs with known threat actor profiles      │
│     └── Assess false positive risk                           │
│                                                              │
│  3. ENRICHMENT                                               │
│     └── Enrich with VirusTotal, MISP, ThreatConnect          │
│     └── Map to MITRE ATT&CK framework                        │
│                                                              │
│  4. DISTRIBUTION                                             │
│     └── Share via STIX/TAXII formats with trusted partners   │
│     └── Push to SIEM, firewalls, EDR for blocking            │
│                                                              │
│  5. DETECTION & BLOCKING                                     │
│     └── Block IPs/domains at perimeter                       │
│     └── Alert on file hash detections                        │
│                                                              │
│  6. REVIEW & EXPIRY                                          │
│     └── IoCs have a shelf-life; review and expire old ones   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

### 4.5 Common IoC Sharing Standards

| Standard | Description |
|---|---|
| **STIX** (Structured Threat Information Expression) | XML/JSON format for describing cyber threat intelligence |
| **TAXII** (Trusted Automated eXchange of Indicator Information) | Protocol for sharing STIX data between organizations |
| **MISP** (Malware Information Sharing Platform) | Open-source threat intelligence sharing platform |
| **OpenIOC** | XML-based standard by Mandiant for IoC definition and sharing |

---

### 4.6 MITRE ATT&CK Framework and IoCs

> **Definition**: The **MITRE ATT&CK Framework** is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations.

**Key Tactic Categories** (mapped to IR stages):

| ATT&CK Tactic | Description | IoC Type |
|---|---|---|
| Initial Access | How attacker gets in | Phishing email headers, exploit traffic |
| Execution | Running malicious code | Process hashes, script behavior |
| Persistence | Maintaining foothold | Registry keys, scheduled tasks |
| Lateral Movement | Moving through network | Unusual SMB traffic, pass-the-hash artifacts |
| Collection | Gathering target data | Unusual file access patterns |
| Exfiltration | Removing data | Anomalous outbound traffic, DNS tunneling |
| Command & Control | Communication with C2 | Unusual DNS queries, beaconing traffic |

---

## 5. Integrating Digital Forensics and Incident Response

### 5.1 The Relationship Between DF and IR

Digital Forensics (DF) and Incident Response (IR) are complementary disciplines that overlap significantly. The integration of both creates what is known as **DFIR** (Digital Forensics and Incident Response).

```
┌────────────────────────────────────────────────────────────────┐
│           DIGITAL FORENSICS vs. INCIDENT RESPONSE              │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  DIGITAL FORENSICS                INCIDENT RESPONSE            │
│  ─────────────────                ──────────────────────       │
│  Focused on evidence              Focused on containment       │
│  collection and analysis          and recovery                  │
│                                                                │
│  Legally admissible               Operationally driven         │
│  evidence standards               (speed is critical)          │
│                                                                │
│  May not need speed               Requires rapid action        │
│                                                                │
│  Retrospective analysis           Real-time response           │
│                                                                │
│  Strict chain of custody          Evidence preservation        │
│  requirements                     where feasible               │
│                                                                │
│                 DFIR = BOTH DISCIPLINES COMBINED               │
│                 Evidence quality + Speed of response           │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

### 5.2 Digital Forensics Supporting IR

From the book (Ch. 1, p. 30):
> *"The field of digital forensics can also encompass items such as research and incident response. With incident response, most organizations are concerned with protecting their assets and containing the situation, not necessarily prosecuting or finding the person responsible."*

**How DF Supports Each IR Phase**:

| IR Phase | Digital Forensics Contribution |
|---|---|
| **Preparation** | Develop forensic procedures, pre-position imaging tools, train analysts |
| **Identification** | Log analysis, artifact collection, initial triage of affected systems |
| **Containment** | Forensic imaging before systems are isolated or wiped |
| **Eradication** | Malware analysis, root cause determination, persistence mechanism discovery |
| **Recovery** | Integrity verification of restored systems via hash comparison |
| **Lessons Learned** | Timeline reconstruction, detailed incident report with forensic findings |

---

### 5.3 Evidence Handling in an IR Context

From the book (Ch. 4, p. 136):
> *"Digital evidence can be any information stored or transmitted in digital form... U.S. courts accept digital evidence as physical evidence, which means digital data is treated as a tangible object related to a criminal or civil incident."*

**Evidence Handling Principles During IR**:

```
┌──────────────────────────────────────────────────────────────┐
│             EVIDENCE HANDLING DURING IR                       │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  RULE 1: PRESERVE BEFORE ANALYZING                           │
│    └── Create forensic image before investigation           │
│    └── Never analyze original media directly                 │
│                                                              │
│  RULE 2: VOLATILE DATA FIRST                                 │
│    └── Capture RAM, running processes, network connections  │
│    └── Volatile data is lost when system is powered off      │
│                                                              │
│  RULE 3: DOCUMENT EVERYTHING                                 │
│    └── Use chain of custody forms for all evidence          │
│    └── Log all actions taken on evidence                    │
│                                                              │
│  RULE 4: MAINTAIN CHAIN OF CUSTODY                           │
│    └── Track evidence from collection to court or disposal  │
│    └── Any break in chain can render evidence inadmissible  │
│                                                              │
│  RULE 5: VALIDATE WITH HASH VALUES                           │
│    └── Use MD5/SHA-256 to verify evidence integrity          │
│    └── Hashes confirm that evidence has not been altered    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

### 5.4 The Order of Volatility

When collecting evidence during IR, follow the **Order of Volatility** (most volatile first):

| Order | Data Type | Why Volatile? |
|---|---|---|
| 1 (Most) | CPU registers, cache | Lost immediately |
| 2 | RAM (Random Access Memory) | Lost when powered off |
| 3 | Network state (connections, ARP cache) | Lost when connections close |
| 4 | Running processes and services | Lost when system reboots |
| 5 | Temporary file systems, swap/pagefile | Lost on restart |
| 6 | Disk (hard drive, SSD) | Persists but can be overwritten |
| 7 | Remote logging and monitoring data | Persists on remote server |
| 8 (Least) | Archival/backup media | Most persistent |

---

### 5.5 Digital Investigation Triad

From the book (Ch. 1, p. 33):
> *"Forensics investigators often work as part of a team to secure an organization's computers and networks. The digital investigation function can be viewed as part of a triad that makes up computing security."*

```
┌─────────────────────────────────────────────────────────┐
│              DIGITAL INVESTIGATION TRIAD                 │
├─────────────────────────────────────────────────────────┤
│                                                         │
│                    ┌─────────┐                          │
│                    │         │                          │
│                    │Vulnerability│                      │
│                    │ /Threat │                          │
│                   /│Assessment│\                        │
│                  / └─────────┘ \                        │
│                 /               \                       │
│        ┌──────────┐         ┌──────────┐               │
│        │          │         │          │               │
│        │ Network  │─────────│ Digital  │               │
│        │Intrusion │         │Investiga-│               │
│        │Detection/│         │  tions   │               │
│        │    IR    │         │          │               │
│        └──────────┘         └──────────┘               │
│                                                         │
│  Each function depends on and complements the others    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

### 5.6 NIST Guide: Integrating Forensic Techniques into Incident Response

NIST SP 800-86 (*Guide to Integrating Forensic Techniques into Incident Response*) defines digital forensics as:

> *"The application of science to the identification, collection, examination, and analysis of data while preserving the integrity of the information and maintaining a strict chain of custody for the data."*

**Four-Phase Forensic Process (NIST)**:

```
┌────────────────────────────────────────────────────────────────┐
│          NIST FOUR-PHASE FORENSIC PROCESS                       │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Phase 1: COLLECTION                                           │
│    └── Identify, label, record, and acquire data from         │
│        all possible sources of relevant data                  │
│                                                                │
│  Phase 2: EXAMINATION                                          │
│    └── Forensically process collected data using automated   │
│        and manual methods to assess and extract data          │
│        of particular interest                                  │
│                                                                │
│  Phase 3: ANALYSIS                                             │
│    └── Analyze results of examination using legally           │
│        justifiable methods and techniques to derive           │
│        useful information that addresses the questions        │
│        posed by the investigation                             │
│                                                                │
│  Phase 4: REPORTING                                            │
│    └── Report the results of the analysis, including          │
│        describing the actions used, explaining how tools      │
│        and procedures were selected, determining what         │
│        other actions need to be performed, and providing      │
│        recommendations for improvement                        │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

### 5.7 Handling Live vs. Dead Forensics in IR

| Aspect | Live Forensics | Dead/Post-Mortem Forensics |
|---|---|---|
| **System State** | System running | System powered off |
| **Data Available** | RAM, processes, network state + disk | Disk only |
| **Volatility** | High — data changes rapidly | Low — data is static |
| **When Used** | During active incident | After containment |
| **Tools** | Volatility, WinPMEM, FTK Imager (live) | Autopsy, EnCase, FTK |
| **Risk** | Data may be altered by collection itself | No risk to volatile data (already lost) |

**Key Principle**: During an active incident, always perform **live acquisition first** before shutting down a system, as volatile data (RAM contents, running processes) provides critical forensic evidence about the attack.

From the book (Ch. 1, p. 49):
> *"Before shutting down the computer, a live acquisition should be done to capture RAM too."*

---

*End of Unit 7 Notes*

> **Sources**: 
> - Nelson, B., Phillips, A., & Steuart, C. (2016). *Guide to Computer Forensics and Investigations*, 5th Ed. — Chapters 1, 4
> - NIST SP 800-61 Rev. 2 — Computer Security Incident Handling Guide
> - NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response
> - MITRE ATT&CK Framework
