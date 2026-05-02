# Unit 3: Software Security

> **Course**: Application Security Testing (AST)
> **Unit**: 3 — Software Security
> **Syllabus Duration**: 5 Hours
> **PPT Reference**: *AST_2_Software Security*
> **Reference**: CyBOK, Chapter 14 — *Software Security*

---

## Table of Contents

[[#1. What is Software Security?]]
[[#2. Categories of Software Vulnerabilities]]
[[#3. Prevention of Vulnerabilities]]
[[#4. Detection of Vulnerabilities]]
[[#5. Mitigation of Exploitation]]
[[#6. Testing Frameworks]]
[[#7. CVSS — Common Vulnerability Scoring System]]
[[#8. OWASP Top 10 Web Vulnerabilities]]

---

## 1. What is Software Security?

> **Definition**: A software system is **secure** if it satisfies a specified or implied **security objective**. This security objective specifies confidentiality, integrity, and availability (CIA) requirements for the system's data and functionality.

> **Security Failure**: A scenario where the software system does **not achieve** its security objective.

> **Vulnerability**: The **underlying cause** of a security failure.

> **CWE (Common Weakness Enumeration)**: A community-developed list of vulnerability categories, used as a baseline for vulnerability identification, mitigation, and prevention.

**Example** — Social Networking Service Security Objectives:
- Pictures posted by a user can only be seen by that user's friends (confidentiality)
- A user can like any given post at most once (integrity)
- The service is operational more than 99.9% of the time on average (availability)

---

## 2. Categories of Software Vulnerabilities

```
┌──────────────────────────────────────────────────────────────────┐
│               5 CATEGORIES OF SOFTWARE VULNERABILITIES           │
├──────────────────────────────────────────────────────────────────┤
│  1. Memory Management Vulnerabilities                            │
│  2. Structured Output Generation Vulnerabilities (Injection)     │
│  3. Race Condition Vulnerabilities                               │
│  4. API Vulnerabilities                                          │
│  5. Side-Channel Vulnerabilities                                 │
└──────────────────────────────────────────────────────────────────┘
```

### 2.1 Memory Management Vulnerabilities

> **Definition**: A memory management vulnerability occurs when a program performs an **invalid memory access** — violating the memory management contract — potentially corrupting program code, control flow, or data.

C-like languages offer mutable state allocated, deallocated, and accessed through pointers and array indexing. When memory operations are used incorrectly, the program's behavior becomes **undefined**.

**Two types of memory bugs**:

| Type | Description | Example |
|------|-------------|---------|
| **Spatial Vulnerability** | Indexing into a valid contiguous memory range with an **out-of-bounds index** | Buffer overflow — array accessed beyond its declared size |
| **Temporal Vulnerability** | Accessing memory that was **once allocated but has since been deallocated** | Dereferencing a dangling pointer (use-after-free) |

**Attacker Model**:
- Attacker provides crafted input to **trigger the vulnerability**
- Attacker knows the code and system software stack
- Attacker can send arbitrary input and inspect resulting output

**Classes of memory attacks**:

| Attack Class | Description |
|-------------|-------------|
| **Code Corruption** | Invalid access modifies compiled program code to attacker-specified code |
| **Control-Flow Hijack** | Modifies a code pointer (return address, function pointer) to execute attacker's code or reuse existing code (ROP — Return-Oriented Programming) |
| **Data-Only Attack** | Modifies data variables to grant increased privileges to attacker |
| **Information Leak** | Reads memory to exfiltrate secrets (cryptographic keys, runtime addresses) |

### 2.2 Structured Output Generation Vulnerabilities (Injection)

> **Definition**: Programs dynamically construct structured output (SQL, HTML, shell commands) using string concatenation. When attacker-controlled strings can change the **intended structure** of the output, this is an injection vulnerability.

**Attacker model**: Attacker knows the code and can provide user input and read output.

**Types of Injection Vulnerabilities**:

| Vulnerability | Structured Output | Target |
|--------------|-------------------|--------|
| **SQL Injection** | SQL query | Backend database |
| **Command Injection** | Shell command | Operating system shell |
| **XSS (Script Injection)** | JavaScript | Web browser client-side execution |
| **LDAP Injection** | LDAP query | Directory services |
| **ORM Injection** | ORM query | Object-Relational Mapping layer |

**Complicating Factors**:
- Structured output in languages with sublanguages (HTML with JavaScript, CSS, SVG)
- **Stored injection vulnerabilities** — stored XSS attacks
- **Higher-order injection** — e.g., registering a username `user'--` and authenticating later

### 2.3 Race Condition Vulnerabilities

> **Definition**: Race conditions (concurrency bugs) occur when a program accesses shared resources (memory, files, databases) concurrently, and the behavior depends on which actor accesses the resource first.

**TOCTOU (Time Of Check Time Of Use)**:
- Program checks a condition on a resource, then relies on that condition when using it
- Attacker can **interleave their actions** to invalidate the condition between the check and the use

**Examples of race conditions**:

| Context | Description |
|---------|-------------|
| **File System** | Privileged programs check a condition on a file before acting; attacker can invalidate condition between check and action |
| **Web Application Sessions** | Multi-threaded web servers may handle concurrent HTTP requests; two requests from the same session may access session state concurrently, corrupting it |
| **Heap Memory** | Aliasing (multiple pointers to same memory cell) can cause data races when multiple threads read/write concurrently |

### 2.4 API Vulnerabilities

> **Definition**: An API (Application Programming Interface) vulnerability occurs when the **client of an API violates the API contract**, causing the software system to enter an error state — potentially breaking the security objective.

**Example** — Banking API Attack:
```
Contract:  transfer(from_account, to_account, amount)
Rules:     User authenticated + amount > 0 + balance sufficient

Attack:    transfer(accountA, accountB, -500)
Result:    accountA balance increases, accountB loses money
           → Violates financial integrity
```

### 2.5 Side-Channel Vulnerabilities

> **Definition**: A side-channel is an **information channel** that leaks information about program execution through effects not intended for communication — e.g., timing, power consumption, electromagnetic radiation.

- Many side-channels require **physical access** to the system
- **Software-based side-channels** can be read by software running on the same system
- Critical in **cryptography**: unless an implementation guards against it, power/timing side-channels can leak cryptographic keys

**Micro-architectural side-channels** (examples: Spectre, Meltdown) exploit CPU implementation details.

---

## 3. Prevention of Vulnerabilities

### 3.1 Memory Management

Prevention approaches:
1. **Language design** — choose features that avoid dangerous patterns: no mutable state, no manual deallocation (garbage collection)
2. **Dynamic checks** — impose bounds checking on every array access
3. **Static type systems** — guarantee safe field access through types

**Memory-safe languages**: Java, Python, Rust (with ownership model), Go.

### 3.2 Structured Output Generation

**Approach 1 — Type Systems for Structured Data**:
- Describe structured output using types (e.g., XML types with regular expression types)
- Type-correct programs guaranteed to produce correctly-structured output

**Approach 2 — Primitive Language Features (LINQ)**:
```csharp
// Safe: LINQ uses parameterized expressions, not string concatenation
var result = from user in Users
             where user.Name == input
             select user;
// Generated SQL uses parameters → no SQL injection
```

**Key prevention techniques**:
- **Prepared Statements / Parameterized Queries** — separate SQL structure from user input
- **Input validation and output encoding** — validate/sanitize input, encode output

### 3.3 Race Condition Prevention

- **Ownership model** (e.g., Rust): only one pointer owns a resource; aliases can only read; owner can write only if no aliases exist → eliminates data races
- **Atomic operations** — perform check and action atomically

### 3.4 API Design

- Design APIs to make it **difficult to violate the contract**
- **Assertions, contracts, defensive programming** — make preconditions explicit and check them
- **Design by Contract** — preconditions and postconditions make expectations clear
- **Fat pointers** — pointers maintain bounds information
- **Prepared Statement APIs** — separate SQL structure from user data
- **Secure cryptography libraries** — simpler APIs with secure defaults

### 3.5 Coding Practices

Secure coding rules and recommendations include:
- Avoid **dangerous API functions** (e.g., do not use `system()` in C)
- Avoid **undefined behavior** (e.g., do not access freed memory)
- **Exclude user input from format strings**
- Do not store secrets in Java Strings (JVM may keep them in heap indefinitely)

---

## 4. Detection of Vulnerabilities

> Detection techniques must trade off between **soundness** (no false negatives) and **completeness** (no false positives).

| Property | Description |
|----------|-------------|
| **Sound** | Correctly concludes a program has no vulnerabilities; never misses actual vulnerabilities (no false negatives) |
| **Complete** | Any vulnerability it finds is an actual vulnerability (no false positives) |

### 4.1 Static Detection (Analyze Source or Binary Code)

> Advantage: Can operate on **incomplete code** that is not yet executable.

**Heuristic Static Detection**:
- Builds a semantic model of the program (abstract syntax tree, data flow, control flow)
- Flags violations of simple syntactic rules: "do not use this dangerous API function"
- Widely used in commercial SAST tools

**Sound Static Verification** (three approaches):

| Method | Description |
|--------|-------------|
| **Program Verification** | Formal proof that the program satisfies its specification |
| **Abstract Interpretation** | Over-approximation of all possible program behaviors |
| **Model Checking** | Exhaustive exploration of finite state spaces to verify properties |

### 4.2 Dynamic Detection (Execute and Monitor)

**Monitoring**:

| Type | What It Monitors |
|------|-----------------|
| Memory-management monitoring | Bounds violations, dangling pointers |
| Structured output monitoring | Injection attempts at runtime |
| API vulnerability monitoring | Contract violations |
| Race condition monitoring | Concurrent access violations |

**Generating Relevant Executions (Fuzzing)**:

| Fuzzing Type | Description |
|-------------|-------------|
| **Black-Box Fuzzing** | Does not depend on internal structure; uses only I/O behavior |
| — Random-based | Randomly generated inputs |
| — Model-based | Inputs conform to a model/grammar |
| — Mutation-based | Mutates valid inputs to create test cases |
| **White-Box Fuzzing** | Analyzes internal program structure to generate inputs that drive the program to different execution paths (improves code coverage) |

---

## 5. Mitigation of Exploitation

Even when vulnerabilities exist, exploitation can be mitigated:

### 5.1 Runtime Detection of Attacks

| Technique | How It Works |
|-----------|-------------|
| **Stack Canaries** | Detect violations of call stack integrity (modified return addresses) |
| **Non-Executable Data Memory (NX/DEP)** | Prevents execution of code in data memory → stops direct code injection |
| **Control Flow Integrity (CFI)** | Monitors runtime control flow against expected flow; detects code-reuse attacks (ROP) |

### 5.2 Automated Software Diversity

- **Exploitation often relies on knowing implementation details** (e.g., memory layout for buffer overflow)
- **Address Space Layout Randomization (ASLR)** — randomizes memory layout at each execution
- Makes it harder for an attacker to prepare and test an attack
- Makes it harder to build attacks that work across many systems simultaneously

### 5.3 Limiting Privileges

- Run processes/services with **minimum necessary privileges**
- Use **sandboxing** — limit what resources a process can access
- Use **containers** and **virtual machines** for isolation

### 5.4 Software Integrity Checking

- Verify the integrity of software before execution
- Use **code signing** — cryptographically verify software authenticity
- Regular checksum/hash verification of binaries

---

## 6. Testing Frameworks

### 6.1 NIST Framework

The **National Institute of Standards and Technology (NIST)** provides guidelines for integrating security into software:
- **NIST SP 800-115** — Technical Guide to Information Security Testing and Assessment
- **NIST SP 800-53** — Security and Privacy Controls for Federal Information Systems
- Provides structured approach to: reconnaissance, vulnerability scanning, exploitation, and reporting

### 6.2 OWASP (Open Web Application Security Project)

- A non-profit foundation that works to improve software security
- Maintains the **OWASP Top 10** — the most critical web application security risks
- Also provides: OWASP Testing Guide, OWASP Code Review Guide, ASVS, WebGoat

### 6.3 CWE (Common Weakness Enumeration)

> A community-developed list of common hardware and software weakness types that have security implications.

- Maintained by MITRE
- Each weakness has a **CWE-ID** (e.g., CWE-89: SQL Injection, CWE-79: XSS)
- Used to categorize vulnerabilities in security tools and advisories

| Framework | Purpose |
|-----------|---------|
| **NIST** | Government/enterprise security guidelines and controls |
| **OWASP** | Open-source web app security guidelines and Top 10 risks |
| **CWE** | Common weakness taxonomy for classifying vulnerability types |
| **CVE** | Common Vulnerabilities and Exposures — database of known vulnerabilities |

---

## 7. CVSS — Common Vulnerability Scoring System

> **Definition**: CVSS is an open framework for communicating the characteristics and severity of software vulnerabilities through a **numerical score** (0–10).

**CVSS Score Ranges**:

| Score | Severity |
|-------|----------|
| 0.0 | None |
| 0.1 – 3.9 | Low |
| 4.0 – 6.9 | Medium |
| 7.0 – 8.9 | High |
| 9.0 – 10.0 | Critical |

**CVSS Metric Groups**:

| Group | Metrics |
|-------|---------|
| **Base Score** | Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, CIA Impact |
| **Temporal Score** | Exploit Code Maturity, Remediation Level, Report Confidence |
| **Environmental Score** | Organizational customizations (modified base metrics) |

---

## 8. OWASP Top 10 Web Vulnerabilities

The **OWASP Top 10 (2021)** represents the most critical web application security risks:

| Rank | Vulnerability | Description |
|------|--------------|-------------|
| **A01** | Broken Access Control | Failures that allow users to act outside their intended permissions |
| **A02** | Cryptographic Failures | Failures related to cryptography exposing sensitive data |
| **A03** | Injection (incl. XSS) | Injection of untrusted data into interpreters (SQL, OS, LDAP, XSS) |
| **A04** | Insecure Design | Design flaws — missing security controls, improper threat modeling |
| **A05** | Security Misconfiguration | Misconfigured permissions, default accounts, XXE processing |
| **A06** | Vulnerable & Outdated Components | Using libraries/frameworks with known vulnerabilities |
| **A07** | Identification & Authentication Failures | Broken authentication, weak passwords, session fixation |
| **A08** | Software & Data Integrity Failures | Insecure deserialization, untrusted CI/CD pipelines |
| **A09** | Security Logging & Monitoring Failures | Insufficient logging; breaches go undetected |
| **A10** | SSRF | Server-Side Request Forgery — fetching remote resources without validation |

### A01: Broken Access Control

> Occurs when access control policies are not properly implemented — allows users to act as other users/admins, access unauthorized data, perform unauthorized operations.

**Attack types**:
- **Insecure Direct Object References (IDOR)** — changing IDs in URLs to access other users' data
- **Missing Function Level Access Control** — accessing admin pages without authorization
- **Forced Browsing** — directly accessing URLs not linked in the application
- **Directory Traversal** — using `../../` in file parameters to access system files
- **Client-side Caching** — sensitive data stored in browser cache accessible to others

### A03: Injection / XSS

**SQL Injection**: Inject SQL commands through user input to manipulate the database.

**XSS (Cross-Site Scripting)** — three types:

| Type | Description |
|------|-------------|
| **Stored XSS** | Malicious script stored in database; executes when other users view the page — affects all visitors |
| **Reflected XSS** | Malicious script reflected off the web application; user must click an infected link |
| **DOM-based XSS** | Malicious string processed by client-side JavaScript; not parsed by browser until legitimate JS executes |

**XSS Exploitations**: malicious script execution, session hijacking, keylogging, brute-force password cracking, data theft, intranet probing.

### A07: Identification & Authentication Failures (Broken Authentication)

> Occurs when functions related to a user's identity, authentication, or session management are not correctly implemented.

**Attack techniques**:
- Brute force / credential stuffing
- Session hijacking
- Session fixation
- CSRF (Cross-Site Request Forgery)
- Execution After Redirect (EAR)
- One-click attacks

### A10: Server-Side Request Forgery (SSRF)

> Occurs when a web application fetches a remote resource without validating the user-supplied URL — allowing an attacker to coerce the application to send requests to unintended destinations.

**SSRF Attack Scenarios**:
1. **Port scanning** — map internal networks, determine open ports
2. **Sensitive data exposure** — access local files (`file:///etc/passwd`) or internal services
3. **Cloud metadata access** — read `http://169.254.169.254/` for cloud credentials
4. **Internal service compromise** — conduct further attacks like RCE or DoS via internal services
