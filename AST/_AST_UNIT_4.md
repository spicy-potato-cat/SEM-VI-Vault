# Unit 4: Web Application Security and Testing

> **Course**: Application Security Testing (AST)
> **Unit**: 4 — Web Application Security and Testing
> **Syllabus Duration**: 10 Hours
> **PPT Reference**: *AST_4_Web Application Security*
> **Text Book**: Richa Gupta, *Hands-on Penetration Testing for Web Applications*, BPB Publications, 2021

---

## Table of Contents

[[#1. Web Application Threats and Pentesting Need]]
[[#2. OWASP Top 10 Web Vulnerabilities (2021)]]
[[#3. SQL Injection (SQLi)]]
[[#4. Cross-Site Scripting (XSS)]]
[[#5. Cross-Site Request Forgery (CSRF)]]
[[#6. Server-Side Template Injection (SSTI)]]
[[#7. Clickjacking]]
[[#8. Authentication and Session Testing]]
[[#9. Secure Channels and Secure Access Control]]
[[#10. API Testing]]
[[#11. Countermeasures]]

---

## 1. Web Application Threats and Pentesting Need

### 1.1 Why Web Applications are Targeted

- Attacks such as **SQL injection** and **cross-site scripting** have made web applications a prime target
- Attackers steal credentials, set up phishing sites, or acquire private information
- Most attacks result from **flawed coding** and improper sanitization of input/output data
- Web application attacks can threaten performance and security simultaneously

### 1.2 Need for Web Application Penetration Testing

> The growth of web applications has changed how businesses share and access data. This has invited malicious actors to intrude into systems. Therefore, **Web Application Pentesting** is essential to defend applications and networks.

**Goal**: Simulate an attacker's approach — understand how hackers hack websites by performing web application penetration testing.

### 1.3 Penetration Testing Methodology

```
┌────────────────────────────────────────────────────────────────────┐
│            WEB APP PENETRATION TESTING METHODOLOGY                 │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  PHASE 1: RECONNAISSANCE                                           │
│  Gather information about the target (passive/active)              │
│  - DNS enumeration, WHOIS, Google dorking                         │
│  - Identify technologies (web servers, frameworks)                 │
│              │                                                     │
│              ▼                                                     │
│  PHASE 2: SCANNING & ENUMERATION                                   │
│  - Port scanning (nmap)                                            │
│  - Web crawling and spidering                                     │
│  - Directory/file enumeration                                      │
│              │                                                     │
│              ▼                                                     │
│  PHASE 3: VULNERABILITY ASSESSMENT                                 │
│  - Automated scanning (OWASP ZAP, Burp Suite)                    │
│  - Manual testing for OWASP Top 10                                │
│              │                                                     │
│              ▼                                                     │
│  PHASE 4: EXPLOITATION                                             │
│  - Attempt to exploit identified vulnerabilities                   │
│  - SQL injection, XSS, CSRF, IDOR, etc.                          │
│              │                                                     │
│              ▼                                                     │
│  PHASE 5: POST-EXPLOITATION                                        │
│  - Assess impact of successful exploits                            │
│  - Privilege escalation, data extraction                          │
│              │                                                     │
│              ▼                                                     │
│  PHASE 6: REPORTING                                                │
│  - Document vulnerabilities, evidence, impact, and remediation    │
└────────────────────────────────────────────────────────────────────┘
```

---

## 2. OWASP Top 10 Web Vulnerabilities (2021)

| Rank | Vulnerability | Key Risk |
|------|--------------|---------|
| **A01** | Broken Access Control | Unauthorized access to resources/functions |
| **A02** | Cryptographic Failures | Sensitive data exposure from weak encryption |
| **A03** | Injection (incl. XSS) | Injection of malicious code into interpreters |
| **A04** | Insecure Design | Design flaws, missing security controls |
| **A05** | Security Misconfiguration + XXE | Exposed sensitive defaults, XXE vulnerabilities |
| **A06** | Vulnerable & Outdated Components | Use of libraries/frameworks with known CVEs |
| **A07** | Identification & Authentication Failures | Broken authentication, credential attacks |
| **A08** | Software & Data Integrity Failures | Insecure deserialization, compromised CI/CD |
| **A09** | Security Logging & Monitoring Failures | Breaches go undetected for months |
| **A10** | Server-Side Request Forgery (SSRF) | App fetches remote resources without URL validation |

### A01: Broken Access Control

> **Definition**: Broken access control occurs when access control enforcement allows a user to **perform actions outside their intended limits**.

**Key Subtypes**:

| Subtype | Description |
|---------|-------------|
| **IDOR (Insecure Direct Object Reference)** | Exposing internal objects (files, DB records) through references — e.g., changing `?id=1337` to `?id=42` to access another user's profile |
| **Missing Function-Level Access Control** | Admin functions accessible without admin role |
| **Forced Browsing** | Accessing unlinked but available resources (e.g., directly visiting `/admin`) |
| **Directory Traversal** | Using `../../` to traverse the file system — e.g., `?file=../../etc/passwd` |
| **Client-side Caching** | Sensitive data stored in browser cache accessible to shared-computer users |

**Attack Scenario**:
1. Attacker uses automated scanning to find unlinked resource `/admin`
2. Initiates forced browsing attack
3. Accesses admin page as unauthenticated user

### A02: Cryptographic Failures (Sensitive Data Exposure)

> Occur when security controls are not properly implemented for **data in transit** or **data at rest** — allowing attackers to steal weakly protected sensitive data.

**Examples**:
- Unsalted password hashes → crackable with rainbow tables
- HTTP instead of HTTPS for credential transmission
- Weak encryption algorithms (MD5, SHA-1) for password storage
- Hardcoded secrets in source code

**Attack Scenario**:
1. Attacker gains access to organization's network
2. Retrieves password database using application flaw
3. Since unsalted hashes are used, attacker uses rainbow table to crack passwords
4. Uses credential stuffing on other websites

### A04: Insecure Design (NEW in 2021)

> Focuses on risks related to **design flaws** — missing or ineffective security controls at the design level.

**Examples**:
- Discount logic flaws allowing large discounts beyond intended maximum (e.g., 100 bookings at group discount rate for 20)
- "Security questions" as credential recovery — a design flaw (questions/answers not acceptable identity proof)
- Lack of bot detection in e-commerce websites

### A05: Security Misconfiguration + XXE

> Security Misconfiguration: security flaws present in misconfigured application frameworks, servers, databases.

> **XXE (XML External Entities)**: Vulnerability occurring when untrusted XML input referencing an external entity is accepted and parsed by a vulnerable XML parser.

**XXE Attack Paths**:
1. **Read arbitrary files**: `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
2. **Perform DoS**: Billion Laughs attack (exponentially expanding XML entities)
3. **SSRF via XXE**: Reference internal URLs in external entity to reach internal services

### A06: Vulnerable and Outdated Components

> Occurs when software components (libraries, frameworks, APIs) are **out of date** or have **known vulnerabilities**.

- Components often run with **same privileges as the application** — any flaw in the component threatens the entire app
- Attack types targeting vulnerable components: code injection, buffer overflow, command injection, XSS

**Attack Scenario**:
1. Attacker gains access to internal network
2. Runs scanning tool to find systems with unpatched/outdated components
3. Exploits flaw in outdated component to install malicious code on app server

### A07: Identification and Authentication Failures

> Occurs when functions related to **identity, authentication, or session management** are incorrectly implemented.

**Attack Techniques**:

| Technique | Description |
|-----------|-------------|
| **Brute Force** | Systematically trying all possible passwords |
| **Credential Stuffing** | Using leaked username/password pairs from one breach on other sites |
| **Session Hijacking** | Stealing a valid session token to impersonate a user |
| **Session Fixation** | Setting the victim's session ID before authentication |
| **CSRF** | Inducing victim to perform unintended actions using their authenticated session |
| **Execution After Redirect (EAR)** | Application logic executed even after redirect response |

### A08: Software and Data Integrity Failures

> Focuses on **insecure deserialization** and assumptions made about software updates and CI/CD pipelines without verifying integrity.

**Attack Scenario**:
1. Attacker identifies insecure CI/CD pipeline
2. Installs malicious code pushed into production
3. Customers unknowingly download the malicious update
4. Attacker gains access to customer environments

### A09: Security Logging and Monitoring Failures

> Failure to **sufficiently log, monitor, or report** security events makes it difficult to detect suspicious behavior — significantly increasing the likelihood of successful exploitation.

**Impact**: An attacker may probe for vulnerabilities over a period of time undetected — eventually finding and exploiting a flaw. Data breaches can continue **undetected for months**.

**Attack scenario**:
1. Attacker gains access to internal network
2. Runs scanning tool to find systems with known vulnerabilities
3. Organization does not follow adequate logging/monitoring → cannot detect active attacks
4. Data breach continues undetected for months

### A10: Server-Side Request Forgery (SSRF)

> Occurs whenever a web application fetches a remote resource **without validating the user-supplied URL** — allowing an attacker to coerce the application to send crafted requests to unintended destinations.

**Attack Scenarios**:

| Scenario | Description |
|----------|-------------|
| **Port Scanning** | `GET /index.php?url=http://192.168.1.X:PORT/` — map internal network |
| **Sensitive Data Exposure** | `?url=file:///etc/passwd` — read local files |
| **Cloud Metadata** | `?url=http://169.254.169.254/` — read AWS/Azure metadata with credentials |
| **Internal Service Compromise** | Abuse internal services for RCE or DoS |

---

## 3. SQL Injection (SQLi)

> **Definition**: SQL injection is a vulnerability where an attacker injects malicious SQL queries into user input fields to gain **unauthorized access to or manipulate a backend database**.

### 3.1 Impact of SQL Injection

- **Confidentiality**: View sensitive information (usernames, passwords)
- **Integrity**: Alter data in the database
- **Availability**: Delete data in the database
- **Remote Code Execution** on the OS (in some configurations)

### 3.2 Types of SQL Injection

```
┌─────────────────────────────────────────────────────┐
│              SQL INJECTION TYPES                    │
├─────────────────────────────────────────────────────┤
│  1. In-Band SQLi (Classic)                         │
│     ├── Error-Based                                │
│     └── Union-Based                               │
│                                                    │
│  2. Blind SQLi (Inferential)                      │
│     ├── Boolean-Based                             │
│     └── Time-Based                               │
│                                                    │
│  3. Out-of-Band SQLi (OAST)                       │
└─────────────────────────────────────────────────────┘
```

### 3.3 In-Band SQLi

> Attacker uses the **same communication channel** to launch the attack and gather results. Retrieved data is presented directly in the application web page.

**Error-Based In-Band SQLi**:
- Attacker extracts information (database version, table names) by **triggering error messages**
- Submit SQL-specific characters (`'` or `"`) and look for errors

**Union-Based In-Band SQLi**:
- Uses the `UNION` SQL operator to **combine results** of original query with attacker's query
- Rules: same number of columns, compatible data types

### 3.4 Blind SQLi

> No actual data is transferred in the web application response. Attacker infers information by **asking true/false questions** and observing behavior.

**Boolean-Based Blind SQLi**:
- If app responds differently to true vs. false payloads → vulnerable
- Attacker reconstructs data by systematically testing conditions:
  - True payload → normal response
  - False payload → altered/error response

**Time-Based Blind SQLi**:
- Injects a **time delay** into the SQL query
- If the response takes the injected delay time → vulnerable
- Used when the application returns the same response for true/false conditions

### 3.5 Out-of-Band (OAST) SQLi

> Used when in-band/blind SQLi doesn't work because the application processes SQL **asynchronously** on a different thread.

- Forces the database server to **make a DNS lookup** or HTTP request to an attacker-controlled server
- Attacker uses **Burp Collaborator** (or similar) to receive out-of-band interactions
- Data can be exfiltrated as a **subdomain in the DNS request**

**Example Workflow**:
1. Inject SQL payload → victim server makes DNS lookup to attacker's server
2. Attacker's server records the DNS request (confirms successful injection)
3. Second payload extracts data (e.g., password hash) as a DNS subdomain
4. Attacker polls their server and reads the extracted data

### 3.6 Finding and Exploiting SQLi

| Approach | Technique |
|----------|-----------|
| **Black Box — Finding** | Submit `'` or `"`, observe errors; submit boolean conditions (OR 1=1); try time-delay payloads; use OAST payloads |
| **White Box — Finding** | Enable web server/DB logging; regex search for DB calls; code review; follow input vectors |
| **Error-Based Exploitation** | Trigger errors containing version/query/server information |
| **Union-Based Exploitation** | Determine number of columns → determine data types → extract data |
| **Blind Exploitation** | Systematically test conditions → extract data character by character |

---

## 4. Cross-Site Scripting (XSS)

> **Definition**: XSS is a structured output generation vulnerability where the structured output is **JavaScript code** sent to a web browser for client-side execution.

### 4.1 Types of XSS

| Type | Also Known As | How It Works |
|------|--------------|-------------|
| **Stored XSS** | Persistent XSS | Malicious script stored in database; executes when other users view the page |
| **Reflected XSS** | Non-persistent XSS | Malicious script reflected from the web app when user clicks a crafted URL |
| **DOM-Based XSS** | Client-side XSS | Malicious string processed by client-side JavaScript without server involvement |

### 4.2 How Reflected XSS Works

1. Attacker crafts a malicious URL with a script payload
2. Distributes it via email or third-party websites (embedded in anchor text)
3. Victim clicks the infected link
4. Request goes to exploited website
5. Server reflects the script back in the response
6. Victim's browser executes the malicious script

### 4.3 How DOM-Based XSS Works

1. Attacker crafts a URL with malicious parameter: `?default=<script>alert(document.cookie)</script>`
2. Victim clicks the URL — request goes to server
3. Server returns page with legitimate JavaScript
4. Legitimate JS processes the URL parameter and writes the malicious script to the DOM
5. Browser executes the malicious script
6. Victim's cookies sent to attacker → session hijacked

### 4.4 XSS vs. Other Attacks

| Comparison | Explanation |
|-----------|-------------|
| **XSS vs. CSRF** | XSS: causes website to return malicious JavaScript; CSRF: induces victim to perform unintended actions |
| **XSS vs. SQL Injection** | XSS: client-side vulnerability targeting other users; SQL Injection: server-side vulnerability targeting the database |

### 4.5 XSS Exploitations

- Malicious script execution
- Redirecting to malicious servers
- Session hijacking
- Keylogging and remote monitoring
- Brute-force password cracking
- Data theft
- Intranet probing
- Ads in hidden iFrames and pop-ups

---

## 5. Cross-Site Request Forgery (CSRF)

> **Definition**: CSRF exploits the trust a web application has in an authenticated user. The **victim holds an active session** with a trusted site, and a malicious site they visit **injects an HTTP request** for the trusted site into the session — compromising its integrity.

### 5.1 How CSRF Works

```
┌──────────────────────────────────────────────────────────────────────┐
│                       CSRF ATTACK FLOW                               │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Victim logs into trusted website (e.g., bank.com)               │
│     → Session cookie stored in browser                               │
│                                                                      │
│  2. Victim visits malicious website (e.g., evil.com)                │
│     → Malicious site contains hidden form or image tag:             │
│     <img src="https://bank.com/transfer?to=attacker&amount=1000">   │
│                                                                      │
│  3. Victim's browser automatically includes bank.com session cookie  │
│     → Request appears legitimate to bank.com                        │
│                                                                      │
│  4. Bank.com processes the unauthorized transfer                     │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### 5.2 CSRF Difference from XSS

| Attack | Exploits | Victim Action |
|--------|---------|---------------|
| **XSS** | Trust a user has in a website (malicious script executed) | None required after visiting page |
| **CSRF** | Trust a website has in a user (authenticated session) | Must be logged in to target site; malicious site crafts the request |

### 5.3 CSRF Prevention

- **CSRF Tokens** — unique, unpredictable tokens per session/request; server validates token on each state-changing request
- **SameSite Cookie Attribute** — cookies not sent on cross-site requests
- **Double Submit Cookie** — send CSRF token in both cookie and request parameter
- **Referer/Origin Header Validation** — check origin of request

---

## 6. Server-Side Template Injection (SSTI)

> **Definition**: SSTI occurs when user input is embedded directly into a server-side template in an **unsafe manner**. The template engine processes the user input as template code, allowing an attacker to inject template directives.

### 6.1 How SSTI Works

- Web applications often use template engines (Jinja2, Twig, FreeMarker, Smarty) to render dynamic content
- If user input is directly concatenated into a template: `"Hello " + user_input` → the user can inject template syntax

**Detection Payload Example**:
```
Input: {{7*7}}
If output shows 49 → template engine is evaluating the expression → SSTI vulnerable
```

**Exploitation Example** (Jinja2/Python):
```python
# Payload to read files
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
# Can lead to Remote Code Execution (RCE)
```

### 6.2 SSTI vs. XSS

| | XSS | SSTI |
|-|-----|------|
| **Execution** | Client-side (browser) | Server-side (template engine) |
| **Impact** | Session hijacking, client-side attacks | RCE, server file access |
| **Payload** | `<script>alert(1)</script>` | `{{7*7}}` or `${7*7}` |

---

## 7. Clickjacking

> **Definition**: Clickjacking (UI Redress Attack) is a malicious technique where a web page is **overlaid with a transparent iframe** containing a different page. The user believes they are clicking on the visible page, but their click is captured by the hidden overlay.

### 7.1 How Clickjacking Works

```
┌─────────────────────────────────────────────────────────────────┐
│                  CLICKJACKING ATTACK                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Malicious Page (visible to user)                               │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  "Click here to win a prize!"          [CLICK ME button]  │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ↑ Transparent iframe (hidden by CSS opacity:0) overlaid:       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  bank.com: "Transfer $1000?"           [CONFIRM button]   │  │
│  └───────────────────────────────────────────────────────────┘  │
│  User clicks "CLICK ME" but actually clicks "CONFIRM"           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 7.2 Clickjacking Prevention

- **X-Frame-Options** header: `DENY` or `SAMEORIGIN` — prevents page from being loaded in an iframe
- **Content Security Policy (CSP)**: `frame-ancestors 'self'` — modern alternative to X-Frame-Options
- **Frame-busting JavaScript** — code to detect and break out of iframes (less reliable)

---

## 8. Authentication and Session Testing

### 8.1 Authentication Testing

Testing areas for authentication security:

| Test Area | Description |
|-----------|-------------|
| **Password Policy** | Minimum length, complexity, lockout after failed attempts |
| **Multi-Factor Authentication** | Verify MFA is properly enforced |
| **Default Credentials** | Check for unchanged default usernames/passwords |
| **Account Enumeration** | Different error messages for valid vs. invalid usernames reveal valid accounts |
| **Credential Transmission** | Verify passwords sent over HTTPS (not HTTP) |
| **Password Storage** | Verify passwords are hashed with salt (bcrypt, Argon2) |

### 8.2 Session Management Testing

| Test Area | Description |
|-----------|-------------|
| **Session Token Entropy** | Tokens must be sufficiently random and unpredictable |
| **Session Fixation** | Server must issue a new session token after authentication |
| **Session Timeout** | Inactive sessions must expire; logout must invalidate session server-side |
| **Secure Cookie Flags** | `HttpOnly` (no JS access), `Secure` (HTTPS only), `SameSite` (CSRF protection) |
| **Token Transmission** | Session tokens must not appear in URLs (logged in server logs) |

---

## 9. Secure Channels and Secure Access Control

### 9.1 Secure Channels

- All sensitive communications must use **TLS (HTTPS)** — tested for:
  - Use of strong cipher suites (avoid RC4, DES, 3DES)
  - Valid and trusted TLS certificate
  - Certificate chain validation
  - Proper redirect from HTTP to HTTPS
  - **HSTS** (HTTP Strict Transport Security) header enforced

### 9.2 Secure Access Control

**Key access control principles**:

| Principle | Description |
|-----------|-------------|
| **Deny by Default** | Access denied unless explicitly granted |
| **Least Privilege** | Users get minimum necessary permissions |
| **Role-Based Access Control (RBAC)** | Permissions assigned to roles, not individuals |
| **Logging** | All access control decisions logged for audit |

**Testing for access control issues**:
- Test **horizontal privilege escalation** — access other users' data at the same privilege level (IDOR)
- Test **vertical privilege escalation** — access higher-privileged functions (admin panel as regular user)
- Test **function-level access control** — all admin/sensitive endpoints require proper authorization

---

## 10. API Testing

### 10.1 API Security Concerns

| Issue | Description |
|-------|-------------|
| **Broken Object Level Authorization** | API allows access to data objects without proper authorization check |
| **Broken User Authentication** | Weak API authentication tokens, poor token validation |
| **Excessive Data Exposure** | API returns more data than necessary, relying on client filtering |
| **Lack of Rate Limiting** | API vulnerable to brute force, DoS, or scraping |
| **Broken Function Level Authorization** | Low-privilege users can access admin-level API endpoints |
| **Mass Assignment** | API allows binding of client-provided data to internal model fields |
| **Security Misconfiguration** | Default credentials, unnecessary HTTP methods enabled, missing headers |
| **Injection** | SQL, NoSQL, command injection through API parameters |

### 10.2 API Testing Methodology

1. **Enumerate API endpoints** — use Burp Suite, Postman, or web crawling
2. **Test authentication** — check for missing/weak auth on all endpoints
3. **Test authorization** — check IDOR and privilege escalation
4. **Test input validation** — inject payloads in all parameters
5. **Test rate limiting** — verify rate limits on login, password reset, etc.
6. **Analyze response data** — check for sensitive data leakage in responses

---

## 11. Countermeasures

### 11.1 Input Validation and Output Encoding

| Vulnerability | Countermeasure |
|--------------|----------------|
| SQL Injection | Use **prepared statements/parameterized queries**; input validation |
| XSS | **Output encoding** (HTML entity encoding); Content Security Policy (CSP) |
| CSRF | **CSRF tokens**; SameSite cookies |
| Command Injection | Avoid shell commands; use APIs; whitelist input |
| SSTI | Separate user input from template code; use sandboxed template engines |

### 11.2 Security Headers

| Header | Purpose |
|--------|---------|
| `Content-Security-Policy` | Controls sources of content; prevents XSS |
| `X-Frame-Options` | Prevents clickjacking |
| `Strict-Transport-Security` | Enforces HTTPS |
| `X-Content-Type-Options` | Prevents MIME type sniffing |
| `Referrer-Policy` | Controls referrer information in requests |
| `Permissions-Policy` | Controls browser feature access |

### 11.3 Authentication & Session Best Practices

- Enforce **strong password policies**
- Implement **multi-factor authentication (MFA)**
- Use **bcrypt/Argon2** for password hashing with salt
- Invalidate sessions on **logout and after timeout**
- Set `HttpOnly`, `Secure`, and `SameSite` flags on session cookies
- Implement **account lockout** after failed attempts

### 11.4 Configuration and Deployment

- **Disable unnecessary HTTP methods** (TRACE, OPTIONS, PUT, DELETE when not needed)
- Remove **default credentials** and unnecessary services
- Apply **least privilege** to database accounts
- Regular **security patches** for frameworks, libraries, servers
- Enable detailed **security logging and monitoring**
- Use **WAF** for an additional layer of protection
