# Theory

Authentication vulnerabilities arise when a web application's login or session mechanism can be bypassed, brute-forced, or manipulated. Weak authentication allows attackers to gain unauthorised access to accounts without knowing valid credentials. Common weaknesses include no rate limiting, verbose error messages that reveal whether a username is valid, and insecure credential storage.

## Key Aspects

	Weak or absent brute-force protection enables password guessing
	Verbose error messages allow username enumeration
	Types: Username Enumeration & Brute Force / Credential Stuffing

# Scenarios
## Username Enumeration

A login page accepts a username and password:

URL:
`https://shop.test/login`

```
POST /login
Body: username=alice&password=wrongpassword
```

The application returns different error messages depending on whether the username exists:
- `"Invalid username"` — username does not exist
- `"Invalid password"` — username exists but password is wrong

### a. Predict the Backend query

```sql
SELECT * FROM users WHERE username = 'alice';
-- If no row returned → "Invalid username"
-- If row returned but password doesn't match → "Invalid password"
```

The application queries the database for the username first, then separately checks the password — and leaks the result of each check via its error message.

### b. Modify the request to perform Username Enumeration

Send POST requests with a known-wrong password and observe the error message:

**Request 1:**
```
POST /login
Body: username=alice&password=wrongpassword
```
Response: `"Invalid username"` → `alice` does **not** exist.

**Request 2:**
```
POST /login
Body: username=admin&password=wrongpassword
```
Response: `"Invalid password"` → `admin` **exists**.

By iterating through a wordlist of common usernames (e.g., `admin`, `user`, `test`, `support`), the attacker can compile a list of **valid usernames** for the next attack stage.

### c. Conditions required for Username Enumeration

1. The application returns **different responses** depending on whether the username exists (different error messages, different HTTP status codes, or different response times).
2. There is **no rate limiting or account lockout** preventing repeated login attempts.
3. The attacker can **send automated requests** with a username wordlist.
4. Usernames are **predictable or guessable** (e.g., first.last format, email addresses, common names).

> Even a subtle difference — like a slightly longer response time when the username exists (due to bcrypt comparison running only for valid users) — is enough to enumerate usernames.

### d. Craft a payload to enumerate usernames using response length difference

If error messages are identical but **response body length** differs:

```
POST /login HTTP/1.1
Host: shop.test
Content-Type: application/x-www-form-urlencoded

username=admin&password=wrongpassword
```

Use Burp Intruder with a username wordlist:
- Set `username` as the payload position.
- Sort results by **Response Length** — a different length identifies valid usernames.

### e. Craft a payload to enumerate usernames using response time difference

Some applications only run the password hash comparison (e.g., `bcrypt`) when the username exists — this adds measurable latency:

```
POST /login
Body: username=<candidate>&password=a
```

- Valid username → bcrypt runs → **~200–500ms response**
- Invalid username → query returns nothing, bcrypt skipped → **~5–20ms response**

Use Burp Intruder's **Pitchfork** mode and record response times:
- Sort by **Response Time** — outliers (slower responses) = valid usernames.

---

## Brute Force Attack

Using the list of valid usernames discovered via enumeration, the attacker now attempts to guess passwords.

The login page has no account lockout and no CAPTCHA:

```
POST /login
Body: username=admin&password=<guess>
```

### a. Predict the Backend query

```sql
SELECT * FROM users WHERE username = 'admin' AND password_hash = bcrypt(<guess>);
```

The server checks the supplied password against the stored hash. Because there is no rate limiting, the attacker can submit thousands of guesses per second.

### b. Modify the request to perform a Brute Force Attack

Use a password wordlist (e.g., `rockyou.txt`) with Burp Intruder:

```
POST /login HTTP/1.1
Host: shop.test
Content-Type: application/x-www-form-urlencoded

username=admin&password=§password§
```

- Set `§password§` as the Intruder payload position.
- Load a common password list.
- Send all requests — a response with a **different length, status code (302 redirect), or "Welcome" content** indicates a successful login.

**Common passwords to try first:**
```
password
123456
admin
admin123
letmein
welcome1
```

### c. Conditions required for Brute Force Attack

1. The application has **no account lockout** after repeated failed attempts.
2. There is **no CAPTCHA** or MFA protecting the login endpoint.
3. The attacker has a **valid username** (obtained via enumeration or public sources).
4. The application responds **differently on success vs failure** (different status code, redirect, or response body).
5. There is **no rate limiting** (IP-based or account-based throttling) that slows or blocks automated requests.

> Credential stuffing is a variant of brute force that uses username/password pairs leaked from other breached databases — effective because users reuse passwords across sites.

### d. Craft a payload to perform Credential Stuffing

Using a leaked credential list (`username:password` pairs from a data breach):

```
POST /login HTTP/1.1
Host: shop.test
Content-Type: application/x-www-form-urlencoded

username=§username§&password=§password§
```

Use Burp Intruder in **Pitchfork** mode:
- Column 1 payload: usernames from leaked list.
- Column 2 payload: corresponding passwords from leaked list.
- Both lists advance in lockstep — each request tries one complete credential pair.

Successful login identified by **HTTP 302 redirect** to `/dashboard`.

### e. State the defences against Authentication attacks and explain how they break the attack

| Defence | How it works | How it breaks the attack |
|---|---|---|
| **Generic error messages** | Always return `"Invalid username or password"` regardless of which field is wrong | Attacker cannot distinguish valid from invalid usernames — enumeration fails |
| **Account lockout** | Lock the account after N failed attempts (e.g., 5) | Brute force stops after a small number of guesses — correct password cannot be reached in reasonable time |
| **Rate limiting / IP throttling** | Slow down or block IPs that exceed a request threshold per minute | Automated wordlist attacks become infeasibly slow |
| **CAPTCHA** | Require human verification on login | Automated scripts cannot solve CAPTCHAs — bulk requests fail |
| **Multi-Factor Authentication (MFA)** | Require a second factor (OTP, authenticator app) after correct password | Even if correct password is guessed, attacker cannot complete login without the second factor |
| **Consistent response time** | Always run bcrypt (with a dummy hash) even for invalid usernames | Timing-based username enumeration is defeated |

---

# Exam-Style Questions

## Question 1 — SecureVault Portal

A password manager web application **SecureVault** has a login page at `https://securevault.test/login`. When tested:

- `username=admin&password=wrong` → Response: `"Incorrect password"` (401, 312 bytes)
- `username=ghost&password=wrong` → Response: `"User not found"` (401, 298 bytes)

There is no CAPTCHA and no rate limiting.

### (a) Identify the vulnerabilities present

1. **Username Enumeration** — different error messages reveal whether the username exists (`"Incorrect password"` vs `"User not found"`).
2. **No brute-force protection** — absence of rate limiting and CAPTCHA allows unlimited login attempts.

### (b) Describe the attack chain

1. Use Burp Intruder with a username wordlist; filter by response message or length — identify `admin` as a valid username (response: `"Incorrect password"`).
2. Use Burp Intruder with `admin` fixed and a password wordlist; identify the correct password by a 200/302 response.
3. Log in as `admin` — full account compromise.

### (c) Recommend fixes

```
1. Return identical error message: "Invalid username or password" in all cases.
2. Implement account lockout after 5 failed attempts with a 15-minute cooldown.
3. Add rate limiting: max 10 login attempts per IP per minute.
4. Enforce MFA for all accounts, especially admin accounts.
5. Run bcrypt comparison unconditionally (even for non-existent users) to prevent timing attacks.
```
