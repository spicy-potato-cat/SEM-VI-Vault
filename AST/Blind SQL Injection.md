
# Theory

Blind SQL Injection is a type of SQL Injection where the attacker does **not** receive direct output from the database. Instead, information is inferred by observing the application's **behavior** — such as whether a page shows results or not, or how long it takes to respond.

## Key Aspects

	No direct data output
	Indirect feedback (behavioral changes)
	Types: Boolean-Based & Time-Based

# Scenarios
## Boolean-Based Blind SQLi

![[Pasted image 20260427180144.png | 600]]

Search URL:
`https://shop.test/search?q=phone`
Application only shows:
"Results Found" or "No Results"
No database errors are shown.

### a. Predict the Backend query

```sql
SELECT * FROM products WHERE name LIKE '%phone%';
```

The application passes the search term directly into a `LIKE` query and returns a boolean-style response based on whether any rows are returned.

### b. Modify the request to test for Boolean-Based Blind SQL Injection

- Boolean-Based Blind SQLi relies on injecting conditions that are **always true** or **always false** and observing the difference in response.

**i. True Condition — "Results Found"**

```
https://shop.test/search?q=phone' AND 1=1--
```

- `1=1` is always true, so the original query still returns results → **"Results Found"**

**ii. False Condition — "No Results"**

```
https://shop.test/search?q=phone' AND 1=2--
```

- `1=2` is always false, so the query returns no rows → **"No Results"**

If the two responses differ, the application is **vulnerable to Boolean-Based Blind SQLi**.

### c. Conditions required for Boolean-Based Blind SQL Injection

1. The application must **pass user input unsanitised** into a SQL query.
2. The application must return **observably different responses** for true vs false conditions (e.g., "Results Found" vs "No Results").
3. **No error messages or direct data output** is necessary — only behavioral differences are needed.
4. The attacker must be able to **send multiple crafted requests** and compare responses to infer data bit by bit.

> Unlike Error-Based or Union-Based SQLi, no data is directly returned. Data is **extracted one character at a time** by asking yes/no questions to the database.

### d. Craft a payload to check if table 'users' exists

```
https://shop.test/search?q=phone' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_name='users')=1--
```

- If the `users` table exists, the subquery returns `1`, making the condition **true** → **"Results Found"**
- If it does not exist, condition is **false** → **"No Results"**

### e. Craft a payload to check if first character of database name is 'a'

```
https://shop.test/search?q=phone' AND SUBSTRING(database(),1,1)='a'--
```

- `database()` returns the current database name.
- `SUBSTRING(database(),1,1)` extracts the **first character**.
- If the first character is `'a'`, the condition is **true** → **"Results Found"**
- Otherwise, condition is **false** → **"No Results"**

By iterating through characters and positions, an attacker can extract the full database name character by character.

---

## Time-Based Blind SQLi

A login page accepts a username and password:

URL:
`https://shop.test/login`

```
POST /login
Body: username=admin&password=secret
```

The application **always returns the same response** regardless of whether credentials are correct or not:
`"Login failed. Please try again."`

No behavioral difference in the response. No errors shown.

### a. Predict the Backend query

```sql
SELECT * FROM users WHERE username = 'admin' AND password = 'secret';
```

The application passes the username and password directly into a SQL query. Since the response is always identical, Boolean-Based Blind SQLi cannot be used — there is no observable difference to exploit.

### b. Modify the request to test for Time-Based Blind SQL Injection

- Time-Based Blind SQLi injects a **conditional time delay** into the query.
- If the condition is true, the database sleeps for a set number of seconds — causing a measurable delay in the response.
- The attacker **observes response time** instead of response content.

**Inject a delay using `SLEEP()`:**

```
username=admin' AND SLEEP(5)-- &password=anything
```

Resulting backend query:
```sql
SELECT * FROM users WHERE username = 'admin' AND SLEEP(5)-- ' AND password = 'anything';
```

- If the response takes **~5 seconds longer than normal**, the injection was executed → **vulnerable to Time-Based Blind SQLi**.
- If the response returns instantly, the injection was not executed or was sanitised.

**Conditional delay (true condition):**
```
username=admin' AND IF(1=1, SLEEP(5), 0)-- &password=anything
```
- `1=1` is always true → `SLEEP(5)` executes → **~5 second delay**

**Conditional delay (false condition):**
```
username=admin' AND IF(1=2, SLEEP(5), 0)-- &password=anything
```
- `1=2` is always false → `SLEEP` is skipped → **instant response**

The difference in response time between these two confirms the vulnerability.

### c. Conditions required for Time-Based Blind SQL Injection

1. The application must **pass user input unsanitised** into a SQL query.
2. The server response must be **identical regardless of query result** — no behavioral difference to exploit (Boolean-Based is not possible).
3. The database must support a **time-delay function** (e.g., `SLEEP(n)` in MySQL, `WAITFOR DELAY` in MSSQL, `pg_sleep(n)` in PostgreSQL).
4. The attacker must be able to **measure response time** reliably (stable network connection required to distinguish delays).

> Time-Based is the last resort form of Blind SQLi — used when there is absolutely no observable difference in the response. It is slower and noisier than Boolean-Based, as each inference requires waiting for the delay.

### d. Craft a payload to check if table 'users' exists

```
username=admin' AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_name='users')=1, SLEEP(5), 0)-- &password=anything
```

- If the `users` table exists → subquery returns `1` → condition is true → **SLEEP(5) executes** → ~5 second delay
- If it does not exist → condition is false → **no delay**

### e. Craft a payload to check if first character of database name is 'a'

```
username=admin' AND IF(SUBSTRING(database(),1,1)='a', SLEEP(5), 0)-- &password=anything
```

- `SUBSTRING(database(),1,1)` extracts the first character of the current database name.
- If it equals `'a'` → **SLEEP(5) executes** → ~5 second delay → character confirmed
- If not → **instant response** → try the next character

Repeat with `SUBSTRING(database(),2,1)`, `SUBSTRING(database(),3,1)`, etc. to extract the full database name one character at a time.