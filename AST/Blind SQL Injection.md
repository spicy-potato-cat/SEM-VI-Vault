
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