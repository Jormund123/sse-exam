# Phase 3: Defensive Coding & Applied Cryptography (~26 pts)

**Lectures:** lect-08 (Defensive Coding), lect-05 (Applied Cryptography)
**Time budget:** ~2 hours
**Exam payoff:** Defensive Coding argument + complexity types (~5 pts), Code snippets (~16 pts), Insecure hash function (~2-3 pts), Hybrid encryption (~2-3 pts)

---

## 1. Defensive Coding — Relationship to Risk Analysis & Secure Design

> **NOT ASKED directly on past exam** — but this is the conceptual foundation for the 21-point Defensive Coding section. Know the chain.

**The chain (from lecture):**
- **Risk Analysis** focuses on the domain, assets, threats, and what-if scenarios. It is global-minded, and prioritization is critical.
- **Secure Design** aims to minimize the attack surface, apply the principle of least privilege, implement defense in depth, and decide where to use crypto and access control.
- **Defensive Coding** addresses two main issues:
  1. **Code must follow the secure architecture.** Even one small change in code can cause a big change in the risk analysis (e.g., storing passwords in the Customer table instead of the Users table).
  2. **Code must be free of internal weaknesses.** This means avoiding all VOTDs and requires specific knowledge of security programming pitfalls in the language at hand.

**Why it matters:** Risk analysis is global, secure design is structural, defensive coding is line-by-line. They feed into each other.

---

## 2. "Complexity is the Enemy of Security" — Gary McGraw

> **ASKED ON EXAM** — Defensive Coding (~5 pts): *"Present an argument for: 'Complexity is the enemy of security.' Name and briefly describe two complexity types."*

### The Argument (write this on the exam):

The more complex a system is, the harder it becomes to understand all execution paths, test thoroughly, audit for security issues, and maintain securely. Complex code creates more hiding places for bugs and vulnerabilities, making it easier for security flaws to slip through unnoticed. A developer who cannot fully understand the code they are writing or reviewing will make mistakes — and mistakes in security-critical code become vulnerabilities.

### Three Complexity Types (exam asks for TWO, know all three):

**1. Structural Complexity (Cyclomatic/Architectural)**
- Having lots of interconnected subsystems leads to architectural complexity, making the system harder to secure as a whole.
- Having lots of if-statements and loops leads to cyclomatic complexity, as measured by McCabe's formula.
- The McCabe formula is **M = E - N + 2P**, where E is the number of edges, N is the number of nodes, and P is the number of connected components (usually 1). A shortcut is to count the number of decision points and add 1.
- McCabe's thresholds are: 1-10 is low risk and easily testable, 11-20 is moderate risk with some paths likely missed, 21-50 is high risk and too complex to fully test, and above 50 is considered untestable with guaranteed bugs.

**2. Cognitive Complexity**
- Cognitive complexity measures how much mental effort is needed to understand how a piece of code works.
- When developers lack understanding of the code, they make mistakes, and those mistakes become vulnerabilities.
- It is subjective but important, because even well-structured code can be hard to reason about if the logic is inherently complex.

**3. Complexity in Inputs**
- More complex inputs create bigger security risks because the system must handle a wider range of possible values.
- For example, web browsers must process complex web pages, and operating systems must handle diverse application inputs — both are frequent sources of vulnerabilities.
- A larger input space directly translates to a larger attack surface.

### Exam answer format for the argument question:

> "Complexity is the enemy of security because complex systems are harder to understand, test, and audit. Two complexity types:
> 1. **Structural complexity** — many interconnected subsystems (architectural) or many decision branches (cyclomatic, measured by McCabe's M = E - N + 2P). Higher cyclomatic complexity means more execution paths to test and audit. Above M=20, code is too complex to fully test.
> 2. **Cognitive complexity** — how much mental effort is needed to understand code. If developers cannot understand what code does, they will make mistakes that become vulnerabilities."

---

## 3. Input Handling: Validation & Sanitization

> **ASKED ON EXAM (indirectly)** — Code snippets test whether you recognize missing/poor input validation (XSS denylist, SQL injection). Worth ~4 pts per snippet.

### Input Validation (Blocking bad inputs)

**Denylist (Blocklist) aka Sanitization approach:**
- A denylist enumerates known bad inputs and rejects anything that matches the list.
- The drawback is that the list of bad inputs is effectively infinite, so it is easy for attackers to get around it with variations.
- The benefit is that denylists can be updated quickly, often without re-compilation, and they are straightforward to implement.

**Allowlist (Whitelist):**
- An allowlist only accepts known good input, often validated using regular expressions.
- The drawbacks are that it is sometimes not possible to block certain characters that are needed, and updates often require re-compilation and patching.
- **The lecture recommends doing both, but preferring the allowlist approach.**

### Input Sanitization (Manipulating bad inputs)

- Instead of blocking bad input, sanitization lets all input through but manipulates it to be safe.
- The input is converted into a form that will not be interpreted as code, usually by inserting escape characters (e.g., in HTML `<` becomes `&lt;`; in Java `"` becomes `\"`).
- The drawback is that you need to know every character to escape, which makes it very denylist-like. You also need to apply the correct sanitization for each context and remember to do it everywhere in the code.
- The recommended approach is to use established libraries such as `org.apache.commons.lang3.StringEscapeUtils.escapeHtml4()`.

### Key principle: **Never trust user input.** Input comes in many forms (strings, numbers, images with metadata, etc.)

---

## 4. Exception Handling

> **NOT ASKED directly on past exam** — but appears in code snippets as CWE-209. Know the pattern.

- You should handle the exceptions you know about and design your system to handle unexpected exceptions at the top level.
- **CWE-209: Information Exposure Through Error Message** means you should never leak configuration paths, database connection strings, or stack traces to users in error messages.
- Avoid declaring `throws Exception` because it is too broad. Instead, deal with related exceptions in one place, close to where the problem occurs.
- Never swallow exceptions silently with an empty catch block like `try{something();} catch{}`, because this hides errors that could indicate security issues.
- Always use the `finally` clause for cleanup tasks such as closing connections and releasing resources.
- Be aware that re-throwing exceptions without sanitizing the message may leak sensitive information to attackers.

---

## 5. Object-Oriented Security Pitfalls

> **NOT ASKED directly on past exam** — low priority for exam, but know the concepts in case of unseen code snippets.

### Immutability
- You should prefer immutable objects because they lead to fewer bugs, better concurrency safety, and better security overall.
- In Java, use the `final` keyword; in Kotlin, use `val`; in Rust, everything is immutable by default.
- For collections passed into constructors, always create a defensive copy (e.g., `this.c = new ArrayList<>(c)`) so that the caller cannot modify the object's internal state after construction.

### Cloning is Insecure
- Java's `clone()` method is error-prone because it allows instantiating classes without going through their constructors, which means security checks in constructors are bypassed.
- Oracle officially recommends not using `java.lang.Cloneable` at all, and suggests overriding the `clone()` method to throw an exception, making classes explicitly unclonable.

### Subclassing Risks
- In untrusted API situations, malicious subclasses can override sensitive methods or even override `finalize()` to resurrect objects that should have been destroyed.
- To prevent this, use the `final` keyword on classes and methods that should not be overridden.

### Global Variables
- Mutable global variables increase complexity, create tampering concerns in untrusted API scenarios, and cause unpredictable behavior in distributed systems.
- Constants are the only acceptable use of global variables.
- A common trap is `public static final List<String> list = new ArrayList<>()` — while the reference itself is final, the list contents are still mutable, so anyone can call `list.add("malicious data")`.

---

## 6. Concurrency

> **NOT ASKED directly on past exam** — know the three risks in case of unseen code snippets.

- Race conditions can lead to Denial of Service when threads interfere with each other's execution.
- Shared memory between threads can lead to potential information leakage if one thread reads data that another thread was processing.
- Unexpected concurrent circumstances can lead to potential tampering if shared state is modified by multiple threads without proper synchronization.
- Common poor assumptions developers make include "there will be only one copy of this thread," "there will only be X threads," and "nobody knows about my mutability."
- Concurrency is ubiquitous in modern software — it appears in web applications, databases, GUIs, and games, so these risks apply broadly.

---

## 7. Serialization / Deserialization

> **NOT ASKED directly on past exam** — but CWE-502 (Unsafe Deserialization) is a major VOTD. Could appear in unseen snippets.

### The Problem
- Deserialization reconstructs objects without any validation, which essentially means it constructs objects without executing their constructors.
- This bypasses all security checks that would normally run in the constructor.
- It is important to remember that serialized data is not encrypted, so there is also a confidentiality disclosure risk if serialized objects contain sensitive fields.

### The Rule: **Never deserialize untrusted data using native object serialization**
- Never use `pickle`, `marshal`, `ObjectInputStream`, or `Serializable` with untrusted input.
- Instead, use structured data-only formats: parse JSON into primitive types, validate the values, and then manually construct your objects.
- Use the `transient` keyword for variables that should not be serialized, such as environment info, timestamps, and cryptographic keys.

### OWASP Defense (override readObject):
```java
private final void readObject(ObjectInputStream in) throws java.io.IOException {
    throw new java.io.IOException("Class cannot be deserialized");
}
```

---

## 8. Unencrypted Storage & Dead Store Removal

> **NOT ASKED directly on past exam** — low priority but know the Java password pattern.

- The best practice is to encrypt and authenticate all data that your processes write to disk, because OS-level file permissions alone are not sufficient if an attacker gains root access.
- Full-disk encryption does not help while the device is running, because running devices decrypt content on the fly.
- **In Java, you should never store passwords in Strings.** A `String` object stays in memory and the string pool until garbage collection, so the password remains accessible long after it is needed. Instead, always use `char[]` arrays, which you can explicitly clear with `Arrays.fill(password, '\0')`. This is why Java's `Console.readPassword()` returns `char[]` instead of `String`.
- Be aware of dead store removal: compilers may optimize away `memset()` or similar clearing calls if the variable is never used again after being cleared, which means the sensitive data remains in memory despite your cleanup code.

---

## 9. Attack Surface

> **ASKED ON EXAM** — Single Statement Q3 (~2-3 pts): *"Describe the concept of 'Attack Surface' and what parameter can have an influence on it."* (Covered in Phase 1 notes — see there for the full answer.)

Quick recap: The attack surface is the number and nature of the inputs for a given system. It increases when you add more user inputs (e.g., new input fields or features) and when the input space for any given input grows larger (e.g., allowing markup language instead of plaintext).

---

## 10. Additional Defensive Coding Principles (Quick Reference)

> **NOT ASKED directly on past exam** — these could appear in unseen code snippets.

| Principle | Key Point |
|---|---|
| Native Wrappers | If you use another language through a native interface (e.g., Java Native Interface), you inherit all the security risks of that language. You should treat native calls as external entities and perform input validation on data passed to them. |
| Character Conversions | Not all character sets use the same size per character. You should always use UTF-8 or UTF-16, and never roll your own character converters. Be aware that Punicode attacks can make malicious URLs look legitimate. |
| HTTP Specs | HTTP GET requests should never have persistent side effects. State-changing operations must use POST or other appropriate methods. Violating this principle makes your application vulnerable to CSRF attacks. |
| DoS Forms | Denial of Service can occur in many ways, including overflowing the hard drive, overflowing memory, causing constant hash collisions with poor hash codes, triggering slow database queries, exploiting poor algorithmic complexity, or causing deadlocks. |
| Config Files | Configuration files are code and should be treated with the same security rigor. Common mistakes include committing hardcoded credentials in `.env` files, leaving default passwords in `docker-compose.yml`, and insecure logging configurations like the Log4j JNDI vulnerability. |

---

## 11. VOTDs: EL Injection (CWE-917)

> **NOT ASKED on past exam** — know the pattern for unseen code snippets.

- Template engines use expression languages to make pages dynamic, such as `${username}` in JSP/Thymeleaf or `%{username}` in Struts2/OGNL.
- If the username contains something like `${Runtime.getRuntime().exec('calc')}`, the template engine will evaluate it as code, leading to Remote Code Execution.
- The core problem is that the string or template engine becomes a code executor when user input is embedded directly.
- The mitigation is to never embed user input directly into expression language contexts and to use parameterized templates that treat user input strictly as data.

---

## 12. VOTDs: Server-Side Request Forgery (CWE-918)

> **NOT ASKED on past exam** — know the pattern for unseen code snippets.

- SSRF occurs when a server fetches URLs that are controlled by user input, which means the server ends up making requests on behalf of the attacker.
- This is dangerous because attackers can bypass firewalls to access internal services (e.g., `http://localhost/admin`), steal cloud credentials (e.g., `http://169.254.169.254/` on AWS returns IAM credentials), and read local files (e.g., `file:///etc/passwd`).
- The mitigation is to use an allowlist of permitted URLs or domains, validate and sanitize all URL inputs, and block requests to internal IP ranges.

---

## 13. VOTDs: Unsafe Deserialization (CWE-502)

> **NOT ASKED on past exam** — but high-profile vulnerability. Know the defense.

- Gadget chain attacks work by chaining together innocent-looking method calls during deserialization. For example, `HashMap.readObject()` calls `hashCode()`, which calls `equals()`, which calls `compare()`, and eventually the chain reaches `Runtime.exec("malicious command")`.
- This vulnerability affects multiple languages: Java (`ObjectInputStream`), Python (`pickle.loads()`), PHP (`unserialize()`), and C# (`BinaryFormatter.Deserialize()`).
- The defense is simple: **never use native object deserialization with untrusted data. Always use structured data-only formats like JSON or Protocol Buffers instead.**

---

## 14. Code Snippet Analysis — Exam Pattern

> **ASKED ON EXAM** — Defensive Coding Principles in Practice (~16 pts total, 4 snippets × 4 pts each): *"Identify the line with the mistake (1 pt), state the issue briefly (1 pt), describe the mitigation briefly (2 pts)."*

### Universal 5-Step Method for ANY Code Snippet (Language-Independent)

You do not need to know the programming language. Every code snippet vulnerability can be found by running through these five steps in order. Apply them line by line, top to bottom.

**Step 1: Find where user input enters the function.**
Look at the function's parameters. Whatever comes in as a parameter from outside is **untrusted user input**. Mentally label it as "TAINTED." This is your starting point — everything that happens to this tainted data matters.

**Step 2: Trace where the tainted data flows.**
Follow the tainted variable through every line. Ask yourself at each line: "Is my tainted data being used here?" Specifically watch for these dangerous destinations (called **sinks**):
- Is the tainted data written into **HTML or a web page**? That is a potential XSS vulnerability.
- Is the tainted data concatenated into a **database query string** (you will see SQL keywords like `SELECT`, `INSERT`, `WHERE`)? That is a potential SQL Injection.
- Is the tainted data used as a **file path**? That is a potential Path Traversal.
- Is the tainted data used as a **URL that the server will fetch**? That is a potential SSRF.
- Is the tainted data passed into a **template engine or expression evaluator** (look for `${}`, `%{}`)? That is a potential Expression Language Injection.
- Is the tainted data fed into a **deserialization function** (look for words like `readObject`, `deserialize`, `pickle`, `unserialize`)? That is a potential Unsafe Deserialization.

**Step 3: Check if there is any sanitization or validation — and whether it is good enough.**
If you see the code doing something to the tainted data before using it (like replacing, filtering, or checking it), ask: "Is this a denylist or an allowlist?" A denylist removes specific bad values (like removing only `<script>`) and is almost always insufficient because attackers can use countless variations. An allowlist only permits known-good values and is the secure approach. If there is no sanitization at all before the data reaches a dangerous sink, that is the vulnerability.

**Step 4: Scan for secrets and credentials in the code.**
Look for any string literals that look like passwords, usernames, API keys, connection strings, or tokens. If you see something like `"root"`, `"password123"`, `"sk_live_..."`, or any string passed as a credential argument to a connection or authentication function, that is a **hardcoded credentials** vulnerability. Secrets must never appear in source code.

**Step 5: Check error handling and resource management.**
Look at `catch` blocks or error handling sections. If an error message includes internal details (file paths, database names, configuration locations, exception stack traces), that is an **information leakage** vulnerability (CWE-209). Also check whether resources that are opened (like database connections or file handles) are properly closed in a `finally` block or equivalent.

### How to Write Your Exam Answer

For each issue you find, write exactly three things:
1. **Line:** State the line number where the problem is.
2. **Issue:** Name the vulnerability type (e.g., "SQL Injection," "XSS," "Hardcoded Credentials") and explain in one sentence why it is dangerous.
3. **Mitigation:** Describe what should be done instead, in one or two sentences. You do not need to write corrected code — a clear description of the fix is enough for full marks.

### Applying the 5-Step Method to Snippet 1 — Web Page Generator

```java
 1  public void generateWebpage(String input) {
 2      BufferedWriter bw = null;
 3      File f = new File(pagePath);
 4      try {
 5          FileWriter fw = new FileWriter(f);
 6          bw = new BufferedWriter(fw);
 7          bw.write("<html>");
 8          bw.write("<body>");
 9          bw.write("<span>Your name is: ");
10          input = StringUtils.replace(input, "<script>", "");  // ← LINE 11 on exam
11          bw.write(input);
12          bw.write("</span>");
13          bw.write("</body>");
14          bw.write("</html>");
15          bw.close();
16      } catch (IOException e) { /* handled */ }
17  }
```

**Walkthrough using the 5 steps:**
- **Step 1:** The parameter `input` is user input. It is tainted.
- **Step 2:** The tainted `input` is written into HTML (lines 7-14 are clearly building an HTML page, and line 11 writes `input` directly into it). This is a dangerous sink for XSS.
- **Step 3:** Line 10 attempts sanitization by replacing `<script>` with an empty string. This is a **denylist** — it only blocks one specific tag. An attacker can bypass it with `<SCRIPT>`, `<scr<script>ipt>`, `<img onerror="alert(1)">`, `<svg onload="...">`, and countless other variations. The sanitization is insufficient.
- **Step 4:** No hardcoded credentials visible.
- **Step 5:** Error handling is noted as correct by the exam.

**Exam answer:**
- **Line:** 11 (the `StringUtils.replace` line)
- **Issue:** This is a denylist-based sanitization that only removes the exact string `<script>`. This is a **Cross-Site Scripting (XSS)** vulnerability because attackers can use endless variations that are not on the denylist, such as `<SCRIPT>`, `<img onerror="...">`, or nested tags like `<scr<script>ipt>`.
- **Mitigation:** Use a proper HTML encoding library that escapes all HTML special characters (`<`, `>`, `"`, `'`, `&`) instead of blocking specific tags. This is an allowlist-based approach where only safe characters pass through unchanged. Alternatively, use a templating engine with automatic output escaping built in.

### Applying the 5-Step Method to Snippet 2 — User Finder

```java
 1  public void findUser(String friendName) {
 2      Connection conn = DriverManager.getConnection(
           "jdbc:mysql://localhost:3306/example_db",
           "root", "root_password1337");  // ← ISSUE 1
 3      Statement stmt = conn.createStatement();
 4      String query = "SELECT * FROM Users WHERE username = '" + userInput + "'";  // ← ISSUE 2
 5      ResultSet rs = stmt.executeQuery(query);
 6      while (rs.next()) {
 7          System.out.println("Found user: " + rs.getString("username"));
 8      }
 9      rs.close();
10      stmt.close();
11      conn.close();
12  }
```

**Walkthrough using the 5 steps:**
- **Step 1:** The parameter `friendName` is user input (and `userInput` on line 4 is also user input based on the variable name). Both are tainted.
- **Step 2:** On line 4, the tainted `userInput` is concatenated directly into a SQL query string using `+`. You can see the SQL keywords `SELECT`, `FROM`, `WHERE` — this is clearly a database query. The tainted data is placed inside the query without any separation between data and code. This is the classic pattern for **SQL Injection**.
- **Step 3:** There is no sanitization or parameterization whatsoever on the user input before it reaches the SQL query.
- **Step 4:** On line 2, you can see two string literals `"root"` and `"root_password1337"` being passed as arguments to a database connection function. These are clearly a username and password written directly in the source code. This is **hardcoded credentials**.
- **Step 5:** Resources are closed on lines 9-11, but not in a `finally` block, so if an exception occurs they will leak. However, the two main issues (SQL Injection and hardcoded credentials) are the primary vulnerabilities here.

**Exam answer — Issue 1 (Hardcoded Credentials):**
- **Line:** 3 (the connection line with `"root"` and `"root_password1337"`)
- **Issue:** Database credentials are **hardcoded in the source code** as plaintext strings. Anyone who can access or reverse-engineer the code can extract these credentials and gain full database access. You cannot keep secrets in source code.
- **Mitigation:** Store credentials in an **external configuration file** with restricted file permissions, or use environment variables or a secure credential management system. Never write passwords directly in code.

**Exam answer — Issue 2 (SQL Injection):**
- **Line:** 5 (the string concatenation with `+ userInput +` inside a SQL query)
- **Issue:** User input is directly concatenated into the SQL query string using `+`. This is a classic **SQL Injection** vulnerability. An attacker can input something like `' OR '1'='1` to return all users, or `'; DROP TABLE Users;--` to delete the entire table.
- **Mitigation:** Use **parameterized queries** (also called prepared statements) where the user input is passed as a separate parameter, not concatenated into the query string. This ensures the database treats user input strictly as data, never as executable SQL code.

### Quick-Reference: Vulnerability Patterns to Scan For

These are the patterns you are looking for when applying Steps 1-5. For each one, you need to know the vulnerability name, how to recognize it, and the mitigation.

| What You See in the Code | Vulnerability Name | Why It Is Dangerous | Mitigation |
|---|---|---|---|
| User input written into HTML or a web page without encoding | **Cross-Site Scripting (XSS)** | An attacker can inject JavaScript that executes in other users' browsers, stealing cookies or session tokens. | Use an HTML encoding library that escapes all special characters, or use a templating engine with auto-escaping. |
| User input concatenated into a SQL query string with `+` or similar | **SQL Injection** | An attacker can modify the query to read, modify, or delete any data in the database, or bypass authentication entirely. | Use parameterized queries (prepared statements) where user input is passed as a separate parameter, never concatenated. |
| Passwords, API keys, or tokens written as string literals in the code | **Hardcoded Credentials** | Anyone with access to the source code or compiled binary can extract the credentials and gain unauthorized access. | Store credentials in external configuration files with proper permissions, or use environment variables or a secret management system. |
| A replace or filter that removes only specific bad values (e.g., removing `<script>`) | **Denylist Sanitization (Incomplete)** | Attackers can always find variations not on the list, such as different capitalizations, nested tags, or alternative HTML elements. | Use an allowlist approach that only permits known-good characters, or use a library that escapes all dangerous characters. |
| Error messages or catch blocks that print file paths, database names, or stack traces | **Information Leakage (CWE-209)** | An attacker learns internal details about the system architecture, file locations, and database structure, making further attacks easier. | Show only generic error messages to users (e.g., "An error occurred"). Log detailed error information internally where users cannot see it. |
| Resources like database connections or files opened but not closed in a `finally` block | **Resource Leak** | If an exception occurs before the close statement, the resource stays open, which can lead to denial of service through resource exhaustion. | Always close resources in a `finally` block or use try-with-resources (in languages that support it) to guarantee cleanup. |
| User input passed into a deserialization function (e.g., `readObject`, `pickle.loads`, `unserialize`) | **Unsafe Deserialization (CWE-502)** | The attacker can craft a malicious serialized object that executes arbitrary code on the server when deserialized. | Never deserialize untrusted data using native object serialization. Use structured data-only formats like JSON and manually construct objects after validation. |
| User input used directly as a file path (especially if you see `../` or path-building logic) | **Path Traversal** | An attacker can use `../../etc/passwd` to access files outside the intended directory, reading sensitive system files. | Use an allowlist of permitted file paths, validate that the resolved path stays within the intended directory, and use proper permission management. |
| User input used as a URL that the server fetches | **Server-Side Request Forgery (SSRF)** | The attacker tricks the server into making requests to internal services, potentially accessing admin panels, cloud credentials, or local files. | Use an allowlist of permitted URLs or domains, block internal IP ranges, and validate all URL inputs before the server fetches them. |
| User input placed inside a format string function like `printf(input)` | **Format String Vulnerability (CWE-134)** | An attacker can use format specifiers like `%x` to read memory or `%n` to write to memory, leading to information disclosure or code execution. | Always use a fixed format string with the user input as a separate argument, like `printf("%s", input)`. |

---

## 15. Secure Code vs. Security Code

> **NOT ASKED directly on past exam** — but important distinction for understanding defensive coding.

- **Secure code** refers to the property of your application code as a whole — it means the software was constructed following a secure development lifecycle.
- **Security code** refers to software components specifically designed to implement security functionality, such as cryptographic libraries, TLS libraries, sanitization libraries, OAuth frameworks, and access-control frameworks.
- Secure code requires both secure implementation of your own code AND secure usage of the security code libraries you depend on.
- **The rule is: unless you are a security expert, do not implement security code yourself.** Instead, use reputable, independently certified, open-source libraries, and always read their documentation (RTFM).

---

## 16. Insecure Cryptographic Hash Function

> **ASKED ON EXAM** — Single Statement Q2 (~2-3 pts): *"Name one insecure cryptographic hash function and describe why it is considered broken."*

### Exam answer:

> **MD5** is an insecure cryptographic hash function. It is considered broken because practical collision attacks have been demonstrated — two different inputs can be found that produce the same hash digest. This means an attacker can create a malicious file with the same hash as a legitimate file, breaking integrity verification. Collision attacks against MD5 can be performed in seconds on modern hardware.

Alternative answer: **SHA-1** is also considered broken — Google demonstrated a practical collision attack ("SHAttered") in 2017.

**Secure alternatives:** SHA-2 family (SHA-256, SHA-512), SHA-3.

---

## 17. Hashing — Full Concept

> **ASKED ON EXAM (partially)** — Q2 tests insecure hashes. Salting/unsalted hashes are important for code review and general knowledge.

### What is Hashing?
- Hashing transforms a chunk of data into a very large number with no way to reverse the process. This provides **integrity** — you can verify that data has not been modified.
- Hashing serves two purposes: first, checking the integrity of data by comparing hash digests, and second, proving possession of a secret (like a password) without revealing the secret itself.
- Even changing a single bit in the input should result in a completely different hash digest.
- A collision occurs when two different inputs produce the same hash digest, which is a serious problem because it undermines integrity.
- The modern secure algorithms are the **SHA-2 family** (SHA-224, SHA-256, SHA-384, SHA-512) and **SHA-3**.

### Authentication with Hashes (Password Storage)
- When a user sets a password, the server hashes it and stores only the hash, never the plaintext.
- When the user authenticates, the server hashes the provided password and compares it to the stored hash.
- If the database is stolen, the attacker only gets the hashes, not the plaintext passwords, so they cannot directly use them.

### Unsalted Hashes — VOTD
- Unsalted hashes are vulnerable to **rainbow table attacks** (precomputed lists of hashes for common passwords), **dictionary attacks** (trying a list of common passwords), and **brute force attacks** (trying every possible password).
- The solution is **salting**, where a random string is appended to the password before hashing.

### How NOT to Salt
- The approach `hash = secureHashAlg("myCompanySalt" + password)` has TWO problems:
  1. The salt is global, meaning an attacker can still precompute a rainbow table for the entire company or service — they just cannot reuse existing rainbow tables from other services.
  2. The salt is prepended to the password, which enables **length-extension attacks**. An attacker can save the internal state of the hashing algorithm after it has processed the known salt, and then very quickly compute individual password hashes from that saved state.

### Salting Done Right
- Each user or password must get a **different, random salt** that is at least 32 bits long.
- The salt should be generated using a **secure random source**.
- The salt is stored in **plaintext** alongside the hashed and salted password. The salt itself is not a secret — its purpose is to make precomputation of rainbow tables infeasible because each password requires its own individual computation.

---

## 18. Symmetric Encryption

> **ASKED ON EXAM (indirectly)** — Q5 tests hybrid encryption, which requires understanding symmetric + asymmetric.

- Symmetric encryption uses **one key** for both encryption and decryption, which means the key must be kept secret by both parties.
- The modern standard algorithm is **AES** (Advanced Encryption Standard), which is fast, widely used, and was standardized by NIST in 2001. It is commonly used for encrypting large data such as backups and hard drives.
- AES is a **block cipher**. It is not mathematically proven to be secure, but it has not yet been cracked.
- The tricky part is that the key must be known by the decrypting party only, which requires either pre-shared keys or secure key-exchange protocols.
- **The fundamental problem with symmetric encryption is key distribution:** how do you securely share the secret key with the other party over an insecure channel?

### Stream vs. Block Ciphers
- A **stream cipher** transforms the key into a continuous keystream, and the plaintext is converted to ciphertext by XOR-ing it with the keystream.
- A **block cipher** splits the plaintext into blocks of fixed size and encrypts each block separately. Block ciphers are quite efficient and can be parallelized.

### Block Cipher Modes of Operation
- **ECB** (Electronic Codebook) encrypts each block independently. It is **insecure** because it preserves patterns in the data (the famous penguin image demonstrates this visually).
- **CBC** (Cipher Block Chaining) XOR's each plaintext block with the previous ciphertext block before encrypting, using an initialization vector for the first block. This hides patterns.
- **CTR** (Counter) encrypts an incrementing counter value and XOR's the result with the plaintext.
- **GCM** (Galois/Counter Mode) combines CTR mode with built-in authentication. It is the preferred mode for authenticated encryption.

---

## 19. Asymmetric (Public-Key) Encryption

> **ASKED ON EXAM (indirectly)** — needed for hybrid encryption answer.

- In asymmetric encryption, every party has **two keys**: a public key that others use to encrypt data, and a private key that only the owner uses to decrypt it.
- This **solves the key exchange problem** because anyone can encrypt a message using your public key, but only you can decrypt it with your private key.
- The disadvantage is that asymmetric encryption is **significantly slower** than symmetric encryption, making it impractical for large amounts of data.
- The modern algorithms are **RSA** (which requires at least 4096-bit key length and is based on the difficulty of factoring large prime numbers) and **ED25519** (which uses Elliptic Curve cryptography).
- The tricky part is ensuring that a key pair actually belongs to the stated person. This problem is solved through **certificates**, where a trusted central authority signs the public key to guarantee its authenticity.

---

## 20. Hybrid Encryption

> **ASKED ON EXAM** — Single Statement Q5 (~2-3 pts): *"Name the problems in symmetric and public-key encryption that hybrid encryption is solving. Describe how."*

### Exam answer:

> **Problems solved:**
> - **Symmetric encryption** is fast but has a **key distribution problem** — both parties need the same secret key, and there's no secure way to exchange it over an insecure channel.
> - **Public-key (asymmetric) encryption** solves key distribution but is **too slow** for encrypting large amounts of data.
>
> **How hybrid encryption solves both:**
> 1. Generate a random **symmetric session key**
> 2. Use **public-key encryption** to encrypt and transmit the session key (slow, but key is small)
> 3. Use the **symmetric session key** to encrypt the actual data (fast, handles large data)
> 4. At end of communication, throw away the session key
>
> This combines the speed of symmetric encryption with the key distribution advantage of public-key encryption.

---

## 21. Message Authentication Codes (MAC)

> **NOT ASKED directly on past exam** — but connects to integrity/authentication. Know the concept.

- A MAC computes a hash for a message **using a symmetric key**, so both the sender and receiver must share the same key.
- MACs provide **authentication and integrity**, meaning they guarantee who sent the message and that the message was not modified in transit.
- MACs do **not** provide confidentiality (the message is not encrypted) or non-repudiation (since both parties share the key, either could have created the MAC).
- There are two main types:
  - **CMAC** is based on block ciphers. The most common form is AES in CBC mode, which is called CBC-MAC.
  - **HMAC** (also called keyed hashes) is based on hashing algorithms. The key and message are hashed together.
- MACs are best suited for single-party scenarios, such as writing a file to disk with a MAC and validating the MAC when reading the file again.

### Combinations (Authenticated Encryption)
- Encryption provides confidentiality, while MACs provide authentication and integrity. Combining both achieves all three properties.
- **Encrypt-then-MAC** is the most secure combination: first encrypt the plaintext, then compute a MAC over the ciphertext, and append the MAC. This provides integrity of both the ciphertext and indirectly the plaintext.
- The other combinations are Encrypt-and-MAC (encrypt and MAC the plaintext separately) and MAC-then-Encrypt (MAC the plaintext, then encrypt both). Both are considered less secure than Encrypt-then-MAC.

---

## 22. Digital Signatures

> **NOT ASKED directly on past exam** — but connects to non-repudiation. Know the concept.

- A digital signature is created with the signer's **private key** by first hashing the message and then "encrypting" the resulting hash.
- The signature is verified with the signer's **public key** by "decrypting" the signature and comparing the result with a freshly computed hash of the original message.
- Digital signatures provide **non-repudiation, authentication, and integrity**. Non-repudiation means the signer cannot deny having signed the message, because only they possess the private key.
- Digital signatures do **not** provide confidentiality — the message itself is not encrypted.
- The tricky part is how to trust that a public key actually belongs to the person who claims to own it. There are four approaches:
  1. Only trust keys you have personally received from the owner.
  2. Use a Web of Trust, where you sign the public keys of people you trust, and others who trust you can transitively trust those keys.
  3. Use trusted key servers that store public keys.
  4. Use **certificates**, where a central authority signs a public key to officially guarantee its authenticity.

### JWT (JSON Web Token)
- JWT is an open standard for securely transmitting information between parties as a digitally signed token.
- JWTs can be signed using either a shared secret or a private/public key pair.
- The structure is **Header.Payload.Signature**: the header specifies the token type and signing algorithm, and the payload contains claims (statements about the entity).
- Claims come in three types: registered claims (like `iss`, `exp`, `sub`, `aud`), public claims, and private claims.
- The payload is only Base64 encoded, which means it is **readable by anyone**. This is important to understand: JWT provides authentication and integrity, but it does **not** provide confidentiality.

---

## 23. TLS (Transport Layer Security)

> **NOT ASKED directly on past exam** — but connects to secure connections. Know the cipher suite.

- TLS (Transport Layer Security) establishes connections that are encrypted, authenticated, and integrity-checked. It is the protocol used in HTTPS.
- TLS is configured with **cipher suites** that specify which algorithms to use. For example, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` defines the key exchange algorithm (Diffie-Hellman with RSA using Elliptic Curves), the bulk encryption algorithm (AES with 128-bit keys in Galois Counter Mode), and the MAC algorithm (SHA256).

### Secure Connection Properties (three requirements):
1. **Encrypted** means that sent messages can only be read at the communicating endpoints, providing confidentiality.
2. **Authenticated** means that both endpoints know for sure they are communicating with the right counterparts, established through cryptographic certificates.
3. **Tamper-proof** means that integrity checks assure messages are received exactly as they were sent, using hashing or MACs.

---

## 24. Hardcoded Credentials — VOTD

> **ASKED ON EXAM (indirectly)** — appears in Snippet 2 of the code review section.

- Hardcoded credentials means passwords are stored as plaintext strings directly in the source code.
- When the code is compiled, these strings can be easily extracted from the bytecode using reverse-engineering tools.
- Attackers can and will reverse-engineer your code, and obfuscation is not a viable defense because attackers have time and are creative.
- The key takeaway from the lecture is: **"You cannot keep secrets in your source code!"** This applies to passwords, license keys, encryption keys, and any other sensitive information.
- **The mitigation is to never store cleartext passwords anywhere in the code.** Instead, store credentials in external configuration files with proper file permissions, or use environment variables or a secure credential management system.

---

## 25. Crypto Takeaway Summary (from lecture)

> **NOT ASKED directly on past exam** — but critical for understanding what primitive to use when.

| Primitive | Provides | Does NOT Provide |
|---|---|---|
| **Encryption** | Confidentiality | Integrity, Authenticity |
| **MAC** | Integrity, Authenticity | Confidentiality, Non-repudiation |
| **Digital Signature** | Integrity, Authenticity, Non-repudiation | Confidentiality |
| **Hashing** | Integrity | Confidentiality, Authentication |

**Key rules:**
- You should never roll your own cryptographic implementations, because even small mistakes can completely break the security.
- However, you should also never skip using cryptography when it is needed, because leaving data unprotected is equally dangerous.
- Always use standardized algorithms such as AES, RSA, and SHA-2/SHA-3.
- The choice of which cryptographic primitive to use depends heavily on the specific application context and what security properties you need.

---

## Active Recall Quiz — Phase 3

Answer these as you would write them on the exam. Cover the notes above first.

**Q1.** Present an argument for "Complexity is the enemy of security." Name and describe two complexity types.

**Q2.** Name one insecure cryptographic hash function and explain why it's broken.

**Q3.** What problems does hybrid encryption solve? How does it solve them?

**Q4.** You see this line in a code review: `input = StringUtils.replace(input, "<script>", "");` — What's the issue? What's the mitigation?

**Q5.** You see `String query = "SELECT * FROM Users WHERE username = '" + userInput + "'";` — Identify the vulnerability and write the mitigation code.

**Q6.** What is the difference between a denylist and an allowlist for input validation? Which does the lecture recommend?

**Q7.** Why should you never store passwords in Java Strings? What should you use instead?

**Q8.** What's wrong with this salting approach: `hash = secureHashAlg("myCompanySalt" + password)`? Name both problems.

---

## Connections to Other Phases

- **Phase 1 → Phase 3:** CIA triad maps directly to crypto primitives (Confidentiality → Encryption, Integrity → Hashing/MAC, Authentication → Signatures/Certificates)
- **Phase 2 → Phase 3:** Trust boundaries identified in threat modeling determine WHERE to apply defensive coding (input validation at every trust boundary crossing). STRIDE threats map to defensive coding mitigations (Tampering → integrity checks, Information Disclosure → encryption, Spoofing → authentication).
- **Phase 3 → Phase 4:** Code review tools (static analysis, taint analysis from Phase 4) automate detection of the exact vulnerabilities you learn to spot manually here.
