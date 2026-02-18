# Phase 4: Code Review, Static/Dynamic Analysis, Vulnerability Assessment & TDD (~10 pts)

**Lectures:** lect-07 (Code Review, Clean Code, TDD, SAST intro), lect-06 (SAST continued, Taint Analysis, DAST), lect-03 (Dynamic Analysis, Fuzzing, Instrumentation), lect-04 (Vulnerability Assessment, CVSS)
**Time budget:** ~1.5 hours
**Exam payoff:** TDD (3 pts), Risk Mgmt vs Vuln Assessment (~2-3 pts already in Phase 1), remaining points come from unseen code snippet VOTDs

---

## 1. Test Driven Development (TDD)

> **ASKED ON EXAM** — TDD (3 pts): *"You must implement a FIFO using TDD. What are the first three tests (1 pt each)? Describe them briefly."*

### What is TDD?

TDD is a development methodology where you convert requirements into test cases and write the tests before writing the implementation code. The idea is to force the requirements to be fulfilled by writing the tests first.

### The TDD Cycle (Red-Green-Blue):

1. **Red:** Write a failing test for the next small piece of functionality, before writing any production code.
2. **Green:** Write the minimum code necessary to make that test pass. Do not write anything beyond what the test demands.
3. **Blue (Refactor):** Clean up the code while keeping all tests passing. Remove duplication and improve structure.

### TDD Rules:

1. Do not write production code that is more specific than what the tests require. Tests make the test suite more specific, while production code makes the application more general.
2. Do not go for the goal. Avoid implementing the central behavior as long as possible — build up to it incrementally.
3. Do not bring TDD to your team if you are not yet skilled at it. Practicing on personal or small projects first is essential.

### Exam Answer — FIFO First Three Tests:

A FIFO (First In, First Out) data structure has the methods `void push(int x)`, `int pop()`, and `int size()`.

> **Test 1:** After creating a new empty FIFO, I expect `size()` to return 0. This establishes the base case that a freshly created FIFO has no elements.
>
> **Test 2:** After calling `push(42)` once on an empty FIFO, I expect `size()` to return 1. This verifies that pushing an element increases the size.
>
> **Test 3:** After calling `push(42)` and then `pop()`, I expect `pop()` to return 42 and `size()` to return 0. This verifies the basic FIFO behavior of retrieving the element that was pushed.

### Security Benefits of TDD:

- Functionality tests already exist, so bugs are easier to find and fix when something breaks.
- Some security requirements can be translated directly into tests (e.g., "user cannot access another user's data").
- Some types of bugs are never created in the first place because the test-first approach forces you to think about edge cases.
- Tests serve as documentation showing how to correctly use functions, which reduces API misuse.
- TDD naturally leads to high test coverage, making it harder for vulnerabilities to hide in untested code paths.

---

## 2. Code Review

> **NOT ASKED on past exam** — but understanding code review variables is useful context for the defensive coding section.

### Why Code Reviews Matter:

Code reviews help catch security issues through human insight. Studies show that code review improves code quality and knowledge sharing, and industry consensus is strong that it also improves security (though isolating the security impact specifically is hard to measure empirically).

### Variables You Can Adjust in Code Reviews:

- Online or offline review
- Pair review or group review
- Asynchronous or synchronous
- During coding or after coding

### Best Practices:

- Keep reviews small — fewer than 200 changes increases participation significantly.
- Ensure adherence to coding conventions.
- Give constructive feedback with good communication.
- Prioritize what to review. Generally, make it easy for the reviewers.

---

## 3. Clean Code and Code Smells

> **NOT ASKED on past exam** — but connects to the complexity argument in Phase 3. Know the definitions.

### Clean Code

Clean code is code that is intuitively understandable. It does not have to be traditional programming code — it can also be YAML, database schemas, or configuration files. Since 80% of a project's lifecycle is spent on maintenance, feature expansion, and bug fixing, writing clean code is essential for long-term security.

### Code Smells

A code smell is a pattern in code that makes it less readable and maintainable. Code smells do not necessarily mean the code is broken, but they indicate potential problems that could lead to bugs or security vulnerabilities. Increased readability and changeability make security issues easier to find and fix.

### Top 3 Antipatterns and Their Refactorings:

1. **Long Method** — methods that are too long are hard to understand, test, and review for security issues. The refactoring is **Extract Method**: break the long method into smaller, focused methods with clear purposes.
2. **Improper Naming** — variables and functions with unclear names (like `data`, `tmp`, `process()`) make it hard to understand what data is trusted or sanitized. The refactoring is **Rename** to use descriptive names that indicate purpose and trust level (e.g., `sanitizedUserInput`, `validateAndParseRequest()`).
3. **Insufficient Encapsulation** — internal implementation details are exposed unnecessarily. The refactoring is **Extract Method** or **Move Method** to hide internals behind proper interfaces.

---

## 4. Static Application Security Testing (SAST)

> **NOT ASKED directly on past exam** — but taint analysis concepts help you understand the 5-step code review method from Phase 3. Know the definition and the four elements.

### Definition

Static Application Security Testing (SAST) analyzes source code for problematic patterns without executing the code. The goal is to find security issues and bad coding patterns early in the development lifecycle.

### What SAST Finds:

- Code injections caused by unvalidated and unsanitized inputs
- Usage of dangerous functions
- Hardcoded credentials
- And many other vulnerability patterns

### When SAST Is Used:

SAST is applied early in the SDLC, ideally in the IDE during development, but it can also be integrated into the build pipeline. It typically works on source code level, though some tools accept bytecode.

### SAST Limitations:

- **False positives (Crying Wolf):** SAST may flag safe code as vulnerable because it cannot always determine if sanitization is sufficient. For example, a custom sanitizer that the tool does not recognize might cause a false alert.
- **False negatives (Missed the Fire):** SAST may miss vulnerabilities when the tainted data flows through multiple classes or uses reflection, dependency injection, or dynamic proxies that are invisible to static analysis. The more abstract the code, the worse static analysis performs.
- There is an inevitable trade-off between false positives and false negatives. Each tool balances these differently, either through vendor defaults or user configuration.

### Tools:

Semgrep, Joern, CodeQL (GitHub/VSCode), SonarQube, IntelliJ built-in inspections.

---

## 5. Four Core Elements of Taint Analysis

> **NOT ASKED directly on past exam** — but this is exactly the theory behind the 5-step code snippet method from Phase 3. Understanding taint analysis helps you think systematically about code review.

Taint analysis tracks how "contaminated" (untrusted) data flows through a program to dangerous operations. It has four core elements:

1. **Sources** are input locations where potentially dangerous data enters the system. Examples include user inputs, HTTP parameters, file reads, environment variables, and database query results. These mark where "taint" enters the system.

2. **Sinks** are critical functions that could be exploited if they receive tainted data. Examples include SQL query execution (`executeQuery`), OS command execution (`system`), file operations, and `eval` functions. These are the dangerous destinations that must be protected.

3. **Propagation** is the tracking of how tainted data flows through the program. It follows data through variable assignments, function calls, and transformations, maintaining the taint status as data moves through intermediate steps.

4. **Sanitizers** are cleansing functions that remove the taint and make data safe. Examples include input validation functions, prepared statements, and escaping functions. These break the taint chain.

The key rule is: if tainted data reaches a sink without passing through a proper sanitizer, it is flagged as a potential vulnerability.

---

## 6. Code Property Graphs (CPG)

> **NOT ASKED on past exam** — low priority. Know that three graphs combine into one.

A Code Property Graph combines three types of program representations into a single queryable structure:

1. **Abstract Syntax Tree (AST)** captures program structure, types, and semantics. It enables pattern matching for bug detection. Its limitation is that it shows structure but not execution order, so you cannot determine which paths are reachable.

2. **Control Flow Graph (CFG)** captures all possible execution sequences from entry to exit. Edges show which statements can follow which, and true/false edges capture branch conditions. Its limitation is that it does not track data dependencies — you can see that a dangerous function can execute, but not where its input came from.

3. **Program Dependence Graph (PDG)** tracks data dependencies (which variables affect which computations) and control dependencies (which statements depend on which conditions). Data edges track value propagation, and control edges show conditional execution. This enables following tainted data from sources to sinks.

The CPG unifies all three into one structure that tools like Joern, Semgrep, and CodeQL can query to find source-to-sink flows along control paths.

---

## 7. Dynamic Application Security Testing (DAST)

> **NOT ASKED directly on past exam** — know the definition and the pros/cons compared to SAST.

### Definition

Dynamic Application Security Testing (DAST) is typically a black-box security testing method that attacks a running system "from outside" and observes its behavior, just like a real attacker would.

### How DAST Works (simplified):

DAST attacks interfaces and endpoints by fuzzing inputs (mutating benign test data and adding randomness), applying attack heuristics, and watching for unexpected behavior and crashes.

### DAST Advantages:

- No source code is required, and it is language-agnostic.
- It finds vulnerabilities that SAST overlooks, such as misconfigurations and real-world runtime errors.
- It provides the concrete input that triggers the vulnerability, which makes verification straightforward.
- It has significantly lower false positive rates than SAST because it observes real behavior.

### DAST Disadvantages:

- Simple source code constructs (like a condition checking for a specific username) can confuse DAST and prevent it from reaching vulnerable code.
- It requires a running system, so it is only applicable later in the SDLC.
- It requires good API documentation to know what endpoints to test.
- There is no defined endpoint — it is unclear when to stop testing.

### SAST vs. DAST Summary:

| Aspect | SAST | DAST |
|---|---|---|
| Development Phase | Early (IDE, build pipeline) | Late (needs running system) |
| Access to Code | Needs source code | No code required |
| False Positives | Frequent (theoretical paths) | Low (real behavior) |
| Code Coverage | 100% including dead code | Depends on test inputs |
| What It Finds | Injections, insecure patterns | Injections, misconfigurations, runtime errors |

The key takeaway is that SAST and DAST are complementary and should both be used as part of a defense-in-depth testing strategy.

---

## 8. Fuzzing and Instrumentation

> **NOT ASKED directly on past exam** — but understanding fuzzing helps with the general concept of security testing.

### Fuzzing

Fuzzing is a dynamic testing technique that sends mutated or malformed inputs to a system to trigger unexpected behavior and discover vulnerabilities. It consists of two main components:

1. **Input Generation** creates test inputs through mutating benign test data, payload variations, boundary value cases, and adding randomness.
2. **Bug Detection** monitors the system for crashes, timeouts, error messages, and data flow anomalies.

### Greybox Testing and Instrumentation

Greybox testing combines elements of black-box and white-box approaches by using partial internal information, specifically instrumentation feedback.

**Instrumentation** is the process of modifying software by injecting tracking markers so that analysis can observe which code paths are executed. For example, counter variables are inserted at each branch point in the code. The fuzzer then uses this coverage feedback to know whether newly generated inputs reached new code paths, and evolves its inputs to maximize coverage.

### Coverage Types:

- **Line/Statement coverage** measures which lines of code were executed during testing.
- **Branch coverage** tracks which decision paths (if/else branches) were taken.
- **Function coverage** records which functions were called.

Higher coverage means more code has been explored for potential vulnerabilities and helps reveal blind spots.

### Bug Detection Mechanisms:

1. **Crash Detection** catches segmentation faults, unhandled exceptions, and timeouts.
2. **Assertion Violations** check custom invariants like `assert()` statements that verify expected properties.
3. **Differential Testing** compares outputs across different implementations of the same functionality. If two parsers disagree on whether input is valid, it indicates a bug.
4. **Round-Trip Testing** verifies that encoding then decoding (or compressing then decompressing) produces the original data.
5. **Bug Oracles** are specialized detectors including memory sanitizers (for C/C++ buffer overflows), grammar-based oracles (that parse SQL queries to detect injection), and honeypot-based detection.

---

## 9. CVSS — Common Vulnerability Scoring System

> **NOT ASKED directly on past exam** — but the exercise covered it in depth, and it connects to risk management vs. vulnerability assessment.

### What is CVSS?

CVSS is an open scoring system from FIRST (Forum for Incident Response & Security Teams) that provides a standardized way to rate the severity of discovered vulnerabilities. It has been adopted by NIST and is added to CVE descriptions. The latest version is v3.1 (2019).

### Three Metric Groups:

**1. Base Metrics** capture core aspects of the vulnerability that do not change over time or across environments.

Exploitability metrics:
- **Attack Vector (AV):** How the vulnerability is accessed. Values range from Physical (P), to Local (L), Adjacent network (A), to Network (N). Network is the worst because it means fully remotely exploitable.
- **Attack Complexity (AC):** How complex the exploitation is. Low (L) means no special conditions and repeatable success. High (H) means specialized knowledge or conditions are needed. Note that Low complexity is bad (easier for attacker).
- **Privileges Required (PR):** What level of access is needed. None (N) means no authentication needed. Low (L) means basic user access. High (H) means administrative privileges.
- **User Interaction (UI):** Whether a user other than the attacker must participate. None (N) means direct exploitation. Required (R) means a user must take an action (like clicking a link).

Impact metrics:
- **Confidentiality, Integrity, Availability Impact:** Each rated as None (N), Low (L), or High (H). For example, reading arbitrary memory is High confidentiality impact, and root-level access is High on all three.

Scope:
- **Scope (S):** Whether the vulnerability can impact resources beyond the vulnerable component. Unchanged (U) means the vulnerable and impacted components are the same. Changed (C) means the vulnerability affects resources beyond its own authority (like a VM vulnerability compromising the host OS).

**2. Temporal Metrics** change over time as exploits become available and patches are released.
- **Exploit Code Maturity (E):** Ranges from Unproven (U) through Proof-of-Concept (POC) to Functional (F) and High/widely disseminated (H).
- **Remediation Level (RL):** Ranges from Unavailable (U) through Workaround (W) and Temporary Fix (TF) to Official Fix (O).
- **Report Confidence (RC):** Ranges from Unconfirmed (U) through Reasonable (R) to Confirmed (C).

**3. Environmental Metrics** reflect your organization's specific priorities and deployment.
- Modified Base Metrics allow recalculating base scores based on your environment.
- Security Requirements (CR, IR, AR) reweight the CIA impact based on how catastrophic each type of loss would be for your specific organization.

### Scoring Tips:

- Score each vulnerability individually, ignoring interactions with other vulnerabilities.
- Assume the most common or default configuration of the system.
- If there are many exploitation impacts, score the greatest one.

### Example — Heartbleed (CVE-2014-0160):

CVSS v3.1 Base Score: 7.5. The vulnerability was network-exploitable (AV:N), low complexity (AC:L), no privileges required (PR:N), no user interaction (UI:N), with high confidentiality impact.

---

## 10. Risk Management vs. Vulnerability Assessment

> **ASKED ON EXAM** — Single Statement Q6 (~2-3 pts): *"What are the differences between Risk Management and Vulnerability Assessment? Name briefly when to use each and why."* (Also covered in Phase 1 notes — see there for the full exam answer.)

Quick recap:

| Aspect | Risk Management | Vulnerability Assessment |
|---|---|---|
| Timing | Starts in early development phases (design) | Only applicable for existing systems |
| Focus | Based on potential threats (theoretical) | Applied to concrete, discovered vulnerabilities |
| Goal | Prevent important vulnerabilities before they occur | Fix and prevent further important vulnerabilities |
| Approach | Proactive — anticipates what could go wrong | Reactive — addresses what has gone wrong |

The key connection is: if risk management is used and updated throughout the lifecycle, it can support vulnerability assessment by providing context about which discovered vulnerabilities are most critical.

---

## 11. VOTDs Phase 4

### 11.1 Compression Bomb (CWE-409)

> **NOT ASKED on past exam** — know the concept for general awareness.

A compression bomb is a malicious file that exploits compression algorithms by creating a small compressed file that expands to an enormous size when decompressed, leading to Denial of Service by exhausting RAM or disk space. The famous example is 42.zip, which is 42 kilobytes compressed but expands to 4.5 petabytes through five layers of nested zip files. Compression bombs can appear in many formats including images (PNG, JPEG), office documents (which are ZIP archives of XML), XML bombs, HTTP responses, and even Git repositories.

**Mitigation:** Track how many bytes have been decompressed and enforce a limit. Limit decompression rounds. Use distrustful decomposition to limit resources available to the decompression process.

### 11.2 Cache Poisoning

> **NOT ASKED on past exam** — know the concept for general awareness.

Cache poisoning is an attack technique where an attacker causes a cache (such as a DNS cache) to store incorrect or malicious data. In the BIND DNS example, the attacker continuously issues DNS queries while also sending forged responses with guessed nonces. When a correct nonce is coincidentally matched, the server caches the bogus record, and all subsequent queries return the attacker's malicious address.

**Mitigation:** Do not allow users much control over caches. Use input validation. For DNS specifically, use DNSSec. For web caches, properly configure cache rules to never cache authenticated content, and use cache-control headers like `Cache-Control: no-store, private`.

### 11.3 Uncontrolled Format String (CWE-134)

> **NOT ASKED directly on past exam** — but could appear in an unseen code snippet (Phase 3 universal method covers this).

This vulnerability occurs when user-controlled input is passed directly as the format string to `printf`-family functions (e.g., `printf(str)` instead of `printf("%s", str)`). Attackers can use format specifiers like `%x` to read memory values from the stack, or `%n` to write arbitrary values to memory.

**Mitigation:** Always set the format string explicitly (e.g., `printf("%s", str)`). If you cannot avoid loading format strings from outside, use allowlist-based sanitization. Enable compiler warnings like `-Wformat-security`.

### 11.4 OS Command Injection (CWE-78)

> **NOT ASKED directly on past exam** — but could appear in an unseen code snippet.

This vulnerability occurs when unsanitized user input is forwarded to an operating system command, similar to SQL injection but targeting the OS shell. String concatenation is typically used to build commands that execute unintended operations. For example, if the input is `8.8.8.8; rm -rf /`, the command `ping 8.8.8.8; rm -rf /` would execute both the ping and the destructive delete.

**Mitigation:** Restrict OS calls to a single command (e.g., in Java, use the `ProcessBuilder` API instead of `Runtime.exec()`). Generally avoid OS calls whenever possible. Restrict inputs to commands via an allowlist.

---

## 12. Linter vs. Full SAST Tool

> **NOT ASKED on past exam** — know the distinction in case of a question about code quality tools.

A **linter** focuses on code style, formatting, and simple patterns. It performs surface-level, syntactic checks like naming conventions, indentation, unused variables, and basic code smells. Examples include ESLint, Pylint, and RuboCop.

A **full SAST tool** focuses on security vulnerabilities and complex bugs. It performs deep semantic analysis with data flow tracking, looking for injection vulnerabilities, taint analysis from sources to sinks, authentication issues, cryptographic misuse, race conditions, and memory safety issues. Examples include Semgrep, SonarQube, CodeQL, and Coverity.

The key difference is that linters check **how** code is written (style), while SAST tools check **what** code does (security and correctness).

---

## Active Recall Quiz — Phase 4

Answer these as you would write them on the exam.

**Q1.** You are implementing a FIFO data structure with `push(int x)`, `pop()`, and `size()` using TDD. Write the first three tests.

**Q2.** What are the three steps of the TDD cycle? Name them and describe each in one sentence.

**Q3.** What are the four core elements of taint analysis? Name and describe each briefly.

**Q4.** What is the difference between SAST and DAST? Name one advantage and one disadvantage of each.

**Q5.** What does CVSS stand for and what are its three metric groups?

---

## Connections to Other Phases

- **Phase 1 connections:** Risk Management vs. Vulnerability Assessment was first introduced in Phase 1. CVSS connects to the risk formula `Risk = p(occurrence) × impact` by providing a standardized way to score the impact side.
- **Phase 2 connections:** STRIDE threat modeling identifies theoretical threats; vulnerability assessment (CVSS) rates concrete discovered vulnerabilities. Protection Poker assesses risk before implementation; CVSS assesses severity after discovery.
- **Phase 3 connections:** The taint analysis concepts (sources, sinks, sanitizers, propagation) are the formal theory behind the 5-step universal code snippet method from Phase 3. SAST tools automate the exact pattern you apply manually during code review. The VOTDs from Phase 3 (XSS, SQL injection, hardcoded credentials) are exactly what SAST tools scan for.
- **Full chain:** Risk Analysis (Phase 2) feeds into Secure Design (Phase 2), which feeds into Defensive Coding (Phase 3), which is verified by Code Review + SAST + DAST (Phase 4), and any discovered issues are rated by CVSS (Phase 4).
