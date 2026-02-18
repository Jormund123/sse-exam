# Secure Software Engineering Exam — Model Answers (SSE 2425 WS 1)

Based on the SePA scenario from question-1.md.

---

## 1. Single Statement Questions (16 pts)

---

### Q1 (3 pts)

**Question:** What does the AAA principle stand for? Please name all three elements and describe them briefly.

**Answer:**

**Authentication** is the provision of assurance that a claimed characteristic of an entity is correct [ISO 27000:2016]. It verifies "who you are," for example through passwords, biometrics, or certificates.

**Authorization** is a right or permission that is granted to a system entity to access a system resource [IEC 62443-1-1]. It determines "what you can do," for example through access control lists or role-based permissions.

**Accountability (Non-Repudiation)** is the ability to prove the occurrence of a claimed event or action and its originating entities [ISO 27000:2016]. It ensures actions can be traced back to the responsible party, for example through logging, audit trails, or digital signatures.

---

### Q2 (2 pts)

**Question:** Please name one insecure cryptographic hash function and describe why it is considered broken.

**Answer:**

**MD5** is an insecure cryptographic hash function. It is considered broken because practical collision attacks have been demonstrated — two different inputs can be found that produce the same hash digest. This means an attacker can create a malicious file with the same hash as a legitimate file, breaking integrity verification. Collision attacks against MD5 can be performed in seconds on modern hardware.

---

### Q3 (2 pts)

**Question:** Please describe the concept of "Attack Surface" and what parameter can have an influence on it briefly.

**Answer:**

The attack surface is the number and nature of the inputs for a given system. It represents all the points where an attacker could potentially interact with the system to exploit a vulnerability.

The attack surface increases with **more user inputs** (e.g., adding new input fields or new features increases the number of entry points) and with a **larger input space for a given input** (e.g., allowing a markup language instead of plaintext dramatically increases the range of possible inputs the system must handle safely).

---

### Q4 (4 pts)

**Question:** Imagine you are using an LLM as one component in your software. Please describe two security considerations briefly that you have to address in this scenario.

**Answer:**

**1. Prompt Injection:** An attacker can craft malicious inputs that manipulate the LLM's behavior, causing it to ignore its instructions, reveal confidential system prompts, or perform unintended actions. The LLM cannot reliably distinguish between trusted instructions and untrusted user input, so all LLM output must be treated as untrusted and validated before acting on it.

**2. Data Leakage / Confidentiality:** The LLM may have been trained on or may be sent sensitive data. If user inputs are forwarded to an external LLM API, confidential information such as patient records or internal system details could be exposed to the LLM provider. Additionally, the LLM might reproduce sensitive training data in its outputs. Data sent to the LLM must be carefully controlled, and outputs must be sanitized before being shown to users or used in further processing.

---

### Q5 (3 pts)

**Question:** Please name the problems in symmetric and public-key encryption that hybrid encryption is solving. Describe how hybrid encryption is doing that briefly.

**Answer:**

**Problem with symmetric encryption:** It is fast, but both parties need the same secret key. There is no secure way to exchange this key over an insecure channel (the key distribution problem).

**Problem with public-key (asymmetric) encryption:** It solves the key distribution problem because anyone can encrypt with the public key and only the owner can decrypt with the private key. However, it is too slow for encrypting large amounts of data.

**How hybrid encryption solves both:** A random symmetric session key is generated. This small session key is encrypted using the recipient's public key and transmitted (slow, but the key is small). The actual data is then encrypted using the fast symmetric session key. At the end of the communication, the session key is thrown away. This combines the speed of symmetric encryption with the key distribution advantage of public-key encryption.

---

### Q6 (2 pts)

**Question:** What are the differences between Risk Management and Vulnerability Assessment? Please name briefly when to use each and why.

**Answer:**

**Risk Management** starts in early development phases (e.g., during design). It is based on potential threats to the system and is proactive — it anticipates what could go wrong. Use it early and throughout development to prevent important vulnerabilities before they occur.

**Vulnerability Assessment** is only applicable for existing systems. It is applied to concrete, discovered vulnerabilities and (ideally) corresponding exploits. It is reactive — it addresses what has already gone wrong. Use it after deployment or when vulnerabilities are found, to rate their severity and fix the most critical ones first.

If risk management is used and updated throughout the software lifecycle, it can also support vulnerability assessment by providing context about which discovered vulnerabilities are most critical for the specific system.

---

## 2. Misuse + Abuse Cases (7 pts)

---

### Q2a (3 pts)

**Question:** Please explain how:
1. Misuse/abuse cases differ from standard use cases in software engineering.
2. What roles Mis- and Abuse cases play in identifying and addressing potential security threats?

**Answer:**

**1. How they differ from standard use cases:**

Standard use cases describe the intended functionality of a system from the perspective of a legitimate user achieving a desired goal. Misuse and abuse cases, on the other hand, describe how the system can be used in ways that are harmful, either unintentionally or intentionally.

- A **misuse case** describes an unintentional misuse of the system by a legitimate user who makes a mistake or encounters an unexpected situation. It is a crime of opportunity. For example, a doctor accidentally views the wrong patient's records due to a typo.
- An **abuse case** describes an intentional attack by a malicious actor who actively seeks to exploit vulnerabilities. For example, an attacker deliberately tries to access patient data by stealing a doctor's chip card.

The key distinction is **intent**: misuse is unintentional (legitimate user making mistakes), while abuse is intentional (malicious actor seeking vulnerabilities).

**2. Roles in identifying and addressing security threats:**

Misuse and abuse cases help identify security threats by forcing the development team to think about what could go wrong from an attacker's perspective. They complement standard use cases by systematically exploring how functionality can be exploited. They feed directly into threat modeling and risk analysis, helping prioritize which threats need countermeasures. They also help define security requirements and security test cases that verify the system is resilient against these scenarios.

---

### Q2b (4 pts)

**Question:** Please describe two abuse cases for the scenario presented on the paper in front of you (SePA). In your answer, focus on typical real-world threats rather than highly specialized scenarios, and be sure to list any assumptions you make about the environment or users.

**Answer:**

**Abuse Case 1: Stolen Insurance Card**

- **Actor:** A malicious person who has stolen or found a patient's insurance card.
- **Goal:** Gain unauthorized access to the patient's medical records.
- **Scenario:** The attacker takes the stolen insurance card to a doctor's office (possibly by impersonating the patient or colluding with a doctor). The card is inserted into the Card Reader Terminal, which authorizes access to the patient's data for 30 days. The attacker (or colluding doctor) can now read sensitive medical records such as illness history, past visits, and referrals.
- **Assumption:** The system does not have additional identity verification beyond the physical insurance card (e.g., no photo ID check or biometric verification at the terminal).
- **Threatened properties:** Confidentiality (patient data is disclosed to unauthorized parties).

**Abuse Case 2: Rogue Doctor Accessing Records After Authorization Expires**

- **Actor:** A doctor (or someone who has gained access to the doctor's Office PC) who intentionally exploits the 30-day authorization window.
- **Goal:** Access patient records without the patient's ongoing consent or knowledge.
- **Scenario:** After a patient's visit, the doctor's authorization to access that patient's data remains valid for 30 days. The doctor (or an attacker who compromises the Office PC) can continue to read and modify the patient's records during this entire window without the patient being present or aware. The doctor could sell sensitive medical data, use it for blackmail, or modify records to cover up medical errors.
- **Assumption:** The system does not log or alert patients when their data is accessed, and no mechanism exists to revoke the 30-day authorization early.
- **Threatened properties:** Confidentiality (unauthorized reading of records), Integrity (unauthorized modification of records).

---

## 3. Threat Modeling (22 pts)

---

### Q3a (2 pts)

**Question:** Please name the three phases of the general threat modeling approach. You don't need to describe them.

**Answer:**

1. **Decompose** (the application)
2. **Determine** (the threats)
3. **Determine** (the countermeasures and mitigations)

---

### Q3b (8 pts)

**Question:** The following figure shows a data flow diagram for the SePA application. Please write down all trust boundaries you would define in this scenario by naming them based on the advice in the lecture and describing the corresponding edge numbers. Also, provide your reasoning for them briefly.

> E.g.: "Trust boundary 'Intergalactic interface' (Edges 10, 13, and 42): Since aliens can read our thoughts, ..."

**SePA DFD Edges:**
- Edge 1: Patient → CRT ("Provides patient ID")
- Edge 2: Office PC → CRT ("Requests read/write")
- Edge 3: CRT → Office PC ("Provides data from database")
- Edge 4: CRT → PDS ("Forwards read/write request")
- Edge 5: PDS → CRT ("authenticates")
- Edge 6: PDS → PDB ("Query for Patient Data")
- Edge 7: PDB → PDS ("Patient Data")

**Answer:**

**Trust Boundary 1: "Physical patient interface" (Edge 1)**
The patient is an external entity outside the system's control. When the patient provides their insurance card to the Card Reader Terminal, data crosses from an untrusted physical environment into the system. The patient's identity cannot be verified by the system beyond the card itself, so the card data must be validated. A stolen or cloned card would appear legitimate.

**Trust Boundary 2: "Doctor's office network boundary" (Edges 2, 3)**
The Office PC runs the doctor's software and communicates with the Card Reader Terminal over the local office network. The Office PC is a general-purpose computer that could be compromised by malware, used by unauthorized staff, or manipulated by a rogue doctor. Data flowing between the Office PC and the CRT crosses from a less trusted general-purpose environment to the secure gateway. Read/write requests from the Office PC must be validated by the CRT before forwarding.

**Trust Boundary 3: "VPN / Network boundary" (Edges 4, 5)**
Data flows between the Card Reader Terminal and the PatientDataService cross the network boundary via VPN. Even though the VPN provides encryption and authentication, this is a critical trust boundary because data leaves the physically controlled doctor's office environment and travels over an external network to the data provider's infrastructure. The CRT and PDS must mutually authenticate, and all data must be encrypted and integrity-checked.

**Trust Boundary 4: "Service-Database boundary" (Edges 6, 7)**
The PatientDataService communicates with the PatientDataDB. The database is only reachable by the service (not directly by clients), which is a deliberate trust boundary. The service must validate and sanitize all queries before passing them to the database to prevent SQL injection. The service acts as a gatekeeper ensuring that only properly authorized and well-formed requests reach the database.

---

### Q3c (12 pts)

**Question:** Based on the same figure, please conduct a **STRIDE per Element** analysis for the external entity "Patient" and name one threat for each element (if applicable).

> E.g.:
> - **S:** Possible, because an attacker...
> - **I:** Not possible, because we assume that...

**Answer:**

The Patient is an external entity in the DFD. The Patient provides their insurance card (containing PatientID and private key) to the Card Reader Terminal via Edge 1.

- **S — Spoofing: Possible.** An attacker could steal or clone a patient's insurance card and impersonate that patient at the Card Reader Terminal. Since the system relies on the physical card for identification, anyone who possesses the card can present themselves as the patient. The system has no additional biometric or photo verification to confirm the person is the actual cardholder.

- **T — Tampering: Possible.** An attacker could tamper with the insurance card's data (e.g., modifying the PatientID or the health information stored on it) if the card's data is not cryptographically signed or if the signature verification can be bypassed. A modified card could cause the system to retrieve or associate data with the wrong patient file.

- **R — Repudiation: Possible.** A patient could deny having visited a doctor or deny that their card was used to authorize access to their records. If the system does not maintain tamper-proof logs of when and where insurance cards were used, there is no way to prove that a specific patient authorized a specific data access.

- **I — Information Disclosure: Possible.** When the patient hands their physical card to the office staff, the card itself contains sensitive information (PatientID, private key, allergies, blood type, organ donor status). This information could be read, copied, or photographed by anyone who handles the card, even briefly. Additionally, if the card communicates wirelessly, the data could potentially be intercepted.

- **D — Denial of Service: Possible.** An attacker could damage or demagnetize a patient's insurance card, preventing the patient from authenticating and accessing their medical records. Alternatively, an attacker could flood the Card Reader Terminal with invalid card reads, preventing legitimate patients from being served.

- **E — Elevation of Privilege: Possible.** If an attacker obtains a patient's card, they gain the privileges associated with that patient — specifically the ability to authorize data access for 30 days. In normal operation, the patient should only be able to authorize access to their own data, but if the card's private key is extracted, it could potentially be used to forge authorization requests or sign requests for elevated actions not intended for patients.

---

## 4. Protection Poker (8 pts)

---

### Q4 (8 pts)

**Question:** Imagine that the SePA application should be extended with the following three features:

- **A:** A patient moves and needs to update their address.
- **B:** The medical data should be accessible to researchers in an anonymized way.
- **C:** Tracking the spread of viral infection should be possible by cross-referencing illness occurrences and addresses (by authorized research institutes).

The following assets are available:

1. Patient Name
2. Address
3. Phone number
4. Illness record
5. Past doctor visits
6. Open referrals to other doctors

> The Fibonacci Numbers up to 100 are: 1, 2, 3, 5, 8, 13, 21, 34, 55, and 89.

Your task is to conduct risk assessment using protection poker. Please fill out the missing fields in the following tables. While the header row (right of Patient Data) should be filled out, there may be fields you can leave blank.

**Answer:**

### Assets Table

The headers for the two columns are **Value** and **Used in Feature #**. New assets must be created for the new features.

| Patient Data                    | Value | Used in Feature # | Your additional comments |
| ------------------------------- | ----- | ----------------- | ------------------------ |
| Patient Name                    | 8     | A, B              | Can identify a person; needed for address update and research data |
| Patient Address                 | 8     | A, C              | Personally identifiable; core of Feature A, used for location in Feature C |
| Phone Number                    | 5     | A                  | Contact info, moderate sensitivity |
| Illness Records                 | 34    | B, C              | Highly sensitive medical data; core of Features B and C |
| Past doctor visits              | 13    | B                  | Sensitive medical history |
| Open referrals to other doctors | 5     | B                  | Moderate sensitivity |
| Anonymized research data        | 8     | B                  | New asset: derived data for researchers, risk of de-anonymization |
| Infection tracking report       | 13    | C                  | New asset: cross-referenced illness + address data, very sensitive |
| Research institute credentials  | 13    | B, C              | New asset: access credentials for authorized research institutes |

### Features Table

The headers are **Total Value Points**, **Ease Points**, and **Security Risk**.

Total Value Points = sum of all asset values used by that feature.
Ease Points = estimated ease of attack (1 = very hard, 100 = very easy), using Fibonacci numbers.
Security Risk = Total Value Points × Ease Points.

| Feature                            | Total Value Points | Ease Points | Security Risk |
| ---------------------------------- | ------------------ | ----------- | ------------- |
| A: Patient moves                   | 21 (8+8+5)         | 3           | 63            |
| B: Anonymous access to researchers | 81 (8+34+13+5+8+13)| 8           | 648           |
| C: Viral infection spread tracking | 68 (8+34+13+13)    | 13          | 884           |

**Reasoning for Ease Points:**
- **Feature A (Ease = 3):** Updating an address is a relatively straightforward operation behind the existing VPN-authenticated system. An attacker would need a patient's card or VPN access to exploit it, making it hard to attack.
- **Feature B (Ease = 8):** Exposing anonymized data to researchers introduces a new external interface. There is a risk of de-anonymization through correlation attacks, and the research API creates a new attack surface. Moderate ease of attack.
- **Feature C (Ease = 13):** Cross-referencing illness occurrences with addresses is highly sensitive and requires combining multiple data types. The research institute interface is external and must handle authorization for multiple institutes. The combination of location and illness data makes de-anonymization easier. Relatively higher ease of attack due to the broader access requirements.

### Which feature has the highest risk?

**Feature C** (Viral infection spread tracking) has the highest security risk at 884 points. This is because it combines highly sensitive assets (illness records + addresses), creates a new external access channel for research institutes, and the cross-referencing of illness and location data makes de-anonymization attacks significantly easier.

---

## 5. Defensive Coding (21 pts)

---

### Q5a (5 pts)

**Question:** Present an argument for the following statement: "Complexity is the enemy of security."

**Answer:**

The more complex a system is, the harder it becomes to understand all possible execution paths, test all branches thoroughly, audit every component for security issues, and maintain the system securely over time. Complex code creates more hiding places for bugs and vulnerabilities, making it easier for security flaws to slip through code reviews and testing unnoticed. A developer who cannot fully understand the code they are writing or reviewing will inevitably make mistakes — and in security-critical code, mistakes become exploitable vulnerabilities. Furthermore, complex systems have more interactions between components, which increases the likelihood of unexpected behaviors that attackers can exploit.

---

### Q5b (4 pts)

**Question:** Please name and briefly describe two of the complexity types you've learned in the lecture that affect the system.

**Answer:**

**1. Structural Complexity (Cyclomatic):** This refers to the number of independent execution paths through a piece of code, caused by having many if-statements, loops, and nested branches. It is measured by McCabe's formula M = E - N + 2P (edges minus nodes plus two times connected components). Higher cyclomatic complexity means more paths to test and audit. Code with a McCabe score above 20 is considered too complex to fully test, making it very likely to contain hidden vulnerabilities.

**2. Cognitive Complexity:** This measures how much mental effort a developer needs to understand how a piece of code works. When developers lack understanding of the code, they make mistakes, and those mistakes become vulnerabilities. Cognitive complexity is subjective but important — even well-structured code can be hard to reason about if the underlying logic is inherently complex, leading to incorrect assumptions and insecure implementations.

---

### Q5c — Defensive Coding Principles in Practice (12 pts)

**Question:** The following Java code snippets may contain one or more coding mistakes that violate defensive coding guidelines. Your task is to:
- Identify the line with the mistake. _(1 Point)_
- State the issue briefly. _(1 Point)_
- Describe the mitigation briefly. _(2 Points)_

If there is no coding mistake in the snippet, state this and briefly explain why.

---

#### Snippet 1 — Web Page Generator

```java
 1  // This function takes user input to generate a welcome web page
 2  public void generateWebpage(String input) {
 3      BufferedWriter bw = null;
 4      File f = new File(pagePath); // pagePath is defined outside this function and safe.
 5      try {
 6          FileWriter fw = new FileWriter(f);
 7          bw = new BufferedWriter(fw);
 8          bw.write("<html>");
 9          bw.write("<body>");
10          bw.write("<span>Your name is: ");
11          input = StringUtils.replace(input, "<script>", "");
12          bw.write(input);
13          bw.write("</span>");
14          bw.write("</body>");
15          bw.write("</html>");
16          bw.close();
17      } catch (IOException e) {
18          // [For the exam please think that error handling is done correctly here.]
19      }
20  }
```

**Answer:**

- **Line:** 11 (`input = StringUtils.replace(input, "<script>", "")`)
- **Issue:** This is a **denylist-based sanitization** that only removes the exact string `<script>`. This is a **Cross-Site Scripting (XSS)** vulnerability because attackers can bypass it with countless variations such as `<SCRIPT>`, `<scr<script>ipt>`, `<img onerror="alert(1)">`, `<svg onload="...">`, and many other HTML elements that execute JavaScript. A denylist can never enumerate all possible attack vectors.
- **Mitigation:** Use a proper **HTML encoding library** (such as `StringEscapeUtils.escapeHtml4()` from Apache Commons) that escapes all HTML special characters (`<`, `>`, `"`, `'`, `&`) rather than trying to block specific tags. This is an allowlist-based approach where every character is either known-safe or escaped. Alternatively, use a templating engine with automatic output escaping.

---

#### Snippet 2 — User Finder

```java
 1  // This function takes user input to look for a username in the database.
 2  public void findUser(String friendName) {
 3      Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/example_db",
         "root", "root_password1337");
 4      Statement stmt = conn.createStatement();
 5      String query = "SELECT * FROM Users WHERE username = '" + userInput + "'";
 6      ResultSet rs = stmt.executeQuery(query);
 7      while (rs.next()) {
 8          System.out.println("Found user: " + rs.getString("username"));
 9      }
10      rs.close();
11      stmt.close();
12      conn.close();
13  }
```

**Answer:**

**Issue 1 (Hardcoded Credentials):**

- **Line:** 3 (`DriverManager.getConnection(... "root", "root_password1337")`)
- **Issue:** The database username `"root"` and password `"root_password1337"` are **hardcoded directly in the source code**. Anyone who can access or reverse-engineer the compiled code can extract these credentials and gain full database access. You cannot keep secrets in source code.
- **Mitigation:** Store credentials in an **external configuration file** with restricted file permissions, or use environment variables or a secure credential management system. Never write passwords directly in source code.

**Issue 2 (SQL Injection):**

- **Line:** 5 (`String query = "SELECT * FROM Users WHERE username = '" + userInput + "'"`)
- **Issue:** User input is directly concatenated into the SQL query string. This is a classic **SQL Injection** vulnerability. An attacker can input `' OR '1'='1` to return all users, or `'; DROP TABLE Users;--` to delete the entire table.
- **Mitigation:** Use **parameterized queries (prepared statements)** where user input is passed as a separate parameter, never concatenated into the query string. This ensures the database treats user input strictly as data, never as executable SQL code.

---

## 6. Test Driven Development (3 pts)

---

### Q6 (3 pts)

**Question:** Suppose you are tasked with implementing a FIFO (First in-First out) data structure on integers only, and you must use Test Driven Development. What are the first three tests (1 point each) you are implementing? Describe them briefly in words.

> E.g.: "Test 1: After method A is called with parameter X, I expect Y to be returned by method B."

A FIFO data structure has the following methods:
- `void push(int x)`
- `int pop()`
- `int size()`

**Answer:**

**Test 1:** After creating a new empty FIFO, I call `size()` and expect it to return 0. This establishes the base case that a freshly created FIFO contains no elements.

**Test 2:** After calling `push(42)` once on an empty FIFO, I call `size()` and expect it to return 1. This verifies that pushing an element correctly increases the size of the FIFO.

**Test 3:** After calling `push(42)` on an empty FIFO and then calling `pop()`, I expect `pop()` to return 42 and `size()` to return 0. This verifies the fundamental FIFO behavior: the first element pushed is the first element popped.

---

## 7. Insider Threats (12 pts)

---

### Q7 (12 pts)

**Question:** Assume you are a full-stack (Frontend, Backend, Databases) developer working on the SePA software part that doctors use to interact with the Card Reader Terminal.

Please describe possible insider threats if:

**Case A:** Your goal is to gain an advantage for yourself.

**Case B:** Your goal is to do as much damage as possible.

- Briefly describe two insider threats for each case.
- Briefly describe one mitigation for an insider threat of Case A and one of Case B.

**Answer:**

### Case A: Goal is to gain an advantage for yourself (2 threats)

**Threat A1: Selling patient data.**
As a full-stack developer with access to the backend and database code, I could insert a hidden function that copies patient records (illness histories, personal data, addresses) to an external server under my control. I could then sell this highly sensitive medical data to insurance companies, employers, or on the black market for personal financial gain.

**Threat A2: Creating a backdoor for unauthorized access.**
I could embed a hidden backdoor in the authentication logic of the doctor's software — for example, a hardcoded master credential that allows me to access any patient's records without going through the normal Card Reader Terminal authentication flow. I could use this to access the medical records of specific people (celebrities, colleagues, family members) for personal advantage such as blackmail or curiosity.

### Case B: Goal is to do as much damage as possible (2 threats)

**Threat B1: Deploying a logic bomb to corrupt the database.**
I could plant a time-delayed logic bomb in the backend code that, on a specific date, executes mass modification or deletion of patient records in the PatientDataDB. Since I have access to the database layer, I could write code that scrambles illness records, swaps patient data between files, or deletes records entirely. This would compromise the integrity and availability of the entire system and could endanger patients' lives if doctors rely on incorrect medical data.

**Threat B2: Disabling security controls to enable external attacks.**
I could subtly weaken the VPN authentication or disable certificate validation in the Card Reader Terminal's communication code, making the system vulnerable to man-in-the-middle attacks. I could also introduce a vulnerability in the input handling (such as removing SQL injection protection) that would allow external attackers to exploit the system. This would open the door for widespread data breaches affecting all patients in the system.

### Mitigations

**Mitigation for Case A (Threat A1 — Selling patient data):**
Implement **mandatory code reviews** where every code change must be reviewed and approved by at least one other developer before it can be merged. This makes it significantly harder to insert hidden data exfiltration code because another person would see the suspicious network calls or data copying logic. Additionally, implement audit logging on all database access so that unusual query patterns (like bulk data extraction) are detected and flagged.

**Mitigation for Case B (Threat B1 — Logic bomb):**
Implement the **principle of least privilege** by separating development roles so that no single developer has full access to all layers (frontend, backend, and database) in the production environment. Use a controlled deployment pipeline where production code is built from a reviewed, signed repository, and database migrations require separate approval from a database administrator. This prevents any single developer from deploying destructive code to production without oversight.
