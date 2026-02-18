# Phase 1: Foundations & Definitions (~28 pts)

**Lectures:** lect-00, lect-01, lect-02
**Time budget:** ~2 hours
**Exam payoff:** Single-statement questions (16 pts), Misuse/Abuse cases (7 pts), Insider Threats (12 pts)

---

## 1. Core Security Terms (MEMORIZE THESE — they are the vocabulary for everything)

> **NOT ASKED directly on past exam** — but these are assumed knowledge for every answer you write. You cannot do STRIDE, abuse cases, or insider threats without these terms.

### 1.1 Asset

> An asset is any tangible or intangible thing or characteristic that has value to an organization. [ISO/IEC 27000:2014]

**SePA examples:** Patient health data, PatientID, private keys on insurance card, doctor credentials, VPN connection data.

### 1.2 Threat

> A threat is a potential cause of an unwanted incident, which may result in harm to a system or organization. [ISO/IEC 27000:2016]

### 1.3 Adversary

> An adversary is any person or thing that acts (or has the power to act) to cause, carry, transmit, or support a threat. [Younis and Malaiya 2015]

**Relationship:** The adversary is the actor that carries out or supports the threat.

### 1.4 Security

> Security provides a form of protection where a separation is created between the assets and the threat. [OSSTMM 3]

### 1.5 Security Policy

> A security policy is a definition of what it means to be secure for a system, organization, or other entity.

### 1.6 Attack Vector

> An attack vector is a path or means by which an attacker can gain access to a computer or network server in order to deliver a malicious outcome. [ISO 27032:2012]

### 1.7 Vulnerability

> A vulnerability is a weakness of an asset (or control) that can be exploited by one or more threats. [ISO/IEC 27000:2016]

**Also:** "An instance of a mistake in the specification, development, or configuration of software such that the execution can violate the explicit or implicit security policy." [Ozment 2007]

> **Attack vector vs Vulnerability distinction (exam-tested in exercises):** Attack vector = the "how/route" of the attack. Vulnerability = the "weakness" that enables it. Don't confuse them — they are different concepts that work together.

### 1.8 Exploit

> An exploit is a method that identifies and takes advantage of a vulnerability in an asset. [Younis and Malaiya 2015]

- Can be manual or automated
- Malware may contain automated exploits
- Exploits do NOT need to be malicious
- Many different ways to exploit just one vulnerability

### 1.9 Attack

> An attack is an attempt to destroy, expose, alter, disable, steal, or gain unauthorized access to or make unauthorized use of an asset. [ISO 27000:2016]

### 1.10 Countermeasure / Mitigation

> A countermeasure (or control/safeguard) is used to minimize or eliminate the probability of a threat exploiting a vulnerability in an asset.

> Risk mitigation is the process of taking actions to eliminate or reduce the probability of compromising the CIA of valued information assets to acceptable levels.

### 1.11 Terms & Relations Diagram (know this chain)

```
Asset → has Vulnerability → exploited by Exploit → derived from Attack → targets Asset
                                                                    ↑
Threat → threatens Asset                           Countermeasure → mitigates Threat
                                                                    → safeguards Asset
```

**Extended (with Security Properties):**

```
Threat → violates → Security Property (CIA)
Countermeasure → contributes to → Security Property (CIA)
```

---

## 2. CIA Triad

> **NOT ASKED directly on past exam** — but used implicitly in STRIDE analysis, every VOTD analysis, and Protection Poker. You need these definitions word-perfect because they underpin 40+ points of other questions.

### Confidentiality

> The property that information is not made available or disclosed to unauthorized individuals, entities, or processes. [ISO/IEC 27000:2016]

**Achieve with:** Encryption, access controls, authentication mechanisms.

### Integrity

> The property of safeguarding the accuracy and completeness of assets. [ISO/IEC 27000:2016]

**Achieve with:** Checksums, digital signatures, version control.

### Availability

> The property of being accessible and usable upon demand by an authorized entity. [ISO/IEC 27000:2016]

**Achieve with:** Redundancy, backups, DDoS protection, load balancing.

```
        Confidentiality
             /\
            /  \
           /    \
          / INFO \
         / SEC.   \
        /----------\
Integrity -------- Availability
```

---

## 3. AAA Principle

> **ASKED ON EXAM** — Single Statement Q1 (~2-3 pts): _"What does the AAA principle stand for? Please name all three elements and describe them briefly."_

### Authentication

> The provision of assurance that a claimed characteristic of an entity is correct. [ISO 27000:2016]

- Verifies **"who you are"**
- Checks knowledge of a secret only the right user can know
- Possible secrets: password, secret cryptographic key, fingerprint
- The secret itself is NEVER transmitted in plaintext — only proof that the secret is known
- **Examples:** Passwords, biometrics, certificates

### Authorization

> A right or permission that is granted to a system entity to access a system resource. [IEC 62443-1-1]

- Verifies **"what you can do"**
- Typically involves access-control lists
- **Examples:** Role-based permissions, ACLs

### Accountability / Auditability / Non-Repudiation

> Non-repudiation is the ability to prove the occurrence of a claimed event or action and its originating entities. [ISO 27000:2016]

- Proves **"who did what"**
- **Examples:** Logging, audit trails, digital signatures

> **Common exam mistake:** Don't confuse Authentication with Authorization. Authentication = identity verification. Authorization = permission checking. They are separate steps. CSRF exploits inconsistent authentication — the exam specifically notes this.

### AAA vs CIA Connection

| AAA Element    | Protects CIA Property       |
| -------------- | --------------------------- |
| Authentication | Confidentiality, Integrity  |
| Authorization  | Confidentiality, Integrity  |
| Accountability | Integrity (non-repudiation) |

---

## 4. Safety vs Security

> **NOT ASKED on past exam** — but tested in exercises. Could appear as a single-statement question on future exams.

| Aspect         | Safety                                                        | Security                                          |
| -------------- | ------------------------------------------------------------- | ------------------------------------------------- |
| **Direction**  | Risks arising FROM the system → impacting the environment     | Risks FROM the environment → impacting the system |
| **Intent**     | Accidental risks                                              | Malicious risks                                   |
| **Definition** | Absence of catastrophic consequences on users and environment | Protection separating assets from threats         |

> **Key distinction for the exam:** Safety = system hurts environment (accidental). Security = environment hurts system (malicious). Get the direction right.

---

## 5. Compliance vs Security

> **NOT ASKED on past exam** — low priority. Know it exists.

- Compliance = complying with rules (laws, regulations)
- Security-compliance rules SHOULD align with security goals, but sometimes they don't
- Being security-compliant is usually advisable but **insufficient**
- **Example from lecture:** German banking app certified by TÜV Rheinland but had: static salt, only 20 rounds of hashing, password stored as String

---

## 6. Attack Surface

> **ASKED ON EXAM** — Single Statement Q3 (~2-3 pts): _"Please describe the concept of 'Attack Surface' and what parameter can have an influence on it briefly."_

### Definition

The attack surface is the sum of all points (attack vectors) where an unauthorized user can try to enter or extract data from a system.

### What influences it

- **Complexity** — more code, more features = larger attack surface
- Number of input points (APIs, forms, file uploads, network ports)
- Amount of running code / services
- Number of user-accessible features
- External dependencies and third-party libraries
- Network exposure (internet-facing vs. internal)

### How to reduce it

- Remove unnecessary features and code
- Minimize exposed APIs and services
- Apply principle of least privilege
- Use distrustful decomposition (Phase 2 topic)

> **Connection to later phases:** Attack surface reduction is a defensive coding principle (Phase 3). Trust boundaries in threat modeling (Phase 2) define WHERE the attack surface is.

---

## 7. Misuse vs Abuse Cases

> **ASKED ON EXAM** — Misuse/Abuse Cases section (7 pts): _"Explain how misuse/abuse cases differ from standard use cases"_ + _"Describe two abuse cases for SePA."_ Get the intent difference right or lose the full points.

### Distinction

| Aspect     | Misuse Case                     | Abuse Case                       |
| ---------- | ------------------------------- | -------------------------------- |
| **Intent** | **Unintentional**               | **Intentional**                  |
| **Nature** | Crime of opportunity            | Actively seeking vulnerabilities |
| **Actor**  | Legitimate user making mistakes | Malicious actor (black/grey hat) |

### How they differ from standard use cases

- Standard use cases describe **intended functionality** (what the system should do)
- Misuse/abuse cases describe **unintended usage** (what could go wrong)
- They help identify security threats by thinking from the attacker's/user's perspective

### Role in identifying security threats

- Force developers to think about negative scenarios early in the SDLC
- Feed directly into threat modeling (STRIDE) and risk assessment
- Help identify security requirements that wouldn't come from standard use cases

### Two Abuse Cases for SePA (EXAM ANSWER FORMAT)

**Abuse Case 1: Stolen Insurance Card**

- **Actor:** Malicious individual who steals/finds a patient's insurance card
- **Goal:** Access the victim's medical records
- **Scenario:** Attacker inserts the stolen card into a card reader terminal at a compromised/cooperative doctor's office, gains access to the patient's medical data for 30 days
- **Assumption:** Physical access to a card reader terminal is possible
- **Threat:** Confidentiality breach of patient health data; potential identity fraud

**Abuse Case 2: Rogue Doctor / Insider**

- **Actor:** Authorized doctor with legitimate access
- **Goal:** Harvest patient data for sale or blackmail
- **Scenario:** Doctor uses their legitimate 30-day access window to bulk-export patient records, medical histories, and personal information from the PatientDataService
- **Assumption:** Doctor has valid chip card and VPN access
- **Threat:** Mass confidentiality breach; data exfiltration by trusted insider

> **Partial credit tip:** Even if you can only name ONE abuse case with a vague description, you still get partial points. Never leave this blank. Start with: Actor → Goal → How → What's threatened.

---

## 8. Insider Threats

> **ASKED ON EXAM** — Insider Threats section (12 pts): _"You are a full-stack developer on SePA. Describe 2 insider threats for Case A (gain advantage) and Case B (do damage), plus 1 mitigation each."_

### Case A: Gain an Advantage for Yourself (2 threats)

**Threat A1: Data Theft for Personal Gain**

- As a developer with database access, you copy patient records (names, addresses, health data) to sell on the black market or to insurance companies
- You have direct access to PatientDataDB and know the schema

**Threat A2: Backdoor for Future Access**

- You embed a hidden admin account or backdoor in the code (CWE-506) that lets you access the system after leaving the company
- You could then sell access or use it for blackmail

### Case B: Do Maximum Damage (2 threats)

**Threat B1: Data Destruction**

- You write a script or modify code to delete or corrupt all patient records in PatientDataDB
- As a full-stack developer, you know the database structure and can bypass application-level protections

**Threat B2: Sabotage the VPN/Authentication**

- You weaken the VPN configuration or authentication mechanism so that external attackers can gain access
- You introduce a vulnerability in the Card Reader Terminal code that leaks doctor credentials

### Mitigations

**Mitigation for Case A (e.g., Threat A1):**

- **Code review + 4-eyes principle:** All code changes require review by another developer before deployment. Database access is logged and monitored. No single developer can push changes to production alone.

**Mitigation for Case B (e.g., Threat B1):**

- **Principle of least privilege + backups:** Developers do not have direct production database access. Production deployments go through CI/CD pipeline with approval gates. Regular encrypted backups ensure data can be restored. Database access is restricted to read-only for development purposes.

> **General insider threat mitigations (safe to mention any of these):**
>
> - Separation of duties
> - Code review / 4-eyes principle
> - Audit logging and monitoring
> - Principle of least privilege
> - Background checks
> - Access revocation procedures when employees leave
> - Regular access reviews

---

## 9. Software Security Fundamentals

> **NOT ASKED on past exam** — but tested in exercises. The "People + Processes + Technology" framing is a safe answer for any "what makes up software security?" question.

### What software security IS:

> The process of designing, building, and testing software for security. [McGraw 2004]

Following the "Security by Design" principle.

### What software security is NOT:

- NOT an arcane black art
- NOT a set of features ("Secure software > Security software")
- NOT just a cryptography problem ("pick-proof lock vs. open window")
- NOT just a networking/OS problem
- NOT only about internet-connected applications (think "security in depth")
- NOT just about technology — also about **people and processes**

### Three pillars of software security:

1. **People** — need security awareness; low awareness → mistakes → vulnerabilities
2. **Processes** — proper procedures for controlled, effective security activities
3. **Technology** — proper implementation; poor tech → exploitable vulnerabilities

### Security Maturity Levels (from lecture)

1. **Denial** — "Let me just code. Leave it to the experts."
2. **Irrational fear** — "ENCRYPT EVERYTHING!!!"
3. **Bag of tricks** — "We've done these 10 things. Close enough."
4. **Reasoned, balanced, defensive mindset** — "If we do X, we mitigate Y, because of Z."

> The exam rewards level 4 thinking. Frame your answers as: threat → mitigation → reasoning.

---

## 10. CSRF — Cross-Site Request Forgery (Vulnerability of the Day)

> **NOT ASKED on past exam** — but listed as a VOTD in lect-01 recap. Know the mechanism and mitigation in case it appears as a VOTD question or "name a vulnerability" prompt.

CWE-352.

### What it is

A web application accepts state-modifying requests without proper user authentication. Any web page in the same browser can make requests on the user's behalf.

### How it works

```
1. User is logged into facebook.com
2. User visits evil.com
3. evil.com contains: <img src="https://facebook.com/delete_account.php?are_you_sure=yes">
4. Browser sends the request WITH the user's facebook session cookie
5. Facebook executes the action thinking it's the user
```

### CSRF exploits inconsistent authentication

- The server trusts the session cookie but doesn't verify the REQUEST actually came from the user

### Mitigations

1. **CSRF tokens (nonces)** — embed pseudo-random token in form/cookie, verify on server
2. **POST instead of GET** for state-changing operations (makes attacks harder, NOT impossible alone)
3. **SameSite cookie attribute** — prevents cookies from being sent in cross-site requests

### Real-world example

- **Bugzilla CSRF (CVE-2012-0453):** Bugzilla 4.0.2-4.0.4 had CSRF in xmlrpc.cgi allowing attackers to hijack authentication and modify product installations

### CIA Impact

- **Integrity:** PRIMARY — unauthorized modifications to user data
- **Availability:** POTENTIAL — if accounts are deleted/disabled
- **Confidentiality:** NOT directly affected — CSRF causes unwanted actions, doesn't expose information

---

## 11. LLM Security Considerations

> **ASKED ON EXAM** — Single Statement Q4 (~2-3 pts): _"Imagine you are using an LLM as one component in your software. Please describe two security considerations briefly."_

### Consideration 1: Prompt Injection / Input Manipulation

- LLMs can be manipulated through crafted inputs to bypass safety measures or produce harmful outputs
- Untrusted user input passed to an LLM can alter its behavior (similar to SQL injection but for natural language)
- **Mitigation:** Treat LLM input/output as untrusted; validate and sanitize both

### Consideration 2: Hallucinations / Unreliable Output

- LLMs generate probabilistic output — they can produce incorrect, fabricated, or insecure code/advice
- If LLM output is used to make security decisions (e.g., generating code, making access control decisions), hallucinated output can introduce vulnerabilities
- **Mitigation:** Never trust LLM output for security-critical decisions without human review; use LLMs as assistants, not decision-makers

### Additional considerations (if the exam asks for more):

- **Data leakage:** LLMs trained on sensitive data may leak it in responses
- **Supply chain risk:** Using third-party LLM APIs introduces dependency on external services (availability, confidentiality of data sent to them)

---

## 12. Supply Chain Security / CWE-506 (from lect-02)

> **NOT ASKED on past exam** — but connects to insider threats and embedded malicious code. Know the XZ example as a fallback for "name a real-world supply chain attack."

### CWE-506: Embedded Malicious Code

- Attacker convinces victim to load a controlled "open-source" library with a hidden backdoor
- Approaches: build legitimate library + insert backdoor, compromise maintainer, typosquatting

### XZ Utils Backdoor (CVE-2024-3094)

- Attacker "Jia Tan" built trust over ~2 years with legitimate contributions
- Malicious code hidden in binary test files (not in source code!)
- Targeted OpenSSH via systemd integration → allowed unauthorized remote access
- Discovered by accident: Andres Freund noticed 500ms SSH latency + CPU spikes
- **Key lesson:** Code review won't catch build-time injection. Static analysis sees clean source. CI/CD passes all checks.

---

## 13. Secure SDLC Overview (from lect-00 and lect-01)

> **NOT ASKED directly on past exam** — but this is the skeleton the entire exam follows. Knowing which security activity maps to which phase helps you structure any answer.

| SDLC Phase               | Security Activity                   | What You Do                               |
| ------------------------ | ----------------------------------- | ----------------------------------------- |
| Requirements & Use Cases | Abuse Cases + Security Requirements | Get into the attacker's mind              |
| Architecture & Design    | Risk Analysis (STRIDE)              | Uncover and rank architectural flaws      |
| Code                     | Code Review (+tools)                | Identify implementation bugs              |
| Test Plans               | Risk-Based Security Tests           | Test security functionality + abuse cases |
| Test & Results           | Penetration Testing                 | Reveal issues in real environment         |
| Feedback from Field      | Security Operations                 | Admins and network professionals involved |

---

## 14. VOTDs (Vulnerabilities of the Day) — Quick Reference

> **NOT ASKED as a standalone section on past exam** — but VOTDs appear inside code review snippets and are safe fallback examples for "name a real-world example" questions.

| VOTD                    | CWE     | Example                                 |
| ----------------------- | ------- | --------------------------------------- |
| SQL Injection           | CWE-89  | TalkTalk breach (2015), 157K customers  |
| XSS                     | CWE-79  | Twitter XSS worm (2010), onmouseover    |
| CSRF                    | CWE-352 | Bugzilla (CVE-2012-0453)                |
| Log Overflow            | CWE-400 | Xen PCI backend (CVE-2013-0231)         |
| Path Traversal          | CWE-22  | Apache Tomcat (CVE-2009-2902)           |
| Hardcoded Credentials   | CWE-798 | Pyftpd (CVE-2010-2073)                  |
| Hashing without Salt    | —       | Banking app with static salt, 20 rounds |
| Cache Poisoning         | —       | Web Cache Deception (2017, PayPal)      |
| Format String           | CWE-134 | printf(str) vs printf("%s", str)        |
| Embedded Malicious Code | CWE-506 | XZ Utils (CVE-2024-3094)                |
| Compression Bomb        | CWE-409 | 42.zip (4.5 petabytes)                  |

---

## 15. Risk Management vs Vulnerability Assessment

> **ASKED ON EXAM** — Single Statement Q6 (~2-3 pts): _"What are the differences between Risk Management and Vulnerability Assessment? Please name briefly when to use each and why."_

| Aspect       | Risk Management                                     | Vulnerability Assessment                     |
| ------------ | --------------------------------------------------- | -------------------------------------------- |
| **Timing**   | Early development phases (during design)            | Only for existing systems                    |
| **Focus**    | Potential threats to the system                     | Concrete vulnerabilities and exploits        |
| **Goal**     | Prevent important vulnerabilities before they occur | Fix and prevent further vulnerabilities      |
| **Approach** | **Proactive** — anticipates what could go wrong     | **Reactive** — addresses what has gone wrong |
| **Scope**    | Theoretical risk scenarios                          | Actual discovered vulnerabilities            |

> **WRITE THIS ON THE EXAM:** Risk Management = proactive, early, prevents. Vulnerability Assessment = reactive, late, fixes. If risk management is updated throughout the lifecycle, it can support vulnerability assessment by providing context about which vulnerabilities are most critical.

---

## 16. Authentication vs Authorization vs Encryption (know the distinction)

> **NOT ASKED as its own question on past exam** — but the distinction is built into AAA (which IS asked). Knowing this prevents you from confusing terms in other answers.

| Concept            | What it does                                            | Example                                                |
| ------------------ | ------------------------------------------------------- | ------------------------------------------------------ |
| **Authentication** | Assures WHO is issuing a request                        | Checking password, verifying certificate               |
| **Authorization**  | Determines WHAT PERMISSIONS an authenticated entity has | Access control lists, role-based permissions           |
| **Encryption**     | Keeps DATA CONFIDENTIAL                                 | AES, TLS — completely different concept from the above |

---

## 17. Protection Against [Exploits | Threats | Vulnerabilities]

> **NOT ASKED on past exam** — but this is the core message of the course. Safe to reference in "present an argument" questions.

| Protect Against     | How                                             | Effectiveness                        |
| ------------------- | ----------------------------------------------- | ------------------------------------ |
| **Exploits**        | Anti-virus, intrusion detection, firewalls      | Cannot stop determined adversaries   |
| **Threats**         | Engineer secure software, forensics, punishment | Does not stop determined adversaries |
| **Vulnerabilities** | **Engineer secure software!**                   | **Makes attacks more demanding!**    |

> The best protection is engineering secure software that eliminates vulnerabilities. This is the core message of the entire course.

---

## Phase 1 — Active Recall Quiz

Answer these as you would on the exam paper. Then check against the notes above.

1. **What does AAA stand for? Name all three elements and describe them briefly.**

2. **What is the difference between a misuse case and an abuse case? Give one example of each for a banking system.**

   **Misuse Case (Banking):**
   1. **Actor:** Legitimate banking customer
   2. **Goal:** Transfer money to a friend
   3. **Scenario:** The user mistypes the IBAN or double-clicks the "Transfer" button due to UI lag, sending the funds to the wrong recipient or twice.
   4. **Assumption:** The UI does not have a confirmation step or debouncing for key presses.
   5. **Threat:** Financial loss for the customer.

   **Abuse Case (Banking):**
   1. **Actor:** Malicious attacker
   2. **Goal:** Steal money from victim's account
   3. **Scenario:** Attacker uses a list of leaked username/passwords from another breach (credential stuffing) to automatically try logging into the banking portal. Once successful, they transfer funds out.
   4. **Assumption:** The user reuses passwords across sites and the bank doesn't enforce 2FA.
   5. **Threat:** Financial loss, Identity theft, Confidentiality breach.

3. **Describe the concept of "Attack Surface" and what parameter can have an influence on it.**

4. **You are using an LLM as a component in your software. Describe two security considerations.**

5. **What are the differences between Risk Management and Vulnerability Assessment? When do you use each?**

6. **You are a full-stack developer on SePA. Describe one insider threat where your goal is to gain an advantage, and one where your goal is to cause maximum damage. Give one mitigation for each.**

7. **Name the three elements of the CIA triad and define each in one sentence.**

8. **What is the difference between Safety and Security?**
