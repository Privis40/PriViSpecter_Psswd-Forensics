<div align="center">

# 🛡️ PriViSpecter — Forensic Credential Analysis Suite: Developed by PriViSecurity

![PriViSpecter Dashboard](PriViSpecter.PNG)

</div>

### Forensic Password Intelligence & Credential Auditing Tool
**Developed by Prince Ubebe | [PriViSecurity](https://github.com/Privis40)**

---

## ⚠️ Legal Notice

> **This tool is intended ONLY for auditing credentials you own or have explicit written authorization to assess.**
> Running credential audits against accounts or password lists you do not own is illegal under the Computer Misuse Act, the CFAA, and equivalent laws worldwide.
> **PriViSecurity accepts no liability for unauthorized or malicious use of this tool.**

---

## What It Does

PriViSpecter is a forensic credential analysis suite that evaluates password strength, detects breach exposure, and generates branded PDF audit reports. It combines multiple analysis engines — entropy scoring, pattern detection, breach lookup, and passphrase generation — into a single workflow designed for authorized security assessments and employee password hygiene audits.

It is designed for:
- Security teams running authorized corporate password hygiene audits
- Penetration testers assessing credential strength during authorized engagements
- IT administrators evaluating password policy compliance
- Security trainers and educators in classroom and lab settings

---

## Features

| Feature | Description |
|---|---|
| 📊 Shannon Entropy Analysis | Measures true randomness of a password using information entropy |
| 🎱 Pool Entropy Scoring | Scores based on character set diversity (lower, upper, digits, symbols) |
| ⏱️ Crack Time Estimation | Estimates time to crack at 10 billion guesses/second |
| 🔴 HIBP Breach Lookup | Checks Have I Been Pwned using k-anonymity — password never sent in plaintext |
| 🔍 Pattern Detection | Detects keyboard walks, leet substitutions, date patterns, common passwords |
| 🧮 Fuzzy Match Scoring | Fuzzy match against top common passwords with similarity scoring |
| 🔐 Secure Password Generator | Cryptographically secure random password generation |
| 📖 Passphrase Generator | Generates memorable multi-word passphrases |
| 📦 Batch Audit Mode | Process entire wordlists with per-line analysis and HIBP rate limiting |
| 📋 PDF Audit Report | Branded PriViSecurity-styled report with all findings |

---

## Requirements

```bash
pip install requests colorama fpdf2
```

---

## Installation

```bash
git clone https://github.com/Privis40/PriViSpecter_Psswd-Forensics.git
cd PriViSpecter_Psswd-Forensics
pip install -r requirements.txt
```

---

## Usage

```bash
# Interactive mode — analyze a single password
python3 privipass.py

# Batch mode — analyze a wordlist file
python3 privipass.py --batch passwords.txt

# Generate a secure password
python3 privipass.py --generate

# Generate a passphrase
python3 privipass.py --passphrase
```

### Example Session

```
[*] PriViSpecter — Forensic Credential Analysis Suite

Enter password to analyze: ••••••••••••

  Shannon Entropy:    3.12 bits/char
  Pool Entropy:       52.4 bits
  Crack Time:         3 minutes at 10B guesses/sec
  HIBP Breach:        FOUND in 47,832 breaches
  Keyboard Walk:      DETECTED (qwerty pattern)
  Common Password:    MATCH (similarity: 94%)

  Grade:  F — CRITICALLY WEAK

[+] PDF report saved: PriViSpecter_Report_20260511_143022.pdf
```

---

## HIBP Integration — Privacy First

PriViSpecter uses the **k-anonymity model** for breach lookups:

1. The password is hashed with SHA-1
2. Only the **first 5 characters** of the hash are sent to the HIBP API
3. HIBP returns all hashes matching that prefix
4. PriViSpecter checks for a match **locally** — your full password hash never leaves your machine

This means breach checking is fully privacy-preserving.

---

## Scoring System

PriViSpecter grades passwords across five levels:

| Grade | Description |
|---|---|
| A — Strong | High entropy, no patterns, no breaches |
| B — Good | Acceptable entropy with minor weaknesses |
| C — Moderate | Detectable patterns or low character diversity |
| D — Weak | Common patterns, low entropy, or breach exposure |
| F — Critical | Common password, breached, or trivially crackable |

---

## Batch Mode

Batch mode processes a wordlist line by line with HIBP rate limiting (0.2s between requests to respect API limits):

```bash
python3 privipass.py --batch rockyou_sample.txt
```

Output includes per-password grade and breach status, plus a summary PDF report.

---

## PDF Report Sections

1. Analysis Summary (password metadata, grade, crack time)
2. Entropy Analysis (Shannon, pool entropy)
3. Breach Intelligence (HIBP result, exposure count)
4. Pattern Detection (keyboard walks, leet, date patterns)
5. Recommendations

---

## What This Tool Does NOT Do

- ❌ Does **not** crack or brute-force any password
- ❌ Does **not** store analyzed passwords
- ❌ Does **not** send full passwords to any external service
- ❌ Does **not** attempt authentication against any system

---

## Tested On

- Kali Linux 2024+
- Ubuntu 22.04 / 24.04
- Python 3.10+

---

## Author & Brand

**Prince Ubebe**
Cybersecurity Analyst | Security Automation Engineer | Founder, PriViSecurity

- GitHub: [github.com/Privis40](https://github.com/Privis40)
- LinkedIn: [linkedin.com/in/prince-ubebe-291573321](https://www.linkedin.com/in/prince-ubebe-291573321)
- YouTube: [@princeubebecyber](https://youtube.com/@princeubebecyber)
- HackerOne / Bugcrowd: Active researcher

---

## License

This tool is released for **authorized security research and professional use only.**
Redistribution or modification for malicious purposes is strictly prohibited.

© 2026 PriViSecurity. All rights reserved.
