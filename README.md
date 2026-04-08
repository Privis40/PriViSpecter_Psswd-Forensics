# 🛡️ PriVi-SPECTER: Forensic Credential Analysis Suite
**Version 4.5 — Forensic Intelligence Edition** **Developed by: PriViSecurity**

<div align="center">

# 🛡️ PriVi-SPECTER: Forensic Credential Analysis Suite
**Version 4.5 — Forensic Intelligence Edition Developed by: PriViSecurity**

![PriVi-SPECTER Dashboard](PriVi-Specter.PNG)

</div>

**PriVi-SPECTER** is a professional-grade terminal suite designed for high-fidelity credential auditing. It bridges the gap between basic complexity checks and advanced forensic analysis by integrating **Shannon Information Theory**, **K-Anonymity breach intelligence**, and **Heuristic Pattern Recognition**.

Built for cybersecurity researchers and bug bounty hunters, PriVi-SPECTER provides a definitive, brand-certified audit report that quantifies the true "attack surface" of a password.

---

## ⚡ Key Features

### 1. Matrix Heuristic Interface
Experience a live-stream data analysis sequence. The suite utilizes a matrix-style heuristic boot sequence to simulate deep memory scanning, providing high-fidelity visual feedback during the forensic audit.

### 2. Shannon Information Density
Moving beyond simple character counts, PriVi-SPECTER measures the actual randomness and unpredictability of a string using Shannon Entropy:

$$H = -\sum_{i=1}^n p(x_i) \log_2 p(x_i)$$

This provides a scientific bit-rating that exposes "repetitive" or "structured" passwords that standard auditors might misclassify as strong.

### 3. K-Anonymity Breach Intelligence
PriVi-SPECTER securely queries over **12 billion breached records** via the HaveIBeenPwned API. By utilizing **SHA-1 Prefixing (K-Anonymity)**, the tool never transmits your actual password. Only the first 5 characters of the hash are sent, ensuring 100% privacy during the leak check.

### 4. Fuzzy Similarity Engine
Equipped with a Gestalt Pattern Matching algorithm, the suite identifies if a target password is a "fuzzy match" for common weak credentials. It catches clever obfuscations such as `P@ssw0rd1!`, `12345678_Admin`, or common keyboard walks.

### 5. Certified PDF Export
Generate **Forensic Audit Reports** instantly. These documents are professionally styled and include:
- **Executive Risk Ratings** (Critical to Elite).
- **Deep-Dive Technical Metrics** (Shannon vs. Pool Entropy).
- **Hardening Roadmaps** for remediation.
- **PriVi-SPECTER Branding** and forensic watermarks.

---

## 🛠️ Installation & Setup

### 1. Requirements
Optimized for Python 3.10+ with the following pinned dependencies:

- `fpdf2==2.7.8` (Advanced PDF Generation)
- `colorama==0.4.6` (Terminal UI Enhancement)
- `requests==2.31.0` (Secure API Communication)

### 2. Deployment
```bash
# Clone the repository
git clone [https://github.com/YOUR_USERNAME/PriVi-SPECTER.git](https://github.com/YOUR_USERNAME/PriVi-SPECTER.git)
cd PriVi-SPECTER

# Install dependencies
pip install -r requirements.txt

# Launch the Suite
python privi_specter.py
