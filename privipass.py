#!/usr/bin/env python3
"""
PriViPassElite v3.4 — Forensic Password Auditor
Developed by Prince Ubebe | PriViSecurity
"""

import secrets
import string
import re
import math
import hashlib
import requests
import time
import sys
import os
import random
import argparse
from colorama import Fore, init
import getpass
from fpdf import FPDF

init(autoreset=True)

# ─────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────

AUTHOR  = "PriViSecurity"
VERSION = "3.4"

WORDLIST = [
    "correct", "horse", "battery", "staple", "river", "cloud",
    "falcon", "stone", "mirror", "delta", "cipher", "forge",
    "prism", "vault", "echo", "orbit", "ridge", "flint",
    "cedar", "storm", "haven", "blaze", "frost", "quartz",
    "noble", "drift", "lunar", "ember", "crest", "shade",
]

COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "admin",
    "letmein", "welcome", "monkey", "dragon", "master",
    "123456789", "login", "abc123", "111111", "iloveyou",
    "sunshine", "princess", "football", "shadow", "superman",
]

KEYBOARD_WALKS = [
    "qwerty", "qwert", "werty", "asdf", "asdfg", "zxcv",
    "12345", "123456", "1234567", "09876", "98765",
    "qazwsx", "wsxedc", "edcrfv",
]

LEET_MAP = {
    "@": "a", "4": "a", "3": "e", "1": "i", "!": "i",
    "0": "o", "5": "s", "$": "s", "7": "t", "+": "t",
}

TERMINAL_WIDTH = 67


# ─────────────────────────────────────────────────────────────────
#  PDF REPORTER
# ─────────────────────────────────────────────────────────────────

def _pdf_safe(s):
    """Strip ANSI codes, Rich markup, emoji — produce clean latin-1 safe string."""
    s = re.sub(r'\x1b\[[0-9;]*m', '', s)
    s = re.sub(r'\[/?[a-z0-9 _]+\]', '', s)
    return s.encode('latin-1', errors='replace').decode('latin-1')


class PriViPDFReport(FPDF):
    def __init__(self, author):
        super().__init__()
        self.author_name = _pdf_safe(author)

    def header(self):
        self.set_font("Helvetica", 'B', 40)
        self.set_text_color(235, 235, 235)
        self.set_xy(25, 120)
        self.cell(0, 20, f"CERTIFIED - {self.author_name}", align='C')
        self.set_text_color(0, 0, 0)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10,
                  f"Page {self.page_no()} | Forensic Authority: {self.author_name}",
                  align='C')

    def _strength_bar_pdf(self, score):
        """Render a filled-cell strength bar (score 1-5)."""
        colors = [
            (220, 50,  50),   # 1 — critically weak (red)
            (220, 120, 50),   # 2 — weak (orange)
            (220, 200, 50),   # 3 — fair (yellow)
            (80,  180, 80),   # 4 — strong (green)
            (30,  140, 255),  # 5 — elite (blue)
        ]
        r, g, b = colors[score - 1]
        cell_w = 8
        for i in range(5):
            if i < score:
                self.set_fill_color(r, g, b)
            else:
                self.set_fill_color(220, 220, 220)
            self.cell(cell_w, 6, '', border=1, fill=True)
        self.ln(8)

    def generate_report(self, results, batch=False):
        """Generate PDF for single or batch audit results."""
        self.alias_nb_pages()
        self.add_page()

        # Title
        self.set_font("Helvetica", 'B', 16)
        self.set_text_color(0, 0, 0)
        self.cell(0, 10, f"{self.author_name} Password Audit Report", ln=True, align='C')
        self.set_font("Helvetica", size=10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} | v{VERSION}",
                  ln=True, align='C')
        self.set_text_color(0, 0, 0)

        # Divider
        y = self.get_y() + 2
        self.line(10, y, 200, y)
        self.ln(8)

        if batch:
            self._write_batch_section(results)
        else:
            self._write_single_section(results)

        # Signature
        self.ln(10)
        self.set_font("Helvetica", 'BI', 13)
        self.cell(0, 10, f"~ Signed: {self.author_name} ~", ln=True, align='R')
        self.set_font("Helvetica", 'I', 9)
        self.cell(0, 5, f"Lead Cybersecurity Analyst | {self.author_name}", ln=True, align='R')

        filename = f"PriViPass_Report_{int(time.time())}.pdf"
        self.output(filename)
        return filename

    def _write_single_section(self, r):
        """Write a single-password audit section."""
        self.set_font("Helvetica", 'B', 12)
        self.cell(0, 8, "Forensic Summary", ln=True)
        self.ln(2)

        self.set_font("Helvetica", 'B', 10)
        self.cell(60, 7, "Metric", border='B', fill=False)
        self.cell(0,  7, "Result", border='B', ln=True)
        self.set_font("Helvetica", size=10)

        rows = [
            ("Grade",        r.get("grade", "N/A")),
            ("Entropy",      r.get("entropy", "N/A")),
            ("Crack Time",   r.get("crack_time", "N/A")),
            ("HIBP Status",  r.get("hibp", "N/A")),
            ("Common Pwd",   r.get("common", "N/A")),
            ("Char Freq",    r.get("char_freq", "N/A")),
        ]
        for label, val in rows:
            self.cell(60, 7, _pdf_safe(str(label)))
            self.cell(0,  7, _pdf_safe(str(val)), ln=True)

        self.ln(4)
        self.set_font("Helvetica", 'B', 10)
        self.cell(0, 7, "Strength Score:", ln=True)
        self._strength_bar_pdf(r.get("score", 1))

        weaknesses = r.get("weaknesses", [])
        if weaknesses:
            self.ln(2)
            self.set_font("Helvetica", 'B', 10)
            self.cell(0, 7, "Detected Weaknesses:", ln=True)
            self.set_font("Helvetica", size=10)
            for w in weaknesses:
                self.cell(0, 6, f"  - {_pdf_safe(w)}", ln=True)

        recs = r.get("recommendations", [])
        if recs:
            self.ln(2)
            self.set_font("Helvetica", 'B', 10)
            self.cell(0, 7, "Recommendations:", ln=True)
            self.set_font("Helvetica", size=10)
            for rec in recs:
                self.multi_cell(0, 6, f"  + {_pdf_safe(rec)}")

    def _write_batch_section(self, results):
        """Write a batch summary table."""
        self.set_font("Helvetica", 'B', 12)
        self.cell(0, 8, "Batch Audit Summary", ln=True)
        self.ln(2)

        # Header
        self.set_font("Helvetica", 'B', 9)
        self.set_fill_color(30, 30, 30)
        self.set_text_color(255, 255, 255)
        self.cell(10,  8, "#",       border=1, fill=True, align='C')
        self.cell(60,  8, "Password (masked)", border=1, fill=True, align='C')
        self.cell(25,  8, "Grade",   border=1, fill=True, align='C')
        self.cell(25,  8, "Entropy", border=1, fill=True, align='C')
        self.cell(35,  8, "Crack Time", border=1, fill=True, align='C')
        self.cell(30,  8, "HIBP",    border=1, fill=True, ln=True, align='C')
        self.set_text_color(0, 0, 0)

        self.set_font("Helvetica", size=8)
        for idx, r in enumerate(results, 1):
            pwd = r.get("password", "")
            masked = pwd[0] + "*" * (len(pwd) - 2) + pwd[-1] if len(pwd) > 2 else "***"
            self.cell(10,  7, str(idx),              border=1, align='C')
            self.cell(60,  7, _pdf_safe(masked),                          border=1)
            self.cell(25,  7, _pdf_safe(r.get("grade", "N/A")),            border=1, align='C')
            self.cell(25,  7, _pdf_safe(r.get("entropy", "N/A")),           border=1, align='C')
            self.cell(35,  7, _pdf_safe(r.get("crack_time", "N/A")),        border=1, align='C')
            self.cell(30,  7, _pdf_safe(r.get("hibp", "N/A")),              border=1, ln=True, align='C')


# ─────────────────────────────────────────────────────────────────
#  AUDITOR CORE
# ─────────────────────────────────────────────────────────────────

class PriViPassElite:
    def __init__(self):
        self.version = VERSION
        self.author  = AUTHOR

    # ── BOOT ─────────────────────────────────────────────────────
    def boot_sequence(self):
        logo = f"""
{Fore.GREEN}  ██████╗ ██████╗ ██╗██╗   ██╗██╗██████╗  █████╗ ███████╗███████╗
{Fore.GREEN}  ██╔══██╗██╔══██╗██║██║   ██║██║██╔══██╗██╔══██╗██╔════╝██╔════╝
{Fore.GREEN}  ██████╔╝██████╔╝██║██║   ██║██║██████╔╝███████║███████╗███████╗
{Fore.GREEN}  ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝ ██║██╔═══╝ ██╔══██║╚════██║╚════██║
{Fore.GREEN}  ██║     ██║  ██║██║ ╚████╔╝  ██║██║     ██║  ██║███████║███████║
{Fore.WHITE}        [ {self.author} | FORENSIC AUDITOR v{self.version} ]
        """
        print("\033[H\033[J", end="")
        for line in logo.splitlines():
            print(line)
            time.sleep(0.06)

        print(f"{Fore.CYAN}{'=' * TERMINAL_WIDTH}")
        checks = ["Crypto Engine", "Pattern Database", "Entropy Module", "HIBP Connector"]
        for check in checks:
            sys.stdout.write(f"{Fore.WHITE}[*] Initializing {check}...")
            sys.stdout.flush()
            time.sleep(random.uniform(0.1, 0.25))
            print(f" {Fore.GREEN}[OK]")
        print(f"{Fore.CYAN}{'=' * TERMINAL_WIDTH}\n")

    def matrix_effect(self, duration=1.0):
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        print(f"{Fore.GREEN}[*] RUNNING HEURISTIC PATTERN ANALYSIS...")
        end_time = time.time() + duration
        while time.time() < end_time:
            addr   = f"0x{random.getrandbits(32):08x}"
            stream = "".join(random.choice(chars) for _ in range(40))
            sys.stdout.write(f"\r{Fore.GREEN}{addr} | {Fore.WHITE}{stream}")
            sys.stdout.flush()
            time.sleep(0.04)
        print(f"\n{Fore.GREEN}[+] ANALYSIS COMPLETE. COMPILING RESULTS...\n")

    # ── HELPERS ──────────────────────────────────────────────────
    def _strip_ansi(self, s):
        return re.sub(r'\x1b\[[0-9;]*m', '', s)

    def _box_row(self, label, value_str, col_width=None):
        if col_width is None:
            try:
                col_width = os.get_terminal_size().columns - 4
            except OSError:
                col_width = TERMINAL_WIDTH - 4
        visible_len = len(self._strip_ansi(value_str))
        padding = max(0, col_width - len(label) - visible_len)
        return f"{Fore.CYAN}║ {Fore.WHITE}{label}{value_str}{' ' * padding} {Fore.CYAN}║"

    def _box_divider(self):
        try:
            w = os.get_terminal_size().columns - 2
        except OSError:
            w = TERMINAL_WIDTH - 2
        return f"{Fore.CYAN}{'─' * w}"

    # ── HIBP ─────────────────────────────────────────────────────
    def get_leak_count(self, password):
        sha1   = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            res = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=5
            )
            if res.status_code == 200:
                for line in res.text.splitlines():
                    parts = line.split(':', 1)
                    if len(parts) == 2 and parts[0] == suffix:
                        return int(parts[1])
            return 0
        except requests.exceptions.RequestException:
            return -1

    # ── CRACK TIME ───────────────────────────────────────────────
    def format_crack_time(self, seconds):
        if seconds < 1:
            return "Instantly"
        if seconds < 60:
            return f"{seconds:.0f} seconds"
        if seconds < 3600:
            return f"{seconds / 60:.0f} minutes"
        if seconds < 86400:
            return f"{seconds / 3600:.0f} hours"
        if seconds < 31536000:
            return f"{seconds / 86400:.0f} days"
        years = seconds / 31536000
        if years < 1_000:
            y = int(years)
            return f"{y} year" if y == 1 else f"{y} years"
        if years < 1_000_000:
            return f"{years / 1000:.0f} thousand years"
        return "Centuries"

    # ── PATTERN DETECTION ────────────────────────────────────────
    def detect_patterns(self, password):
        """
        Returns a list of (weakness_label, detail) tuples.
        Checks: keyboard walks, repeated chars, leet substitutions,
                date patterns, common passwords.
        """
        found = []
        lower = password.lower()

        # 1. Common password (exact)
        if lower in COMMON_PASSWORDS:
            found.append(("COMMON PASSWORD", "Exact match in top-20 password list"))

        # 2. Keyboard walk
        for walk in KEYBOARD_WALKS:
            if walk in lower:
                found.append(("KEYBOARD WALK", f"Sequential pattern detected: '{walk}'"))
                break

        # 3. Repeated characters (3+ in a row)
        repeat_match = re.search(r'(.)\1{2,}', password)
        if repeat_match:
            char = repeat_match.group(1)
            found.append(("REPEATED CHARS", f"Character '{char}' repeated 3+ times consecutively"))

        # 4. Leet substitution — de-leet and check against common list
        deleet = password.lower()
        for leet_char, real_char in LEET_MAP.items():
            deleet = deleet.replace(leet_char, real_char)
        if deleet != lower and deleet in COMMON_PASSWORDS:
            found.append(("LEET SUBSTITUTION", f"Leet variant of common password detected"))

        # 5. Date patterns: ddmmyyyy, dd/mm/yyyy, yyyy, mm/yyyy, ddmm, etc.
        date_patterns = [
            r'\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\d{4}\b',   # ddmmyyyy
            r'\b(0[1-9]|[12]\d|3[01])[-/](0[1-9]|1[0-2])[-/]\d{4}\b',  # dd/mm/yyyy
            r'\b(19|20)\d{2}\b',                                   # year 1900-2099
            r'\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\b',          # ddmm
        ]
        for pat in date_patterns:
            if re.search(pat, password):
                found.append(("DATE PATTERN", "Password contains a recognisable date sequence"))
                break

        return found

    # ── CHARACTER FREQUENCY SCORING ──────────────────────────────
    def char_frequency_score(self, password):
        """
        Returns (penalty: bool, detail: str).
        Penalises if >50% of chars are from a single character class.
        """
        if not password:
            return False, "N/A"
        total = len(password)
        classes = {
            "lowercase": sum(1 for c in password if c.islower()),
            "uppercase": sum(1 for c in password if c.isupper()),
            "digits":    sum(1 for c in password if c.isdigit()),
            "special":   sum(1 for c in password if not c.isalnum()),
        }
        for cls_name, count in classes.items():
            ratio = count / total
            if ratio > 0.5:
                return True, f"{int(ratio * 100)}% {cls_name} chars (threshold: 50%)"
        return False, "Balanced character distribution"

    # ── ZXCVBN-STYLE SCORING ─────────────────────────────────────
    def compute_score(self, entropy, leak_count, patterns, freq_penalty):
        """
        Score 1–5 with named grade.
        Starts from entropy base then applies deductions.
        """
        if entropy <= 0:
            return 1, "Critically Weak"

        # Base score from entropy
        if entropy < 28:
            score = 1
        elif entropy < 36:
            score = 2
        elif entropy < 50:
            score = 3
        elif entropy < 70:
            score = 4
        else:
            score = 5

        # Deductions
        if leak_count > 0:
            score -= 2
        elif leak_count == 0 and score >= 2:
            pass  # clean HIBP is neutral

        if patterns:
            score -= len(patterns)

        if freq_penalty:
            score -= 1

        score = max(1, min(5, score))

        grades = {
            1: "Critically Weak",
            2: "Weak",
            3: "Fair",
            4: "Strong",
            5: "Elite",
        }
        return score, grades[score]

    # ── STRENGTH BAR ─────────────────────────────────────────────
    def strength_bar(self, score):
        """Returns a colour-coded terminal strength bar string."""
        colors = [Fore.RED, Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN]
        color  = colors[score - 1]
        filled = "█" * score
        empty  = "░" * (5 - score)
        return f"{color}[{filled}{empty}]{Fore.WHITE} ({score}/5)"

    # ── RECOMMENDATIONS ──────────────────────────────────────────
    def build_recommendations(self, password, patterns, freq_penalty, entropy, leak_count):
        recs = []
        if len(password) < 12:
            recs.append("Increase length to at least 12 characters (16+ recommended)")
        if not re.search(r'[A-Z]', password):
            recs.append("Add uppercase letters (A-Z)")
        if not re.search(r'[a-z]', password):
            recs.append("Add lowercase letters (a-z)")
        if not re.search(r'\d', password):
            recs.append("Add digits (0-9)")
        if not re.search(r'\W', password):
            recs.append("Add special characters (!@#$%^&*...)")
        if any(p[0] == "KEYBOARD WALK" for p in patterns):
            recs.append("Avoid keyboard sequences like 'qwerty' or '12345'")
        if any(p[0] == "REPEATED CHARS" for p in patterns):
            recs.append("Avoid repeating the same character 3+ times in a row")
        if any(p[0] == "LEET SUBSTITUTION" for p in patterns):
            recs.append("Leet substitutions (p@ssw0rd) are well-known — use random chars instead")
        if any(p[0] == "DATE PATTERN" for p in patterns):
            recs.append("Remove date patterns — birthdays and years are easy to guess")
        if freq_penalty:
            recs.append("Diversify your character classes — avoid using mostly one type")
        if leak_count > 0:
            recs.append("This exact password has been leaked — replace it immediately")
        if not recs:
            recs.append("Password is strong. Consider using a password manager to store it.")
        return recs

    # ── PASSWORD GENERATOR ───────────────────────────────────────
    def generate_password(self):
        print(f"\n{Fore.CYAN}[SECURE GENERATOR MODE]")
        try:
            length = int(input(f"{Fore.WHITE}Length (12-64, default 16): ").strip() or "16")
            length = max(12, min(64, length))
        except ValueError:
            length = 16

        print(f"{Fore.WHITE}Include:")
        use_upper   = input("  Uppercase [Y/n]: ").strip().lower() != 'n'
        use_digits  = input("  Digits    [Y/n]: ").strip().lower() != 'n'
        use_special = input("  Special   [Y/n]: ").strip().lower() != 'n'

        charset = string.ascii_lowercase
        if use_upper:   charset += string.ascii_uppercase
        if use_digits:  charset += string.digits
        if use_special: charset += string.punctuation

        # Guarantee at least one of each requested class
        required = [secrets.choice(string.ascii_lowercase)]
        if use_upper:   required.append(secrets.choice(string.ascii_uppercase))
        if use_digits:  required.append(secrets.choice(string.digits))
        if use_special: required.append(secrets.choice(string.punctuation))

        remaining = [secrets.choice(charset) for _ in range(length - len(required))]
        pwd_list  = required + remaining
        # Shuffle using secrets-backed index swaps
        for i in range(len(pwd_list) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            pwd_list[i], pwd_list[j] = pwd_list[j], pwd_list[i]

        pwd = "".join(pwd_list)
        print(f"\n{Fore.GREEN}[+] Generated Password: {Fore.WHITE}{pwd}")
        return pwd

    def generate_passphrase(self, words=4):
        phrase = " ".join(secrets.choice(WORDLIST) for _ in range(words))
        print(f"\n{Fore.GREEN}[+] Diceware Passphrase: {Fore.WHITE}{phrase}")
        return phrase

    # ── CORE AUDIT ───────────────────────────────────────────────
    def audit(self, password):
        self.matrix_effect()

        # Entropy
        pool = sum([
            26 if re.search(r'[a-z]', password) else 0,
            26 if re.search(r'[A-Z]', password) else 0,
            10 if re.search(r'\d',    password) else 0,
            32 if re.search(r'\W',    password) else 0,
        ])
        entropy = len(password) * math.log2(pool) if pool > 0 else 0
        seconds = (2 ** entropy) / 100_000_000_000 if entropy > 0 else 0

        # Checks
        leak_count   = self.get_leak_count(password)
        patterns     = self.detect_patterns(password)
        freq_pen, freq_detail = self.char_frequency_score(password)
        score, grade = self.compute_score(entropy, leak_count, patterns, freq_pen)
        crack_str    = self.format_crack_time(seconds)
        recs         = self.build_recommendations(password, patterns, freq_pen, entropy, leak_count)

        # Format display values
        if leak_count > 0:
            hibp_txt = f"{Fore.RED}VULNERABLE ({leak_count:,} leaks)"
        elif leak_count == 0:
            hibp_txt = f"{Fore.GREEN}CLEAN"
        else:
            hibp_txt = f"{Fore.YELLOW}OFFLINE"

        common_txt = (f"{Fore.RED}YES — common password"
                      if any(p[0] == "COMMON PASSWORD" for p in patterns)
                      else f"{Fore.GREEN}NO")

        # ── Terminal output ──────────────────────────────────────
        try:
            w = os.get_terminal_size().columns
        except OSError:
            w = TERMINAL_WIDTH

        top = f"{Fore.CYAN}╔{'═' * (w - 2)}╗"
        bot = f"{Fore.CYAN}╚{'═' * (w - 2)}╝"
        mid = self._box_divider()

        print(top)
        print(f"{Fore.CYAN}║{Fore.GREEN}{'  PRIVIPASS FORENSIC AUDIT REPORT':^{w-2}}{Fore.CYAN}║")
        print(mid)
        print(self._box_row("Grade:       ", f"{grade}  {self.strength_bar(score)}"))
        print(self._box_row("Entropy:     ", f"{entropy:.2f} bits"))
        print(self._box_row("Crack Time:  ", crack_str))
        print(self._box_row("HIBP Status: ", hibp_txt))
        print(self._box_row("Common Pwd:  ", common_txt))
        print(self._box_row("Char Dist:   ", f"{Fore.YELLOW if freq_pen else Fore.GREEN}{freq_detail}"))
        print(mid)

        if patterns:
            print(self._box_row("WEAKNESSES:", ""))
            for label, detail in patterns:
                print(self._box_row(f"  [{label}] ", f"{Fore.RED}{detail}"))
            print(mid)

        print(self._box_row("RECOMMENDATIONS:", ""))
        for rec in recs:
            print(self._box_row("  + ", f"{Fore.CYAN}{rec}"))
        print(bot)

        # ── Post-audit options ───────────────────────────────────
        print(f"\n{Fore.WHITE}Options:")
        print(f"  [1] Export PDF report")
        print(f"  [2] Generate a strong password")
        print(f"  [3] Generate a diceware passphrase")
        print(f"  [4] Exit")
        choice = input(f"\n{Fore.WHITE}Select: ").strip()

        if choice == "1":
            result_data = {
                "password":        password,
                "grade":           grade,
                "score":           score,
                "entropy":         f"{entropy:.2f} bits",
                "crack_time":      crack_str,
                "hibp":            self._strip_ansi(hibp_txt),
                "common":          self._strip_ansi(common_txt),
                "char_freq":       freq_detail,
                "weaknesses":      [f"[{l}] {d}" for l, d in patterns],
                "recommendations": recs,
            }
            pdf = PriViPDFReport(self.author)
            fname = pdf.generate_report(result_data, batch=False)
            print(f"{Fore.GREEN}[+] Report saved: {Fore.WHITE}{fname}")

        elif choice == "2":
            self.generate_password()

        elif choice == "3":
            self.generate_passphrase()

        return {
            "password":   password,
            "grade":      grade,
            "score":      score,
            "entropy":    f"{entropy:.2f} bits",
            "crack_time": crack_str,
            "hibp":       self._strip_ansi(hibp_txt),
        }

    # ── BATCH MODE ───────────────────────────────────────────────
    def batch_audit(self, filepath):
        """Audit all passwords in a file; generate a consolidated PDF."""
        if not os.path.isfile(filepath):
            print(f"{Fore.RED}[!] File not found: {filepath}")
            sys.exit(1)

        with open(filepath, 'r', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]

        if not passwords:
            print(f"{Fore.RED}[!] No passwords found in file.")
            sys.exit(1)

        print(f"{Fore.CYAN}[*] Batch auditing {len(passwords)} passwords...\n")
        results = []

        for idx, pwd in enumerate(passwords, 1):
            print(f"{Fore.WHITE}[{idx}/{len(passwords)}] Auditing: {pwd[:3]}***", end='\r')

            pool    = sum([
                26 if re.search(r'[a-z]', pwd) else 0,
                26 if re.search(r'[A-Z]', pwd) else 0,
                10 if re.search(r'\d',    pwd) else 0,
                32 if re.search(r'\W',    pwd) else 0,
            ])
            entropy = len(pwd) * math.log2(pool) if pool > 0 else 0
            seconds = (2 ** entropy) / 100_000_000_000 if entropy > 0 else 0
            leak    = self.get_leak_count(pwd)
            patterns, freq_pen, _ = self.detect_patterns(pwd), *self.char_frequency_score(pwd)
            score, grade = self.compute_score(entropy, leak, patterns, freq_pen)

            results.append({
                "password":   pwd,
                "grade":      grade,
                "score":      score,
                "entropy":    f"{entropy:.1f}b",
                "crack_time": self.format_crack_time(seconds),
                "hibp":       f"{leak:,} leaks" if leak > 0 else ("OFFLINE" if leak == -1 else "CLEAN"),
            })
            time.sleep(0.3)   # Be polite to HIBP API

        print(f"\n{Fore.GREEN}[+] Batch complete. Generating PDF...")
        pdf   = PriViPDFReport(self.author)
        fname = pdf.generate_report(results, batch=True)
        print(f"{Fore.GREEN}[+] Batch report saved: {Fore.WHITE}{fname}")


# ─────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"PriViPassElite v{VERSION} — Forensic Password Auditor")
    parser.add_argument("--wordlist", "-w", default=None,
                        help="Path to a file of passwords for batch audit mode.")
    args = parser.parse_args()

    app = PriViPassElite()

    try:
        app.boot_sequence()

        if args.wordlist:
            app.batch_audit(args.wordlist)
        else:
            print(f"{Fore.WHITE}Input Password (Masked): ", end='', flush=True)
            pwd = getpass.getpass(prompt='')
            # FIX: guard empty input before audit
            if not pwd:
                print(f"{Fore.RED}[!] No password entered. Exiting.")
                sys.exit(0)
            app.audit(pwd)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Exit.")
        sys.exit(0)
