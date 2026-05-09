#!/usr/bin/env python3
"""
PriVi-SPECTER — Forensic Credential Analysis Suite
Developed by PriViSecurity
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
import difflib
from colorama import Fore, init
import getpass
from fpdf import FPDF
from fpdf.enums import XPos, YPos

init(autoreset=True)

# ─────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────

AUTHOR  = "PriViSecurity"
VERSION = "1.0"

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
    "p@ssword", "root", "password123", "qwertyuiop"
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

TERMINAL_WIDTH = 75


# ─────────────────────────────────────────────────────────────────
#  PDF REPORTER (fpdf2 Optimized)
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
        # Professional Slate Header
        self.set_fill_color(44, 62, 80)
        self.rect(0, 0, 210, 35, 'F')
        
        self.set_xy(10, 10)
        self.set_font("helvetica", 'B', 20)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, "PRIVI-SPECTER FORENSIC AUDIT", border=0, align='L', 
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        self.set_xy(10, 18)
        self.set_font("helvetica", '', 10)
        self.set_text_color(180, 180, 180)
        self.cell(0, 10, f"Engine: v{VERSION} | Auditor: {self.author_name}", border=0, align='L', 
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"PriViSecurity Confidential - Page {self.page_no()}", align='C')

    def generate_report(self, results, batch=False):
        """Generate PDF for single or batch audit results."""
        self.alias_nb_pages()
        self.add_page()
        self.set_text_color(0, 0, 0)

        if batch:
            self._write_batch_section(results)
        else:
            self._write_single_section(results)

        # Signature
        self.ln(10)
        self.set_font("helvetica", 'BI', 13)
        self.cell(0, 10, f"~ Signed: {self.author_name} ~", align='R', 
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_font("helvetica", 'I', 9)
        self.cell(0, 5, f"Cybersecurity Professional | {self.author_name}", align='R', 
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        if not os.path.exists('reports'):
            os.makedirs('reports')
        
        filename = f"reports/PriVi_Specter_{int(time.time())}.pdf"
        self.output(filename)
        return filename

    def _write_single_section(self, r):
        """Write a single-password audit section."""
        # Risk Summary
        self.set_font("helvetica", 'B', 14)
        self.set_text_color(44, 62, 80)
        self.cell(0, 10, "1. Executive Risk Rating", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        score = r.get("score", 1)
        score_map = {
            1: ("CRITICAL", (231, 76, 60)), 
            2: ("HIGH", (230, 126, 34)),
            3: ("MEDIUM", (241, 196, 15)),
            4: ("STRONG", (46, 204, 113)),
            5: ("ELITE", (52, 152, 219))
        }
        label, color = score_map.get(score, ("UNKNOWN", (100, 100, 100)))
        
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font("helvetica", 'B', 12)
        self.cell(50, 12, f"{label} ({score}/5)", border=0, fill=True, align='C', 
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(5)

        # Technical Metrics
        self.set_text_color(0, 0, 0)
        self.set_font("helvetica", 'B', 11)
        self.cell(0, 10, "2. Deep Forensic Analysis", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        self.set_font("helvetica", 'B', 10)
        self.set_fill_color(240, 240, 240)
        self.cell(70, 10, " Metric", border=1, fill=True)
        self.cell(0,  10, " Result", border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        self.set_font("helvetica", '', 10)
        rows = [
            ("Shannon Entropy",  f"{r.get('shannon', 'N/A')} bits/char"),
            ("Complexity Pool",  f"{r.get('entropy', 'N/A')} total bits"),
            ("HIBP Breach Status", r.get("hibp", "N/A")),
            ("Crack Time Estimate", r.get("crack_time", "N/A")),
            ("Character Distribution", r.get("char_freq", "N/A")),
        ]
        for m, v in rows:
            self.cell(70, 9, f" {m}", border=1)
            self.cell(0,  9, f" {_pdf_safe(str(v))}", border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        weaknesses = r.get("weaknesses", [])
        if weaknesses:
            self.ln(5)
            self.set_font("helvetica", 'B', 11)
            self.cell(0, 10, "3. Detected Vulnerabilities", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_font("helvetica", '', 10)
            for w in weaknesses:
                self.multi_cell(0, 7, f" - {_pdf_safe(w)}", border='L', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        recs = r.get("recommendations", [])
        if recs:
            self.ln(5)
            self.set_font("helvetica", 'B', 11)
            self.set_fill_color(235, 245, 255)
            self.cell(0, 10, " 4. Mitigation Strategies", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_font("helvetica", '', 10)
            for rec in recs:
                self.multi_cell(0, 7, f" [*] {_pdf_safe(rec)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def _write_batch_section(self, results):
        """Write a batch summary table."""
        self.set_font("helvetica", 'B', 14)
        self.cell(0, 10, "Batch Forensic Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)

        # Header
        self.set_font("helvetica", 'B', 9)
        self.set_fill_color(44, 62, 80)
        self.set_text_color(255, 255, 255)
        self.cell(10,  8, "#",       border=1, fill=True, align='C')
        self.cell(55,  8, "Target (Masked)", border=1, fill=True, align='C')
        self.cell(20,  8, "Score",   border=1, fill=True, align='C')
        self.cell(25,  8, "Shannon", border=1, fill=True, align='C')
        self.cell(35,  8, "Crack Time", border=1, fill=True, align='C')
        self.cell(45,  8, "Breach Intel",    border=1, fill=True, align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)

        self.set_font("helvetica", size=8)
        for idx, r in enumerate(results, 1):
            pwd = r.get("password", "")
            masked = pwd[0] + "*" * (len(pwd) - 2) + pwd[-1] if len(pwd) > 2 else "***"
            self.cell(10,  8, str(idx),              border=1, align='C')
            self.cell(55,  8, _pdf_safe(masked),                          border=1)
            self.cell(20,  8, f"{r.get('score', 'N/A')}/5",             border=1, align='C')
            self.cell(25,  8, _pdf_safe(str(r.get("shannon", "N/A"))),            border=1, align='C')
            self.cell(35,  8, _pdf_safe(r.get("crack_time", "N/A")),         border=1, align='C')
            self.cell(45,  8, _pdf_safe(r.get("hibp", "N/A")),              border=1, align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)


# ─────────────────────────────────────────────────────────────────
#  AUDITOR CORE
# ─────────────────────────────────────────────────────────────────

class PriViSpecter:
    def __init__(self):
        self.version = VERSION
        self.author  = AUTHOR

    # ── BOOT ─────────────────────────────────────────────────────
    def boot_sequence(self):
        logo = f"""
{Fore.GREEN}  ██████╗ ██████╗ ██╗██╗   ██╗██╗      ███████╗██████╗ ███████╗
{Fore.GREEN}  ██╔══██╗██╔══██╗██║██║   ██║██║      ██╔════╝██╔══██╗██╔════╝
{Fore.GREEN}  ██████╔╝██████╔╝██║██║   ██║██║█████╗███████╗██████╔╝█████╗  
{Fore.GREEN}  ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝ ██║╚════╝╚════██║██╔═══╝ ██╔══╝  
{Fore.GREEN}  ██║     ██║  ██║██║ ╚████╔╝  ██║      ███████║██║     ███████╗
{Fore.GREEN}  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝      ╚══════╝╚═╝     ╚══════╝
{Fore.WHITE}      [ {self.author} | FORENSIC CREDENTIAL SUITE v{self.version} ]
        """
        print("\033[H\033[J", end="")
        for line in logo.splitlines():
            print(line)
            time.sleep(0.04)

        print(f"{Fore.CYAN}{'=' * TERMINAL_WIDTH}")
        checks = ["Heuristic Engine", "Shannon Algorithms", "Fuzzy DB", "K-Anonymity Connector"]
        for check in checks:
            sys.stdout.write(f"{Fore.WHITE}[*] Initializing {check}...")
            sys.stdout.flush()
            time.sleep(random.uniform(0.1, 0.2))
            print(f" {Fore.GREEN}[OK]")
        print(f"{Fore.CYAN}{'=' * TERMINAL_WIDTH}\n")

    def matrix_effect(self, duration=1.0):
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        print(f"{Fore.GREEN}[*] RUNNING DEEP MEMORY HEURISTICS...")
        end_time = time.time() + duration
        while time.time() < end_time:
            addr   = f"0x{random.getrandbits(32):08x}"
            stream = "".join(random.choice(chars) for _ in range(45))
            sys.stdout.write(f"\r{Fore.GREEN}{addr} | {Fore.WHITE}{stream}")
            sys.stdout.flush()
            time.sleep(0.04)
        print(f"\n{Fore.GREEN}[+] HEURISTICS COMPLETE. COMPILING FORENSICS...\n")

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

    # ── METRICS ──────────────────────────────────────────────────
    def get_shannon_entropy(self, pwd):
        if not pwd: return 0
        freq = {char: pwd.count(char) for char in set(pwd)}
        entropy = -sum((count / len(pwd)) * math.log2(count / len(pwd)) for count in freq.values())
        return round(entropy, 2)

    def get_leak_count(self, password):
        sha1   = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
            if res.status_code == 200:
                for line in res.text.splitlines():
                    parts = line.split(':', 1)
                    if len(parts) == 2 and parts[0] == suffix:
                        return int(parts[1])
            return 0
        except requests.exceptions.RequestException:
            return -1

    def format_crack_time(self, seconds):
        if seconds < 1: return "Instantly"
        if seconds < 60: return f"{seconds:.0f} seconds"
        if seconds < 3600: return f"{seconds / 60:.0f} minutes"
        if seconds < 86400: return f"{seconds / 3600:.0f} hours"
        if seconds < 31536000: return f"{seconds / 86400:.0f} days"
        years = seconds / 31536000
        if years < 1_000: return f"{int(years)} years"
        if years < 1_000_000: return f"{years / 1000:.0f} thousand years"
        return "Centuries"

    # ── PATTERN DETECTION ────────────────────────────────────────
    def detect_patterns(self, password):
        found = []
        lower = password.lower()

        # 1. Fuzzy Match (Gestalt Pattern)
        is_fuzzy = False
        for common in COMMON_PASSWORDS:
            ratio = difflib.SequenceMatcher(None, lower, common).ratio()
            if ratio > 0.8:
                found.append(("FUZZY MATCH", f"Input is {int(ratio*100)}% similar to known weak password '{common}'"))
                is_fuzzy = True
                break

        if not is_fuzzy and lower in COMMON_PASSWORDS:
            found.append(("COMMON PASSWORD", "Exact match in high-risk password list"))

        # 2. Keyboard walk
        for walk in KEYBOARD_WALKS:
            if walk in lower:
                found.append(("KEYBOARD WALK", f"Sequential pattern detected: '{walk}'"))
                break

        # 3. Repeated characters
        repeat_match = re.search(r'(.)\1{2,}', password)
        if repeat_match:
            char = repeat_match.group(1)
            found.append(("REPEATED CHARS", f"Character '{char}' repeated 3+ times consecutively"))

        # 4. Leet substitution
        deleet = lower
        for leet_char, real_char in LEET_MAP.items():
            deleet = deleet.replace(leet_char, real_char)
        if deleet != lower and deleet in COMMON_PASSWORDS:
            found.append(("LEET SUBSTITUTION", f"Leet variant of common password detected"))

        # 5. Date patterns
        date_patterns = [
            r'\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\d{4}\b',
            r'\b(0[1-9]|[12]\d|3[01])[-/](0[1-9]|1[0-2])[-/]\d{4}\b',
            r'\b(19|20)\d{2}\b',
        ]
        for pat in date_patterns:
            if re.search(pat, password):
                found.append(("DATE PATTERN", "Password contains a recognisable date sequence"))
                break

        return found

    def char_frequency_score(self, password):
        if not password: return False, "N/A"
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
                return True, f"{int(ratio * 100)}% {cls_name} chars (Imbalanced)"
        return False, "Balanced distribution"

    # ── SCORING ──────────────────────────────────────────────────
    def compute_score(self, pool_entropy, leak_count, patterns, freq_penalty):
        if pool_entropy <= 0: return 1, "Critically Weak"

        if pool_entropy < 35: score = 1
        elif pool_entropy < 50: score = 2
        elif pool_entropy < 75: score = 3
        elif pool_entropy < 90: score = 4
        else: score = 5

        if leak_count > 0: score = 1
        
        if patterns: score -= len(patterns)
        if freq_penalty: score -= 1

        score = max(1, min(5, score))

        grades = {
            1: "CRITICAL RISK",
            2: "HIGH RISK",
            3: "MODERATE",
            4: "STRONG",
            5: "ELITE",
        }
        return score, grades[score]

    def strength_bar(self, score):
        colors = [Fore.RED, Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN]
        color  = colors[score - 1]
        filled = "█" * score
        empty  = "░" * (5 - score)
        return f"{color}[{filled}{empty}]{Fore.WHITE} ({score}/5)"

    # ── RECOMMENDATIONS ──────────────────────────────────────────
    def build_recommendations(self, password, patterns, freq_penalty, pool_entropy, leak_count):
        recs = []
        if len(password) < 12: recs.append("Increase length to at least 12 characters (16+ recommended).")
        if not re.search(r'[A-Z]', password): recs.append("Inject uppercase letters (A-Z).")
        if not re.search(r'\d', password): recs.append("Inject numerical digits (0-9).")
        if not re.search(r'\W', password): recs.append("Inject special characters (!@#$%^&*...).")
        
        if any(p[0] == "FUZZY MATCH" for p in patterns):
            recs.append("Avoid variations of common passwords. Attackers use rule-based mangling.")
        if any(p[0] == "KEYBOARD WALK" for p in patterns):
            recs.append("Eliminate keyboard walks ('qwerty'). They are cracked instantly.")
        if any(p[0] == "DATE PATTERN" for p in patterns):
            recs.append("Remove date structures. Years and birthdays are highly predictable.")
        if freq_penalty:
            recs.append("Diversify character classes to improve Shannon Entropy.")
        
        if leak_count > 0:
            recs.insert(0, "BREACH DETECTED: This exact password has been leaked. Replace it immediately across all accounts.")
        if not recs:
            recs.append("Credential meets Elite forensic standards. Store it securely in a Vault.")
        return recs

    # ── GENERATORS ───────────────────────────────────────────────
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

        required = [secrets.choice(string.ascii_lowercase)]
        if use_upper:   required.append(secrets.choice(string.ascii_uppercase))
        if use_digits:  required.append(secrets.choice(string.digits))
        if use_special: required.append(secrets.choice(string.punctuation))

        remaining = [secrets.choice(charset) for _ in range(length - len(required))]
        pwd_list  = required + remaining
        
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

        # Scientific Metrics
        shannon = self.get_shannon_entropy(password)

        # Pool Entropy
        pool = sum([
            26 if re.search(r'[a-z]', password) else 0,
            26 if re.search(r'[A-Z]', password) else 0,
            10 if re.search(r'\d',    password) else 0,
            32 if re.search(r'\W',    password) else 0,
        ])
        pool_entropy = len(password) * math.log2(pool) if pool > 0 else 0
        seconds = (2 ** pool_entropy) / 100_000_000_000 if pool_entropy > 0 else 0

        # Forensic Checks
        leak_count   = self.get_leak_count(password)
        patterns     = self.detect_patterns(password)
        freq_pen, freq_detail = self.char_frequency_score(password)
        score, grade = self.compute_score(pool_entropy, leak_count, patterns, freq_pen)
        crack_str    = self.format_crack_time(seconds)
        recs         = self.build_recommendations(password, patterns, freq_pen, pool_entropy, leak_count)

        # Format display values
        if leak_count > 0:
            hibp_txt = f"{Fore.RED}VULNERABLE ({leak_count:,} leaks)"
        elif leak_count == 0:
            hibp_txt = f"{Fore.GREEN}CLEAN"
        else:
            hibp_txt = f"{Fore.YELLOW}OFFLINE"

        # ── Terminal output ──────────────────────────────────────
        try:
            w = os.get_terminal_size().columns
        except OSError:
            w = TERMINAL_WIDTH

        top = f"{Fore.CYAN}╔{'═' * (w - 2)}╗"
        bot = f"{Fore.CYAN}╚{'═' * (w - 2)}╝"
        mid = self._box_divider()

        print(top)
        print(f"{Fore.CYAN}║{Fore.GREEN}{'  PRIVI-SPECTER FORENSIC REPORT':^{w-2}}{Fore.CYAN}║")
        print(mid)
        print(self._box_row("Risk Grade:  ", f"{grade}  {self.strength_bar(score)}"))
        print(self._box_row("Shannon Info:", f"{shannon} bits/char"))
        print(self._box_row("Pool Entropy:", f"{pool_entropy:.2f} total bits"))
        print(self._box_row("Crack Time:  ", crack_str))
        print(self._box_row("Breach Intel:", hibp_txt))
        print(self._box_row("Char Dist:   ", f"{Fore.YELLOW if freq_pen else Fore.GREEN}{freq_detail}"))
        print(mid)

        if patterns:
            print(self._box_row("FORENSIC FINDINGS:", ""))
            for label, detail in patterns:
                print(self._box_row(f"   [{label}] ", f"{Fore.RED}{detail}"))
            print(mid)

        print(self._box_row("MITIGATION ROADMAP:", ""))
        for rec in recs:
            print(self._box_row("   + ", f"{Fore.CYAN}{rec}"))
        print(bot)

        # ── Post-audit options ───────────────────────────────────
        print(f"\n{Fore.WHITE}Actions:")
        print(f"  [1] Export Certified PDF Report")
        print(f"  [2] Generate a Strong Password")
        print(f"  [3] Generate a Diceware Passphrase")
        print(f"  [4] Exit")
        choice = input(f"\n{Fore.WHITE}Select [1-4]: ").strip()

        if choice == "1":
            result_data = {
                "password":        password,
                "grade":           grade,
                "score":           score,
                "shannon":         shannon,
                "entropy":         f"{pool_entropy:.2f}",
                "crack_time":      crack_str,
                "hibp":            self._strip_ansi(hibp_txt),
                "char_freq":       freq_detail,
                "weaknesses":      [f"[{l}] {d}" for l, d in patterns],
                "recommendations": recs,
            }
            pdf = PriViPDFReport(self.author)
            fname = pdf.generate_report(result_data, batch=False)
            print(f"{Fore.GREEN}[+] Report saved to: {Fore.WHITE}{fname}")

        elif choice == "2":
            self.generate_password()

        elif choice == "3":
            self.generate_passphrase()

        return

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

        print(f"{Fore.CYAN}[*] Batch auditing {len(passwords)} credentials...\n")
        results = []

        for idx, pwd in enumerate(passwords, 1):
            print(f"{Fore.WHITE}[{idx}/{len(passwords)}] Auditing: {pwd[:3]}***", end='\r')

            shannon = self.get_shannon_entropy(pwd)
            pool    = sum([
                26 if re.search(r'[a-z]', pwd) else 0,
                26 if re.search(r'[A-Z]', pwd) else 0,
                10 if re.search(r'\d',    pwd) else 0,
                32 if re.search(r'\W',    pwd) else 0,
            ])
            pool_entropy = len(pwd) * math.log2(pool) if pool > 0 else 0
            seconds = (2 ** pool_entropy) / 100_000_000_000 if pool_entropy > 0 else 0
            leak    = self.get_leak_count(pwd)
            patterns = self.detect_patterns(pwd)
            freq_pen, freq_detail = self.char_frequency_score(pwd)
            score, grade = self.compute_score(pool_entropy, leak, patterns, freq_pen)

            results.append({
                "password":   pwd,
                "grade":      grade,
                "score":      score,
                "shannon":    shannon,
                "crack_time": self.format_crack_time(seconds),
                "hibp":       f"{leak:,} leaks" if leak > 0 else ("OFFLINE" if leak == -1 else "CLEAN"),
            })
            time.sleep(0.2)   # Be polite to HIBP API

        print(f"\n{Fore.GREEN}[+] Batch complete. Compiling Forensic PDF...")
        pdf   = PriViPDFReport(self.author)
        fname = pdf.generate_report(results, batch=True)
        print(f"{Fore.GREEN}[+] Batch report saved to: {Fore.WHITE}{fname}")


# ─────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"PriVi-SPECTER v{VERSION} — Forensic Credential Suite")
    parser.add_argument("--wordlist", "-w", default=None,
                        help="Path to a file of passwords for batch audit mode.")
    args = parser.parse_args()

    app = PriViSpecter()

    try:
        app.boot_sequence()

        if args.wordlist:
            app.batch_audit(args.wordlist)
        else:
            print(f"{Fore.WHITE}Input Target Credential (Masked): ", end='', flush=True)
            pwd = getpass.getpass(prompt='')
            if not pwd:
                print(f"{Fore.RED}[!] No password entered. Aborting.")
                sys.exit(0)
            app.audit(pwd)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Exit triggered. Memory cleared.")
        sys.exit(0)
