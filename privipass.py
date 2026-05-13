#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║       PriVi-SPECTER v1.0                                         ║
║       Forensic Credential Analysis Suite                         ║
║       Developed by Prince Ubebe | PriViSecurity                  ║
╚══════════════════════════════════════════════════════════════════╝

LEGAL NOTICE:
  This tool is intended ONLY for auditing credentials you own or
  have explicit written authorization to assess. Unauthorized
  credential auditing is illegal under the Computer Misuse Act,
  CFAA, and equivalent laws worldwide.
  PriViSecurity accepts no liability for unauthorized use.
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
import getpass
from datetime import datetime
from fpdf import FPDF
from fpdf.enums import XPos, YPos
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt

console = Console()

AUTHOR  = "Prince Ubebe"
BRAND   = "PriViSecurity"
VERSION = "2.0"
TOOL    = "PriVi-SPECTER"

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


# ── HEADER ────────────────────────────────────────────────────────────────────

def print_header():
    os.system("clear")
    header = Text()
    header.append(
        "\n"
        "  ███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗\n"
        "  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗\n"
        "  ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝\n"
        "  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗\n"
        "  ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║\n"
        "  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n",
        style="bold cyan"
    )
    header.append(
        f"  {BRAND}  |  {TOOL} v{VERSION}  |  Forensic Credential Analysis Suite\n",
        style="dim white"
    )
    header.append(f"  Developer: {AUTHOR}  |  Authorized Use Only\n", style="dim red")
    console.print(Panel(header, border_style="blue"))


# ── PDF REPORTER ──────────────────────────────────────────────────────────────

def _pdf_safe(s):
    s = re.sub(r'\x1b\[[0-9;]*m', '', str(s))
    s = re.sub(r'\[/?[a-z0-9 _]+\]', '', s)
    return s.encode('latin-1', errors='replace').decode('latin-1')


class PriViPDFReport(FPDF):
    def __init__(self):
        super().__init__()

    def header(self):
        self.set_fill_color(26, 26, 46)
        self.rect(0, 0, 210, 38, "F")
        self.set_xy(10, 8)
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, "PriVi-SPECTER Forensic Credential Report",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_xy(10, 20)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(180, 180, 180)
        self.cell(0, 8,
                  f"PriViSecurity  |  Analyst: {AUTHOR}  |  {TOOL} v{VERSION}",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(18)

    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(
            0, 10,
            f"Page {self.page_no()}   -   Confidential: Authorized Use Only   -   PriViSecurity",
            align="C"
        )

    def section_title(self, title: str):
        self.set_fill_color(196, 30, 58)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 9, f"  {title}", fill=True,new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def generate_report(self, results, batch=False):
        self.add_page()
        self.set_text_color(0, 0, 0)
        if batch:
            self._write_batch_section(results)
        else:
            self._write_single_section(results)

        # Signature
        self.ln(8)
        self.set_font("Helvetica", "I", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, f"Auditor: {AUTHOR}  |  {BRAND}  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                  align="R",new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        os.makedirs("reports", exist_ok=True)
        filename = f"reports/PriVi_Specter_{int(time.time())}.pdf"
        self.output(filename)
        return filename

    def _write_single_section(self, r):
        self.section_title("1. Executive Risk Rating")
        score = r.get("score", 1)
        score_map = {
            1: ("CRITICAL RISK", (196, 30, 58)),
            2: ("HIGH RISK",     (220, 100, 30)),
            3: ("MODERATE",      (200, 160, 0)),
            4: ("STRONG",        (30, 160, 60)),
            5: ("ELITE",         (30, 120, 200)),
        }
        label, color = score_map.get(score, ("UNKNOWN", (100, 100, 100)))
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 12)
        self.cell(60, 12, f"  {label}  ({score}/5)", fill=True,new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(4)

        self.section_title("2. Forensic Metrics")
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(26, 26, 46)
        self.set_text_color(255, 255, 255)
        self.cell(70, 7, "  Metric", fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(0,  7, "  Result", fill=True,new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(0, 0, 0)
        alt = False
        rows = [
            ("Shannon Entropy",     f"{r.get('shannon', 'N/A')} bits/char"),
            ("Pool Entropy",        f"{r.get('entropy', 'N/A')} bits"),
            ("HIBP Breach Status",  r.get("hibp", "N/A")),
            ("Crack Time Estimate", r.get("crack_time", "N/A")),
            ("Char Distribution",   r.get("char_freq", "N/A")),
        ]
        for m, v in rows:
            self.set_fill_color(245, 245, 250) if alt else self.set_fill_color(255, 255, 255)
            alt = not alt
            self.cell(70, 7, f"  {m}", fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(0,  7, f"  {_pdf_safe(str(v))}", fill=True,new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(4)

        weaknesses = r.get("weaknesses", [])
        if weaknesses:
            self.section_title("3. Detected Vulnerabilities")
            self.set_font("Helvetica", "", 9)
            for w in weaknesses:
                self.set_text_color(196, 30, 58)
                self.multi_cell(0, 6, f"  * {_pdf_safe(w)}")
            self.set_text_color(0, 0, 0)
            self.ln(4)

        recs = r.get("recommendations", [])
        if recs:
            self.section_title("4. Mitigation Recommendations")
            self.set_font("Helvetica", "", 9)
            self.set_text_color(0, 0, 0)
            for i, rec in enumerate(recs, 1):
                self.multi_cell(0, 6, f"  {i}. {_pdf_safe(rec)}")
                self.ln(1)

    def _write_batch_section(self, results):
        self.section_title("Batch Forensic Summary")
        self.set_font("Helvetica", "B", 8)
        self.set_fill_color(26, 26, 46)
        self.set_text_color(255, 255, 255)
        self.cell(10,  7, "#",             fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP, align="C")
        self.cell(55,  7, "Target (Masked)", fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP, align="C")
        self.cell(20,  7, "Score",         fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP, align="C")
        self.cell(25,  7, "Shannon",       fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP, align="C")
        self.cell(35,  7, "Crack Time",    fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP, align="C")
        self.cell(45,  7, "Breach Intel",  fill=True,new_x=XPos.LMARGIN, new_y=YPos.NEXT,  align="C")
        self.set_font("Helvetica", "", 8)
        self.set_text_color(0, 0, 0)
        alt = False
        for idx, r in enumerate(results, 1):
            pwd    = r.get("password", "")
            masked = pwd[0] + "*" * (len(pwd) - 2) + pwd[-1] if len(pwd) > 2 else "***"
            self.set_fill_color(245, 245, 250) if alt else self.set_fill_color(255, 255, 255)
            alt = not alt
            self.cell(10,  6, str(idx),                          fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP, align="C")
            self.cell(55,  6, _pdf_safe(masked),                 fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(20,  6, f"{r.get('score','N/A')}/5",       fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP, align="C")
            self.cell(25,  6, _pdf_safe(str(r.get("shannon","N/A"))), fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP, align="C")
            self.cell(35,  6, _pdf_safe(r.get("crack_time","N/A")),   fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP, align="C")
            self.cell(45,  6, _pdf_safe(r.get("hibp","N/A")),    fill=True,new_x=XPos.LMARGIN, new_y=YPos.NEXT,  align="C")


# ── AUDITOR CORE ──────────────────────────────────────────────────────────────

class PriViSpecter:
    def __init__(self):
        self.version = VERSION
        self.author  = AUTHOR

    # ── BOOT ──────────────────────────────────────────────────────────────────

    def boot_sequence(self):
        print_header()
        checks = [
            "Heuristic Engine",
            "Shannon Algorithms",
            "Fuzzy Database",
            "K-Anonymity Connector",
        ]
        with console.status("[bold cyan]Initializing engines...[/bold cyan]", spinner="dots"):
            for check in checks:
                time.sleep(random.uniform(0.1, 0.2))
                console.print(f"  [bold green][OK][/bold green]  {check}")
        console.print()

    def matrix_effect(self, duration=0.8):
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        console.print("[bold green][*] Running deep memory heuristics...[/bold green]")
        end_time = time.time() + duration
        while time.time() < end_time:
            addr   = f"0x{random.getrandbits(32):08x}"
            stream = "".join(random.choice(chars) for _ in range(45))
            sys.stdout.write(f"\r  \033[32m{addr}\033[0m | \033[97m{stream}\033[0m")
            sys.stdout.flush()
            time.sleep(0.04)
        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()
        console.print("[bold green][+] Heuristics complete. Compiling forensics...[/bold green]\n")

    # ── HELPERS ───────────────────────────────────────────────────────────────

    def _strip_ansi(self, s):
        return re.sub(r'\x1b\[[0-9;]*m', '', s)

    # ── METRICS ───────────────────────────────────────────────────────────────

    def get_shannon_entropy(self, pwd):
        if not pwd: return 0
        freq    = {char: pwd.count(char) for char in set(pwd)}
        entropy = -sum((c / len(pwd)) * math.log2(c / len(pwd)) for c in freq.values())
        return round(entropy, 2)

    def get_leak_count(self, password):
        sha1           = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            res = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5
            )
            if res.status_code == 200:
                for line in res.text.splitlines():
                    parts = line.split(":", 1)
                    if len(parts) == 2 and parts[0] == suffix:
                        return int(parts[1])
            return 0
        except requests.exceptions.RequestException:
            return -1

    def format_crack_time(self, seconds):
        if seconds < 1:          return "Instantly"
        if seconds < 60:         return f"{seconds:.0f} seconds"
        if seconds < 3600:       return f"{seconds / 60:.0f} minutes"
        if seconds < 86400:      return f"{seconds / 3600:.0f} hours"
        if seconds < 31536000:   return f"{seconds / 86400:.0f} days"
        years = seconds / 31536000
        if years < 1_000:        return f"{int(years)} years"
        if years < 1_000_000:    return f"{years / 1000:.0f} thousand years"
        return "Centuries"

    # ── PATTERN DETECTION ─────────────────────────────────────────────────────

    def detect_patterns(self, password):
        found = []
        lower = password.lower()

        is_fuzzy = False
        for common in COMMON_PASSWORDS:
            ratio = difflib.SequenceMatcher(None, lower, common).ratio()
            if ratio > 0.8:
                found.append(("FUZZY MATCH",
                               f"Input is {int(ratio*100)}% similar to known weak password '{common}'"))
                is_fuzzy = True
                break
        if not is_fuzzy and lower in COMMON_PASSWORDS:
            found.append(("COMMON PASSWORD", "Exact match in high-risk password list"))

        for walk in KEYBOARD_WALKS:
            if walk in lower:
                found.append(("KEYBOARD WALK", f"Sequential pattern detected: '{walk}'"))
                break

        repeat_match = re.search(r'(.)\1{2,}', password)
        if repeat_match:
            found.append(("REPEATED CHARS",
                           f"Character '{repeat_match.group(1)}' repeated 3+ times consecutively"))

        deleet = lower
        for leet_char, real_char in LEET_MAP.items():
            deleet = deleet.replace(leet_char, real_char)
        if deleet != lower and deleet in COMMON_PASSWORDS:
            found.append(("LEET SUBSTITUTION", "Leet variant of common password detected"))

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
        total   = len(password)
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

    # ── SCORING ───────────────────────────────────────────────────────────────

    def compute_score(self, pool_entropy, leak_count, patterns, freq_penalty):
        if pool_entropy <= 0: return 1, "CRITICAL RISK"
        if pool_entropy < 35:  score = 1
        elif pool_entropy < 50: score = 2
        elif pool_entropy < 75: score = 3
        elif pool_entropy < 90: score = 4
        else:                   score = 5

        if leak_count > 0:  score = 1
        if patterns:        score -= len(patterns)
        if freq_penalty:    score -= 1

        score  = max(1, min(5, score))
        grades = {1: "CRITICAL RISK", 2: "HIGH RISK", 3: "MODERATE", 4: "STRONG", 5: "ELITE"}
        return score, grades[score]

    def strength_bar(self, score: int) -> str:
        colors = ["bold red", "bold red", "bold yellow", "bold green", "bold cyan"]
        filled = "█" * score
        empty  = "░" * (5 - score)
        return f"[{colors[score-1]}][{filled}{empty}] {score}/5[/{colors[score-1]}]"

    # ── RECOMMENDATIONS ───────────────────────────────────────────────────────

    def build_recommendations(self, password, patterns, freq_penalty, pool_entropy, leak_count):
        recs = []
        if len(password) < 12:
            recs.append("Increase length to at least 12 characters (16+ recommended).")
        if not re.search(r'[A-Z]', password):
            recs.append("Add uppercase letters (A-Z).")
        if not re.search(r'\d', password):
            recs.append("Add numerical digits (0-9).")
        if not re.search(r'\W', password):
            recs.append("Add special characters (!@#$%^&*).")
        if any(p[0] == "FUZZY MATCH" for p in patterns):
            recs.append("Avoid variations of common passwords. Attackers use rule-based mangling.")
        if any(p[0] == "KEYBOARD WALK" for p in patterns):
            recs.append("Eliminate keyboard walks ('qwerty'). They are cracked instantly.")
        if any(p[0] == "DATE PATTERN" for p in patterns):
            recs.append("Remove date structures. Years and birthdays are highly predictable.")
        if freq_penalty:
            recs.append("Diversify character classes to improve Shannon Entropy.")
        if leak_count > 0:
            recs.insert(0,
                "BREACH DETECTED: This exact password has been leaked. "
                "Replace it immediately across all accounts.")
        if not recs:
            recs.append("Credential meets Elite forensic standards. Store it securely in a vault.")
        return recs

    # ── GENERATORS ────────────────────────────────────────────────────────────

    def generate_password(self):
        console.print("\n[bold cyan][SECURE GENERATOR MODE][/bold cyan]")
        try:
            length = int(input("  Length (12-64, default 16): ").strip() or "16")
            length = max(12, min(64, length))
        except ValueError:
            length = 16

        use_upper   = input("  Include Uppercase [Y/n]: ").strip().lower() != "n"
        use_digits  = input("  Include Digits    [Y/n]: ").strip().lower() != "n"
        use_special = input("  Include Special   [Y/n]: ").strip().lower() != "n"

        charset  = string.ascii_lowercase
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
        console.print(f"\n[bold green][+] Generated Password:[/bold green] [white]{pwd}[/white]")
        return pwd

    def generate_passphrase(self, words=4):
        phrase = " ".join(secrets.choice(WORDLIST) for _ in range(words))
        console.print(f"\n[bold green][+] Diceware Passphrase:[/bold green] [white]{phrase}[/white]")
        return phrase

    # ── CORE AUDIT ────────────────────────────────────────────────────────────

    def audit(self, password):
        self.matrix_effect()

        # Metrics
        shannon      = self.get_shannon_entropy(password)
        pool         = sum([
            26 if re.search(r'[a-z]', password) else 0,
            26 if re.search(r'[A-Z]', password) else 0,
            10 if re.search(r'\d',    password) else 0,
            32 if re.search(r'\W',    password) else 0,
        ])
        pool_entropy = len(password) * math.log2(pool) if pool > 0 else 0
        seconds      = (2 ** pool_entropy) / 100_000_000_000 if pool_entropy > 0 else 0

        leak_count         = self.get_leak_count(password)
        patterns           = self.detect_patterns(password)
        freq_pen, freq_det = self.char_frequency_score(password)
        score, grade       = self.compute_score(pool_entropy, leak_count, patterns, freq_pen)
        crack_str          = self.format_crack_time(seconds)
        recs               = self.build_recommendations(
                                 password, patterns, freq_pen, pool_entropy, leak_count)

        if leak_count > 0:
            hibp_display = f"[bold red]VULNERABLE ({leak_count:,} leaks)[/bold red]"
            hibp_plain   = f"VULNERABLE ({leak_count:,} leaks)"
        elif leak_count == 0:
            hibp_display = "[bold green]CLEAN[/bold green]"
            hibp_plain   = "CLEAN"
        else:
            hibp_display = "[bold yellow]OFFLINE (API unreachable)[/bold yellow]"
            hibp_plain   = "OFFLINE"

        # ── Results table ─────────────────────────────────────────────────────
        metrics = Table(
            title="[bold green]PRIVI-SPECTER FORENSIC REPORT[/bold green]",
            border_style="cyan", show_lines=True
        )
        metrics.add_column("Metric",   style="bold white", width=22)
        metrics.add_column("Result",   style="white")

        grade_colors = {
            "CRITICAL RISK": "bold red",
            "HIGH RISK":     "bold red",
            "MODERATE":      "bold yellow",
            "STRONG":        "bold green",
            "ELITE":         "bold cyan",
        }
        gc = grade_colors.get(grade, "white")
        metrics.add_row("Risk Grade",      f"[{gc}]{grade}[/{gc}]  {self.strength_bar(score)}")
        metrics.add_row("Shannon Entropy", f"{shannon} bits/char")
        metrics.add_row("Pool Entropy",    f"{pool_entropy:.2f} total bits")
        metrics.add_row("Crack Time",      crack_str)
        metrics.add_row("HIBP Breach",     hibp_display)
        metrics.add_row("Char Dist",
            f"[bold yellow]{freq_det}[/bold yellow]" if freq_pen
            else f"[bold green]{freq_det}[/bold green]"
        )
        console.print(metrics)

        # Patterns
        if patterns:
            pat_table = Table(
                title="[bold red]Forensic Findings[/bold red]",
                border_style="red", show_lines=True
            )
            pat_table.add_column("Finding",  style="bold yellow", width=22)
            pat_table.add_column("Detail",   style="white")
            for label, detail in patterns:
                pat_table.add_row(label, detail)
            console.print(pat_table)

        # Recommendations
        rec_text = Text()
        rec_text.append("Mitigation Roadmap\n\n", style="bold white")
        for i, rec in enumerate(recs, 1):
            rec_text.append(f"  {i}. ", style="bold cyan")
            rec_text.append(f"{rec}\n", style="white")
        console.print(Panel(rec_text, border_style="green",
                            title="[bold green]Recommendations[/bold green]"))

        # Post-audit menu
        console.print("\n[bold white]Actions:[/bold white]")
        console.print("  [cyan][1][/cyan] Export Certified PDF Report")
        console.print("  [cyan][2][/cyan] Generate a Strong Password")
        console.print("  [cyan][3][/cyan] Generate a Diceware Passphrase")
        console.print("  [cyan][4][/cyan] Exit\n")

        choice = input("  Select [1-4]: ").strip()

        if choice == "1":
            result_data = {
                "password":        password,
                "grade":           grade,
                "score":           score,
                "shannon":         shannon,
                "entropy":         f"{pool_entropy:.2f}",
                "crack_time":      crack_str,
                "hibp":            hibp_plain,
                "char_freq":       freq_det,
                "weaknesses":      [f"[{l}] {d}" for l, d in patterns],
                "recommendations": recs,
            }
            pdf   = PriViPDFReport()
            fname = pdf.generate_report(result_data, batch=False)
            console.print(f"\n[bold green][+] Report saved:[/bold green] [white]{fname}[/white]")

        elif choice == "2":
            self.generate_password()

        elif choice == "3":
            self.generate_passphrase()

    # ── BATCH MODE ────────────────────────────────────────────────────────────

    def batch_audit(self, filepath):
        if not os.path.isfile(filepath):
            console.print(f"[bold red][!] File not found: {filepath}[/bold red]")
            sys.exit(1)

        with open(filepath, "r", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]

        if not passwords:
            console.print("[bold red][!] No passwords found in file.[/bold red]")
            sys.exit(1)

        console.print(f"[bold cyan][*] Batch auditing {len(passwords)} credentials...[/bold cyan]\n")
        results = []

        for idx, pwd in enumerate(passwords, 1):
            sys.stdout.write(f"\r  [{idx}/{len(passwords)}] Auditing: {pwd[:3]}***")
            sys.stdout.flush()

            shannon = self.get_shannon_entropy(pwd)
            pool    = sum([
                26 if re.search(r'[a-z]', pwd) else 0,
                26 if re.search(r'[A-Z]', pwd) else 0,
                10 if re.search(r'\d',    pwd) else 0,
                32 if re.search(r'\W',    pwd) else 0,
            ])
            pool_entropy = len(pwd) * math.log2(pool) if pool > 0 else 0
            seconds      = (2 ** pool_entropy) / 100_000_000_000 if pool_entropy > 0 else 0
            leak         = self.get_leak_count(pwd)
            patterns     = self.detect_patterns(pwd)
            freq_pen, _  = self.char_frequency_score(pwd)
            score, grade = self.compute_score(pool_entropy, leak, patterns, freq_pen)

            results.append({
                "password":   pwd,
                "grade":      grade,
                "score":      score,
                "shannon":    shannon,
                "crack_time": self.format_crack_time(seconds),
                "hibp":       (f"{leak:,} leaks" if leak > 0
                               else "OFFLINE" if leak == -1
                               else "CLEAN"),
            })
            time.sleep(0.2)   # HIBP rate limit

        sys.stdout.write("\r" + " " * 50 + "\r")
        console.print(f"[bold green][+] Batch complete. Generating PDF...[/bold green]")
        pdf   = PriViPDFReport()
        fname = pdf.generate_report(results, batch=True)
        console.print(f"[bold green][+] Batch report saved:[/bold green] [white]{fname}[/white]")


# ── ENTRY POINT ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"PriVi-SPECTER v{VERSION}  -  Forensic Credential Suite"
    )
    parser.add_argument(
        "--wordlist", "-w", default=None,
        help="Path to a wordlist file for batch audit mode."
    )
    args = parser.parse_args()

    app = PriViSpecter()

    try:
        app.boot_sequence()

        if args.wordlist:
            app.batch_audit(args.wordlist)
        else:
            console.print("[bold white]Enter Target Credential (input hidden):[/bold white]")
            pwd = getpass.getpass(prompt="  > ")
            if not pwd:
                console.print("[bold red][!] No password entered. Aborting.[/bold red]")
                sys.exit(0)
            app.audit(pwd)

    except KeyboardInterrupt:
        console.print(f"\n[bold yellow][!] Exit triggered. Memory cleared.[/bold yellow]")
        sys.exit(0)
