#!/usr/bin/env python3

import time
import hashlib
import getpass
import random
import sys
#import pyfiglet
from datetime import datetime

MAX_ATTEMPTS_BEFORE_LOCK = 5
LOCK_DURATION_SECONDS = 30
THROTTLE_SECONDS = 0.5 
ATTEMPT_LOG = "sim_attempts.log"

REAL_USERNAME = "testuser"
REAL_PASSWORD_PLAIN = "nish"
REAL_PASSWORD_HASH = hashlib.sha256(REAL_PASSWORD_PLAIN.encode()).hexdigest()

def log_attempt(username, attempt, success):
    ts = datetime.now().isoformat()
    with open(ATTEMPT_LOG, "a") as f:
        f.write(f"{ts}\t{username}\t{attempt}\t{'SUCCESS' if success else 'FAIL'}\n")

def check_password(password_guess):
    """Simulated password check against in-memory hash. No IO/network."""
    return hashlib.sha256(password_guess.encode()).hexdigest() == REAL_PASSWORD_HASH

def password_strength(password):
    """Simple strength heuristic (educational). Returns (score, notes)."""
    score = 0
    notes = []
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        notes.append("Too short (use >= 12 chars for strong).")
    if any(c.islower() for c in password): score += 1
    else: notes.append("Add lowercase letters.")
    if any(c.isupper() for c in password): score += 1
    else: notes.append("Add uppercase letters.")
    if any(c.isdigit() for c in password): score += 1
    else: notes.append("Add digits.")
    if any(not c.isalnum() for c in password): score += 1
    else: notes.append("Add special characters like !@#$.")
    return score, notes

def generate_wordlist(base, max_len=3, digits="0123456789", max_words=10000):
    suffixes = ["", "123", "!", "@", "2023", "2024"]
    out = []
    for suf in suffixes:
        candidate = base + suf
        out.append(candidate)
        if len(out) >= max_words:
            break
    for l in range(1, max_len+1):
        for i in range(min(100, len(digits)**l)):
            s = "".join(random.choice(digits) for _ in range(l))
            out.append(base + s)
            if len(out) >= max_words:
                break
        if len(out) >= max_words:
            break
    return out

def simulate_bruteforce(wordlist, username=REAL_USERNAME):
    attempts = 0
    locked_until = 0
    print(f"\nStarting simulation against local account '{username}'.")
    for pw in wordlist:
        now = time.time()
        if now < locked_until:
            wait = int(locked_until - now)
            print(f"[LOCKED] Account locked for {wait} more second(s).")
            time.sleep(min(wait, 3))
            continue

        attempts += 1
        print(f"Attempt {attempts}: trying '{pw}' ... ", end="", flush=True)
        time.sleep(THROTTLE_SECONDS)

        success = check_password(pw)
        log_attempt(username, pw, success)
        if success:
            print("SUCCESS!")
            print(f"Password cracked in {attempts} attempts (simulation).")
            return True
        else:
            print("fail")
            if attempts % MAX_ATTEMPTS_BEFORE_LOCK == 0:
                locked_until = time.time() + LOCK_DURATION_SECONDS
                print(f"[DEFENSE] Simulated lockout activated for {LOCK_DURATION_SECONDS}s.")
    print("Finished wordlist; password not found in the provided list (simulation).")
    return False

def run_password_checker():
    print("\nPassword Strength Checker (local-only).")
    pw = getpass.getpass("Enter password to evaluate (hidden): ")
    score, notes = password_strength(pw)
    print(f"Score: {score}/6")
    if notes:
        print("Suggestions:")
        for n in notes:
            print(" -", n)
    else:
        print("Looks reasonably strong (educational heuristic).")

def make_wordlist_interactive():
    print("\nWordlist generator (simple, local).")
    base = input("Base word (e.g., name or root): ").strip()
    if not base:
        print("Base required.")
        return []
    try:
        max_len = int(input("Max digit suffix length (1-4) [default 2]: ") or "2")
    except ValueError:
        max_len = 2
    max_words = int(input("Max words to generate [default 500]: ") or "500")
    wl = generate_wordlist(base, max_len=max_len, max_words=max_words)
    print(f"Generated {len(wl)} words. Sample:")
    for i, w in enumerate(wl[:20], 1):
        print(f"{i:3d}. {w}")
    save = input("Save to file? (y/N): ").strip().lower()
    if save == "y":
        fname = input("Filename to save (e.g., wordlist.txt): ").strip() or "wordlist.txt"
        with open(fname, "w") as f:
            for w in wl:
                f.write(w + "\n")
        print(f"Saved to {fname}")
    return wl

def load_wordlist_from_file():
    fname = input("Path to wordlist file: ").strip()
    try:
        with open(fname, "r") as f:
            wl = [line.strip() for line in f if line.strip()]
        print(f"Loaded {len(wl)} words from {fname}")
        return wl
    except Exception as e:
        print("Failed to load file:", e)
        return []

def view_log():
    try:
        with open(ATTEMPT_LOG, "r") as f:
            data = f.read().strip()
            if not data:
                print("Log is empty.")
            else:
                print("\n--- Attempt log (most recent last) ---")
                print(data.splitlines()[-50:])
    except FileNotFoundError:
        print("Log file not found. No attempts logged yet.")

def main_menu():
    #name=pyfiglet.figlet_format("Oblivion")
    #print(name)
    print("\nOblivion V1.0 by Nishil Bhimani & Riya Mittal")
    print("\nDISCLAIMER Oblivion V1.0 is a educational security tool designed for learning purposes only. This tool should ONLY be used on systems you own or have explicit written permission to test. Unauthorized use against systems you don't own is illegal and unethical.")
    print("\nThis project is for educational purposes. Please use responsibly and in compliance with all applicable laws.")
    print("\nTHE TOOL IS STILL IN IT'S BETA PHASE")
    print("\nhttps://github.com/nishilxy/Brute-Force-by-Nish")
    
    while True:
        print("\nOblivion is tool to guess/crack valid login/password pairs.")
        print("\nMenu:")
        print(" 1) Simulate brute-force attack (use generated wordlist)")
        print(" 2) Load wordlist from file and simulate")
        print(" 3) Generate wordlist interactively")
        print(" 4) Password strength checker")
        print(" 5) View local attempt log")
        print(" 6) Show safety & defensive tips")
        print(" 0) Exit")
        choice = input("\nChoose an option: ").strip()
        if choice == "1":
            base = input("Base for auto wordlist (e.g., 'password' or 'john'): ").strip() or "password"
            wl = generate_wordlist(base, max_len=2, max_words=500)
            simulate_bruteforce(wl)
        elif choice == "2":
            wl = load_wordlist_from_file()
            if wl:
                simulate_bruteforce(wl)
        elif choice == "3":
            wl = make_wordlist_interactive()
            if wl:
                ask = input("Run simulation with this list now? (y/N): ").strip().lower()
                if ask == "y":
                    simulate_bruteforce(wl)
        elif choice == "4":
            run_password_checker()
        elif choice == "5":
            view_log()
        elif choice == "6":
            print_safety_and_defenses()
        elif choice == "0":
            print("Exiting. Remember: test only on systems you own or have permission to test.")
            break
        else:
            print("Invalid choice. Try again.")

def print_safety_and_defenses():
    print("\nSafety & Defense (educational):")
    tips = [
        "Always obtain explicit written permission before testing systems you don't own.",
        "Use rate limiting, progressive delays, and account lockouts to defend against brute-force.",
        "Enforce multi-factor authentication (MFA).",
        "Use slow hash functions (bcrypt, scrypt, Argon2) for password storage.",
        "Require long, random passphrases; avoid common words and predictable patterns.",
        "Monitor and alert on unusual login attempts and velocity.",
        "Use CAPTCHA or device fingerprinting to limit automated attacks.",
    ]
    for t in tips:
        print(" -", t)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nInterrupted. Bye.")
        sys.exit(0)

