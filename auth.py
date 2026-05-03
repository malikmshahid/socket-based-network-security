"""
=============================================================================
auth.py - Login Screen v11.0
AI-Powered Vulnerability Assessment System
Credentials: Shahid / Shahid123
=============================================================================
"""

import tkinter as tk
from tkinter import messagebox
import hashlib, json, os, socket, time
from datetime import datetime

# ── Theme colours ──────────────────────────────────────────────────────────
BG_DEEP  = "#050A0F"
BG_PANEL = "#0A1628"
BG_CARD  = "#0D1F35"
CYAN     = "#00D4FF"
CYAN_DIM = "#007A94"
GREEN    = "#00FF88"
RED      = "#FF2D55"
ORANGE   = "#FF8C42"
TEXT_MID = "#7BAFD4"
TEXT_DIM = "#3A6080"

CREDS_FILE    = "credentials.json"
DEFAULT_USER  = "Shahid"
DEFAULT_PASS  = "Shahid123"
MAX_ATTEMPTS  = 5      # attempts before cooldown
COOLDOWN_SECS = 30     # seconds cooldown (not permanent lock)


def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def _load_credentials() -> dict:
    """Load or create credentials file with Shahid/Shahid123."""
    if not os.path.exists(CREDS_FILE):
        creds = {
            "users": {
                DEFAULT_USER: {
                    "password": _hash(DEFAULT_PASS),
                    "role":     "admin",
                    "created":  datetime.now().strftime("%Y-%m-%d"),
                }
            }
        }
        with open(CREDS_FILE, "w") as f:
            json.dump(creds, f, indent=2)
        return creds

    with open(CREDS_FILE, "r") as f:
        creds = json.load(f)

    # Auto-migrate: if "admin" exists but "Shahid" doesn't, add Shahid
    users = creds.get("users", {})
    if DEFAULT_USER not in users:
        users[DEFAULT_USER] = {
            "password": _hash(DEFAULT_PASS),
            "role":     "admin",
            "created":  datetime.now().strftime("%Y-%m-%d"),
        }
        creds["users"] = users
        with open(CREDS_FILE, "w") as f:
            json.dump(creds, f, indent=2)

    return creds


def reset_credentials():
    """Force-reset credentials file to Shahid/Shahid123."""
    creds = {
        "users": {
            DEFAULT_USER: {
                "password": _hash(DEFAULT_PASS),
                "role":     "admin",
                "created":  datetime.now().strftime("%Y-%m-%d"),
            }
        }
    }
    with open(CREDS_FILE, "w") as f:
        json.dump(creds, f, indent=2)
    return creds


class LoginScreen:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("AI Vulnerability Assessment System — Login")
        self.root.geometry("500x620")
        self.root.resizable(False, False)
        self.root.configure(bg=BG_DEEP)
        self.root.attributes("-topmost", True)

        # Center on screen
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x  = (sw - 500) // 2
        y  = (sh - 620) // 2
        self.root.geometry(f"500x620+{x}+{y}")

        self.login_success  = False
        self.logged_in_user = ""
        self.attempts       = 0
        self.locked_until   = 0   # epoch time when cooldown ends

        self.creds = _load_credentials()
        self._build_ui()
        self.root.bind("<Return>", lambda e: self._attempt_login())

    def _build_ui(self):
        tk.Frame(self.root, bg=CYAN, height=3).pack(fill=tk.X)
        main = tk.Frame(self.root, bg=BG_DEEP)
        main.pack(fill=tk.BOTH, expand=True, padx=50)

        tk.Label(main, text="", bg=BG_DEEP).pack(pady=16)

        # Animated-style logo
        logo_frame = tk.Frame(main, bg=BG_CARD, padx=20, pady=16,
                              relief=tk.FLAT)
        logo_frame.pack()
        tk.Label(logo_frame, text="◈", font=("Segoe UI Emoji", 44, "bold"),
                 bg=BG_CARD, fg=CYAN).pack()

        tk.Label(main, text="", bg=BG_DEEP).pack(pady=4)
        tk.Label(main, text="CYBERSHIELD PRO",
                 font=("Consolas", 16, "bold"), bg=BG_DEEP, fg=CYAN).pack()
        tk.Label(main, text="AI VULNERABILITY ASSESSMENT SYSTEM  ·  v11.0",
                 font=("Consolas", 8), bg=BG_DEEP, fg=TEXT_DIM).pack(pady=(2,0))
        tk.Label(main, text="SecureNet Solutions  —  Professional Edition",
                 font=("Consolas", 7), bg=BG_DEEP, fg="#1A3050").pack()

        tk.Label(main, text="", bg=BG_DEEP).pack(pady=10)

        # Login card
        card = tk.Frame(main, bg=BG_PANEL, pady=20, padx=20)
        card.pack(fill=tk.X)
        tk.Frame(card, bg=CYAN, height=2).pack(fill=tk.X, pady=(0, 16))

        # Username
        tk.Label(card, text="USERNAME", font=("Consolas", 8, "bold"),
                 bg=BG_PANEL, fg=CYAN_DIM, anchor="w").pack(fill=tk.X)
        uf = tk.Frame(card, bg=CYAN, padx=1, pady=1)
        uf.pack(fill=tk.X, pady=(2, 10))
        self.user_var = tk.StringVar(value=DEFAULT_USER)
        self.user_entry = tk.Entry(uf, textvariable=self.user_var,
                                    font=("Consolas", 12), bg=BG_CARD,
                                    fg=GREEN, insertbackground=GREEN,
                                    relief=tk.FLAT, bd=6)
        self.user_entry.pack(fill=tk.X)

        # Password
        tk.Label(card, text="PASSWORD", font=("Consolas", 8, "bold"),
                 bg=BG_PANEL, fg=CYAN_DIM, anchor="w").pack(fill=tk.X)
        pf = tk.Frame(card, bg=CYAN, padx=1, pady=1)
        pf.pack(fill=tk.X, pady=(2, 4))
        self.pass_var   = tk.StringVar()
        self.pass_entry = tk.Entry(pf, textvariable=self.pass_var,
                                    font=("Consolas", 12), bg=BG_CARD,
                                    fg=GREEN, insertbackground=GREEN,
                                    relief=tk.FLAT, show="●", bd=6)
        self.pass_entry.pack(fill=tk.X)

        # Show/hide row
        sr = tk.Frame(card, bg=BG_PANEL); sr.pack(fill=tk.X, pady=(4, 10))
        self.show_pw = tk.BooleanVar(value=False)
        tk.Checkbutton(sr, text="Show password", variable=self.show_pw,
                       font=("Consolas", 8), bg=BG_PANEL, fg=TEXT_DIM,
                       selectcolor=BG_CARD, activebackground=BG_PANEL,
                       command=self._toggle_show).pack(side=tk.LEFT)

        # Attempts message
        self.attempt_var = tk.StringVar(value="")
        tk.Label(card, textvariable=self.attempt_var,
                 font=("Consolas", 8), bg=BG_PANEL, fg=RED).pack()

        # Login button
        self.btn_login = tk.Button(card, text="▶  AUTHENTICATE",
                                    font=("Consolas", 11, "bold"),
                                    bg=CYAN, fg=BG_DEEP,
                                    activebackground="#00FFFF",
                                    relief=tk.FLAT, cursor="hand2",
                                    pady=10, command=self._attempt_login)
        self.btn_login.pack(fill=tk.X, pady=(8, 0))

        # Reset button (shows only after lockout)
        self.btn_reset = tk.Button(card, text="🔓 RESET & TRY AGAIN",
                                    font=("Consolas", 9, "bold"),
                                    bg=ORANGE, fg=BG_DEEP,
                                    relief=tk.FLAT, cursor="hand2",
                                    pady=6, command=self._reset_lock)
        # Hidden by default

        # Status
        self.status_var = tk.StringVar(value="Enter credentials to continue")
        tk.Label(main, textvariable=self.status_var,
                 font=("Consolas", 8), bg=BG_DEEP, fg=TEXT_DIM).pack(pady=8)

        # Credentials hint — UPDATED
        hint = tk.Frame(main, bg=BG_CARD, pady=8, padx=12)
        hint.pack(fill=tk.X, pady=(4, 0))
        tk.Label(hint, text=f"LOGIN: {DEFAULT_USER} / {DEFAULT_PASS}",
                 font=("Consolas", 9, "bold"), bg=BG_CARD, fg=GREEN).pack()
        tk.Label(hint, text="Change password in Settings after login",
                 font=("Consolas", 7), bg=BG_CARD, fg=TEXT_DIM).pack()

        # Footer
        tk.Frame(self.root, bg=CYAN_DIM, height=1).pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(self.root,
                 text=f"HOST: {socket.gethostname()}  ●  {datetime.now().strftime('%Y-%m-%d')}",
                 font=("Consolas", 7), bg=BG_DEEP, fg=TEXT_DIM).pack(
                 side=tk.BOTTOM, pady=4)

    def _toggle_show(self):
        self.pass_entry.configure(show="" if self.show_pw.get() else "●")

    def _attempt_login(self):
        # Check cooldown
        now = time.time()
        if self.locked_until > now:
            remaining_secs = int(self.locked_until - now)
            self.attempt_var.set(
                f"⏳ Cooldown: wait {remaining_secs}s then try again")
            return

        username = self.user_var.get().strip()
        password = self.pass_var.get()
        users    = self.creds.get("users", {})

        if username in users and users[username]["password"] == _hash(password):
            # SUCCESS
            self.login_success  = True
            self.logged_in_user = username
            self.attempt_var.set("")
            self.status_var.set("✓ Authentication successful!")
            self.btn_login.configure(bg=GREEN, text="✓ LOGIN SUCCESSFUL")
            self.root.after(800, self.root.destroy)
        else:
            self.attempts += 1
            remaining = MAX_ATTEMPTS - self.attempts

            if remaining <= 0:
                # Cooldown — NOT permanent lock
                self.locked_until = time.time() + COOLDOWN_SECS
                self.attempt_var.set(
                    f"⚠ COOLDOWN: Wait {COOLDOWN_SECS}s — too many attempts")
                self.btn_login.configure(bg=ORANGE, text="⏳ COOLDOWN ACTIVE")
                self.status_var.set(
                    f"Cooldown active. Auto-reset in {COOLDOWN_SECS} seconds.")
                # Show reset button
                self.btn_reset.pack(fill=tk.X, pady=(6, 0))
                # Auto-reset after cooldown
                self.root.after(COOLDOWN_SECS * 1000, self._reset_lock)
                # Countdown ticker
                self._countdown(COOLDOWN_SECS)
            else:
                self.attempt_var.set(
                    f"⚠ Wrong credentials — {remaining} attempt(s) remaining")
                self.status_var.set("Authentication failed. Try again.")
                self.pass_var.set("")
                self.pass_entry.focus()

    def _countdown(self, secs):
        """Tick countdown on button."""
        if secs > 0 and self.locked_until > time.time():
            self.btn_login.configure(text=f"⏳ Wait {secs}s...")
            self.root.after(1000, lambda: self._countdown(secs - 1))

    def _reset_lock(self):
        """Reset the lock — allow retry."""
        self.attempts    = 0
        self.locked_until = 0
        self.attempt_var.set("🔓 Reset complete — try again")
        self.status_var.set("Enter credentials to continue")
        self.btn_login.configure(state=tk.NORMAL, bg=CYAN,
                                  text="▶  AUTHENTICATE")
        try:
            self.btn_reset.pack_forget()
        except Exception:
            pass
        self.pass_var.set("")
        self.pass_entry.focus()

    def show(self) -> tuple:
        """Show login. Returns (success: bool, username: str)."""
        self.root.mainloop()
        return self.login_success, self.logged_in_user


def show_login() -> tuple:
    screen = LoginScreen()
    return screen.show()
