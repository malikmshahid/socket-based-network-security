"""
registration.py — CyberShield Pro Registration System v11.0
License types: Free Trial (7 days) | Pro ($29) | Enterprise ($99)
"""

import tkinter as tk
from tkinter import messagebox, ttk
import hashlib, json, os, uuid, datetime, re, socket, threading, time

# ── Branding ────────────────────────────────────────────────────────────────
APP_NAME    = "CyberShield Pro"
APP_VERSION = "11.0"
COMPANY     = "SecureNet Solutions"

# ── Colors ──────────────────────────────────────────────────────────────────
BG_DEEP  = "#050A0F"
BG_PANEL = "#0A1628"
BG_CARD  = "#0D1F35"
BG_ELEV  = "#112240"
CYAN     = "#00D4FF"
GREEN    = "#00FF88"
RED      = "#FF2D55"
ORANGE   = "#FF8C42"
YELLOW   = "#FFD60A"
PURPLE   = "#AA44FF"
TEXT_MID = "#7BAFD4"
TEXT_DIM = "#3A6080"

REG_FILE     = "registration.json"
LICENSE_FILE = "license.key"

PLANS = {
    "free":       {"name": "Free Trial",    "days": 7,    "price": "$0",   "color": GREEN,  "features": ["Basic Scanning","Network Map","5 Tabs"]},
    "pro":        {"name": "Pro",           "days": 365,  "price": "$29",  "color": CYAN,   "features": ["All 57 Tabs","PDF Reports","AI Chat","Pentest Tools"]},
    "enterprise": {"name": "Enterprise",    "days": 3650, "price": "$99",  "color": PURPLE, "features": ["Everything in Pro","Source Code","Priority Support","White-label"]},
}

# Demo license keys (in production, validate against server)
VALID_KEYS = {
    "CYBER-PRO-2024-DEMO":  "pro",
    "CYBER-ENT-2024-DEMO":  "enterprise",
    "SHIELD-PRO-ABCD-1234": "pro",
    "SHIELD-ENT-WXYZ-5678": "enterprise",
}


def _hash(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def _machine_id() -> str:
    try:
        mid = str(uuid.getnode()) + socket.gethostname()
        return _hash(mid)[:16].upper()
    except Exception:
        return "UNKNOWN-MACHINE"


def load_registration() -> dict:
    if not os.path.exists(REG_FILE):
        return {}
    try:
        with open(REG_FILE,'r') as f:
            return json.load(f)
    except Exception:
        return {}

def save_registration(data: dict):
    with open(REG_FILE,'w') as f:
        json.dump(data, f, indent=2)

def check_license() -> dict:
    """Check if app is registered and license is valid."""
    reg = load_registration()
    if not reg:
        return {"valid": False, "reason": "not_registered", "plan": "free"}

    # Check expiry
    try:
        expiry = datetime.datetime.fromisoformat(reg.get("expiry","2000-01-01"))
        if datetime.datetime.now() > expiry:
            return {"valid": False, "reason": "expired", "plan": reg.get("plan","free"),
                    "name": reg.get("name",""), "expiry": str(expiry.date())}
    except Exception:
        pass

    return {
        "valid":    True,
        "plan":     reg.get("plan","free"),
        "name":     reg.get("name",""),
        "email":    reg.get("email",""),
        "expiry":   reg.get("expiry",""),
        "key":      reg.get("key",""),
        "machine":  reg.get("machine",""),
    }

def activate_license(key: str, name: str, email: str) -> dict:
    """Activate a license key."""
    key = key.strip().upper()

    # Check demo keys
    if key in VALID_KEYS:
        plan  = VALID_KEYS[key]
        days  = PLANS[plan]["days"]
        expiry = (datetime.datetime.now() + datetime.timedelta(days=days)).isoformat()
        reg = {
            "name":    name,
            "email":   email,
            "key":     key,
            "plan":    plan,
            "expiry":  expiry,
            "machine": _machine_id(),
            "activated": datetime.datetime.now().isoformat(),
        }
        save_registration(reg)
        return {"success": True, "plan": plan, "expiry": expiry}

    # Free trial activation
    if key == "" or key == "FREE-TRIAL":
        expiry = (datetime.datetime.now() + datetime.timedelta(days=7)).isoformat()
        reg = {
            "name":    name,
            "email":   email,
            "key":     "FREE-TRIAL",
            "plan":    "free",
            "expiry":  expiry,
            "machine": _machine_id(),
            "activated": datetime.datetime.now().isoformat(),
        }
        save_registration(reg)
        return {"success": True, "plan": "free", "expiry": expiry}

    return {"success": False, "error": "Invalid license key. Check your purchase email."}


class RegistrationScreen:
    """Full registration / activation screen."""

    def __init__(self, license_info: dict = None):
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} — Registration & Activation")
        self.root.geometry("780x680")
        self.root.resizable(False, False)
        self.root.configure(bg=BG_DEEP)
        self.root.attributes("-topmost", True)

        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        self.root.geometry(f"780x680+{(sw-780)//2}+{(sh-680)//2}")

        self.license_info = license_info or {}
        self.result = "cancel"
        self._build()

    def _build(self):
        # ── Top bar ────────────────────────────────────────────────────────
        for c, h in [(CYAN, 3), ("#1A4A6A", 1)]:
            tk.Frame(self.root, bg=c, height=h).pack(fill=tk.X)

        # ── Header ─────────────────────────────────────────────────────────
        hdr = tk.Frame(self.root, bg=BG_PANEL, padx=30, pady=20)
        hdr.pack(fill=tk.X)
        left = tk.Frame(hdr, bg=BG_PANEL); left.pack(side=tk.LEFT)
        tk.Label(left, text="🛡", font=("Segoe UI Emoji",38),
                 bg=BG_PANEL, fg=CYAN).pack(side=tk.LEFT, padx=(0,16))
        info = tk.Frame(left, bg=BG_PANEL); info.pack(side=tk.LEFT)
        tk.Label(info, text=APP_NAME.upper(), font=("Consolas",18,"bold"),
                 bg=BG_PANEL, fg=CYAN).pack(anchor="w")
        tk.Label(info, text=f"v{APP_VERSION}  ·  {COMPANY}",
                 font=("Consolas",9), bg=BG_PANEL, fg=TEXT_MID).pack(anchor="w")
        tk.Label(info, text="Professional Cybersecurity Assessment Suite",
                 font=("Segoe UI",9), bg=BG_PANEL, fg=TEXT_DIM).pack(anchor="w")

        # Machine ID
        mid_frame = tk.Frame(hdr, bg=BG_CARD, padx=12, pady=8)
        mid_frame.pack(side=tk.RIGHT)
        tk.Label(mid_frame, text="Machine ID:", font=("Consolas",7),
                 bg=BG_CARD, fg=TEXT_DIM).pack(anchor="e")
        tk.Label(mid_frame, text=_machine_id(), font=("Consolas",9,"bold"),
                 bg=BG_CARD, fg=CYAN).pack(anchor="e")

        tk.Frame(self.root, bg=BG_ELEV, height=1).pack(fill=tk.X)

        # ── Notebook ───────────────────────────────────────────────────────
        body = tk.Frame(self.root, bg=BG_DEEP); body.pack(fill=tk.BOTH, expand=True)

        nb = ttk.Notebook(body)
        nb.pack(fill=tk.BOTH, expand=True, padx=16, pady=12)
        sty = ttk.Style(); sty.theme_use("clam")
        sty.configure("Reg.TNotebook", background=BG_DEEP, borderwidth=0)
        sty.configure("Reg.TNotebook.Tab", background=BG_PANEL, foreground=TEXT_DIM,
                       padding=[16,8], font=("Consolas",9,"bold"))
        sty.map("Reg.TNotebook.Tab",
                background=[("selected",BG_ELEV)], foreground=[("selected",CYAN)])
        nb.configure(style="Reg.TNotebook")

        # Tab 1: Activate
        act_f = tk.Frame(nb, bg=BG_DEEP); nb.add(act_f, text=" 🔑 Activate ")
        self._build_activate_tab(act_f)

        # Tab 2: Plans
        plan_f = tk.Frame(nb, bg=BG_DEEP); nb.add(plan_f, text=" 💎 Plans & Pricing ")
        self._build_plans_tab(plan_f)

        # Tab 3: Status
        stat_f = tk.Frame(nb, bg=BG_DEEP); nb.add(stat_f, text=" 📋 License Status ")
        self._build_status_tab(stat_f)

        # Tab 4: About
        abt_f = tk.Frame(nb, bg=BG_DEEP); nb.add(abt_f, text=" ℹ About ")
        self._build_about_tab(abt_f)

        # ── Bottom bar ─────────────────────────────────────────────────────
        bot = tk.Frame(self.root, bg=BG_PANEL, padx=20, pady=10)
        bot.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Button(bot, text="⬛ Cancel / Exit", font=("Consolas",9),
                  bg=BG_CARD, fg=TEXT_DIM, relief=tk.FLAT, cursor="hand2",
                  padx=12, pady=6,
                  command=self._cancel).pack(side=tk.LEFT)
        tk.Button(bot, text="▶  Continue to App", font=("Consolas",10,"bold"),
                  bg=CYAN, fg=BG_DEEP, relief=tk.FLAT, cursor="hand2",
                  padx=20, pady=6,
                  command=self._continue).pack(side=tk.RIGHT)

    def _build_activate_tab(self, parent):
        """Registration / License Key activation."""
        pad = tk.Frame(parent, bg=BG_DEEP, padx=30, pady=20)
        pad.pack(fill=tk.BOTH, expand=True)

        # Current status banner
        lic = check_license()
        if lic.get("valid"):
            plan_name = PLANS.get(lic["plan"],{}).get("name","?")
            banner_bg = GREEN if lic["plan"] != "free" else ORANGE
            banner_txt = f"✅  ACTIVE — {plan_name.upper()}  ·  Expires: {lic['expiry'][:10]}"
        else:
            banner_bg = RED
            reason = lic.get("reason","")
            banner_txt = "❌  NOT ACTIVATED" if reason == "not_registered" else f"⚠  LICENSE EXPIRED ({lic.get('expiry','')[:10]})"

        tk.Label(pad, text=banner_txt, font=("Consolas",10,"bold"),
                 bg=banner_bg, fg="white", padx=16, pady=8,
                 anchor="w").pack(fill=tk.X, pady=(0,20))

        # Form
        tk.Label(pad, text="FULL NAME", font=("Consolas",8,"bold"),
                 bg=BG_DEEP, fg=CYAN, anchor="w").pack(fill=tk.X)
        nf = tk.Frame(pad, bg=CYAN, padx=1, pady=1); nf.pack(fill=tk.X, pady=(2,10))
        self.reg_name = tk.StringVar(value=lic.get("name",""))
        tk.Entry(nf, textvariable=self.reg_name, font=("Consolas",12),
                 bg=BG_CARD, fg=GREEN, insertbackground=GREEN,
                 relief=tk.FLAT, bd=6).pack(fill=tk.X)

        tk.Label(pad, text="EMAIL ADDRESS", font=("Consolas",8,"bold"),
                 bg=BG_DEEP, fg=CYAN, anchor="w").pack(fill=tk.X)
        ef = tk.Frame(pad, bg=CYAN, padx=1, pady=1); ef.pack(fill=tk.X, pady=(2,10))
        self.reg_email = tk.StringVar(value=lic.get("email",""))
        tk.Entry(ef, textvariable=self.reg_email, font=("Consolas",12),
                 bg=BG_CARD, fg=GREEN, insertbackground=GREEN,
                 relief=tk.FLAT, bd=6).pack(fill=tk.X)

        tk.Label(pad, text="LICENSE KEY  (leave blank for 7-day free trial)",
                 font=("Consolas",8,"bold"), bg=BG_DEEP, fg=CYAN, anchor="w").pack(fill=tk.X)
        kf = tk.Frame(pad, bg=CYAN, padx=1, pady=1); kf.pack(fill=tk.X, pady=(2,4))
        self.reg_key = tk.StringVar(value=lic.get("key","") if lic.get("key","") != "FREE-TRIAL" else "")
        tk.Entry(kf, textvariable=self.reg_key, font=("Consolas",12),
                 bg=BG_CARD, fg=YELLOW, insertbackground=YELLOW,
                 relief=tk.FLAT, bd=6).pack(fill=tk.X)

        # Key hint
        key_hint = tk.Frame(pad, bg=BG_CARD, padx=12, pady=6)
        key_hint.pack(fill=tk.X, pady=(4,16))
        tk.Label(key_hint, text="Demo keys to test Pro/Enterprise features:",
                 font=("Consolas",8,"bold"), bg=BG_CARD, fg=TEXT_DIM).pack(anchor="w")
        for k, plan in [("CYBER-PRO-2024-DEMO","Pro"),("CYBER-ENT-2024-DEMO","Enterprise")]:
            row = tk.Frame(key_hint, bg=BG_CARD); row.pack(fill=tk.X)
            tk.Label(row, text=k, font=("Consolas",9), bg=BG_CARD, fg=CYAN).pack(side=tk.LEFT)
            tk.Label(row, text=f" → {plan}", font=("Consolas",8),
                     bg=BG_CARD, fg=GREEN).pack(side=tk.LEFT, padx=8)
            tk.Button(row, text="USE", font=("Consolas",7), bg=BG_ELEV,
                      fg=CYAN, relief=tk.FLAT, cursor="hand2",
                      command=lambda _k=k: self.reg_key.set(_k)).pack(side=tk.RIGHT)

        # Activate button
        self.reg_status = tk.StringVar(value="")
        self.reg_btn = tk.Button(pad, text="🔑  ACTIVATE LICENSE",
                                  font=("Consolas",12,"bold"),
                                  bg=CYAN, fg=BG_DEEP, relief=tk.FLAT,
                                  cursor="hand2", pady=12,
                                  command=self._do_activate)
        self.reg_btn.pack(fill=tk.X, pady=(0,8))
        tk.Button(pad, text="🎁  START FREE TRIAL (7 days)",
                  font=("Consolas",10), bg=GREEN, fg=BG_DEEP,
                  relief=tk.FLAT, cursor="hand2", pady=8,
                  command=self._do_free_trial).pack(fill=tk.X)
        tk.Label(pad, textvariable=self.reg_status,
                 font=("Consolas",9,"bold"), bg=BG_DEEP,
                 fg=GREEN).pack(pady=8)

    def _build_plans_tab(self, parent):
        """Show all pricing plans."""
        pad = tk.Frame(parent, bg=BG_DEEP, padx=20, pady=16)
        pad.pack(fill=tk.BOTH, expand=True)
        tk.Label(pad, text="CHOOSE YOUR PLAN",
                 font=("Consolas",14,"bold"), bg=BG_DEEP, fg=CYAN).pack(pady=(0,4))
        tk.Label(pad, text="Professional Cybersecurity Suite — Secure your network today",
                 font=("Segoe UI",9), bg=BG_DEEP, fg=TEXT_DIM).pack(pady=(0,16))

        cards_row = tk.Frame(pad, bg=BG_DEEP); cards_row.pack(fill=tk.BOTH, expand=True)
        for plan_key, plan in PLANS.items():
            card = tk.Frame(cards_row, bg=BG_CARD, padx=16, pady=16,
                            relief=tk.FLAT, bd=0)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6)
            color = plan["color"]

            tk.Frame(card, bg=color, height=4).pack(fill=tk.X)
            tk.Label(card, text="", bg=BG_CARD).pack()
            tk.Label(card, text=plan["name"].upper(),
                     font=("Consolas",13,"bold"), bg=BG_CARD, fg=color).pack()
            tk.Label(card, text=plan["price"],
                     font=("Consolas",28,"bold"), bg=BG_CARD, fg="white").pack()
            tk.Label(card, text=f"{plan['days']} days" if plan['days'] < 3650 else "Lifetime",
                     font=("Consolas",9), bg=BG_CARD, fg=TEXT_DIM).pack()
            tk.Frame(card, bg=BG_ELEV, height=1).pack(fill=tk.X, pady=10)
            for feat in plan["features"]:
                row = tk.Frame(card, bg=BG_CARD); row.pack(fill=tk.X, pady=2)
                tk.Label(row, text="✓", font=("Consolas",10,"bold"),
                         bg=BG_CARD, fg=color, width=2).pack(side=tk.LEFT)
                tk.Label(row, text=feat, font=("Consolas",8),
                         bg=BG_CARD, fg=TEXT_MID).pack(side=tk.LEFT)
            tk.Label(card, text="", bg=BG_CARD).pack()
            if plan_key == "free":
                btn_text = "Start Free Trial"
                btn_cmd  = self._do_free_trial
            else:
                btn_text = f"Buy {plan['name']} →"
                btn_cmd  = lambda p=plan_key: self._buy_plan(p)
            tk.Button(card, text=btn_text, font=("Consolas",9,"bold"),
                      bg=color, fg=BG_DEEP, relief=tk.FLAT, cursor="hand2",
                      pady=8, command=btn_cmd).pack(fill=tk.X)

        # Purchase info
        info = tk.Frame(pad, bg=BG_PANEL, padx=16, pady=10)
        info.pack(fill=tk.X, pady=(16,0))
        tk.Label(info, text="💳  To purchase: Contact us at cybershield@secnet.com  |  WhatsApp: +92-300-XXXXXXX",
                 font=("Consolas",8), bg=BG_PANEL, fg=TEXT_MID).pack()
        tk.Label(info, text="After payment you will receive your license key via email within minutes",
                 font=("Consolas",8), bg=BG_PANEL, fg=TEXT_DIM).pack()

    def _build_status_tab(self, parent):
        """Show current license status."""
        pad = tk.Frame(parent, bg=BG_DEEP, padx=30, pady=20)
        pad.pack(fill=tk.BOTH, expand=True)
        lic = check_license()

        tk.Label(pad, text="LICENSE STATUS", font=("Consolas",13,"bold"),
                 bg=BG_DEEP, fg=CYAN).pack(pady=(0,16))

        # Status details
        details = [
            ("Status",      "✅ ACTIVE" if lic.get("valid") else "❌ INACTIVE",
             GREEN if lic.get("valid") else RED),
            ("Plan",        PLANS.get(lic.get("plan","free"),{}).get("name","Free Trial"), CYAN),
            ("Name",        lic.get("name","Not registered"), TEXT_MID),
            ("Email",       lic.get("email","—"), TEXT_MID),
            ("License Key", lic.get("key","—") or "FREE TRIAL", YELLOW),
            ("Expiry",      lic.get("expiry","—")[:10] if lic.get("expiry") else "—", ORANGE),
            ("Machine ID",  _machine_id(), TEXT_DIM),
            ("App Version", f"v{APP_VERSION}", TEXT_DIM),
        ]

        for label, value, color in details:
            row = tk.Frame(pad, bg=BG_CARD, padx=16, pady=8)
            row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=label + ":", font=("Consolas",9,"bold"),
                     bg=BG_CARD, fg=TEXT_DIM, width=14, anchor="w").pack(side=tk.LEFT)
            tk.Label(row, text=str(value), font=("Consolas",10,"bold"),
                     bg=BG_CARD, fg=color, anchor="w").pack(side=tk.LEFT, padx=8)

        # Days remaining
        if lic.get("valid") and lic.get("expiry"):
            try:
                exp = datetime.datetime.fromisoformat(lic["expiry"])
                days_left = (exp - datetime.datetime.now()).days
                color = GREEN if days_left > 30 else ORANGE if days_left > 7 else RED
                tk.Label(pad, text=f"⏳  {days_left} day(s) remaining",
                         font=("Consolas",12,"bold"), bg=BG_DEEP, fg=color).pack(pady=16)
            except Exception:
                pass

    def _build_about_tab(self, parent):
        """About the software."""
        pad = tk.Frame(parent, bg=BG_DEEP, padx=30, pady=20)
        pad.pack(fill=tk.BOTH, expand=True)

        tk.Label(pad, text="🛡", font=("Segoe UI Emoji",52),
                 bg=BG_DEEP, fg=CYAN).pack()
        tk.Label(pad, text=APP_NAME.upper(),
                 font=("Consolas",18,"bold"), bg=BG_DEEP, fg=CYAN).pack()
        tk.Label(pad, text=f"Version {APP_VERSION}  ·  {COMPANY}",
                 font=("Consolas",10), bg=BG_DEEP, fg=TEXT_MID).pack(pady=4)

        info_box = tk.Frame(pad, bg=BG_CARD, padx=20, pady=16)
        info_box.pack(fill=tk.X, pady=16)

        about_lines = [
            "CyberShield Pro is a complete AI-powered cybersecurity suite",
            "designed for IT professionals, students, and businesses.",
            "",
            "FEATURES:",
            "  • 57+ security analysis tools",
            "  • Real-time network monitoring",
            "  • AI-powered vulnerability assessment",
            "  • Pentesting toolkit (educational)",
            "  • PDF security reports",
            "  • WiFi security analysis",
            "  • Password management vault",
            "  • Multi-language (English / Urdu)",
            "  • Day / Night themes",
            "",
            "DEVELOPER: M. Shahid Malik",
            "PLATFORM: Windows 10/11 (Python 3.11+)",
            "SUPPORT: cybershield@secnet.com",
        ]
        for line in about_lines:
            fg = CYAN if line.endswith(":") else TEXT_MID if line.startswith("  •") else TEXT_DIM
            tk.Label(info_box, text=line, font=("Consolas",9),
                     bg=BG_CARD, fg=fg, anchor="w").pack(fill=tk.X)

    # ── Actions ─────────────────────────────────────────────────────────────
    def _do_activate(self):
        name  = self.reg_name.get().strip()
        email = self.reg_email.get().strip()
        key   = self.reg_key.get().strip()

        if not name:
            self.reg_status.set("⚠  Please enter your name")
            return
        if not email or "@" not in email:
            self.reg_status.set("⚠  Please enter a valid email")
            return

        self.reg_btn.configure(state=tk.DISABLED, text="⏳ Activating...")
        self.reg_status.set("")

        def _bg():
            result = activate_license(key, name, email)
            self.root.after(0, lambda r=result: self._show_result(r))

        threading.Thread(target=_bg, daemon=True).start()

    def _do_free_trial(self):
        name  = self.reg_name.get().strip() or "Trial User"
        email = self.reg_email.get().strip() or "trial@user.com"
        result = activate_license("FREE-TRIAL", name, email)
        self._show_result(result)

    def _show_result(self, result):
        self.reg_btn.configure(state=tk.NORMAL, text="🔑  ACTIVATE LICENSE")
        if result.get("success"):
            plan     = result["plan"]
            plan_name = PLANS.get(plan,{}).get("name","?")
            expiry   = result.get("expiry","")[:10]
            self.reg_status.configure(fg=GREEN)
            self.reg_status.set(f"✅  {plan_name.upper()} activated! Expires: {expiry}")
            messagebox.showinfo("Activated!",
                f"🎉 {plan_name.upper()} License Activated!\n\n"
                f"Valid until: {expiry}\n\nClick Continue to launch the app.")
        else:
            self.reg_status.configure(fg=RED)
            self.reg_status.set("❌  " + result.get("error","Activation failed"))

    def _buy_plan(self, plan_key):
        plan = PLANS.get(plan_key, {})
        messagebox.showinfo(
            f"Buy {plan.get('name','')}",
            f"To purchase {plan.get('name','')} ({plan.get('price','')}):\n\n"
            f"📧 Email: cybershield@secnet.com\n"
            f"📱 WhatsApp: +92-300-XXXXXXX\n\n"
            f"After payment, you'll receive your license key\n"
            f"within 24 hours via email.\n\n"
            f"Machine ID: {_machine_id()}\n"
            f"(Send this with your payment)")

    def _continue(self):
        lic = check_license()
        if not lic.get("valid"):
            ans = messagebox.askyesno(
                "Not Activated",
                "License not activated.\n\nContinue with limited features?\n"
                "(Activate for full access)")
            if not ans:
                return
        self.result = "continue"
        self.root.destroy()

    def _cancel(self):
        self.result = "cancel"
        self.root.destroy()

    def show(self) -> str:
        self.root.mainloop()
        return self.result


def show_registration(force: bool = False) -> bool:
    """Show registration screen. Returns True if should continue."""
    lic = check_license()

    # If valid and not forced, skip registration
    if lic.get("valid") and not force:
        return True

    # Show registration
    screen = RegistrationScreen(lic)
    result = screen.show()
    return result == "continue"


if __name__ == "__main__":
    show_registration(force=True)
