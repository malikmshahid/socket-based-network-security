"""
splash.py — CyberShield Pro v11.0
Animated splash — thread-safe destroy
"""
import tkinter as tk
import threading
import time
import socket
import math
from datetime import datetime


def show_splash():
    root = tk.Tk()
    root.overrideredirect(True)
    root.configure(bg="#000000")
    root.attributes("-topmost", True)

    W, H = 720, 440
    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
    try:
        root.attributes("-alpha", 0.97)
    except Exception:
        pass

    canvas = tk.Canvas(root, width=W, height=H, bg="#000000",
                       highlightthickness=0)
    canvas.pack(fill=tk.BOTH, expand=True)

    CYAN  = "#00D4FF"
    GREEN = "#00FF88"
    DIM   = "#0A1628"

    # Background gradient
    for i in range(H):
        ratio = i / H
        r = int(2  + 3*ratio)
        g = int(4  + 6*ratio)
        b = int(10 + 20*ratio)
        canvas.create_line(0, i, W, i, fill=f"#{r:02x}{g:02x}{b:02x}")

    # Grid
    for x in range(0, W, 40):
        canvas.create_line(x, 0, x, H, fill="#040D1A", width=1)
    for y in range(0, H, 40):
        canvas.create_line(0, y, W, y, fill="#040D1A", width=1)

    # Corner brackets
    BL = 35
    corners = [
        [(12,12),(12+BL,12)], [(12,12),(12,12+BL)],
        [(W-12,12),(W-12-BL,12)], [(W-12,12),(W-12,12+BL)],
        [(12,H-12),(12+BL,H-12)], [(12,H-12),(12,H-12-BL)],
        [(W-12,H-12),(W-12-BL,H-12)], [(W-12,H-12),(W-12,H-12-BL)],
    ]
    for p1, p2 in corners:
        canvas.create_line(p1[0],p1[1],p2[0],p2[1], fill=CYAN, width=2)

    # Shield
    cx, cy = W//2, 150
    sp = [cx,cy-72, cx+58,cy-42, cx+58,cy+22, cx,cy+72, cx-58,cy+22, cx-58,cy-42]
    canvas.create_polygon(sp, fill=DIM, outline=CYAN, width=2)
    ip = [cx,cy-56, cx+44,cy-32, cx+44,cy+16, cx,cy+56, cx-44,cy+16, cx-44,cy-32]
    canvas.create_polygon(ip, fill="#020810", outline="#005A7A", width=1)
    canvas.create_text(cx, cy+6, text="◈", font=("Consolas",34,"bold"), fill=CYAN)

    # Ring dots
    ring_items = []
    for angle in range(0, 360, 10):
        rad = math.radians(angle)
        rx = cx + 88*math.cos(rad)
        ry = cy + 88*math.sin(rad)
        d = canvas.create_oval(rx-2,ry-2,rx+2,ry+2, fill="#002030", outline="")
        ring_items.append((d, angle))

    # Title
    canvas.create_text(W//2, 262, text="CYBERSHIELD PRO",
                       font=("Consolas",24,"bold"), fill=CYAN)
    canvas.create_text(W//2, 290, text="AI-POWERED VULNERABILITY ASSESSMENT SYSTEM",
                       font=("Consolas",9), fill="#3A7090")
    canvas.create_text(W//2, 307, text="v11.0  ·  SecureNet Solutions  ·  Professional Edition",
                       font=("Consolas",8), fill="#1A4060")

    # Progress bar
    BX, BY, BW, BH = 100, 348, W-200, 8
    canvas.create_rectangle(BX, BY, BX+BW, BY+BH,
                             fill="#060F1C", outline="#1A4060", width=1)
    pbar     = canvas.create_rectangle(BX, BY, BX, BY+BH, fill=CYAN, outline="")
    pglow    = canvas.create_rectangle(BX, BY-3, BX, BY+BH+3, fill="#003A52", outline="")
    pct_lbl  = canvas.create_text(W//2, BY+20, text="0%",
                                   font=("Consolas",8,"bold"), fill="#3A7090")
    status_t = canvas.create_text(W//2, BY+36, text="Initializing...",
                                   font=("Consolas",9), fill="#3A7090")
    steps = [
        (10,  "Initializing core engine..."),
        (25,  "Loading threat database..."),
        (40,  "Starting network modules..."),
        (55,  "Configuring AI engine..."),
        (70,  "Loading security tools..."),
        (85,  "Connecting services..."),
        (95,  "Finalizing configuration..."),
        (100, "SYSTEM READY"),
    ]

    # Footer
    try:
        host = socket.gethostname()
        ip_s = socket.gethostbyname(host)
    except Exception:
        host = "UNKNOWN"; ip_s = "127.0.0.1"
    canvas.create_text(22, H-16, text=f"HOST: {host}  |  IP: {ip_s}",
                       font=("Consolas",7), fill="#1A3050", anchor="w")
    canvas.create_text(W-22, H-16,
                       text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"),
                       font=("Consolas",7), fill="#1A3050", anchor="e")

    # Top stripe
    top_stripe = canvas.create_rectangle(0,0,100,3, fill=CYAN, outline="")

    # ── Animation state ───────────────────────────────────────────────────
    state = {
        "frame":    0,
        "ring_off": 0,
        "stripe_x": 0,
        "done":     False,
        "destroyed":False,   # ← key flag: canvas is gone
    }

    # ── Safe canvas update helper ─────────────────────────────────────────
    def safe_update(fn):
        """Run fn only if canvas still exists."""
        if state["destroyed"] or state["done"]:
            return
        try:
            fn()
        except Exception:
            state["destroyed"] = True

    # ── Animation loop (background thread) ───────────────────────────────
    def animate():
        while not state["done"]:
            f   = state["frame"]
            pct = min(f / 70.0, 1.0)

            def _frame(pct=pct, f=f):
                if state["destroyed"]:
                    return
                # Progress bar
                nx = BX + int(BW * pct)
                canvas.coords(pbar,  BX, BY, nx, BY+BH)
                canvas.coords(pglow, nx-6, BY-3, nx+6, BY+BH+3)
                pct_int = int(pct*100)
                canvas.itemconfig(pct_lbl, text=f"{pct_int}%",
                                  fill=CYAN if pct_int==100 else "#3A7090")
                for threshold, msg in reversed(steps):
                    if pct_int >= threshold:
                        canvas.itemconfig(status_t, text=msg,
                                          fill=GREEN if pct_int==100 else "#3A7090")
                        break

                # Ring
                off = state["ring_off"]
                for dot, base_angle in ring_items:
                    a = (base_angle + off) % 360
                    bright = int(40 + 215*max(0, math.cos(math.radians(a))))
                    r = bright//8; g = bright//3; b = min(bright,255)
                    canvas.itemconfig(dot, fill=f"#{r:02x}{g:02x}{b:02x}")
                state["ring_off"] = (off + 5) % 360

                # Stripe
                sx = state["stripe_x"]
                canvas.coords(top_stripe, sx, 0, sx+120, 3)
                pulse = int(128 + 127*math.sin(f*0.12))
                r2=pulse//5; g2=pulse//2; b2=min(pulse,255)
                canvas.itemconfig(top_stripe, fill=f"#{r2:02x}{g2:02x}{b2:02x}")
                state["stripe_x"] = (sx + 10) % W
                state["frame"] = f + 1

            # Schedule update on main thread via after()
            try:
                if not state["done"] and not state["destroyed"]:
                    root.after(0, _frame)
            except Exception:
                break

            time.sleep(0.035)

    threading.Thread(target=animate, daemon=True).start()

    # ── Close: stop thread FIRST, then wait, then destroy ────────────────
    def close():
        state["done"] = True           # tell thread to stop
        state["destroyed"] = True      # block any pending _frame calls
        time.sleep(0.08)               # wait for thread's current sleep
        try:
            root.destroy()
        except Exception:
            pass

    root.after(2500, close)
    root.mainloop()


if __name__ == "__main__":
    show_splash()
