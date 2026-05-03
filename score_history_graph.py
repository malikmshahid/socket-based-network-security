"""
score_history_graph.py  -  Vulnerability Score History Graph
Tracks scan scores over time and provides graph data for tkinter Canvas
"""
import json, os
from datetime import datetime

GRAPH_FILE = "score_graph_data.json"

RISK_COLORS = {
    "CRITICAL": "#FF2D55",
    "HIGH":     "#FF8C42",
    "MEDIUM":   "#FFD60A",
    "LOW":      "#00FF88",
}

def load_graph_data() -> list:
    if not os.path.exists(GRAPH_FILE): return []
    try:
        with open(GRAPH_FILE) as f: return json.load(f)
    except Exception: return []

def save_graph_data(data: list):
    try:
        with open(GRAPH_FILE, "w") as f: json.dump(data[-100:], f)  # keep last 100
    except Exception: pass

def add_scan_point(risk_score: int, risk_level: str, target_ip: str = ""):
    data = load_graph_data()
    data.append({
        "score":    risk_score,
        "level":    risk_level,
        "target":   target_ip,
        "time":     datetime.now().strftime("%H:%M"),
        "date":     datetime.now().strftime("%Y-%m-%d"),
        "datetime": datetime.now().isoformat(),
    })
    save_graph_data(data)

def get_stats(data: list) -> dict:
    if not data:
        return {"count": 0, "avg": 0, "min": 0, "max": 0,
                "trend": "no data", "worst_level": "N/A"}
    scores = [d["score"] for d in data]
    trend = "STABLE"
    if len(scores) >= 3:
        recent = sum(scores[-3:]) / 3
        older  = sum(scores[:-3]) / len(scores[:-3]) if len(scores) > 3 else recent
        if recent > older + 5:   trend = "WORSENING ↑"
        elif recent < older - 5: trend = "IMPROVING ↓"
    levels = [d.get("level","LOW") for d in data]
    order  = ["LOW","MEDIUM","HIGH","CRITICAL"]
    worst  = max(levels, key=lambda l: order.index(l) if l in order else 0)
    return {
        "count":       len(data),
        "avg":         round(sum(scores)/len(scores), 1),
        "min":         min(scores),
        "max":         max(scores),
        "trend":       trend,
        "worst_level": worst,
        "latest":      scores[-1],
        "latest_level": data[-1].get("level","LOW"),
    }

def draw_graph(canvas, data: list, W: int, H: int,
               bg: str = "#020609", line_color: str = "#00D4FF",
               text_color: str = "#7BAFD4"):
    """Draw score history graph on a tk.Canvas."""
    canvas.delete("all")
    canvas.create_rectangle(0, 0, W, H, fill=bg, outline="")

    if not data:
        canvas.create_text(W//2, H//2, text="No scan history yet.\nRun scans to see graph.",
                           font=("Consolas",10), fill=text_color, justify="center")
        return

    PAD_L, PAD_R, PAD_T, PAD_B = 55, 20, 20, 35
    gW = W - PAD_L - PAD_R
    gH = H - PAD_T - PAD_B

    # Grid
    for i in range(5):
        y = PAD_T + gH * i // 4
        val = 100 - (100 * i // 4)
        canvas.create_line(PAD_L, y, PAD_L + gW, y, fill="#0D1F35", width=1)
        canvas.create_text(PAD_L - 6, y, text=str(val), font=("Consolas",7),
                           fill=text_color, anchor="e")

    # Axes
    canvas.create_line(PAD_L, PAD_T, PAD_L, PAD_T+gH, fill=text_color, width=1)
    canvas.create_line(PAD_L, PAD_T+gH, PAD_L+gW, PAD_T+gH, fill=text_color, width=1)
    canvas.create_text(12, H//2, text="RISK\nSCORE", font=("Consolas",7),
                       fill=text_color, angle=90, justify="center")

    scores = [d["score"] for d in data]
    n      = len(scores)
    if n == 1: scores = [scores[0], scores[0]]; n = 2

    def _xy(i, score):
        x = PAD_L + gW * i // (n - 1)
        y = PAD_T + gH - int(gH * score / 100)
        return x, y

    # Shaded area under line
    pts = []
    for i, score in enumerate(scores):
        x, y = _xy(i, score)
        pts.extend([x, y])
    pts += [PAD_L + gW, PAD_T + gH, PAD_L, PAD_T + gH]
    if len(pts) >= 6:
        canvas.create_polygon(pts, fill="#001A30", outline="")

    # Line segments colored by risk level
    for i in range(1, n):
        x0, y0 = _xy(i-1, scores[i-1])
        x1, y1 = _xy(i,   scores[i])
        lvl   = data[i].get("level","LOW") if i < len(data) else "LOW"
        color = RISK_COLORS.get(lvl, line_color)
        canvas.create_line(x0, y0, x1, y1, fill=color, width=2, smooth=True)

    # Dots + tooltips
    for i, score in enumerate(scores):
        x, y = _xy(i, score)
        lvl   = data[i].get("level","LOW") if i < len(data) else "LOW"
        color = RISK_COLORS.get(lvl, line_color)
        canvas.create_oval(x-4, y-4, x+4, y+4, fill=color, outline="white", width=1)

    # X-axis labels (show first, middle, last)
    show_idx = [0, n//4, n//2, 3*n//4, n-1]
    for i in show_idx:
        if 0 <= i < len(data):
            x, _ = _xy(min(i, n-1), 0)
            lbl = data[i].get("time","") + "\n" + data[i].get("date","")[-5:]
            canvas.create_text(x, PAD_T + gH + 14, text=lbl,
                               font=("Consolas",6), fill=text_color, justify="center")

    # Latest value label
    if scores:
        x, y = _xy(n-1, scores[-1])
        lvl  = data[-1].get("level","LOW") if data else "LOW"
        c    = RISK_COLORS.get(lvl, line_color)
        canvas.create_text(x, y - 14, text=f"{scores[-1]}",
                           font=("Consolas",9,"bold"), fill=c)
