"""
vuln_timeline.py  -  Vulnerability Timeline & Calendar View
Scan history ko calendar mein dikhata hai — kab kab kya vulnerability thi
"""
import json, os, calendar
from datetime import datetime, date

TIMELINE_FILE = "score_graph_data.json"

def load_timeline() -> list:
    if not os.path.exists(TIMELINE_FILE): return []
    try:
        with open(TIMELINE_FILE) as f: return json.load(f)
    except Exception: return []

def get_calendar_data(year: int, month: int) -> dict:
    """Return dict: day -> list of scan entries for that day."""
    data = load_timeline()
    cal  = {}
    for entry in data:
        try:
            d = datetime.fromisoformat(entry["datetime"])
            if d.year == year and d.month == month:
                day = d.day
                if day not in cal: cal[day] = []
                cal[day].append(entry)
        except Exception:
            pass
    return cal

def get_day_color(entries: list) -> str:
    """Return color based on worst scan of the day."""
    if not entries: return ""
    order  = ["LOW","MEDIUM","HIGH","CRITICAL"]
    worst  = max(entries, key=lambda e: order.index(e.get("level","LOW")) if e.get("level","LOW") in order else 0)
    return {"CRITICAL":"#FF2D55","HIGH":"#FF8C42","MEDIUM":"#FFD60A","LOW":"#00FF88"}.get(worst.get("level","LOW"),"#00FF88")

def get_all_months() -> list:
    """Return list of (year, month) tuples that have scan data."""
    data   = load_timeline()
    months = set()
    for e in data:
        try:
            d = datetime.fromisoformat(e["datetime"])
            months.add((d.year, d.month))
        except Exception:
            pass
    today = date.today()
    months.add((today.year, today.month))
    return sorted(months)

def draw_calendar(canvas, year: int, month: int, W: int, H: int,
                  bg: str = "#020609", on_click=None):
    """Draw interactive calendar on tk.Canvas."""
    canvas.delete("all")
    canvas.create_rectangle(0, 0, W, H, fill=bg, outline="")

    cal_data = get_calendar_data(year, month)
    month_name = calendar.month_name[month]
    day_names  = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]

    # Header
    canvas.create_text(W//2, 20, text=f"{month_name} {year}",
                       font=("Consolas",12,"bold"), fill="#00D4FF")
    # Day headers
    cell_w = W // 7
    cell_h = (H - 55) // 6
    for i, d in enumerate(day_names):
        x = i * cell_w + cell_w // 2
        color = "#FF2D55" if d in ("Sat","Sun") else "#7BAFD4"
        canvas.create_text(x, 42, text=d, font=("Consolas",8,"bold"), fill=color)

    # Calendar grid
    cal_matrix = calendar.monthcalendar(year, month)
    cell_tags  = {}
    for row, week in enumerate(cal_matrix):
        for col, day in enumerate(week):
            x0 = col * cell_w + 2
            y0 = 52 + row * cell_h + 2
            x1 = x0 + cell_w - 4
            y1 = y0 + cell_h - 4
            if day == 0:
                canvas.create_rectangle(x0,y0,x1,y1, fill="#030A10", outline="#0A1628", width=1)
                continue
            entries   = cal_data.get(day, [])
            day_color = get_day_color(entries)
            bg_fill   = "#050F1A"
            border    = "#0A1628"
            if entries:
                bg_fill = {"#FF2D55":"#2A050C","#FF8C42":"#2A1505","#FFD60A":"#1A1400","#00FF88":"#001A10"}.get(day_color,"#050F1A")
                border  = day_color
            # Today highlight
            today = date.today()
            if day == today.day and month == today.month and year == today.year:
                border = "#00D4FF"; bg_fill = "#001A2A"
            canvas.create_rectangle(x0,y0,x1,y1, fill=bg_fill, outline=border, width=1)
            # Day number
            canvas.create_text(x0+10, y0+12, text=str(day),
                               font=("Consolas",8,"bold"),
                               fill=day_color if entries else "#3A6080", anchor="w")
            # Scan count badge
            if entries:
                canvas.create_oval(x1-16,y0+2,x1-2,y0+16, fill=day_color, outline="")
                canvas.create_text(x1-9, y0+9, text=str(len(entries)),
                                   font=("Consolas",7,"bold"), fill="#000000")
            # Score
            if entries:
                avg_score = sum(e.get("score",0) for e in entries) // len(entries)
                canvas.create_text(W//2 + (col - 3)*cell_w//2, y0+cell_h-10,
                                   text="", font=("Consolas",7), fill=day_color)
                canvas.create_text(x0+10, y0+cell_h-12, text=f"{avg_score}",
                                   font=("Consolas",8,"bold"), fill=day_color, anchor="w")
            # Clickable tag
            tag = f"day_{day}"
            canvas.create_rectangle(x0,y0,x1,y1, fill="", outline="", tags=(tag,))
            cell_tags[tag] = (day, entries)
            if on_click and entries:
                canvas.tag_bind(tag, "<Button-1>",
                                lambda e, d=day, ent=entries: on_click(d, ent))

    return cell_tags
