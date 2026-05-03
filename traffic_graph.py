"""
traffic_graph.py  -  Live Network Traffic Graph
Real-time network bytes sent/received graph using psutil
"""
import threading, time, collections, os
from datetime import datetime

MAX_POINTS = 60  # 60 seconds of history

class TrafficMonitor:
    def __init__(self, update_callback=None, interval=1.0):
        self.cb          = update_callback
        self.interval    = interval
        self.running     = False
        self._thread     = None
        self.recv_hist   = collections.deque([0]*MAX_POINTS, maxlen=MAX_POINTS)
        self.sent_hist   = collections.deque([0]*MAX_POINTS, maxlen=MAX_POINTS)
        self.timestamps  = collections.deque([""]* MAX_POINTS, maxlen=MAX_POINTS)
        self._last_recv  = 0
        self._last_sent  = 0
        self.total_recv  = 0
        self.total_sent  = 0

    def _get_net_stats(self) -> tuple:
        try:
            import psutil
            net = psutil.net_io_counters()
            return net.bytes_recv, net.bytes_sent
        except ImportError:
            # Fallback: read from /proc/net/dev or Windows
            try:
                import subprocess
                r = subprocess.run(
                    ["netstat","-e"], capture_output=True, text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0,
                    timeout=3)
                for line in r.stdout.splitlines():
                    if "Bytes" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return int(parts[1]), int(parts[2])
            except Exception: pass
            return 0, 0

    def start(self):
        recv, sent       = self._get_net_stats()
        self._last_recv  = recv
        self._last_sent  = sent
        self.running     = True
        self._thread     = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self): self.running = False

    def _loop(self):
        while self.running:
            time.sleep(self.interval)
            try:
                recv, sent    = self._get_net_stats()
                d_recv        = max(0, recv - self._last_recv)
                d_sent        = max(0, sent - self._last_sent)
                self._last_recv = recv
                self._last_sent = sent
                self.total_recv += d_recv
                self.total_sent += d_sent
                # Convert to KB/s
                recv_kbs = d_recv / 1024
                sent_kbs = d_sent / 1024
                self.recv_hist.append(recv_kbs)
                self.sent_hist.append(sent_kbs)
                self.timestamps.append(datetime.now().strftime("%H:%M:%S"))
                if self.cb:
                    self.cb({
                        "recv_kbs":   recv_kbs,
                        "sent_kbs":   sent_kbs,
                        "recv_hist":  list(self.recv_hist),
                        "sent_hist":  list(self.sent_hist),
                        "total_recv": self.total_recv,
                        "total_sent": self.total_sent,
                        "time":       self.timestamps[-1],
                    })
            except Exception: pass

def draw_traffic_graph(canvas, recv_hist: list, sent_hist: list,
                       W: int, H: int, bg: str = "#020609"):
    canvas.delete("all")
    canvas.create_rectangle(0,0,W,H,fill=bg,outline="")

    PAD_L, PAD_R, PAD_T, PAD_B = 60, 10, 20, 30
    gW = W - PAD_L - PAD_R
    gH = H - PAD_T - PAD_B

    all_vals = recv_hist + sent_hist
    max_val  = max(all_vals) if any(v>0 for v in all_vals) else 1
    max_val  = max(max_val, 1)

    # Grid lines
    for i in range(5):
        y = PAD_T + gH * i // 4
        v = max_val * (4-i) / 4
        canvas.create_line(PAD_L,y,PAD_L+gW,y, fill="#0D1F35", width=1)
        label = f"{v:.0f}K" if v < 1024 else f"{v/1024:.1f}M"
        canvas.create_text(PAD_L-4, y, text=label, font=("Consolas",7),
                           fill="#3A6080", anchor="e")

    # Axes
    canvas.create_line(PAD_L,PAD_T,PAD_L,PAD_T+gH, fill="#3A6080", width=1)
    canvas.create_line(PAD_L,PAD_T+gH,PAD_L+gW,PAD_T+gH, fill="#3A6080", width=1)

    n = len(recv_hist)
    if n < 2: return

    def _xy(i, val):
        x = PAD_L + int(gW * i / (n-1))
        y = PAD_T + gH - int(gH * min(val, max_val) / max_val)
        return x, y

    # Draw recv (cyan) fill
    pts = [PAD_L, PAD_T+gH]
    for i,v in enumerate(recv_hist):
        x,y = _xy(i,v); pts.extend([x,y])
    pts.extend([PAD_L+gW, PAD_T+gH])
    if len(pts)>=6: canvas.create_polygon(pts, fill="#002233", outline="")

    # Draw recv line
    for i in range(1, n):
        x0,y0 = _xy(i-1, recv_hist[i-1]); x1,y1 = _xy(i, recv_hist[i])
        canvas.create_line(x0,y0,x1,y1, fill="#00D4FF", width=2)

    # Draw sent (orange) line
    for i in range(1, n):
        x0,y0 = _xy(i-1, sent_hist[i-1]); x1,y1 = _xy(i, sent_hist[i])
        canvas.create_line(x0,y0,x1,y1, fill="#FF8C42", width=2)

    # Legend
    canvas.create_line(PAD_L+10,PAD_T+8,PAD_L+30,PAD_T+8, fill="#00D4FF", width=2)
    canvas.create_text(PAD_L+35,PAD_T+8, text="DOWNLOAD", font=("Consolas",7,"bold"), fill="#00D4FF", anchor="w")
    canvas.create_line(PAD_L+110,PAD_T+8,PAD_L+130,PAD_T+8, fill="#FF8C42", width=2)
    canvas.create_text(PAD_L+135,PAD_T+8, text="UPLOAD", font=("Consolas",7,"bold"), fill="#FF8C42", anchor="w")

    # Current values
    cr = recv_hist[-1] if recv_hist else 0
    cs = sent_hist[-1] if sent_hist else 0
    r_lbl = f"↓ {cr:.1f} KB/s" if cr < 1024 else f"↓ {cr/1024:.2f} MB/s"
    s_lbl = f"↑ {cs:.1f} KB/s" if cs < 1024 else f"↑ {cs/1024:.2f} MB/s"
    canvas.create_text(W-10, PAD_T+8, text=r_lbl, font=("Consolas",8,"bold"), fill="#00D4FF", anchor="e")
    canvas.create_text(W-10, PAD_T+22, text=s_lbl, font=("Consolas",8,"bold"), fill="#FF8C42", anchor="e")
