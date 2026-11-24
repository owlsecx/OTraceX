#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                                                                          ║
# ║    ██████╗ ████████╗██████╗  █████╗  ██████╗███████╗██╗  ██╗            ║
# ║   ██╔═══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝╚██╗██╔╝           ║
# ║   ██║   ██║   ██║   ██████╔╝███████║██║     █████╗   ╚███╔╝            ║
# ║   ██║   ██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝   ██╔██╗            ║
# ║   ╚██████╔╝   ██║   ██║  ██║██║  ██║╚██████╗███████╗██╔╝ ██╗           ║
# ║    ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝          ║
# ║                                                                          ║
# ║   Tool        : OTraceX — Advanced TCP Path Tracer                       ║
# ║   Category    : ORecon / Network Intelligence                            ║
# ║   Purpose     : TCP session-based traceroute through firewalls           ║
# ║   Developer   : khaled.s.haddad                                          ║
# ║   Website     : owlsec.org                                               ║
# ║   Version     : v1.0                                                     ║
# ║   Year        : 2026                                                     ║
# ║   Platform    : Debian Linux / OwlOS                                     ║
# ║                                                                          ║
# ║   Requirements: pip install scapy  |  Must run as root                   ║
# ╚══════════════════════════════════════════════════════════════════════════╝

import os
import sys
import json
import csv
import time
import signal
import socket
import struct
import random
import hashlib
import tempfile
import threading
import subprocess
import ipaddress
import re
import io
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

# ── Scapy ──────────────────────────────────────────────────────────────────
SCAPY_OK = False
try:
    from scapy.all import (
        IP, TCP, ICMP, UDP, Raw,
        send, sniff, sr1, conf as scapy_conf
    )
    scapy_conf.verb = 0
    SCAPY_OK = True
except ImportError:
    pass

# ── GeoIP (optional) ───────────────────────────────────────────────────────
GEOIP_OK = False
try:
    import geoip2.database  # type: ignore
    GEOIP_OK = True
except ImportError:
    pass

# ─── VERSION ───────────────────────────────────────────────────────────────
VERSION   = "v1.0"
TOOL_NAME = "OTraceX"
DEVELOPER = "khaled.s.haddad"
WEBSITE   = "owlsec.org"
PLATFORM  = "OwlOS / Debian Linux"

# ─── COLORS ────────────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
    MAGENTA = "\033[95m"
    DIM     = "\033[2m"
    ORANGE  = "\033[38;5;208m"
    BLUE    = "\033[94m"
    INVERT  = "\033[7m"
    UNDER   = "\033[4m"
    BG_DARK = "\033[48;5;235m"

def c(text: Any, *clrs: str) -> str:
    return "".join(clrs) + str(text) + C.RESET

def strip_ansi(text: str) -> str:
    return re.sub(r'\033\[[0-9;]*m', '', text)

def visible_len(text: str) -> int:
    return len(strip_ansi(text))

# ─── TERMINAL SIZE ─────────────────────────────────────────────────────────
def term_width() -> int:
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 80

# ─── BANNER ────────────────────────────────────────────────────────────────
BANNER_ART = r"""
  ██████╗ ████████╗██████╗  █████╗  ██████╗███████╗██╗  ██╗
 ██╔═══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝╚██╗██╔╝
 ██║   ██║   ██║   ██████╔╝███████║██║     █████╗   ╚███╔╝ 
 ██║   ██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝   ██╔██╗ 
 ╚██████╔╝   ██║   ██║  ██║██║  ██║╚██████╗███████╗██╔╝ ██╗
  ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝"""

def banner():
    w = max(term_width(), 64)
    print(c(BANNER_ART, C.CYAN))
    print()
    print(c(f"  {'Advanced TCP Session Traceroute  ' + VERSION:^{w-4}}", C.MAGENTA, C.BOLD))
    print(c(f"  {'Firewall Bypass · RTT/Jitter/Loss · Hop Analysis · Export':^{w-4}}", C.WHITE))
    print()
    print(
        "  " + c("Developer : ", C.DIM, C.WHITE) + c(DEVELOPER, C.CYAN) +
        c("   │   ", C.DIM) +
        c("Website : ", C.DIM, C.WHITE) + c(WEBSITE, C.CYAN) +
        c("   │   ", C.DIM) +
        c("Platform : ", C.DIM, C.WHITE) + c(PLATFORM, C.DIM, C.WHITE)
    )
    print()
    warnings = []
    if not SCAPY_OK:
        warnings.append(c("  [!] Scapy not found — run:  pip install scapy", C.YELLOW))
    if os.geteuid() != 0:
        warnings.append(c("  [!] Root privileges required for raw sockets", C.ORANGE))
    if not GEOIP_OK:
        warnings.append(c("  [~] GeoIP disabled — pip install geoip2  (optional)", C.DIM))
    for w_line in warnings:
        print(w_line)
    if warnings:
        print()
    print(c("─" * max(term_width(), 64), C.CYAN))
    print()

# ─── HELP ──────────────────────────────────────────────────────────────────
def show_help():
    W = 70
    sep_top   = "╔" + "═" * W + "╗"
    sep_mid   = "╠" + "═" * W + "╣"
    sep_sub   = "╟" + "─" * W + "╢"
    sep_bot   = "╚" + "═" * W + "╝"

    def hline(text: str, color1=C.WHITE, bold=False):
        raw   = "  " + text
        pad   = W - visible_len(raw)
        inner = (C.BOLD if bold else "") + color1 + raw + " " * max(pad, 0) + C.RESET
        print(c("║", C.CYAN) + inner + c("║", C.CYAN))

    def blank():
        print(c("║", C.CYAN) + " " * W + c("║", C.CYAN))

    def section_hdr(title: str):
        print(c(sep_sub, C.CYAN))
        raw   = "  ▸ " + title
        pad   = W - visible_len(raw)
        inner = C.YELLOW + C.BOLD + raw + " " * max(pad, 0) + C.RESET
        print(c("║", C.CYAN) + inner + c("║", C.CYAN))
        blank()

    def item(key: str, val: str, kc=C.CYAN, vc=C.WHITE):
        raw   = "    " + key
        kpad  = 22 - visible_len(raw)
        vraw  = " " * max(kpad, 1) + val
        full  = raw + vraw
        pad   = W - visible_len(full)
        inner = kc + raw + C.RESET + vc + vraw + " " * max(pad, 0) + C.RESET
        print(c("║", C.CYAN) + inner + c("║", C.CYAN))

    def note(text: str):
        raw = "    ⚑ " + text
        pad = W - visible_len(raw)
        inner = C.DIM + raw + " " * max(pad, 0) + C.RESET
        print(c("║", C.CYAN) + inner + c("║", C.CYAN))

    print()
    print(c(sep_top, C.CYAN))
    # Title bar
    title_raw = f"  {TOOL_NAME} {VERSION}  ─  Help & Reference"
    tpad = W - visible_len(title_raw)
    print(c("║", C.CYAN) +
          c(title_raw, C.BOLD, C.WHITE) + " " * max(tpad, 0) +
          c("║", C.CYAN))
    sub_raw = f"  {WEBSITE}"
    spad = W - visible_len(sub_raw)
    print(c("║", C.CYAN) +
          c(sub_raw, C.DIM) + " " * max(spad, 0) +
          c("║", C.CYAN))
    blank()

    # ── HOW IT WORKS ──
    section_hdr("HOW IT WORKS")
    steps = [
        ("Step 1", "Open a real TCP session to the target in another terminal"),
        ("",       "  Example:  nc google.com 80    OR    curl -v google.com"),
        ("Step 2", "OTraceX sniffs the established session passively"),
        ("Step 3", "Injects TCP PSH+ACK probes at TTL = 1, 2, 3 …"),
        ("Step 4", "ICMP time-exceeded replies identify each hop"),
        ("Step 5", "Trace ends when target IP responds (no more TTL-exceeded)"),
    ]
    for k, v in steps:
        if k:
            item(k, v, kc=C.CYAN)
        else:
            hline(v, C.DIM)
    blank()

    # ── MENU OPTIONS ──
    section_hdr("MENU OPTIONS")
    menu = [
        ("[1]", "Start Trace",     "TCP session-based — bypasses firewalls / NAT"),
        ("[2]", "Quick Trace",     "ICMP-based fallback — no active session needed"),
        ("[3]", "UDP Trace",       "UDP probe mode — port 33434+ by default"),
        ("[4]", "Interface List",  "Enumerate local network interfaces + state"),
        ("[5]", "View Last Hops",  "Full hop table from the last completed trace"),
        ("[6]", "Export Results",  "Save to JSON / CSV / TXT / HTML / XML"),
        ("[7]", "Ping Sweep",      "Quick ICMP reachability sweep of a range"),
        ("[8]", "AS Lookup",       "ASN / Org info for all hops in last trace"),
        ("[H]", "Help",            "This reference page"),
        ("[0]", "Exit",            "Quit OTraceX"),
    ]
    for num, name, desc in menu:
        item(f"{num} {name}", desc)
    blank()

    # ── METRICS ──
    section_hdr("METRICS EXPLAINED")
    metrics = [
        ("RTT min/avg/max", "Round-trip time in milliseconds per hop"),
        ("Jitter",          "Avg RTT variation between consecutive probes"),
        ("Loss %",          "Percentage of probes lost at each hop"),
        ("PTR / Hostname",  "Reverse-DNS lookup of hop IP"),
        ("ASN / Org",       "Autonomous System Number and organisation name"),
        ("GeoIP",           "Country / city location (requires GeoIP DB)"),
    ]
    for k, v in metrics:
        item(k, v)
    blank()

    # ── EXPORT FORMATS ──
    section_hdr("EXPORT FORMATS")
    fmts = [
        ("JSON",  "Full structured data — machine-readable"),
        ("CSV",   "Spreadsheet-compatible — per-hop rows"),
        ("TXT",   "Human-readable plain-text report"),
        ("HTML",  "Standalone styled web report"),
        ("XML",   "Enterprise / SIEM-compatible format"),
    ]
    for k, v in fmts:
        item(k, v)
    blank()

    # ── RTT COLOUR KEY ──
    section_hdr("RTT COLOUR CODING")
    rtt_keys = [
        (c("● GREEN",  C.GREEN),  "< 10 ms   — excellent"),
        (c("● YELLOW", C.YELLOW), "10–49 ms  — good"),
        (c("● ORANGE", C.ORANGE), "50–149 ms — moderate"),
        (c("● RED",    C.RED),    "≥ 150 ms  — high latency"),
    ]
    for col, desc in rtt_keys:
        hline(col + c(f"  {desc}", C.DIM))
    blank()

    # ── TIPS ──
    section_hdr("TIPS & BEST PRACTICES")
    tips = [
        "Use port 80 / 443 / 22 to bypass stateless packet filters.",
        "Increase retries to 3–5 for lossy or congested links.",
        "Keep your nc / curl session open for the full trace duration.",
        "UDP Trace is useful when ICMP is filtered end-to-end.",
        "Export to HTML for a shareable visual report.",
        "Run with --no-rdns to skip reverse-DNS and speed up traces.",
    ]
    for t in tips:
        note(t)
    blank()

    # ── REQUIREMENTS ──
    section_hdr("REQUIREMENTS")
    reqs = [
        ("Python",  "3.8 or later"),
        ("Scapy",   "pip install scapy          (required)"),
        ("geoip2",  "pip install geoip2          (optional — GeoIP features)"),
        ("Root",    "sudo / root — raw socket / packet injection"),
        ("OS",      "Linux (OwlOS / Debian recommended)"),
    ]
    for k, v in reqs:
        item(k, v)
    blank()

    print(c(sep_bot, C.CYAN))
    print()

# ─── UI HELPERS ────────────────────────────────────────────────────────────
def clear():
    os.system("clear")

def pause():
    input(c("\n  [↩] Press Enter to return to main menu…", C.YELLOW))

def print_header(title: str, subtitle: str = ""):
    w = max(term_width(), 64)
    print()
    print(c("╔" + "═" * (w - 2) + "╗", C.CYAN))
    t = f"  {TOOL_NAME} {VERSION}  ─  {title}"
    tpad = (w - 2) - visible_len(t) - 1
    print(c("║", C.CYAN) + c(t, C.BOLD, C.CYAN) +
          " " * max(tpad, 0) + c("║", C.CYAN))
    if subtitle:
        s = f"  {subtitle}"
        spad = (w - 2) - visible_len(s) - 1
        print(c("║", C.CYAN) + c(s, C.DIM) +
              " " * max(spad, 0) + c("║", C.CYAN))
    print(c("╚" + "═" * (w - 2) + "╝", C.CYAN))

def section(title: str):
    print()
    print(c(f"  ┌─ {title}", C.YELLOW, C.BOLD))

def row(key: str, val: Any, width: int = 22, val_color: str = None):
    vc  = val_color or C.WHITE
    pad = width - len(str(key))
    print("  " + c("│", C.YELLOW) + "  " +
          c(str(key) + ":" + " " * max(pad, 1), C.CYAN) +
          c(str(val), vc))

def ok(msg: str):
    print("  " + c("[✔]", C.GREEN)  + "  " + c(msg, C.WHITE))

def err(msg: str):
    print("  " + c("[✘]", C.RED)    + "  " + c(msg, C.RED))

def warn(msg: str):
    print("  " + c("[!]", C.ORANGE) + "  " + c(msg, C.YELLOW))

def nfo(msg: str):
    print("  " + c("[*]", C.CYAN)   + "  " + c(msg, C.DIM, C.WHITE))

def dbg(msg: str):
    print("  " + c("[~]", C.DIM)    + "  " + c(msg, C.DIM))

def ask(prompt: str, default: str = "") -> str:
    dflt = f" [{default}]" if default else ""
    val  = input(c("  [»] ", C.YELLOW) + c(f"{prompt}{dflt}: ", C.WHITE)).strip()
    return val or default

def ask_int(prompt: str, default: int, lo: int = 1, hi: int = 65535) -> int:
    while True:
        raw = ask(prompt, str(default))
        if raw.isdigit() and lo <= int(raw) <= hi:
            return int(raw)
        warn(f"Enter a number between {lo} and {hi}")

def ask_float(prompt: str, default: float) -> float:
    raw = ask(prompt, str(default))
    try:
        return float(raw)
    except ValueError:
        return default

def ask_choice(prompt: str, choices: List[str], default: str = "") -> str:
    """Prompt until the user enters one of the valid choices."""
    choices_lower = [x.lower() for x in choices]
    while True:
        val = ask(prompt, default).lower()
        if val in choices_lower:
            return val
        warn(f"Valid options: {' / '.join(choices)}")

def _spinner(msg: str, stop_ev: threading.Event):
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    i = 0
    while not stop_ev.is_set():
        print(c(f"  [{frames[i % len(frames)]}] ", C.CYAN) +
              c(msg, C.DIM, C.WHITE), end="\r", flush=True)
        time.sleep(0.1)
        i += 1
    print(" " * (len(msg) + 14), end="\r")

def rtt_color(rtt: float) -> str:
    if rtt <= 0:   return C.DIM
    if rtt < 10:   return C.GREEN
    if rtt < 50:   return C.YELLOW
    if rtt < 150:  return C.ORANGE
    return C.RED

def loss_color(loss: float) -> str:
    if loss == 0:  return C.GREEN
    if loss < 5:   return C.YELLOW
    if loss < 20:  return C.ORANGE
    return C.RED

def progress_bar(value: float, total: float, width: int = 20,
                 clr: str = C.GREEN) -> str:
    if total <= 0:
        return c("[" + "─" * width + "]", C.DIM)
    pct   = min(value / total, 1.0)
    filled = int(pct * width)
    bar = "█" * filled + "░" * (width - filled)
    return c("[", C.DIM) + c(bar, clr) + c("]", C.DIM)

# ═══════════════════════════════════════════════════════════════════════════
#   DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════

class HopStatus(Enum):
    UNKNOWN    = "unknown"
    RESPONDING = "responding"
    TIMEOUT    = "timeout"
    TARGET     = "target"
    FILTERED   = "filtered"

class TraceMode(Enum):
    TCP  = "tcp"
    ICMP = "icmp"
    UDP  = "udp"


@dataclass
class HopInfo:
    ttl:         int
    ip:          str
    hostname:    Optional[str]  = None
    asn:         Optional[str]  = None
    org:         Optional[str]  = None
    country:     Optional[str]  = None
    city:        Optional[str]  = None
    rtt_min:     float          = float("inf")
    rtt_max:     float          = 0.0
    rtt_avg:     float          = 0.0
    rtt_samples: List[float]    = field(default_factory=list)
    pkts_sent:   int            = 0
    pkts_recv:   int            = 0
    status:      HopStatus      = HopStatus.UNKNOWN

    def add_rtt(self, rtt: float):
        self.rtt_samples.append(rtt)
        self.rtt_min = min(self.rtt_min, rtt)
        self.rtt_max = max(self.rtt_max, rtt)
        self.rtt_avg = sum(self.rtt_samples) / len(self.rtt_samples)
        self.pkts_recv += 1

    @property
    def loss(self) -> float:
        if not self.pkts_sent:
            return 0.0
        return (self.pkts_sent - self.pkts_recv) / self.pkts_sent * 100

    @property
    def jitter(self) -> float:
        s = self.rtt_samples
        if len(s) < 2:
            return 0.0
        return sum(abs(s[i] - s[i-1]) for i in range(1, len(s))) / (len(s) - 1)

    def to_dict(self) -> dict:
        return {
            "ttl":        self.ttl,
            "ip":         self.ip,
            "hostname":   self.hostname,
            "asn":        self.asn,
            "org":        self.org,
            "country":    self.country,
            "city":       self.city,
            "rtt_min_ms": round(self.rtt_min, 3) if self.rtt_min != float("inf") else None,
            "rtt_avg_ms": round(self.rtt_avg, 3),
            "rtt_max_ms": round(self.rtt_max, 3),
            "jitter_ms":  round(self.jitter, 3),
            "loss_pct":   round(self.loss, 2),
            "pkts_sent":  self.pkts_sent,
            "pkts_recv":  self.pkts_recv,
            "status":     self.status.value,
        }


@dataclass
class TCPSession:
    session_id: str
    src_ip:     str
    src_port:   int
    dst_ip:     str
    dst_port:   int
    seq:        int = 0
    ack:        int = 0
    window:     int = 8192
    state:      int = 0   # 0=none 1=SYN 2=SYN-ACK 3=established

    def __post_init__(self):
        if not self.session_id:
            self.session_id = hashlib.md5(
                f"{self.src_ip}:{self.src_port}-"
                f"{self.dst_ip}:{self.dst_port}-"
                f"{time.time()}".encode()
            ).hexdigest()[:10]


@dataclass
class TraceResult:
    target:      str
    target_ip:   str
    port:        int
    iface:       str
    mode:        TraceMode
    start_time:  float
    end_time:    float = 0.0
    hops:        Dict[int, HopInfo] = field(default_factory=dict)
    probes_sent: int = 0
    probes_recv: int = 0
    retries:     int = 2
    max_ttl:     int = 30
    notes:       str = ""

    @property
    def total_hops(self) -> int:
        return len(self.hops)

    @property
    def duration(self) -> float:
        return (self.end_time or time.time()) - self.start_time

    @property
    def success_rate(self) -> float:
        if not self.probes_sent:
            return 0.0
        return self.probes_recv / self.probes_sent * 100

    @property
    def avg_rtt(self) -> float:
        rtts = [h.rtt_avg for h in self.hops.values()
                if h.status in (HopStatus.RESPONDING, HopStatus.TARGET)]
        return sum(rtts) / len(rtts) if rtts else 0.0

    def to_dict(self) -> dict:
        return {
            "tool":        TOOL_NAME,
            "version":     VERSION,
            "developer":   DEVELOPER,
            "website":     WEBSITE,
            "generated":   datetime.now().isoformat(),
            "target":      self.target,
            "target_ip":   self.target_ip,
            "port":        self.port,
            "mode":        self.mode.value,
            "interface":   self.iface,
            "duration_s":  round(self.duration, 2),
            "total_hops":  self.total_hops,
            "probes_sent": self.probes_sent,
            "probes_recv": self.probes_recv,
            "success_pct": round(self.success_rate, 1),
            "avg_rtt_ms":  round(self.avg_rtt, 2),
            "notes":       self.notes,
            "hops":        [h.to_dict() for _, h in sorted(self.hops.items())],
        }


# ═══════════════════════════════════════════════════════════════════════════
#   SESSION SNIFFER
# ═══════════════════════════════════════════════════════════════════════════

class SessionSniffer:
    """Passively sniff TCP 3-way handshake and maintain live session state."""

    def __init__(self, target_ip: str, port: int,
                 iface: str, verbose: bool = False):
        self.target_ip = target_ip
        self.port      = port
        self.iface     = iface
        self.verbose   = verbose
        self.session:  Optional[TCPSession] = None
        self._lock     = threading.Lock()
        self._stop     = threading.Event()
        self._thread:  Optional[threading.Thread] = None

    def _handle(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return
        ip_l  = pkt[IP]
        tcp_l = pkt[TCP]
        to_t   = (ip_l.dst == self.target_ip and tcp_l.dport == self.port)
        from_t = (ip_l.src == self.target_ip and tcp_l.sport == self.port)
        if not (to_t or from_t):
            return
        flags = int(tcp_l.flags)
        SYN, ACK, PSH, RST, FIN = 0x02, 0x10, 0x08, 0x04, 0x01
        with self._lock:
            if self.session is None:
                if to_t and (flags & SYN) and not (flags & ACK):
                    self.session = TCPSession(
                        session_id="",
                        src_ip=ip_l.src, src_port=tcp_l.sport,
                        dst_ip=ip_l.dst, dst_port=tcp_l.dport,
                        seq=tcp_l.seq + 1, window=tcp_l.window, state=1)
                    if self.verbose:
                        nfo(f"SYN  {ip_l.src}:{tcp_l.sport} → {self.target_ip}:{self.port}")
                return
            s = self.session
            if from_t and (flags & SYN) and (flags & ACK) and s.state == 1:
                s.ack   = tcp_l.seq + 1
                s.state = 2
                if self.verbose:
                    nfo("SYN-ACK received — handshake in progress")
            elif to_t and (flags & ACK) and not (flags & PSH) and s.state == 2:
                s.seq   = tcp_l.seq
                s.state = 3
                if self.verbose:
                    ok(f"Session established — ID {s.session_id}")
            elif s.state == 3:
                pl = len(bytes(tcp_l.payload)) if tcp_l.payload else 0
                if to_t and pl:
                    s.seq += pl
                elif from_t and pl:
                    s.ack += pl
                # Detect graceful close / reset
                if (flags & FIN) or (flags & RST):
                    if self.verbose:
                        warn("Session closed by remote")

    def start(self):
        bpf = f"tcp and host {self.target_ip} and port {self.port}"
        def _sniff():
            try:
                sniff(iface=self.iface, filter=bpf, prn=self._handle,
                      store=False, stop_filter=lambda _: self._stop.is_set())
            except Exception as exc:
                if self.verbose:
                    err(f"Sniffer error: {exc}")
        self._thread = threading.Thread(target=_sniff, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def wait_established(self, timeout: float = 60.0) -> Optional[TCPSession]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if self.session and self.session.state == 3:
                    return self.session
            time.sleep(0.2)
        return None


# ═══════════════════════════════════════════════════════════════════════════
#   PROBE ENGINE  (TCP PSH+ACK mode)
# ═══════════════════════════════════════════════════════════════════════════

class ProbeEngine:
    """Inject TCP probes at controlled TTL values and collect ICMP replies."""

    MAGIC = 0xAB1E7000

    def __init__(self, session: TCPSession, result: TraceResult,
                 iface: str, timeout: float = 3.0,
                 retries: int = 2, payload_size: int = 20,
                 verbose: bool = False, rdns: bool = True):
        self.sess         = session
        self.result       = result
        self.iface        = iface
        self.timeout      = timeout
        self.retries      = retries
        self.payload_size = max(payload_size, 14)
        self.verbose      = verbose
        self.rdns         = rdns
        self._pending:    Dict[int, Tuple[int, float]] = {}
        self._lock        = threading.Lock()
        self._stop        = threading.Event()
        self._target_hit  = threading.Event()

    def _mk_id(self) -> int:
        return self.MAGIC | (random.getrandbits(12) & 0xFFF)

    def _build_payload(self, pid: int, ttl: int) -> bytes:
        ts  = int(time.time() * 1000) & 0xFFFFFFFF
        hdr = struct.pack("!I H I", pid, ttl, ts)
        pad = max(0, self.payload_size - len(hdr))
        return hdr + bytes(pad)

    def _send(self, ttl: int) -> Optional[int]:
        pid     = self._mk_id()
        payload = self._build_payload(pid, ttl)
        pkt = (IP(dst=self.sess.dst_ip, ttl=ttl) /
               TCP(sport=self.sess.src_port, dport=self.sess.dst_port,
                   seq=self.sess.seq, ack=self.sess.ack,
                   flags="PA", window=self.sess.window) /
               Raw(load=payload))
        try:
            send(pkt, iface=self.iface, verbose=0)
            with self._lock:
                self._pending[pid] = (ttl, time.time())
            self.result.probes_sent += 1
            self.sess.seq += len(payload)
            return pid
        except Exception as exc:
            if self.verbose:
                err(f"Send error TTL={ttl}: {exc}")
            return None

    def _resolve(self, ip: str) -> Optional[str]:
        if not self.rdns:
            return None
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    def _handle_icmp(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
            return
        icmp_l = pkt[ICMP]
        # Accept time-exceeded (11/0) and port-unreachable (3/3 — target reached)
        if icmp_l.type == 11 and icmp_l.code == 0:
            reached = False
        elif icmp_l.type == 3 and icmp_l.code in (0, 1, 2, 3, 9, 10, 13):
            reached = True
        else:
            return
        inner = icmp_l.payload
        if not inner.haslayer(IP):
            return
        oi = inner[IP]
        if oi.dst != self.sess.dst_ip:
            return
        # Try to extract probe ID from TCP payload
        pid = None
        if inner.haslayer(TCP):
            ot = inner[TCP]
            if ot.dport != self.sess.dst_port:
                return
            try:
                raw = bytes(ot.payload)
                if len(raw) >= 4:
                    pid = struct.unpack("!I", raw[:4])[0]
            except Exception:
                pass
        with self._lock:
            if pid is not None and pid not in self._pending:
                return
            if pid is not None:
                ttl, sent_ts = self._pending.pop(pid)
            else:
                # Fallback: match by TTL in inner header
                ttl     = oi.ttl
                sent_ts = time.time() - 0.001
        rtt       = (time.time() - sent_ts) * 1000
        responder = pkt[IP].src
        self.result.probes_recv += 1
        hostname  = self._resolve(responder)
        hop = self.result.hops.setdefault(
            ttl, HopInfo(ttl=ttl, ip=responder, hostname=hostname,
                         status=HopStatus.RESPONDING))
        hop.ip       = responder
        if hostname and not hop.hostname:
            hop.hostname = hostname
        if reached or responder == self.sess.dst_ip:
            hop.status = HopStatus.TARGET
            self._target_hit.set()
        else:
            hop.status = HopStatus.RESPONDING
        hop.add_rtt(rtt)
        _print_hop_live(hop)

    def run(self, max_ttl: int = 30) -> TraceResult:
        section("Live Hop Table  (TCP mode)")
        _print_hop_header()
        stop_ev = threading.Event()
        def _sniff():
            try:
                sniff(iface=self.iface, filter="icmp", prn=self._handle_icmp,
                      store=False, stop_filter=lambda _: stop_ev.is_set())
            except Exception:
                pass
        sniff_t = threading.Thread(target=_sniff, daemon=True)
        sniff_t.start()

        for ttl in range(1, max_ttl + 1):
            if self._target_hit.is_set():
                break
            hop = self.result.hops.setdefault(
                ttl, HopInfo(ttl=ttl, ip="*", status=HopStatus.TIMEOUT))
            hop.pkts_sent += self.retries + 1
            for _ in range(self.retries + 1):
                self._send(ttl)
                time.sleep(random.uniform(0.05, 0.15))
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                h = self.result.hops.get(ttl)
                if h and h.status in (HopStatus.RESPONDING, HopStatus.TARGET):
                    break
                if self._target_hit.is_set():
                    break
                time.sleep(0.05)
            current = self.result.hops.get(ttl)
            if current and current.status == HopStatus.TIMEOUT:
                _print_hop_timeout(ttl)

        stop_ev.set()
        self.result.end_time = time.time()
        return self.result


# ═══════════════════════════════════════════════════════════════════════════
#   ICMP QUICK TRACE
# ═══════════════════════════════════════════════════════════════════════════

def icmp_trace(target_ip: str, iface: str, max_ttl: int = 30,
               timeout: float = 2.0, retries: int = 2,
               rdns: bool = True) -> TraceResult:
    result = TraceResult(
        target=target_ip, target_ip=target_ip,
        port=0, iface=iface, mode=TraceMode.ICMP,
        start_time=time.time()
    )
    section("Live Hop Table  (ICMP mode)")
    _print_hop_header()
    for ttl in range(1, max_ttl + 1):
        hop = HopInfo(ttl=ttl, ip="*", status=HopStatus.TIMEOUT)
        hop.pkts_sent = retries + 1
        responded = False
        for _ in range(retries + 1):
            try:
                pkt  = IP(dst=target_ip, ttl=ttl) / ICMP()
                t0   = time.time()
                resp = sr1(pkt, iface=iface, timeout=timeout, verbose=0)
                if resp is None:
                    continue
                rtt       = (time.time() - t0) * 1000
                result.probes_sent += 1
                result.probes_recv += 1
                responder = resp[IP].src
                hostname: Optional[str] = None
                if rdns:
                    try:
                        hostname = socket.gethostbyaddr(responder)[0]
                    except Exception:
                        pass
                hop.ip       = responder
                hop.hostname = hostname
                if resp.haslayer(ICMP) and resp[ICMP].type == 0:
                    hop.status = HopStatus.TARGET
                else:
                    hop.status = HopStatus.RESPONDING
                hop.add_rtt(rtt)
                responded = True
                break
            except Exception:
                pass
        if not responded:
            result.probes_sent += retries + 1
        result.hops[ttl] = hop
        if responded:
            _print_hop_live(hop)
        else:
            _print_hop_timeout(ttl)
        if hop.status == HopStatus.TARGET:
            break
    result.end_time = time.time()
    return result


# ═══════════════════════════════════════════════════════════════════════════
#   UDP TRACE
# ═══════════════════════════════════════════════════════════════════════════

def udp_trace(target_ip: str, iface: str, start_port: int = 33434,
              max_ttl: int = 30, timeout: float = 2.0,
              retries: int = 2, rdns: bool = True) -> TraceResult:
    result = TraceResult(
        target=target_ip, target_ip=target_ip,
        port=start_port, iface=iface, mode=TraceMode.UDP,
        start_time=time.time()
    )
    section("Live Hop Table  (UDP mode)")
    _print_hop_header()
    dport = start_port
    for ttl in range(1, max_ttl + 1):
        hop = HopInfo(ttl=ttl, ip="*", status=HopStatus.TIMEOUT)
        hop.pkts_sent = retries + 1
        responded = False
        for _ in range(retries + 1):
            try:
                pkt  = IP(dst=target_ip, ttl=ttl) / UDP(dport=dport)
                t0   = time.time()
                resp = sr1(pkt, iface=iface, timeout=timeout, verbose=0)
                dport += 1
                if resp is None:
                    continue
                rtt       = (time.time() - t0) * 1000
                result.probes_sent += 1
                result.probes_recv += 1
                responder = resp[IP].src
                hostname: Optional[str] = None
                if rdns:
                    try:
                        hostname = socket.gethostbyaddr(responder)[0]
                    except Exception:
                        pass
                hop.ip       = responder
                hop.hostname = hostname
                # ICMP port-unreachable = target reached
                if resp.haslayer(ICMP) and resp[ICMP].type == 3:
                    hop.status = HopStatus.TARGET
                else:
                    hop.status = HopStatus.RESPONDING
                hop.add_rtt(rtt)
                responded = True
                break
            except Exception:
                pass
        if not responded:
            result.probes_sent += retries + 1
        result.hops[ttl] = hop
        if responded:
            _print_hop_live(hop)
        else:
            _print_hop_timeout(ttl)
        if hop.status == HopStatus.TARGET:
            break
    result.end_time = time.time()
    return result


# ═══════════════════════════════════════════════════════════════════════════
#   LIVE HOP PRINTING HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _print_hop_header():
    print("  " + c("│", C.YELLOW) + "  " +
          c("St  TTL  IP Address         RTT avg    Jitter     Loss   Hostname", C.DIM))
    print("  " + c("│", C.YELLOW) + c("  " + "─" * 67, C.DIM))

def _print_hop_live(hop: HopInfo):
    rclr = rtt_color(hop.rtt_avg)
    lclr = loss_color(hop.loss)
    icon = "★" if hop.status == HopStatus.TARGET else "●"
    iclr = C.GREEN + C.BOLD if hop.status == HopStatus.TARGET else C.CYAN
    jit  = f"{hop.jitter:7.2f} ms" if hop.jitter else "    --- ms"
    hn   = c(f" {hop.hostname[:28]}", C.DIM) if hop.hostname else ""
    print("  " + c(icon, iclr) + "  " +
          c(f"{hop.ttl:<4}", C.WHITE) + " " +
          c(f"{hop.ip:<18}", C.CYAN) +
          c(f"{hop.rtt_avg:7.2f} ms", rclr) + "  " +
          c(jit, C.YELLOW) + "  " +
          c(f"{hop.loss:5.1f}%", lclr) + hn)

def _print_hop_timeout(ttl: int):
    print("  " + c("○", C.DIM) + "  " +
          c(f"{ttl:<4}", C.DIM) + " " +
          c("*                  ---        ---        ---   timeout", C.DIM))


# ═══════════════════════════════════════════════════════════════════════════
#   DISPLAY & SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

def display_hops(result: TraceResult):
    if not result.hops:
        warn("No hops recorded"); return
    section("Full Hop Detail Table")
    _print_hop_header()
    for ttl, hop in sorted(result.hops.items()):
        if hop.status == HopStatus.TIMEOUT:
            _print_hop_timeout(ttl)
        else:
            _print_hop_live(hop)
            if hop.hostname:
                hn_line = "         " + c(f"  ↳ {hop.hostname}", C.DIM)
                print("  " + c("│", C.YELLOW) + hn_line)
            if hop.org:
                org_line = "         " + c(f"  ↳ {hop.asn}  {hop.org}", C.DIM)
                print("  " + c("│", C.YELLOW) + org_line)
            if hop.country:
                geo_line = "         " + c(f"  ↳ {hop.city or ''}  {hop.country}", C.DIM)
                print("  " + c("│", C.YELLOW) + geo_line)


def display_summary(result: TraceResult):
    section("Trace Summary")
    row("Target",       f"{result.target} ({result.target_ip})")
    row("Mode",         result.mode.value.upper(), val_color=C.CYAN)
    row("Port",         str(result.port) if result.port else "ICMP")
    row("Interface",    result.iface)
    row("Started",      datetime.fromtimestamp(result.start_time)
                             .strftime("%Y-%m-%d %H:%M:%S"))
    row("Duration",     f"{result.duration:.2f} s")
    row("Total hops",   str(result.total_hops), val_color=C.CYAN)
    row("Avg RTT",
        f"{result.avg_rtt:.2f} ms" if result.avg_rtt else "—",
        val_color=rtt_color(result.avg_rtt))
    row("Probes sent",  str(result.probes_sent))
    row("Probes recv",  str(result.probes_recv),
        val_color=C.GREEN if result.probes_recv else C.DIM)
    sr = result.success_rate
    row("Success rate",
        f"{sr:.1f}%  {progress_bar(sr, 100, 16, C.GREEN if sr > 60 else C.YELLOW)}",
        val_color=C.GREEN if sr > 60 else C.YELLOW)
    if result.notes:
        row("Notes", result.notes, val_color=C.DIM)
    # Worst hops
    worst = [h for h in result.hops.values()
             if h.status == HopStatus.RESPONDING and h.rtt_avg > 0]
    if worst:
        worst_hop = max(worst, key=lambda h: h.rtt_avg)
        row("Worst hop",
            f"TTL {worst_hop.ttl}  {worst_hop.ip}  {worst_hop.rtt_avg:.2f} ms",
            val_color=rtt_color(worst_hop.rtt_avg))
    lossy = [h for h in result.hops.values() if h.loss > 0]
    if lossy:
        max_loss = max(lossy, key=lambda h: h.loss)
        row("Highest loss",
            f"TTL {max_loss.ttl}  {max_loss.ip}  {max_loss.loss:.1f}%",
            val_color=loss_color(max_loss.loss))


# ═══════════════════════════════════════════════════════════════════════════
#   EXPORT
# ═══════════════════════════════════════════════════════════════════════════

def atomic_write(path: str, text: str):
    d  = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass
        raise


def export_json(result: TraceResult, path: str):
    atomic_write(path, json.dumps(result.to_dict(), indent=2, ensure_ascii=False))


def export_csv(result: TraceResult, path: str):
    buf = io.StringIO()
    w   = csv.writer(buf)
    w.writerow(["TTL","IP","Hostname","ASN","Org","Country","City",
                "RTTmin_ms","RTTavg_ms","RTTmax_ms","Jitter_ms",
                "Loss_pct","PktsSent","PktsRecv","Status"])
    for ttl, h in sorted(result.hops.items()):
        w.writerow([
            ttl, h.ip, h.hostname or "", h.asn or "", h.org or "",
            h.country or "", h.city or "",
            round(h.rtt_min, 3) if h.rtt_min != float("inf") else "",
            round(h.rtt_avg, 3), round(h.rtt_max, 3),
            round(h.jitter, 3), round(h.loss, 2),
            h.pkts_sent, h.pkts_recv, h.status.value
        ])
    atomic_write(path, buf.getvalue())


def export_txt(result: TraceResult, path: str):
    d = result.to_dict()
    lines = [
        f"{'=' * 60}",
        f"  {TOOL_NAME} {VERSION}  —  Trace Report",
        f"{'=' * 60}",
        f"Target     : {d['target']} ({d['target_ip']})",
        f"Mode       : {d['mode'].upper()}",
        f"Port       : {d['port'] or 'ICMP'}",
        f"Interface  : {d['interface']}",
        f"Generated  : {d['generated']}",
        f"Duration   : {d['duration_s']} s",
        f"Hops       : {d['total_hops']}",
        f"Probes     : {d['probes_sent']} sent / {d['probes_recv']} recv",
        f"Success    : {d['success_pct']}%",
        "",
        f"{'TTL':<4} {'IP':<18} {'RTTavg':>9} {'Jitter':>9} {'Loss':>7} {'Status':<12} Hostname",
        "─" * 80,
    ]
    for h in d["hops"]:
        rtt  = f"{h['rtt_avg_ms']:.2f} ms" if h['rtt_avg_ms'] else "   ---"
        jit  = f"{h['jitter_ms']:.2f} ms"  if h['jitter_ms']  else "   ---"
        loss = f"{h['loss_pct']:.1f}%"
        hn   = h["hostname"] or ""
        asn  = f"[{h['asn']} {h['org']}]" if h.get("asn") else ""
        lines.append(
            f"{h['ttl']:<4} {h['ip']:<18} {rtt:>9} {jit:>9} {loss:>7}"
            f" {h['status']:<12} {hn} {asn}"
        )
    lines += ["", "─" * 80,
              f"  Generated by {TOOL_NAME} {VERSION} — {WEBSITE}"]
    atomic_write(path, "\n".join(lines))


def export_html(result: TraceResult, path: str):
    d    = result.to_dict()
    rows = ""
    for h in d["hops"]:
        rtt  = f"{h['rtt_avg_ms']:.2f}" if h['rtt_avg_ms'] else "*"
        jit  = f"{h['jitter_ms']:.2f}"  if h['jitter_ms']  else "—"
        loss = f"{h['loss_pct']:.1f}"
        hn   = h["hostname"] or "—"
        org  = f"{h.get('asn','')} {h.get('org','')}".strip() or "—"
        geo  = " ".join(filter(None, [h.get("city"), h.get("country")])) or "—"
        st   = h["status"]
        row_cls = "target" if st == "target" else ("timeout" if st == "timeout" else "")
        rows += (
            f"<tr class='{row_cls}'>"
            f"<td>{h['ttl']}</td>"
            f"<td>{h['ip']}</td>"
            f"<td>{hn}</td>"
            f"<td>{rtt}</td>"
            f"<td>{jit}</td>"
            f"<td>{loss}%</td>"
            f"<td>{h['pkts_sent']}/{h['pkts_recv']}</td>"
            f"<td>{org}</td>"
            f"<td>{geo}</td>"
            f"<td><span class='badge {st}'>{st}</span></td>"
            f"</tr>\n"
        )
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{TOOL_NAME} {VERSION} — Trace Report</title>
<style>
:root {{
  --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
  --cyan: #58a6ff; --green: #3fb950; --yellow: #d29922;
  --orange: #e3642a; --red: #f85149; --dim: #8b949e;
  --white: #f0f6fc; --border: #30363d;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--white); font-family: 'Segoe UI', monospace; }}
header {{ background: var(--bg2); border-bottom: 1px solid var(--border);
          padding: 2rem; display: flex; align-items: center; gap: 2rem; }}
header h1 {{ font-size: 1.8rem; color: var(--cyan); }}
header p  {{ color: var(--dim); font-size: .9rem; }}
.meta {{ display: flex; flex-wrap: wrap; gap: .5rem 2rem; padding: 1.5rem 2rem;
         background: var(--bg2); border-bottom: 1px solid var(--border); }}
.meta-item {{ display: flex; flex-direction: column; }}
.meta-item .label {{ font-size: .7rem; color: var(--dim); text-transform: uppercase; }}
.meta-item .value {{ font-size: 1rem; color: var(--cyan); font-weight: 600; }}
.container {{ padding: 2rem; }}
table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
th {{ background: var(--bg3); color: var(--dim); padding: .5rem .75rem;
      text-align: left; border-bottom: 2px solid var(--border);
      font-size: .75rem; text-transform: uppercase; letter-spacing: .05em; }}
td {{ padding: .45rem .75rem; border-bottom: 1px solid var(--border); }}
tr:hover {{ background: var(--bg3); }}
tr.target td:first-child {{ border-left: 3px solid var(--green); }}
tr.timeout {{ opacity: .4; }}
.badge {{ font-size: .7rem; padding: .15rem .5rem; border-radius: 9999px; font-weight: 600; }}
.badge.responding {{ background: #1c3a2a; color: var(--green); }}
.badge.target     {{ background: #1c3a2a; color: #7ee787; }}
.badge.timeout    {{ background: #2a1a1a; color: var(--dim); }}
.badge.unknown    {{ background: var(--bg3); color: var(--dim); }}
footer {{ text-align: center; padding: 2rem; color: var(--dim); font-size: .8rem;
          border-top: 1px solid var(--border); }}
</style>
</head>
<body>
<header>
  <div>
    <h1>🦉 {TOOL_NAME} {VERSION}</h1>
    <p>{WEBSITE} — Advanced TCP Path Tracer</p>
  </div>
</header>
<div class="meta">
  <div class="meta-item"><span class="label">Target</span>
    <span class="value">{d['target']} ({d['target_ip']})</span></div>
  <div class="meta-item"><span class="label">Mode</span>
    <span class="value">{d['mode'].upper()}</span></div>
  <div class="meta-item"><span class="label">Port</span>
    <span class="value">{d['port'] or 'ICMP'}</span></div>
  <div class="meta-item"><span class="label">Interface</span>
    <span class="value">{d['interface']}</span></div>
  <div class="meta-item"><span class="label">Hops</span>
    <span class="value">{d['total_hops']}</span></div>
  <div class="meta-item"><span class="label">Duration</span>
    <span class="value">{d['duration_s']} s</span></div>
  <div class="meta-item"><span class="label">Success</span>
    <span class="value">{d['success_pct']}%</span></div>
  <div class="meta-item"><span class="label">Generated</span>
    <span class="value">{d['generated']}</span></div>
</div>
<div class="container">
<table>
<thead>
  <tr>
    <th>TTL</th><th>IP Address</th><th>Hostname</th>
    <th>RTT avg (ms)</th><th>Jitter (ms)</th><th>Loss</th>
    <th>Pkts S/R</th><th>ASN / Org</th><th>GeoIP</th><th>Status</th>
  </tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</div>
<footer>Generated by {TOOL_NAME} {VERSION} — {WEBSITE} — {d['generated']}</footer>
</body>
</html>"""
    atomic_write(path, html)


def export_xml(result: TraceResult, path: str):
    d = result.to_dict()
    def esc(v: Any) -> str:
        return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<trace tool="{esc(TOOL_NAME)}" version="{esc(VERSION)}" '
        f'website="{esc(WEBSITE)}">',
        f'  <meta>',
        f'    <target>{esc(d["target"])}</target>',
        f'    <target_ip>{esc(d["target_ip"])}</target_ip>',
        f'    <mode>{esc(d["mode"])}</mode>',
        f'    <port>{esc(d["port"])}</port>',
        f'    <interface>{esc(d["interface"])}</interface>',
        f'    <generated>{esc(d["generated"])}</generated>',
        f'    <duration_s>{esc(d["duration_s"])}</duration_s>',
        f'    <total_hops>{esc(d["total_hops"])}</total_hops>',
        f'    <probes_sent>{esc(d["probes_sent"])}</probes_sent>',
        f'    <probes_recv>{esc(d["probes_recv"])}</probes_recv>',
        f'    <success_pct>{esc(d["success_pct"])}</success_pct>',
        f'  </meta>',
        f'  <hops>',
    ]
    for h in d["hops"]:
        lines.append(f'    <hop ttl="{h["ttl"]}" status="{esc(h["status"])}">')
        for field_name, field_val in h.items():
            if field_name in ("ttl", "status"):
                continue
            v = "" if field_val is None else esc(field_val)
            lines.append(f'      <{field_name}>{v}</{field_name}>')
        lines.append('    </hop>')
    lines += ['  </hops>', '</trace>']
    atomic_write(path, "\n".join(lines))


def export_result(result: TraceResult, path: str):
    if   path.endswith(".json"): export_json(result, path)
    elif path.endswith(".csv"):  export_csv(result, path)
    elif path.endswith(".html"): export_html(result, path)
    elif path.endswith(".xml"):  export_xml(result, path)
    else:                        export_txt(result, path)


# ═══════════════════════════════════════════════════════════════════════════
#   AS / ORG LOOKUP  (via whois)
# ═══════════════════════════════════════════════════════════════════════════

def _asn_lookup(ip: str) -> Tuple[Optional[str], Optional[str]]:
    """Best-effort ASN lookup via Team Cymru whois."""
    try:
        import socket as _s
        with _s.socket(_s.AF_INET, _s.SOCK_STREAM) as sock:
            sock.settimeout(4)
            sock.connect(("whois.cymru.com", 43))
            sock.sendall(f" -f {ip}\n".encode())
            data = b""
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                data += chunk
        parts = data.decode(errors="ignore").strip().split("|")
        if len(parts) >= 3:
            asn  = parts[0].strip()
            org  = parts[2].strip()
            return (f"AS{asn}" if asn.isdigit() else asn) or None, org or None
    except Exception:
        pass
    return None, None


def module_as_lookup():
    print_header("AS / Organisation Lookup", "Resolve ASN info for each hop")
    result = _state.get("result")
    if not result:
        warn("No trace results — run a trace first"); return
    section("Querying Team Cymru Whois")
    for ttl, hop in sorted(result.hops.items()):
        if hop.ip in ("*", "") or hop.status == HopStatus.TIMEOUT:
            continue
        stop_ev = threading.Event()
        sp = threading.Thread(target=_spinner,
                              args=(f"TTL {ttl}  {hop.ip}", stop_ev), daemon=True)
        sp.start()
        asn, org = _asn_lookup(hop.ip)
        stop_ev.set(); sp.join()
        hop.asn = asn
        hop.org = org
        tag = f"{asn}  {org}" if asn else "—"
        print("  " + c(f"TTL {ttl:<3}", C.WHITE) + "  " +
              c(f"{hop.ip:<18}", C.CYAN) + c(tag, C.YELLOW))
    ok("AS lookup complete — data stored in last trace result")


# ═══════════════════════════════════════════════════════════════════════════
#   PING SWEEP
# ═══════════════════════════════════════════════════════════════════════════

def module_ping_sweep():
    print_header("Ping Sweep", "ICMP reachability of a network range")
    if not SCAPY_OK:  err("Scapy required"); return
    if os.geteuid() != 0: err("Root required"); return

    cidr = ask("CIDR range (e.g. 192.168.1.0/24)", "").strip()
    if not cidr:
        err("No range specified"); return
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        err(f"Invalid CIDR: {exc}"); return

    hosts   = list(net.hosts())
    timeout = ask_float("Timeout per host (s)", 0.5)
    section(f"Sweeping {len(hosts)} hosts in {cidr}")
    alive, dead = [], []
    for idx, ip in enumerate(hosts):
        ip_s = str(ip)
        pkt  = IP(dst=ip_s) / ICMP()
        try:
            resp = sr1(pkt, timeout=timeout, verbose=0)
        except Exception:
            resp = None
        if resp and resp.haslayer(ICMP) and resp[ICMP].type == 0:
            rtt = 0.0
            alive.append(ip_s)
            print("  " + c("[UP]", C.GREEN) + "  " + c(ip_s, C.CYAN))
        else:
            dead.append(ip_s)
            print("  " + c("[--]", C.DIM)   + "  " + c(ip_s, C.DIM), end="\r")
    print(" " * 60, end="\r")
    print()
    ok(f"Up: {len(alive)}   Down: {len(dead)}   Total: {len(hosts)}")
    if alive:
        section("Live Hosts")
        for ip_s in alive:
            print("  " + c("●", C.GREEN) + "  " + c(ip_s, C.CYAN))


# ═══════════════════════════════════════════════════════════════════════════
#   INTERFACE HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _list_interfaces() -> List[str]:
    net = "/sys/class/net"
    return sorted(os.listdir(net)) if os.path.isdir(net) else []

def _iface_info(iface: str) -> Tuple[str, str, str]:
    state = mac = ip4 = ""
    try:
        with open(f"/sys/class/net/{iface}/operstate") as f:
            state = f.read().strip()
    except Exception:
        pass
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            mac = f.read().strip().upper()
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface],
            stderr=subprocess.DEVNULL, timeout=2
        ).decode()
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out)
        if m:
            ip4 = m.group(1)
    except Exception:
        pass
    return state, mac, ip4

def _ask_iface() -> str:
    ifaces = [i for i in _list_interfaces() if i != "lo"]
    if not ifaces:
        return "eth0"
    section("Select Network Interface")
    for i, iface in enumerate(ifaces):
        state, mac, ip4 = _iface_info(iface)
        sclr = C.GREEN if state == "up" else C.DIM
        print("  " + c("│", C.YELLOW) + "  " +
              c(f"[{i}]", C.CYAN) + "  " +
              c(iface.ljust(12), C.WHITE) +
              c(state.ljust(8), sclr) +
              c(ip4.ljust(20), C.CYAN) +
              c(mac, C.DIM))
    ch = ask("Interface # or name", ifaces[0])
    if ch.isdigit() and int(ch) < len(ifaces):
        return ifaces[int(ch)]
    return ch if ch in ifaces else ifaces[0]

def _resolve(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None

def _ask_save_path(result: TraceResult) -> Tuple[str, str]:
    """
    Ask the user WHERE and in WHAT FORMAT to save.
    Returns (path, ext).
    """
    section("Output Destination")
    print()
    print("  " + c("Format options:", C.CYAN, C.BOLD))
    fmts = [
        ("1", "json", "Full structured data"),
        ("2", "csv",  "Spreadsheet-compatible"),
        ("3", "txt",  "Plain-text report"),
        ("4", "html", "Styled web report"),
        ("5", "xml",  "Enterprise / SIEM format"),
    ]
    for num, ext, desc in fmts:
        print("  " + c(f"[{num}]", C.CYAN) + "  " +
              c(f".{ext:<6}", C.WHITE) + c(f"─ {desc}", C.DIM))
    print()
    choice = ask_choice("Format", ["1","2","3","4","5","json","csv","txt","html","xml"], "1")
    ext_map = {"1":"json","2":"csv","3":"txt","4":"html","5":"xml"}
    ext = ext_map.get(choice, choice if choice in ("json","csv","txt","html","xml") else "json")

    section("Save Location")
    print()
    print("  " + c("Location options:", C.CYAN, C.BOLD))
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    tgt = re.sub(r"[^\w\-.]", "_", result.target)
    default_name = f"otracex_{tgt}_{ts}.{ext}"

    locs = [
        ("1", "current directory",    os.path.join(os.getcwd(), default_name)),
        ("2", "home directory",       os.path.join(Path.home(), default_name)),
        ("3", "/tmp",                 os.path.join("/tmp", default_name)),
        ("4", "custom path",          ""),
    ]
    for num, label, preview in locs:
        pv = c(f"  → {preview}", C.DIM) if preview else ""
        print("  " + c(f"[{num}]", C.CYAN) + "  " +
              c(label.ljust(22), C.WHITE) + pv)
    print()
    loc_ch = ask_choice("Location", ["1","2","3","4"], "1")
    if loc_ch == "1":
        path = os.path.join(os.getcwd(), default_name)
    elif loc_ch == "2":
        path = os.path.join(str(Path.home()), default_name)
    elif loc_ch == "3":
        path = os.path.join("/tmp", default_name)
    else:
        path = ask("Full file path", default_name)
        # Auto-append extension if missing
        if not path.endswith(f".{ext}"):
            path = path.rstrip("/") + ("" if path.endswith(".") else ".") + ext

    return path, ext


# ═══════════════════════════════════════════════════════════════════════════
#   MODULES
# ═══════════════════════════════════════════════════════════════════════════

def _common_trace_config(mode_label: str) -> Tuple[str, str, str, int, float, int, bool]:
    """Shared configuration prompts. Returns (target, target_ip, iface, max_ttl, timeout, retries, rdns)."""
    section("Configuration")
    target = ask("Target hostname or IP", "").strip()
    if not target:
        err("No target specified"); return None
    target_ip = _resolve(target)
    if not target_ip:
        err(f"Cannot resolve: {target}"); return None
    nfo(f"Resolved → {target_ip}")
    iface   = _ask_iface()
    max_ttl = ask_int("Max hops", 30, 1, 64)
    timeout = ask_float("Probe timeout (s)", 3.0 if mode_label == "TCP" else 2.0)
    retries = ask_int("Retries per hop", 2, 0, 10)
    rdns_s  = ask_choice("Reverse DNS lookup", ["y","n"], "y")
    rdns    = (rdns_s == "y")
    return target, target_ip, iface, max_ttl, timeout, retries, rdns


def module_start_trace():
    print_header("TCP Session Trace", "Bypass firewalls via established session injection")
    if not SCAPY_OK:  err("Scapy required — pip install scapy"); return
    if os.geteuid() != 0: err("Root required for raw sockets"); return

    cfg = _common_trace_config("TCP")
    if cfg is None: return
    target, target_ip, iface, max_ttl, timeout, retries, rdns = cfg

    port = ask_int("Target port", 80, 1, 65535)

    section("Waiting for TCP Session")
    warn(f"Open a connection now:  nc {target} {port}  OR  curl {target}")
    nfo("Session detection timeout: 60 s")
    print()

    sniffer = SessionSniffer(target_ip, port, iface, verbose=False)
    sniffer.start()
    stop_ev = threading.Event()
    sp = threading.Thread(target=_spinner,
                          args=("Sniffing for TCP handshake…", stop_ev), daemon=True)
    sp.start()
    sess = sniffer.wait_established(timeout=60.0)
    stop_ev.set(); sp.join()

    if not sess:
        err("No established session detected in 60 s")
        sniffer.stop(); return

    ok(f"Session {sess.session_id}  "
       f"{sess.src_ip}:{sess.src_port} → {sess.dst_ip}:{sess.dst_port}")

    result = TraceResult(
        target=target, target_ip=target_ip,
        port=port, iface=iface, mode=TraceMode.TCP,
        start_time=time.time(), retries=retries, max_ttl=max_ttl
    )
    engine = ProbeEngine(sess, result, iface,
                         timeout=timeout, retries=retries, verbose=False, rdns=rdns)
    result = engine.run(max_ttl=max_ttl)
    sniffer.stop()
    display_hops(result)
    display_summary(result)
    _state["result"] = result


def module_quick_trace():
    print_header("Quick Trace — ICMP Mode", "No active session required")
    if not SCAPY_OK:  err("Scapy required"); return
    if os.geteuid() != 0: err("Root required"); return

    cfg = _common_trace_config("ICMP")
    if cfg is None: return
    target, target_ip, iface, max_ttl, timeout, retries, rdns = cfg

    result = icmp_trace(target_ip, iface,
                        max_ttl=max_ttl, timeout=timeout,
                        retries=retries, rdns=rdns)
    result.target = target
    display_hops(result)
    display_summary(result)
    _state["result"] = result


def module_udp_trace():
    print_header("UDP Trace Mode", "Probe via UDP datagrams — useful when ICMP is filtered")
    if not SCAPY_OK:  err("Scapy required"); return
    if os.geteuid() != 0: err("Root required"); return

    cfg = _common_trace_config("UDP")
    if cfg is None: return
    target, target_ip, iface, max_ttl, timeout, retries, rdns = cfg

    start_port = ask_int("Starting UDP destination port", 33434, 1024, 65000)
    result = udp_trace(target_ip, iface,
                       start_port=start_port, max_ttl=max_ttl,
                       timeout=timeout, retries=retries, rdns=rdns)
    result.target = target
    display_hops(result)
    display_summary(result)
    _state["result"] = result


def module_iface_list():
    print_header("Network Interfaces", "Local interface enumeration")
    ifaces = _list_interfaces()
    if not ifaces:
        warn("Cannot read /sys/class/net"); return
    section("Available Interfaces")
    print("  " + c("│", C.YELLOW) + "  " +
          c("Interface   State   IPv4                 MAC", C.DIM))
    print("  " + c("│", C.YELLOW) + c("  " + "─" * 55, C.DIM))
    for iface in ifaces:
        state, mac, ip4 = _iface_info(iface)
        sclr = C.GREEN if state == "up" else C.DIM
        print("  " + c("│", C.YELLOW) + "  " +
              c(iface.ljust(12), C.WHITE) +
              c(state.ljust(8), sclr) +
              c(ip4.ljust(22), C.CYAN) +
              c(mac, C.DIM))


def module_view_last():
    print_header("Last Trace Results", "Full hop table and summary")
    result = _state.get("result")
    if not result:
        warn("No trace results — run a trace first"); return
    display_hops(result)
    display_summary(result)


def module_export():
    print_header("Export Results", "Save trace to file")
    result = _state.get("result")
    if not result:
        warn("No trace results — run a trace first"); return

    try:
        path, ext = _ask_save_path(result)
    except (KeyboardInterrupt, EOFError):
        warn("Export cancelled"); return

    try:
        export_result(result, path)
        ok(f"Saved → {path}  ({os.path.getsize(path):,} bytes)")
    except Exception as exc:
        err(f"Export failed: {exc}")


# ═══════════════════════════════════════════════════════════════════════════
#   SESSION STATE
# ═══════════════════════════════════════════════════════════════════════════

_state: Dict[str, Any] = {"result": None}


# ═══════════════════════════════════════════════════════════════════════════
#   MAIN MENU
# ═══════════════════════════════════════════════════════════════════════════

def main_menu():
    while True:
        clear()
        banner()

        # Status bar
        r = _state.get("result")
        if r:
            sr_clr = C.GREEN if r.success_rate > 60 else C.YELLOW
            print("  " + c("Last trace : ", C.DIM, C.WHITE) +
                  c(r.target, C.CYAN) +
                  c("  │  Mode : ", C.DIM) +
                  c(r.mode.value.upper(), C.YELLOW) +
                  c("  │  Hops : ", C.DIM) +
                  c(str(r.total_hops), C.GREEN) +
                  c("  │  Success : ", C.DIM) +
                  c(f"{r.success_rate:.0f}%", sr_clr))
        else:
            print("  " + c("No trace session active", C.DIM))
        print()

        items = [
            ("1", "Start Trace    ",
             "TCP session-based — firewall/NAT bypass",    C.GREEN),
            ("2", "Quick Trace    ",
             "ICMP fallback    — no session needed",        C.GREEN),
            ("3", "UDP Trace      ",
             "UDP probe mode   — bypasses ICMP filters",    C.GREEN),
            ("4", "Interface List ",
             "Show local interfaces + IPv4 / state",        C.CYAN),
            ("5", "View Last Hops ",
             "Full hop table from last trace",              C.CYAN),
            ("6", "Export Results ",
             "Save to JSON / CSV / TXT / HTML / XML",       C.YELLOW),
            ("7", "Ping Sweep     ",
             "ICMP reachability sweep of a CIDR range",     C.YELLOW),
            ("8", "AS Lookup      ",
             "Resolve ASN / Org for all hops",              C.MAGENTA),
        ]
        for num, name, desc, clr in items:
            print("  " + c(f"[{num}]", clr) + "  " +
                  c(name, C.WHITE) + " " +
                  c("─ " + desc, C.DIM))
        print()
        print(c("  [H]", C.YELLOW) + c("  Help           ", C.WHITE) +
              c("─ Reference manual, metrics, tips", C.DIM))
        print(c("  [0]", C.RED)    + c("  Exit", C.WHITE))
        print()
        print(c("─" * max(term_width(), 64), C.CYAN))

        try:
            choice = input(c("\n  [»] Select option: ", C.YELLOW)).strip().upper()
        except (EOFError, KeyboardInterrupt):
            choice = "0"

        dispatch = {
            "0": None,
            "H": lambda: (clear(), banner(), show_help(), pause()),
            "1": lambda: (module_start_trace(),  pause()),
            "2": lambda: (module_quick_trace(),  pause()),
            "3": lambda: (module_udp_trace(),    pause()),
            "4": lambda: (module_iface_list(),   pause()),
            "5": lambda: (module_view_last(),    pause()),
            "6": lambda: (module_export(),       pause()),
            "7": lambda: (module_ping_sweep(),   pause()),
            "8": lambda: (module_as_lookup(),    pause()),
        }

        if choice == "0":
            print(c(f"\n  [✔] Goodbye!  —  {WEBSITE}  🦉\n", C.GREEN))
            sys.exit(0)

        action = dispatch.get(choice)
        if action:
            action()
        else:
            err("Invalid option — press H for help")
            time.sleep(1.2)


# ─── ENTRY POINT ───────────────────────────────────────────────────────────

def run_self_test() -> int:
    """Offline path-trace data-model self-test. No raw sockets / no probes."""
    import tempfile, shutil as _sh
    sandbox = Path(tempfile.mkdtemp(prefix="otracex_selftest_", dir="/tmp"))
    passed = failed = 0
    def check(name, cond):
        nonlocal passed, failed
        mark = c("[ OK ]", C.GREEN) if cond else c("[FAIL]", C.RED)
        print(f"  {mark} {name}")
        if cond: passed += 1
        else:    failed += 1
    print(c("  OTraceX Self-Test  (offline / sandboxed)", C.CYAN + C.BOLD))
    try:
        h = HopInfo(ttl=1, ip="10.0.0.1", status=HopStatus.RESPONDING)
        h.pkts_sent = 3
        h.add_rtt(12.5); h.add_rtt(13.0); h.add_rtt(11.8)
        check("HopInfo RTT avg set", abs(h.rtt_avg - (12.5+13.0+11.8)/3) < 0.01)
        check("HopInfo jitter computed", h.jitter >= 0)
        check("HopInfo loss 0% when all recv", h.loss == 0.0)
        d = h.to_dict()
        check("HopInfo.to_dict serializable", d["ip"] == "10.0.0.1" and d["status"] == "responding")

        result = TraceResult(target="example.test", target_ip="93.184.216.34",
                             port=443, mode=TraceMode.TCP, iface="lo",
                             start_time=time.time() - 1.5)
        result.end_time = time.time()
        result.hops[1] = h
        result.hops[2] = HopInfo(ttl=2, ip="93.184.216.34", status=HopStatus.TARGET)
        result.hops[2].pkts_sent = 1; result.hops[2].add_rtt(40.0)
        result.probes_sent = 4; result.probes_recv = 4
        out = sandbox / "trace.json"
        payload = result.to_dict() if hasattr(result, "to_dict") else {
            "target": result.target, "hops": [hh.to_dict() for _, hh in sorted(result.hops.items())]
        }
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        check("trace JSON written under /tmp", out.is_file() and out.stat().st_size > 20)
        check("two hops in export", len(payload.get("hops", [])) == 2)
        check("TraceMode enum TCP", TraceMode.TCP.value == "tcp")
        check("SCAPY optional flag is bool", isinstance(SCAPY_OK, bool))
    except Exception as e:
        print(c(f"  [FAIL] crashed: {e}", C.RED))
        failed += 1
    finally:
        try: _sh.rmtree(sandbox, ignore_errors=True)
        except Exception: pass
    if failed == 0:
        print(c(f"  [✔] ALL {passed} CHECKS PASSED — trace model healthy.", C.GREEN))
        return 0
    print(c(f"  [✘] {failed} FAILED, {passed} passed.", C.RED))
    return 1


def _handle_exit(sig, frame):
    print(c(f"\n\n  [✔] Interrupted — {WEBSITE} 🦉\n", C.YELLOW))
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT,  _handle_exit)
    signal.signal(signal.SIGTERM, _handle_exit)
    try:
        if len(sys.argv) > 1 and sys.argv[1] in ("--self-test", "-T"):
            banner(); sys.exit(run_self_test())
        if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
            banner(); show_help(); sys.exit(0)
        main_menu()
    except KeyboardInterrupt:
        _handle_exit(None, None)
    except Exception as exc:
        print(c(f"\n  [✘] Fatal error: {exc}", C.RED))
        import traceback
        traceback.print_exc()
        sys.exit(1)
