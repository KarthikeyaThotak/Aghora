"""
Aghora Malware Analysis Report Generator
Produces a professional PDF report from complete_analysis.json data.
The LLM writes the core narrative — all other sections are data-driven
and only rendered when they contain actual evidence.
"""

import os
import io
import re
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)
from reportlab.platypus.flowables import Flowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas as rl_canvas


# ── Brand palette ─────────────────────────────────────────────────────────────
C_BG_DARK  = colors.HexColor("#0f1117")
C_BG_CARD  = colors.HexColor("#1a1d27")
C_ACCENT   = colors.HexColor("#dc2626")
C_ACCENT2  = colors.HexColor("#3b82f6")
C_GOLD     = colors.HexColor("#f59e0b")
C_GREEN    = colors.HexColor("#10b981")
C_VIOLET   = colors.HexColor("#8b5cf6")
C_CYAN     = colors.HexColor("#06b6d4")
C_WHITE    = colors.HexColor("#f8fafc")
C_MUTED    = colors.HexColor("#94a3b8")
C_BORDER   = colors.HexColor("#2d3148")
C_ROW_ALT  = colors.HexColor("#f1f5f9")

RISK_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high":     colors.HexColor("#f97316"),
    "medium":   colors.HexColor("#eab308"),
    "low":      colors.HexColor("#22c55e"),
    "unknown":  colors.HexColor("#94a3b8"),
}
RISK_BG = {
    "critical": colors.HexColor("#fef2f2"),
    "high":     colors.HexColor("#fff7ed"),
    "medium":   colors.HexColor("#fefce8"),
    "low":      colors.HexColor("#f0fdf4"),
    "unknown":  colors.HexColor("#f8fafc"),
}

PAGE_W, PAGE_H = letter
MARGIN = 0.65 * inch


# ── LLM narrative generation ──────────────────────────────────────────────────
def _call_llm(prompt: str) -> str:
    """Call the configured LLM (Ollama or OpenAI) and return the text response."""
    try:
        from openai import OpenAI
        from dotenv import load_dotenv
        load_dotenv()
        provider = os.getenv("LLM_PROVIDER", "ollama").lower()
        model    = os.getenv("LLM_MODEL", "gemma4:e4b")
        if provider == "ollama":
            client = OpenAI(
                base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
                api_key="ollama",
            )
        else:
            client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system",
                 "content": (
                    "You are a senior malware analyst writing a professional "
                    "technical threat intelligence report. Write clearly, "
                    "concisely, and with confidence. Use plain prose — no "
                    "markdown, no bullet points, no headers. Respond with "
                    "analysis text only."
                 )},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=1800,
            timeout=300,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return f"[LLM narrative unavailable: {e}]"


def _build_evidence_prompt(analysis: Dict) -> str:
    """Compile collected evidence into a prompt that asks the LLM to write
    a full analyst narrative explaining why this file is malicious."""
    fi     = analysis.get("tool_results", {}).get("tools", {})
    finfo  = fi.get("fileinfo", {}).get("data", {}) or {}
    ai     = analysis.get("ai_analysis", {}) or {}
    pe     = fi.get("pestudio", {}).get("data", {}) or {}
    sp     = (fi.get("strings", {}).get("data", {}) or {}).get("suspicious_patterns", {}) or {}
    die    = fi.get("die", {}).get("data", {}) or {}
    ghidra = fi.get("ghidra", {}).get("data", {}) or {}

    lines = []
    lines.append("=== EVIDENCE COLLECTED BY AGHORA ===\n")

    # File identity
    lines.append(f"File: {finfo.get('file_name','?')}  "
                 f"Size: {finfo.get('size','?')} bytes  "
                 f"Type: {finfo.get('file_type','?')}")
    lines.append(f"SHA-256: {finfo.get('sha256','?')}")
    if die.get("detections"):
        lines.append(f"Detect-it-Easy detections: {die['detections']}")
    lines.append("")

    # AI preliminary verdict
    lines.append(f"Preliminary AI verdict: {ai.get('threat_level','?').upper()} — "
                 f"Family: {ai.get('malware_family','?')}")
    if ai.get("threat_summary"):
        lines.append(f"Summary: {ai['threat_summary']}")
    lines.append("")

    # PE structure
    if pe:
        sections = pe.get("sections", [])
        if sections:
            high_ent = [s for s in sections
                        if isinstance(s.get("entropy"), (int,float)) and s["entropy"] > 6.5]
            lines.append(f"PE sections: {len(sections)} total, "
                         f"{len(high_ent)} with high entropy (>6.5 — packed/encrypted).")
            for s in high_ent[:3]:
                lines.append(f"  Section {s.get('name','?')}: entropy {s.get('entropy',0):.2f}")
        if pe.get("compile_time"):
            lines.append(f"Compile timestamp: {pe['compile_time']}")
        imports = pe.get("imports", [])
        lines.append(f"Import count: {len(imports)}")
        lines.append("")

    # Suspicious APIs
    API_SIGS = {
        "Process Injection": {"VirtualAllocEx","WriteProcessMemory","CreateRemoteThread",
                              "NtCreateThreadEx","RtlCreateUserThread","SetWindowsHookEx",
                              "QueueUserAPC","NtMapViewOfSection","VirtualAlloc"},
        "Process Control":   {"OpenProcess","TerminateProcess","CreateProcess",
                              "ShellExecute","WinExec","CreateProcessAsUser"},
        "Network Access":    {"WSAStartup","connect","send","recv","HttpOpenRequest",
                              "InternetOpenUrl","URLDownloadToFile","socket",
                              "WSAConnect","InternetConnect","WinHttpOpen","gethostbyname"},
        "Surveillance":      {"GetAsyncKeyState","GetKeyState","GetForegroundWindow",
                              "GetWindowText","BitBlt","PrintWindow","ReadProcessMemory",
                              "GetClipboardData","EnumWindows"},
        "Anti-Analysis":     {"IsDebuggerPresent","CheckRemoteDebuggerPresent",
                              "NtQueryInformationProcess","GetTickCount","Sleep",
                              "VirtualProtect","NtSetInformationThread"},
        "Cryptography":      {"CryptEncrypt","CryptDecrypt","CryptGenKey","CryptHashData",
                              "BCryptEncrypt","BCryptDecrypt","BCryptGenRandom"},
        "Persistence APIs":  {"RegSetValueEx","RegCreateKeyEx","CreateService",
                              "ChangeServiceConfig","NtSetValueKey"},
    }
    all_apis: set = set()
    for imp in pe.get("imports", []):
        all_apis.add(imp.get("name","") if isinstance(imp,dict) else str(imp))
    for api in sp.get("suspicious_apis", []):
        all_apis.add(str(api))

    matched_cats = []
    for cat, sigs in API_SIGS.items():
        hits = sorted(all_apis & sigs)
        if hits:
            matched_cats.append(f"{cat}: {', '.join(hits[:5])}")
    if matched_cats:
        lines.append("Suspicious Win32 API categories detected:")
        for c in matched_cats:
            lines.append(f"  - {c}")
        lines.append("")

    # Network IOCs
    ips     = sp.get("ips", [])
    domains = sp.get("domains", [])
    urls    = sp.get("urls", [])
    if ips or domains or urls:
        lines.append("Network indicators found in binary strings:")
        if ips:      lines.append(f"  IPs: {', '.join(ips[:8])}")
        if domains:  lines.append(f"  Domains: {', '.join(domains[:8])}")
        if urls:     lines.append(f"  URLs: {', '.join(u[:80] for u in urls[:5])}")
        lines.append("")

    # Registry / persistence
    reg_keys   = sp.get("registry_keys", [])
    file_paths = sp.get("file_paths", [])
    if reg_keys or file_paths:
        lines.append("Persistence indicators:")
        for k in reg_keys[:5]:   lines.append(f"  Registry: {k}")
        for p in file_paths[:5]: lines.append(f"  Path: {p}")
        lines.append("")

    # Ghidra RE
    if ghidra.get("functions"):
        lines.append(f"Ghidra reverse engineering: {ghidra.get('function_count','?')} functions analysed.")
        interesting = ghidra.get("interesting", [])
        if interesting:
            lines.append(f"  Interesting patterns: {'; '.join(str(x) for x in interesting[:5])}")
        crypto = ghidra.get("crypto_constants", [])
        if crypto:
            lines.append(f"  Crypto constants detected: {', '.join(str(x) for x in crypto[:5])}")
        decomp = ghidra.get("decompiled", {})
        if decomp:
            first_fn, first_code = next(iter(decomp.items()))
            lines.append(f"  Decompiled function '{first_fn}' (excerpt): "
                         f"{str(first_code)[:300]}")
        lines.append("")

    # AI key findings
    kf = ai.get("key_findings", [])
    if isinstance(kf, str): kf = [kf]
    if kf:
        lines.append("Key findings from preliminary AI analysis:")
        for f in kf[:6]:
            lines.append(f"  - {f}")
        lines.append("")

    # Behavior tags
    bt = ai.get("behavior_tags", [])
    if isinstance(bt, str): bt = [bt]
    if bt:
        lines.append(f"Behavior tags: {', '.join(bt[:10])}")

    evidence = "\n".join(lines)

    return (
        f"You are writing Section 2 of a formal malware threat intelligence report "
        f"for the file '{finfo.get('file_name','unknown')}'.\n\n"
        f"Using ONLY the evidence below, write a thorough analyst narrative (4–6 "
        f"paragraphs) titled nothing — just the prose. Explain:\n"
        f"1. What type of malware this appears to be and its likely purpose\n"
        f"2. The specific technical evidence that supports the malicious classification\n"
        f"3. The capabilities identified (network, persistence, injection, surveillance, etc.)\n"
        f"4. The threat to a target organisation\n"
        f"5. Any notable evasion or anti-analysis techniques observed\n\n"
        f"Be precise, cite specific evidence (API names, IPs, registry keys, entropy "
        f"values) from the data. Do not fabricate evidence not present below. "
        f"Write in plain prose — no bullet points, no markdown, no headers.\n\n"
        f"{evidence}"
    )


# ── Canvas callback ────────────────────────────────────────────────────────────
class _PageDecorator:
    def __init__(self, file_name: str, analysis: dict = None):
        self.file_name = file_name
        self._analysis = analysis or {}

    def on_first_page(self, cvs: rl_canvas.Canvas, doc):
        _draw_cover(cvs, self._analysis)

    def on_later_pages(self, cvs: rl_canvas.Canvas, doc):
        cvs.saveState()
        cvs.setStrokeColor(C_ACCENT)
        cvs.setLineWidth(2)
        cvs.line(MARGIN, PAGE_H - 0.45*inch, PAGE_W - MARGIN, PAGE_H - 0.45*inch)

        cvs.setFont("Helvetica-Bold", 7)
        cvs.setFillColor(C_ACCENT)
        cvs.drawString(MARGIN, PAGE_H - 0.38*inch, "AGHORA")
        cvs.setFont("Helvetica", 7)
        cvs.setFillColor(C_MUTED)
        cvs.drawString(MARGIN + 0.52*inch, PAGE_H - 0.38*inch,
                       f"Malware Analysis Report  ·  {self.file_name}")
        cvs.drawRightString(PAGE_W - MARGIN, PAGE_H - 0.38*inch, "CONFIDENTIAL")

        cvs.setStrokeColor(C_BORDER)
        cvs.setLineWidth(0.5)
        cvs.line(MARGIN, 0.45*inch, PAGE_W - MARGIN, 0.45*inch)
        cvs.setFont("Helvetica", 7)
        cvs.setFillColor(C_MUTED)
        cvs.drawCentredString(PAGE_W / 2, 0.3*inch, f"Page {doc.page}")
        cvs.restoreState()


# ── Styles ────────────────────────────────────────────────────────────────────
def _make_styles() -> Dict[str, ParagraphStyle]:
    s = {}

    def add(name, **kw):
        s[name] = ParagraphStyle(name, **kw)

    add("CoverTitle",   fontName="Helvetica-Bold", fontSize=26, leading=32,
        textColor=C_WHITE, alignment=TA_LEFT)
    add("H1",           fontName="Helvetica-Bold", fontSize=14, leading=18,
        textColor=C_ACCENT, spaceBefore=14, spaceAfter=4)
    add("H2",           fontName="Helvetica-Bold", fontSize=11, leading=14,
        textColor=colors.HexColor("#1e293b"), spaceBefore=10, spaceAfter=3)
    add("Body",         fontName="Helvetica", fontSize=9.5, leading=15,
        textColor=colors.HexColor("#1e293b"), spaceAfter=6, alignment=TA_JUSTIFY)
    add("BodySmall",    fontName="Helvetica", fontSize=8.5, leading=12,
        textColor=colors.HexColor("#334155"))
    add("Narrative",    fontName="Helvetica", fontSize=10, leading=16,
        textColor=colors.HexColor("#0f172a"), spaceAfter=8, alignment=TA_JUSTIFY,
        leftIndent=0, rightIndent=0)
    add("Mono",         fontName="Courier", fontSize=7.5, leading=11,
        textColor=colors.HexColor("#334155"))
    add("BulletBody",   fontName="Helvetica", fontSize=9, leading=13,
        textColor=colors.HexColor("#334155"),
        leftIndent=12, spaceAfter=2)
    add("Label",        fontName="Helvetica-Bold", fontSize=8, leading=11,
        textColor=C_MUTED)
    add("Caption",      fontName="Helvetica-Oblique", fontSize=8, leading=11,
        textColor=C_MUTED, spaceAfter=4)

    return s


# ── Helper flowables ──────────────────────────────────────────────────────────
class _SectionBar(Flowable):
    def __init__(self, text: str, color=None):
        super().__init__()
        self.text  = text
        self.color = color or C_ACCENT
        self.width = PAGE_W - 2 * MARGIN
        self.height = 24

    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.rect(0, 2, 4, 18, fill=1, stroke=0)
        self.canv.setFillColor(colors.HexColor("#0f172a"))
        self.canv.setFont("Helvetica-Bold", 11)
        self.canv.drawString(12, 7, self.text)


def _hr(color=None) -> HRFlowable:
    return HRFlowable(width="100%", thickness=0.5,
                      color=color or C_BORDER, spaceAfter=6)


def _sp(h: float = 6) -> Spacer:
    return Spacer(1, h)


def _kv_table(rows: List[tuple], styles_map: Dict) -> Table:
    data = [[Paragraph(k, styles_map["Label"]),
             Paragraph(str(v), styles_map["Mono"])]
            for k, v in rows]
    t = Table(data, colWidths=[1.7*inch, PAGE_W - 2*MARGIN - 1.7*inch])
    t.setStyle(TableStyle([
        ("VALIGN",        (0,0),(-1,-1),"TOP"),
        ("TOPPADDING",    (0,0),(-1,-1),4),
        ("BOTTOMPADDING", (0,0),(-1,-1),4),
        ("LEFTPADDING",   (0,0),(-1,-1),6),
        ("RIGHTPADDING",  (0,0),(-1,-1),6),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.white, C_ROW_ALT]),
        ("GRID",          (0,0),(-1,-1),0.4, C_BORDER),
        ("FONTNAME",      (0,0),(0,-1),"Helvetica-Bold"),
    ]))
    return t


def _data_table(headers: List[str], rows: List[List[Any]],
                col_widths: List[float], styles_map: Dict,
                highlight_col: int = -1) -> Table:
    header_row = [Paragraph(h, ParagraphStyle(
        "TH", fontName="Helvetica-Bold", fontSize=8, textColor=C_WHITE
    )) for h in headers]
    body_rows = [[Paragraph(str(c), styles_map["BodySmall"]) for c in row]
                 for row in rows]
    data = [header_row] + body_rows
    t = Table(data, colWidths=col_widths)
    ts = [
        ("BACKGROUND",    (0,0),(-1,0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR",     (0,0),(-1,0), C_WHITE),
        ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,0), 8),
        ("TOPPADDING",    (0,0),(-1,-1),4),
        ("BOTTOMPADDING", (0,0),(-1,-1),4),
        ("LEFTPADDING",   (0,0),(-1,-1),6),
        ("RIGHTPADDING",  (0,0),(-1,-1),6),
        ("VALIGN",        (0,0),(-1,-1),"TOP"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, C_ROW_ALT]),
        ("GRID",          (0,0),(-1,-1),0.4, C_BORDER),
        ("FONTNAME",      (0,1),(-1,-1),"Helvetica"),
        ("FONTSIZE",      (0,1),(-1,-1),8),
    ]
    if highlight_col >= 0 and rows:
        for i, row in enumerate(rows, start=1):
            val = str(row[highlight_col]).lower()
            rc = RISK_COLORS.get(val)
            rb = RISK_BG.get(val)
            if rc and rb:
                ts += [
                    ("BACKGROUND",(highlight_col,i),(highlight_col,i), rb),
                    ("TEXTCOLOR", (highlight_col,i),(highlight_col,i), rc),
                    ("FONTNAME",  (highlight_col,i),(highlight_col,i),"Helvetica-Bold"),
                ]
    t.setStyle(TableStyle(ts))
    return t


# ── Cover page ────────────────────────────────────────────────────────────────
def _draw_cover(cvs: rl_canvas.Canvas, analysis: Dict):
    finfo      = analysis.get("tool_results",{}).get("tools",{}).get("fileinfo",{}).get("data",{})
    ai_data    = analysis.get("ai_analysis", {})
    file_name  = finfo.get("file_name", analysis.get("file_path","Unknown"))
    sha256     = finfo.get("sha256","")
    threat_lvl = ai_data.get("threat_level","unknown").upper()
    ts         = analysis.get("timestamp", datetime.now().isoformat())
    try:
        ts_fmt = datetime.fromisoformat(ts).strftime("%B %d, %Y  %H:%M UTC")
    except Exception:
        ts_fmt = ts

    cvs.setFillColor(C_BG_DARK)
    cvs.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

    cvs.setFillColor(C_ACCENT)
    cvs.rect(0, 0, 6, PAGE_H, fill=1, stroke=0)

    cvs.setFillColor(colors.HexColor("#161a28"))
    cvs.rect(0, PAGE_H - 1.1*inch, PAGE_W, 1.1*inch, fill=1, stroke=0)

    cvs.setFillColor(C_ACCENT)
    cvs.setFont("Helvetica-Bold", 22)
    cvs.drawString(MARGIN + 0.1*inch, PAGE_H - 0.65*inch, "AGHORA")
    cvs.setFont("Helvetica", 9)
    cvs.setFillColor(C_MUTED)
    cvs.drawString(MARGIN + 0.1*inch, PAGE_H - 0.87*inch,
                   "Agentic Guided Heuristic, Orchestration, Reasoning, and Analysis")

    cvs.setStrokeColor(C_ACCENT)
    cvs.setLineWidth(1.5)
    cvs.line(MARGIN + 0.1*inch, PAGE_H - 1.6*inch, PAGE_W - MARGIN - 0.1*inch, PAGE_H - 1.6*inch)

    y = PAGE_H - 2.5*inch
    cvs.setFillColor(C_WHITE)
    cvs.setFont("Helvetica-Bold", 28)
    cvs.drawString(MARGIN + 0.1*inch, y, "MALWARE ANALYSIS")
    cvs.setFont("Helvetica", 28)
    cvs.drawString(MARGIN + 0.1*inch, y - 0.45*inch, "REPORT")

    risk_color = RISK_COLORS.get(threat_lvl.lower(), C_MUTED)
    badge_y = y - 1.05*inch
    cvs.setFillColor(risk_color)
    cvs.roundRect(MARGIN + 0.1*inch, badge_y, 110, 22, 5, fill=1, stroke=0)
    cvs.setFillColor(C_WHITE)
    cvs.setFont("Helvetica-Bold", 10)
    cvs.drawCentredString(MARGIN + 0.1*inch + 55, badge_y + 7, f"THREAT: {threat_lvl}")

    sep_y = badge_y - 0.4*inch
    cvs.setStrokeColor(C_BORDER)
    cvs.setLineWidth(0.5)
    cvs.line(MARGIN + 0.1*inch, sep_y, PAGE_W - MARGIN - 0.1*inch, sep_y)

    info_y = sep_y - 0.38*inch
    cvs.setFont("Helvetica-Bold", 9)
    cvs.setFillColor(C_MUTED)
    cvs.drawString(MARGIN + 0.1*inch, info_y, "TARGET FILE")
    info_y -= 0.22*inch
    cvs.setFont("Helvetica-Bold", 13)
    cvs.setFillColor(C_WHITE)
    fn = file_name if len(file_name) <= 48 else file_name[:45] + "\u2026"
    cvs.drawString(MARGIN + 0.1*inch, info_y, fn)

    info_y -= 0.32*inch
    cvs.setFont("Helvetica-Bold", 8)
    cvs.setFillColor(C_MUTED)
    cvs.drawString(MARGIN + 0.1*inch, info_y, "SHA-256")
    info_y -= 0.18*inch
    cvs.setFont("Courier", 8)
    cvs.setFillColor(colors.HexColor("#7dd3fc"))
    cvs.drawString(MARGIN + 0.1*inch, info_y, sha256 if sha256 else "\u2014")

    strip_h = 0.75*inch
    cvs.setFillColor(colors.HexColor("#161a28"))
    cvs.rect(0, 0, PAGE_W, strip_h, fill=1, stroke=0)
    cvs.setFont("Helvetica", 8)
    cvs.setFillColor(C_MUTED)
    cvs.drawString(MARGIN + 0.1*inch, strip_h - 0.25*inch, f"Generated  {ts_fmt}")
    cvs.drawString(MARGIN + 0.1*inch, strip_h - 0.45*inch,
                   "CONFIDENTIAL \u2014 For authorized use only")
    cvs.setFillColor(C_ACCENT)
    cvs.setFont("Helvetica-Bold", 8)
    cvs.drawRightString(PAGE_W - MARGIN - 0.1*inch, strip_h - 0.25*inch,
                        "AGHORA Intelligence Platform")


# ── Main report builder ────────────────────────────────────────────────────────
def generate_report(analysis: Dict, output_path: Optional[str] = None) -> bytes:
    buf    = io.BytesIO()
    styles = _make_styles()

    # ── Extract all data upfront ──────────────────────────────────────────────
    tools       = analysis.get("tool_results", {}).get("tools", {})
    finfo       = tools.get("fileinfo", {}).get("data", {}) or {}
    pe_data     = tools.get("pestudio", {}).get("data", {}) or {}
    strings_raw = tools.get("strings", {}).get("data", {}) or {}
    sp          = strings_raw.get("suspicious_patterns", strings_raw) or {}
    ai_data     = analysis.get("ai_analysis", {}) or {}
    die_data    = tools.get("die", {}).get("data", {}) or {}
    ghidra_data = tools.get("ghidra", {}).get("data", {}) or {}

    file_name  = finfo.get("file_name", analysis.get("file_path", "Unknown"))
    sha256     = finfo.get("sha256", "\u2014")
    md5        = finfo.get("md5", "\u2014")
    file_size  = finfo.get("size", "\u2014")
    threat_lvl = ai_data.get("threat_level", "unknown")

    try:
        ts_fmt = datetime.fromisoformat(
            analysis.get("timestamp", "")).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        ts_fmt = analysis.get("timestamp", "\u2014")

    # ── Gather IOCs / APIs now (needed for appendix and API section) ──────────
    ip_list     = sp.get("ips", [])
    domain_list = sp.get("domains", [])
    url_list    = sp.get("urls", [])
    reg_keys    = sp.get("registry_keys", [])
    file_paths  = sp.get("file_paths", [])

    API_SIGS = {
        "Process Injection": {"VirtualAllocEx","WriteProcessMemory","CreateRemoteThread",
                              "NtCreateThreadEx","RtlCreateUserThread","SetWindowsHookEx",
                              "QueueUserAPC","NtMapViewOfSection","VirtualAlloc",
                              "NtAllocateVirtualMemory"},
        "Process Control":   {"OpenProcess","TerminateProcess","CreateProcess",
                              "ShellExecute","WinExec","CreateProcessAsUser",
                              "NtOpenProcess","NtTerminateProcess"},
        "Network Access":    {"WSAStartup","connect","send","recv","HttpOpenRequest",
                              "InternetOpenUrl","URLDownloadToFile","socket","WSAConnect",
                              "InternetConnect","WinHttpOpen","WinHttpSendRequest",
                              "gethostbyname","getaddrinfo","InternetReadFile"},
        "Surveillance":      {"GetAsyncKeyState","GetKeyState","GetForegroundWindow",
                              "GetWindowText","BitBlt","PrintWindow","ReadProcessMemory",
                              "GetClipboardData","EnumWindows","SetWinEventHook"},
        "Anti-Analysis":     {"IsDebuggerPresent","CheckRemoteDebuggerPresent",
                              "NtQueryInformationProcess","GetTickCount","Sleep",
                              "VirtualProtect","NtSetInformationThread",
                              "OutputDebugString","FindWindow"},
        "Cryptography":      {"CryptEncrypt","CryptDecrypt","CryptGenKey","CryptHashData",
                              "BCryptEncrypt","BCryptDecrypt","BCryptGenRandom",
                              "CryptAcquireContext","CryptCreateHash"},
        "Persistence APIs":  {"RegSetValueEx","RegCreateKeyEx","CreateService",
                              "ChangeServiceConfig","NtSetValueKey",
                              "SHGetSpecialFolderPath","SHGetKnownFolderPath"},
        "File Operations":   {"CreateFile","WriteFile","ReadFile","DeleteFile",
                              "MoveFile","CopyFile","NtCreateFile","NtWriteFile"},
    }

    all_apis: set = set()
    for imp in pe_data.get("imports", []):
        all_apis.add(imp.get("name","") if isinstance(imp,dict) else str(imp))
    for api in pe_data.get("suspicious_apis", []):
        if isinstance(api, str): all_apis.add(api)
    for api in sp.get("suspicious_apis", []):
        if isinstance(api, str): all_apis.add(api)

    matched_api_rows = []
    all_matched_apis = []
    for cat, sigs in API_SIGS.items():
        hits = sorted(all_apis & sigs)
        if hits:
            all_matched_apis.extend(hits)
            sample = ", ".join(hits[:5])
            if len(hits) > 5: sample += f" (+{len(hits)-5} more)"
            # Determine risk level for the category
            risk_map = {
                "Process Injection":"critical","Surveillance":"critical",
                "Process Control":"high","Network Access":"high",
                "Anti-Analysis":"high","Persistence APIs":"high",
                "Cryptography":"medium","File Operations":"medium",
            }
            matched_api_rows.append([cat, risk_map.get(cat,"medium"),
                                      str(len(hits)), sample])

    # ── Generate LLM narrative ────────────────────────────────────────────────
    print("[REPORT] Generating LLM analyst narrative...")
    llm_prompt    = _build_evidence_prompt(analysis)
    llm_narrative = _call_llm(llm_prompt)
    print("[REPORT] LLM narrative received.")

    # ── Document setup ────────────────────────────────────────────────────────
    decorator = _PageDecorator(file_name, analysis)
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=0.75*inch, bottomMargin=0.65*inch,
        title=f"Malware Analysis Report \u2014 {file_name}",
        author="AGHORA",
        subject="Malware Threat Intelligence",
    )

    story = []

    # ────────────────────────────────────────────────────────────────────────
    # PAGE 1 — Cover (painted entirely via on_first_page canvas callback)
    # ────────────────────────────────────────────────────────────────────────
    story.append(PageBreak())

    # ────────────────────────────────────────────────────────────────────────
    # PAGE 2 — Executive Summary
    # ────────────────────────────────────────────────────────────────────────
    story.append(_SectionBar("EXECUTIVE SUMMARY", C_ACCENT))
    story.append(_sp(8))

    family       = (ai_data.get("malware_family") or ai_data.get("family") or "Unknown")
    summary_text = (ai_data.get("threat_summary") or ai_data.get("summary")
                    or ai_data.get("analysis_summary") or "")

    overview_rows = [
        ("Threat Level",   threat_lvl.upper()),
        ("Malware Family", family),
        ("File Name",      file_name),
        ("Analysis Date",  ts_fmt),
        ("Session ID",     analysis.get("session_id", "\u2014")),
    ]
    story.append(_kv_table(overview_rows, styles))
    story.append(_sp(10))

    if summary_text:
        story.append(Paragraph("Initial Assessment", styles["H2"]))
        story.append(Paragraph(str(summary_text)[:800], styles["Body"]))
        story.append(_sp(6))

    key_findings = ai_data.get("key_findings", [])
    if isinstance(key_findings, str):
        key_findings = [key_findings]
    if key_findings:
        story.append(Paragraph("Key Findings", styles["H2"]))
        for f in key_findings[:8]:
            if f:
                story.append(Paragraph(f"\u2022  {str(f)}", styles["BulletBody"]))
        story.append(_sp(6))

    mitigations = ai_data.get("mitigation", []) or ai_data.get("recommendations", [])
    if isinstance(mitigations, str):
        mitigations = [mitigations]
    if mitigations:
        story.append(Paragraph("Recommended Actions", styles["H2"]))
        for m in mitigations[:6]:
            if m:
                story.append(Paragraph(f"\u2022  {str(m)}", styles["BulletBody"]))

    story.append(PageBreak())

    # ────────────────────────────────────────────────────────────────────────
    # PAGE 3 — Analyst Assessment (LLM-written narrative)
    # ────────────────────────────────────────────────────────────────────────
    story.append(_SectionBar("ANALYST ASSESSMENT", colors.HexColor("#7c3aed")))
    story.append(_sp(6))
    story.append(Paragraph(
        "The following assessment was generated by AGHORA\u2019s AI engine using only "
        "the evidence collected during static analysis of this specific sample.",
        styles["Caption"]
    ))
    story.append(_sp(8))

    # Split narrative into paragraphs on double newlines or single newlines
    paragraphs = [p.strip() for p in re.split(r'\n{2,}', llm_narrative) if p.strip()]
    if len(paragraphs) == 1:
        # Single block — split on sentence groups
        paragraphs = [p.strip() for p in llm_narrative.split('\n') if p.strip()]

    for para in paragraphs:
        if para:
            story.append(Paragraph(para, styles["Narrative"]))

    story.append(PageBreak())

    # ────────────────────────────────────────────────────────────────────────
    # PAGE 4 — File Metadata (only if data available)
    # ────────────────────────────────────────────────────────────────────────
    meta_rows: List[tuple] = []
    if finfo.get("file_name"):
        meta_rows.append(("File Name",   file_name))
    if sha256 and sha256 != "\u2014":
        meta_rows.append(("SHA-256",     sha256))
    if md5 and md5 != "\u2014":
        meta_rows.append(("MD5",         md5))
    if file_size and file_size != "\u2014":
        meta_rows.append(("File Size",
            f"{file_size:,} bytes" if isinstance(file_size, int) else str(file_size)))
    if finfo.get("file_type"):
        meta_rows.append(("File Type",   finfo["file_type"]))
    if finfo.get("magic"):
        meta_rows.append(("Magic Bytes", finfo["magic"]))
    if pe_data.get("compile_time"):
        meta_rows.append(("Compile Time",  pe_data["compile_time"]))
    if pe_data.get("machine_type"):
        meta_rows.append(("Machine Type",  pe_data["machine_type"]))
    if pe_data.get("entry_point"):
        meta_rows.append(("Entry Point",   pe_data["entry_point"]))
    if pe_data.get("imports") is not None:
        meta_rows.append(("Imports",       str(len(pe_data["imports"]))))
    if pe_data.get("exports") is not None:
        meta_rows.append(("Exports",       str(len(pe_data["exports"]))))
    if die_data.get("detections"):
        meta_rows.append(("DIE Detections", str(die_data["detections"])[:120]))

    if meta_rows:
        story.append(_SectionBar("FILE METADATA", C_ACCENT2))
        story.append(_sp(8))
        story.append(_kv_table(meta_rows, styles))
        story.append(_sp(14))

    # PE Sections (skip if no section data)
    pe_sections = pe_data.get("sections", [])
    if pe_sections:
        story.append(_SectionBar("PE SECTION ANALYSIS", C_CYAN))
        story.append(_sp(8))
        story.append(Paragraph(
            "Sections with entropy above 6.5 are consistent with packing or encryption. "
            "Values above 7.0 are a strong indicator of shellcode, ransomware payloads, "
            "or custom encryption routines.",
            styles["Caption"]
        ))
        sect_rows = []
        for sec in pe_sections:
            name = (sec.get("name","?") or "?").strip("\x00").strip()
            entropy = sec.get("entropy", 0.0)
            try:   entropy = float(entropy)
            except: entropy = 0.0
            vsize = sec.get("virtual_size", sec.get("size", 0))
            cls = ("ENCRYPTED" if entropy > 7.0
                   else "PACKED" if entropy > 6.5
                   else "COMPRESSED" if entropy > 5.5
                   else "Normal")
            sect_rows.append([
                name,
                f"{entropy:.3f}",
                cls,
                f"{vsize:,}" if isinstance(vsize, int) else str(vsize),
            ])
        cw = PAGE_W - 2*MARGIN
        story.append(_data_table(
            ["Section","Entropy","Classification","Virtual Size (B)"],
            sect_rows,
            [cw*0.2, cw*0.18, cw*0.32, cw*0.3],
            styles,
        ))

    if meta_rows or pe_sections:
        story.append(PageBreak())

    # ────────────────────────────────────────────────────────────────────────
    # Network Indicators (skip entire page if none)
    # ────────────────────────────────────────────────────────────────────────
    has_network = bool(ip_list or domain_list or url_list)
    if has_network:
        story.append(_SectionBar("NETWORK INDICATORS OF COMPROMISE", C_ACCENT2))
        story.append(_sp(8))

        if ip_list:
            story.append(Paragraph("IP Addresses", styles["H2"]))
            ip_rows = []
            for ip in ip_list[:25]:
                is_priv = bool(re.match(
                    r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)", ip))
                cat  = "Internal Network" if is_priv else "External / C2"
                risk = "low" if is_priv else "high"
                ip_rows.append([ip, cat, risk])
            cw = PAGE_W - 2*MARGIN
            story.append(_data_table(
                ["IP Address","Classification","Risk"],
                ip_rows, [cw*0.35, cw*0.45, cw*0.2],
                styles, highlight_col=2
            ))
            story.append(_sp(10))

        if domain_list:
            story.append(Paragraph("Domains", styles["H2"]))
            dom_rows = []
            for d in domain_list[:25]:
                dl = d.lower()
                if dl.endswith(".onion"):
                    cat, risk = "Tor Hidden Service","critical"
                elif any(k in dl for k in ["no-ip","ddns","duckdns","afraid","dyndns"]):
                    cat, risk = "Dynamic DNS (C2)","high"
                elif any(k in dl for k in ["pastebin","paste.ee","hastebin"]):
                    cat, risk = "Paste Site C2","critical"
                else:
                    cat, risk = "External Domain","medium"
                dom_rows.append([d, cat, risk])
            cw = PAGE_W - 2*MARGIN
            story.append(_data_table(
                ["Domain","Classification","Risk"],
                dom_rows, [cw*0.40, cw*0.40, cw*0.20],
                styles, highlight_col=2
            ))
            story.append(_sp(10))

        if url_list:
            story.append(Paragraph("Embedded URLs", styles["H2"]))
            url_rows = []
            for u in url_list[:20]:
                ul = u.lower()
                if any(k in ul for k in [".exe",".dll",".ps1","download","payload","drop"]):
                    cat, risk = "Payload Download","critical"
                elif any(k in ul for k in ["/gate","/bot","/cmd","/panel","/beacon"]):
                    cat, risk = "C2 Beacon","critical"
                elif any(k in ul for k in ["upload","exfil","steal","report","log"]):
                    cat, risk = "Data Exfiltration","critical"
                else:
                    cat, risk = "Embedded URL","high"
                display = u if len(u) <= 60 else u[:57] + "\u2026"
                url_rows.append([display, cat, risk])
            cw = PAGE_W - 2*MARGIN
            story.append(_data_table(
                ["URL","Classification","Risk"],
                url_rows, [cw*0.45, cw*0.35, cw*0.20],
                styles, highlight_col=2
            ))

        story.append(PageBreak())

    # ────────────────────────────────────────────────────────────────────────
    # Persistence Mechanisms (skip if none)
    # ────────────────────────────────────────────────────────────────────────
    has_persist = bool(reg_keys or file_paths)
    if has_persist:
        story.append(_SectionBar("PERSISTENCE MECHANISMS", colors.HexColor("#f97316")))
        story.append(_sp(8))

        if reg_keys:
            story.append(Paragraph("Registry Keys", styles["H2"]))
            reg_rows = []
            for key in reg_keys[:25]:
                kl = key.lower()
                if "run" in kl and "currentversion" in kl:
                    cat, risk = "Autorun Key","critical"
                elif "winlogon" in kl:
                    cat, risk = "Winlogon Hook","critical"
                elif "services" in kl:
                    cat, risk = "Malicious Service","critical"
                elif "appinit_dlls" in kl:
                    cat, risk = "AppInit DLL Injection","critical"
                elif "image file execution" in kl:
                    cat, risk = "IFEO Hijack","critical"
                else:
                    cat, risk = "Registry Modification","high"
                short = key if len(key) <= 65 else key[:62]+"\u2026"
                reg_rows.append([short, cat, risk])
            cw = PAGE_W - 2*MARGIN
            story.append(_data_table(
                ["Registry Key","Technique","Risk"],
                reg_rows, [cw*0.50, cw*0.32, cw*0.18],
                styles, highlight_col=2
            ))
            story.append(_sp(10))

        if file_paths:
            story.append(Paragraph("File Paths", styles["H2"]))
            fp_rows = []
            for path in file_paths[:20]:
                pl = path.lower()
                if "\\appdata\\roaming\\" in pl or "%appdata%" in pl:
                    cat, risk = "AppData Persistence","critical"
                elif "\\system32\\" in pl or "\\syswow64\\" in pl:
                    cat, risk = "System Directory","critical"
                elif "\\startup\\" in pl:
                    cat, risk = "Startup Folder","critical"
                elif "\\temp\\" in pl or "%temp%" in pl:
                    cat, risk = "Temp Drop","high"
                else:
                    cat, risk = "Suspicious Path","medium"
                short = path if len(path) <= 65 else path[:62]+"\u2026"
                fp_rows.append([short, cat, risk])
            cw = PAGE_W - 2*MARGIN
            story.append(_data_table(
                ["File Path","Technique","Risk"],
                fp_rows, [cw*0.50, cw*0.32, cw*0.18],
                styles, highlight_col=2
            ))

        story.append(PageBreak())

    # ────────────────────────────────────────────────────────────────────────
    # Win32 API Analysis (skip if no APIs matched)
    # ────────────────────────────────────────────────────────────────────────
    if matched_api_rows:
        story.append(_SectionBar("WIN32 API TECHNIQUE ANALYSIS", C_VIOLET))
        story.append(_sp(8))
        story.append(Paragraph(
            "Win32 API imports matched against known malware technique categories. "
            "Each category represents a distinct attack capability observed in this sample.",
            styles["Caption"]
        ))
        cw = PAGE_W - 2*MARGIN
        story.append(_data_table(
            ["Technique Category","Risk","APIs Matched","Examples"],
            matched_api_rows,
            [cw*0.26, cw*0.12, cw*0.10, cw*0.52],
            styles, highlight_col=1
        ))
        story.append(_sp(10))
        story.append(Paragraph("Full Matched API List", styles["H2"]))
        story.append(Paragraph("   ".join(sorted(set(all_matched_apis))), styles["Mono"]))
        story.append(PageBreak())

    # ────────────────────────────────────────────────────────────────────────
    # Ghidra Reverse Engineering (skip if Ghidra not run)
    # ────────────────────────────────────────────────────────────────────────
    if ghidra_data.get("function_count"):
        story.append(_SectionBar("REVERSE ENGINEERING (GHIDRA)", colors.HexColor("#0d9488")))
        story.append(_sp(8))

        ghidra_meta = [
            ("Functions Analysed", str(ghidra_data.get("function_count","?"))),
        ]
        if ghidra_data.get("interesting"):
            ghidra_meta.append(("Interesting Patterns",
                                str(len(ghidra_data["interesting"]))))
        if ghidra_data.get("crypto_constants"):
            ghidra_meta.append(("Crypto Constants",
                                str(len(ghidra_data["crypto_constants"]))))
        story.append(_kv_table(ghidra_meta, styles))
        story.append(_sp(8))

        interesting = ghidra_data.get("interesting", [])
        if interesting:
            story.append(Paragraph("Interesting Patterns", styles["H2"]))
            for item in interesting[:15]:
                story.append(Paragraph(f"\u2022  {item}", styles["BulletBody"]))
            story.append(_sp(6))

        crypto = ghidra_data.get("crypto_constants", [])
        if crypto:
            story.append(Paragraph("Cryptographic Constants Detected", styles["H2"]))
            for c in crypto[:10]:
                story.append(Paragraph(f"\u2022  {c}", styles["BulletBody"]))
            story.append(_sp(6))

        decomp = ghidra_data.get("decompiled", {})
        if decomp:
            story.append(Paragraph("Decompiled Functions", styles["H2"]))
            story.append(Paragraph(
                "Pseudocode extracted by Ghidra\u2019s decompiler for the most significant functions.",
                styles["Caption"]
            ))
            for fn_name, code in list(decomp.items())[:5]:
                story.append(Paragraph(fn_name, styles["H2"]))
                code_str = str(code)[:1200]
                for line in code_str.split("\n")[:40]:
                    if line.strip():
                        story.append(Paragraph(line, styles["Mono"]))
                story.append(_sp(4))

        story.append(PageBreak())

    # ────────────────────────────────────────────────────────────────────────
    # MITRE ATT&CK (only if mapped)
    # ────────────────────────────────────────────────────────────────────────
    mitre = ai_data.get("mitre_techniques", []) or ai_data.get("mitre", [])
    if mitre:
        story.append(_SectionBar("MITRE ATT\u0026CK MAPPING", colors.HexColor("#be185d")))
        story.append(_sp(8))
        mitre_rows = []
        for t in mitre:
            if isinstance(t, dict):
                mitre_rows.append([t.get("id","\u2014"), t.get("name","\u2014"),
                                   t.get("tactic","\u2014")])
            elif isinstance(t, str):
                mitre_rows.append([t, "\u2014", "\u2014"])
        if mitre_rows:
            cw = PAGE_W - 2*MARGIN
            story.append(_data_table(
                ["Technique ID","Name","Tactic"],
                mitre_rows, [cw*0.18, cw*0.48, cw*0.34],
                styles
            ))
        story.append(PageBreak())

    # ────────────────────────────────────────────────────────────────────────
    # IOC Appendix (only if there are any IOCs at all)
    # ────────────────────────────────────────────────────────────────────────
    has_iocs = bool(ip_list or domain_list or url_list or reg_keys
                    or file_paths or all_matched_apis or sha256 != "\u2014")
    if has_iocs:
        story.append(_SectionBar("APPENDIX \u2014 RAW IOC LIST", C_MUTED))
        story.append(_sp(8))
        story.append(Paragraph(
            "Complete list of indicators extracted from this sample. "
            "Import into your SIEM, EDR, or threat intelligence platform for detection.",
            styles["Caption"]
        ))

        def _ioc_block(title, items, max_items=50):
            if not items: return
            story.append(Paragraph(title, styles["H2"]))
            for item in items[:max_items]:
                story.append(Paragraph(str(item), styles["Mono"]))
            story.append(_sp(6))

        _ioc_block("IP Addresses",   ip_list)
        _ioc_block("Domains",        domain_list)
        _ioc_block("URLs",           url_list)
        _ioc_block("Registry Keys",  reg_keys)
        _ioc_block("File Paths",     file_paths)
        _ioc_block("Suspicious APIs",sorted(set(all_matched_apis)))

        story.append(Paragraph("File Hashes", styles["H2"]))
        if sha256 and sha256 != "\u2014":
            story.append(Paragraph(f"SHA-256:  {sha256}", styles["Mono"]))
        if md5 and md5 != "\u2014":
            story.append(Paragraph(f"MD5:      {md5}", styles["Mono"]))

    # ── Build PDF ─────────────────────────────────────────────────────────────
    doc.build(
        story,
        onFirstPage=decorator.on_first_page,
        onLaterPages=decorator.on_later_pages,
    )

    pdf_bytes = buf.getvalue()
    if output_path:
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)
    return pdf_bytes


# ── CLI helper ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python report_generator.py <complete_analysis.json> [output.pdf]")
        sys.exit(1)
    with open(sys.argv[1], encoding="utf-8") as fh:
        data = json.load(fh)
    out = sys.argv[2] if len(sys.argv) > 2 else "report.pdf"
    generate_report(data, out)
    print(f"Report saved to: {out}")
