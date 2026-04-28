"""
AI-powered malware analyzer -- supports local Ollama/Gemma (default) or OpenAI GPT-4.
Set LLM_PROVIDER=ollama (default) or LLM_PROVIDER=openai in your .env file.
"""

import os
import re
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

# ---- Simple patterns for the direct-answer fast path -----------------------
_HASH_Q     = re.compile(r"\b(sha256|sha-256|hash|checksum|digest)\b", re.I)
_MD5_Q      = re.compile(r"\bmd5\b", re.I)
_SHA1_Q     = re.compile(r"\b(sha1|sha-1)\b", re.I)
_NAME_Q     = re.compile(r"\b(file\s*name|filename|what.*file|name\s+of)\b", re.I)
_SIZE_Q     = re.compile(r"\b(file\s*size|how\s+big|size\s+of)\b", re.I)
_IOC_Q      = re.compile(r"\b(ioc|indicator|ip\s+address|domain|url|registry|c2|c&c)\b", re.I)
_BEHAVIOR_Q = re.compile(
    r"\b(behav|persist|inject|evasion|technique|ransomware|keylog|exfil|lateral)\b", re.I
)
_IMPORT_Q   = re.compile(r"\b(import|api|function|dll)\b", re.I)



def _parse_llm_json(raw: str) -> dict:
    """
    Robustly parse a JSON string that may be truncated by the LLM.
    Strategy:
      1. Try as-is.
      2. Try to auto-close unclosed braces/brackets/strings.
      3. If all else fails, extract whatever key-value pairs are readable.
    """
    # 1. Clean attempt
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # 2. Auto-close: count open braces/brackets and append closing chars
    fixed = raw.rstrip()
    # Remove a trailing comma before we try to close
    if fixed.endswith(","):
        fixed = fixed[:-1]
    # If we're inside a string (odd number of unescaped quotes), close it
    in_string = False
    escape_next = False
    for ch in fixed:
        if escape_next:
            escape_next = False
            continue
        if ch == "\\":
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
    if in_string:
        fixed += '"'

    # Count and close open structures
    depth_brace   = fixed.count("{") - fixed.count("}")
    depth_bracket = fixed.count("[") - fixed.count("]")
    fixed += "]" * max(depth_bracket, 0)
    fixed += "}" * max(depth_brace, 0)

    try:
        return json.loads(fixed)
    except json.JSONDecodeError:
        pass

    # 3. Fallback: pull out whatever we can via regex
    import re as _re
    result = {}
    for key, val in _re.findall(r'"(\w+)"\s*:\s*"([^"]*)"', raw):
        result[key] = val
    for key, val in _re.findall(r'"(\w+)"\s*:\s*(true|false|null|\d+(?:\.\d+)?)', raw):
        result[key] = {"true": True, "false": False, "null": None}.get(val, val)
    return result if result else {}


class AIAnalyzer:
    """AI-powered malware analyzer with chat memory."""

    def __init__(self, api_key=None, model=None):
        self.init_error = None
        self.client = None

        self.llm_provider = os.getenv("LLM_PROVIDER", "ollama").lower()
        ollama_base_url   = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
        default_model     = "gpt-4-turbo-preview" if self.llm_provider == "openai" else "gemma4:e4b"
        self.model        = model or os.getenv("LLM_MODEL", default_model)

        if self.llm_provider == "ollama":
            print(f"[AI] Using local Ollama backend -> {ollama_base_url}  model: {self.model}")
            try:
                self.client  = OpenAI(base_url=ollama_base_url, api_key="ollama")
                self.api_key = "ollama"
                print(f"[AI] Ollama client initialized (model: {self.model})")
            except Exception as e:
                self.init_error = f"Ollama client init failed: {e}"
                print(f"[AI] {self.init_error}")
                import traceback; print(traceback.format_exc())
        else:
            self.api_key = api_key or os.getenv("OPENAI_API_KEY")
            print(f"[AI] Using OpenAI backend  model: {self.model}")
            if self.api_key:
                try:
                    self.client = OpenAI(api_key=self.api_key)
                    print(f"[AI] OpenAI client initialized (model: {self.model})")
                except Exception as e:
                    self.init_error = f"OpenAI client init failed: {e}"
                    print(f"[AI] {self.init_error}")
                    import traceback; print(traceback.format_exc())
            else:
                print("[AI] OPENAI_API_KEY not set -- AI chat disabled.")

        self.chat_memories: Dict[str, List[Dict]] = {}
        self.analysis_data: Dict[str, Dict]       = {}
        self.file_name_to_session: Dict[str, str] = {}

    # -------------------------------------------------------------------------
    # Memory management
    # -------------------------------------------------------------------------

    def add_analysis_to_memory(self, session_id: str, analysis_results: Dict[str, Any]):
        self.analysis_data[session_id] = analysis_results
        print(f"[MEMORY] Stored analysis for session {session_id}")

        tools = analysis_results.get("tools", {})
        if "fileinfo" in tools and tools["fileinfo"].get("status") == "success":
            fi   = tools["fileinfo"].get("data", {})
            name = fi.get("file_name", "")
            if name:
                self.file_name_to_session[name.lower()] = session_id
                print(f"[MEMORY] Mapped '{name}' -> session {session_id}")
            sha256 = fi.get("sha256", "")
            if sha256:
                print(f"[MEMORY] SHA256: {sha256}")

        summary = self._create_analysis_summary(analysis_results)

        if session_id not in self.chat_memories:
            self.chat_memories[session_id] = [
                {"role": "system", "content": self._system_prompt()}
            ]

        self.chat_memories[session_id].append({
            "role": "assistant",
            "content": (
                f"Analysis completed for: {analysis_results.get('file_path', 'Unknown')}\n\n"
                f"{summary}"
            ),
        })

    def get_memory(self, session_id: str) -> List[Dict]:
        return self.chat_memories.get(session_id, [])

    def clear_memory(self, session_id: str):
        self.chat_memories.pop(session_id, None)
        self.analysis_data.pop(session_id, None)

    # -------------------------------------------------------------------------
    # System prompt
    # -------------------------------------------------------------------------

    def _system_prompt(self) -> str:
        return (
            "You are a senior malware reverse engineer embedded in a static analysis platform. "
            "You have complete tool output for the uploaded sample. Your job is to reason from "
            "that evidence and give precise, analyst-grade answers — including a best-guess malware "
            "family even when evidence is partial.\n\n"

            "## MALWARE FAMILY IDENTIFICATION FRAMEWORK\n"
            "When asked about malware family, type, or intentions, reason through ALL THREE layers:\n\n"

            "### Layer 1 — Structural Analysis (Static)\n"
            "- Strings: hardcoded IPs, domains, mutex names, registry paths, error messages, "
            "version strings, author tags, PDB paths, configuration keys\n"
            "- Imports: match API combinations to capability fingerprints (see below)\n"
            "- Hashing: SHA256/imphash matches known family signatures\n"
            "- Compiler/packer: AutoIT, .NET, PyInstaller, UPX, Themida → narrows the family set\n"
            "- PE sections: names, entropy, size anomalies\n"
            "- Code patterns: RC4/AES constants, XOR loops, base64 decode stubs\n\n"

            "### Layer 2 — Operational Intent\n"
            "- Target platform: Windows x86/x64, .NET CLR, Python runtime\n"
            "- Payload type based on API clusters:\n"
            "    RAT/Backdoor   : socket+connect+send/recv, ShellExecute, GetAsyncKeyState\n"
            "    Infostealer    : browser path strings, CryptUnprotectData, clipboard APIs\n"
            "    Ransomware     : CryptEncrypt+FindFirstFile+file-ext lists, shadow copy deletion\n"
            "    Loader/Dropper : URLDownloadToFile, VirtualAlloc+WriteProcessMemory+CreateThread\n"
            "    Keylogger      : SetWindowsHookEx(WH_KEYBOARD), GetAsyncKeyState loop\n"
            "    Worm           : GetAdaptersInfo, WNetEnumResource, SMB/RDP strings\n"
            "- Persistence mechanism: Run key, scheduled task, service install, startup folder\n"
            "- C2 protocol: raw TCP, HTTP/S beaconing, DNS tunnelling, Pastebin staging\n\n"

            "### Layer 3 — Attribution & Artifacts\n"
            "- Mutex names (e.g. AsyncMutex_*, Global\\*, unique GUIDs)\n"
            "- Hardcoded C2 port numbers (e.g. 6606/7707/8808 = NjRAT, 4782 = QuasarRAT, "
            "2463/6666 = AsyncRAT-like, 1604 = DarkComet)\n"
            "- Known string artifacts: 'njq8', 'AsyncRAT', 'Quasar', 'dcrat', 'RedLine', "
            "'AgentTesla', 'Remcos', 'LimeRAT', 'XWorm', 'HVNC'\n"
            "- Author/group markers: embedded usernames, PDB paths, language artifacts\n"
            "- Unique protocol markers: specific handshake bytes, custom base64 alphabets\n\n"

            "## KNOWN FAMILY → SIGNATURE MAP\n"
            "AsyncRAT   : TCP port 6606/8808, AES-128 C2, mutex 'AsyncMutex_*', .NET\n"
            "NjRAT      : ports 1177/5552, 'njq8' string, VB.NET, registry Run persistence\n"
            "QuasarRAT  : port 4782, 'Quasar' strings, .NET, certificate-based auth\n"
            "XWorm      : 'XWorm' strings, port 7000, .NET, HVNC capability\n"
            "RedLine    : Steam API strings, Telegram C2, browser credential theft\n"
            "AgentTesla : SMTP/FTP exfil, keylogger strings, .NET, AutoIT wrapper\n"
            "Remcos     : 'REMCOS' mutex, port 2404, registry HKCU persistence\n"
            "DCRat      : 'dcrat' strings, PHP panel, .NET, plugin architecture\n"
            "Emotet     : HTTPS C2 list, Word macro dropper, heavily obfuscated\n"
            "Metasploit : 'meterpreter', staged payload patterns, pipe names\n"
            "Cobalt Strike: named pipe patterns, 'beacon', Malleable C2 artifacts\n\n"

            "## RESPONSE RULES\n"
            "- ALWAYS make a best-guess family identification. Never refuse or say 'cannot determine'.\n"
            "- Structure family answers as:\n"
            "    Most likely family: <NAME> (confidence: high/medium/low)\n"
            "    Evidence — Structural: <specific strings/APIs/hashes>\n"
            "    Evidence — Operational: <capabilities observed>\n"
            "    Evidence — Attribution: <mutex/port/artifact>\n"
            "    Alternative families: <other possibilities if confidence is low>\n"
            "- For factual questions (hash, IP, port): quote exact values from the analysis data.\n"
            "- Be specific. Name the actual API, string, or value — not generic descriptions.\n"
            "- If PyInstaller/AutoIT/VB.NET is detected, say so — it explains why PE imports are sparse.\n"
            "- Never say the data is unavailable or suggest running more tools."
        )

    # -------------------------------------------------------------------------
    # Direct fact resolver -- no LLM round-trip for simple questions
    # -------------------------------------------------------------------------

    def _try_direct_answer(self, question: str, analysis_data: Dict[str, Any]) -> Optional[str]:
        """Return answer string for simple factual queries, or None."""
        tools = analysis_data.get("tools", {})
        fi = tools.get("fileinfo",  {}).get("data", {})
        st = tools.get("strings",   {}).get("data", {})
        pe = tools.get("pestudio",  {}).get("data", {})
        bh = (tools.get("behavior_heuristics") or tools.get("behavior") or {}).get("data", {})
        q  = question.strip()

        # SHA-256
        if _HASH_Q.search(q) and not _MD5_Q.search(q) and not _SHA1_Q.search(q):
            sha256 = fi.get("sha256", "")
            if sha256:
                name = fi.get("file_name", "the analyzed file")
                return f"**SHA-256** hash of `{name}`:\n```\n{sha256}\n```"

        # MD5
        if _MD5_Q.search(q):
            md5 = fi.get("md5", "")
            if md5:
                name = fi.get("file_name", "the analyzed file")
                return f"**MD5** hash of `{name}`:\n```\n{md5}\n```"

        # SHA-1
        if _SHA1_Q.search(q):
            sha1 = fi.get("sha1", "")
            if sha1:
                name = fi.get("file_name", "the analyzed file")
                return f"**SHA-1** hash of `{name}`:\n```\n{sha1}\n```"

        # File name
        if _NAME_Q.search(q) and not _HASH_Q.search(q):
            name = fi.get("file_name", "")
            if name:
                return f"The analyzed file is named: **`{name}`**"

        # File size
        if _SIZE_Q.search(q):
            size_b = fi.get("file_size_bytes", 0)
            size_m = fi.get("file_size_mb", 0)
            if size_b:
                name = fi.get("file_name", "the file")
                return (
                    f"**File size** of `{name}`:\n"
                    f"- {size_b:,} bytes\n"
                    f"- {size_m:.2f} MB"
                )

        # IOCs
        if _IOC_Q.search(q):
            ips      = st.get("ips",           []) or pe.get("ips",     [])
            domains  = st.get("domains",       []) or pe.get("domains", [])
            urls     = st.get("urls",          []) or pe.get("urls",    [])
            reg_keys = st.get("registry_keys", [])
            lines = []
            if ips:
                lines.append(
                    "**IP Addresses** (" + str(len(ips)) + "):\n"
                    + "\n".join("  - `" + ip + "`" for ip in ips[:20])
                )
            if domains:
                lines.append(
                    "**Domains** (" + str(len(domains)) + "):\n"
                    + "\n".join("  - `" + d + "`" for d in domains[:20])
                )
            if urls:
                lines.append(
                    "**URLs** (" + str(len(urls)) + "):\n"
                    + "\n".join("  - `" + u + "`" for u in urls[:20])
                )
            if reg_keys:
                lines.append(
                    "**Registry Keys** (" + str(len(reg_keys)) + "):\n"
                    + "\n".join("  - `" + k + "`" for k in reg_keys[:20])
                )
            if lines:
                name = fi.get("file_name", "the file")
                return "**IOCs extracted from `" + name + "`:**\n\n" + "\n\n".join(lines)

        # Behavior / techniques
        if _BEHAVIOR_Q.search(q):
            behaviors = bh.get("behaviors", [])
            if behaviors:
                severity = bh.get("severity", "unknown")
                lines = ["**Overall severity:** " + severity.upper()]
                for b in behaviors:
                    sev   = b.get("severity", "?").upper()
                    cat   = b.get("category", "?")
                    inds  = b.get("indicators", [])[:5]
                    score = b.get("score", 0)
                    lines.append(
                        "\n**" + cat + "** [" + sev + "] (score: " + str(score) + ")\n"
                        + "\n".join("  - " + i for i in inds)
                    )
                return "\n".join(lines)

        # Imports / APIs
        if _IMPORT_Q.search(q):
            sus_apis = pe.get("suspicious_apis", []) or st.get("suspicious_apis", [])
            tech     = pe.get("technique_hits", {})
            if sus_apis or tech:
                lines = []
                if tech:
                    lines.append("**Technique categories detected:**")
                    for cat, apis in tech.items():
                        lines.append("  - **" + cat + "**: " + ", ".join(apis[:6]))
                if sus_apis:
                    lines.append(
                        "\n**Suspicious APIs** (" + str(len(sus_apis)) + " total):\n"
                        + ", ".join("`" + a + "`" for a in sus_apis[:30])
                    )
                return "\n".join(lines)

        return None  # needs LLM reasoning

    # -------------------------------------------------------------------------
    # Human-readable summary stored in chat memory after upload
    # -------------------------------------------------------------------------

    def _create_analysis_summary(self, analysis_results: Dict[str, Any]) -> str:
        parts = []
        tools = analysis_results.get("tools", {})

        if "fileinfo" in tools and tools["fileinfo"].get("status") == "success":
            fi = tools["fileinfo"].get("data", {})
            parts += [
                "**File Information:**",
                "- Name:    " + fi.get("file_name", "Unknown"),
                "- Size:    " + str(round(fi.get("file_size_mb", 0), 2)) + " MB  ("
                    + str(fi.get("file_size_bytes", 0)) + " bytes)",
                "- SHA-256: " + fi.get("sha256", "Unknown"),  # full hash, no truncation
                "- MD5:     " + fi.get("md5",    "Unknown"),
                "- SHA-1:   " + fi.get("sha1",   "Unknown"),
                "- Type:    " + fi.get("file_type", "Unknown"),
                "- Entropy: " + str(round(fi.get("entropy", 0), 2)),
                "",
            ]

        if "die" in tools and tools["die"].get("status") == "success":
            dd = tools["die"].get("data", {})
            parts += ["**Detect-it-Easy:**",
                      "- File Type: " + dd.get("file_type", "Unknown")]
            if dd.get("packer"):
                parts.append("- Packer: " + dd["packer"])
            parts.append("")

        if "pestudio" in tools and tools["pestudio"].get("status") == "success":
            pe        = tools["pestudio"].get("data", {})
            tech_hits = pe.get("technique_hits", {})
            anomalies = pe.get("anomalies", [])
            parts += [
                "**PE Analysis (pefile + pestudio-cli):**",
                "- Machine type:    " + pe.get("machine_type", "Unknown"),
                "- Import hash:     " + pe.get("imphash", "N/A"),
                "- Total imports:   " + str(len(pe.get("imports", []))),
                "- Suspicious APIs: " + str(len(pe.get("suspicious_apis", []))),
            ]
            if tech_hits:
                parts.append("- Technique cats:  " + ", ".join(tech_hits.keys()))
            if anomalies:
                parts.append("- Anomalies: " + "; ".join(anomalies[:5]))
            # pestudio-cli enrichment summary
            ps_packers  = pe.get("pestudio_packers", [])
            ps_bl_imp   = pe.get("pestudio_imports", [])
            ps_imp_sum  = pe.get("pestudio_import_summary", {})
            ps_bl_str   = pe.get("pestudio_blacklist_strings", [])
            ps_urls     = pe.get("pestudio_urls", [])
            if ps_packers:
                parts.append("- Packers (pestudio): " + ", ".join(ps_packers))
            if ps_imp_sum:
                parts.append("- Blacklisted imports (pestudio): "
                             + str(ps_imp_sum.get("blacklisted", 0))
                             + " / " + str(ps_imp_sum.get("total", 0)))
            if ps_bl_str:
                parts.append("- Blacklisted strings (pestudio): " + str(len(ps_bl_str)))
            if ps_urls:
                parts.append("- URLs found (pestudio): " + str(len(ps_urls)))
            parts.append("")


        if "ghidra" in tools and tools["ghidra"].get("status") == "success":
            gd = tools["ghidra"].get("data", {})
            decompiled = gd.get("decompiled", {})
            parts += [
                "**Ghidra Reverse Engineering:**",
                "- Functions found:    " + str(gd.get("function_count", 0)),
                "- Interesting hits:   " + str(len(gd.get("interesting", []))),
                "- Crypto constants:   " + str(len(gd.get("crypto_constants", []))),
                "- Decompiled funcs:   " + ", ".join(decompiled.keys()) if decompiled else "- Decompiled funcs:   none",
            ]
            parts.append("")

        if "strings" in tools and tools["strings"].get("status") == "success":
            sd = tools["strings"].get("data", {})
            parts += ["**Strings / IOC Extraction:**"]
            for key, label in [
                ("urls",          "URLs"),
                ("ips",           "IPs"),
                ("domains",       "Domains"),
                ("registry_keys", "Registry keys"),
                ("file_paths",    "File paths"),
                ("cmdlines",      "Command lines"),
                ("base64_blobs",  "Base64 blobs"),
            ]:
                items = sd.get(key, [])
                if items:
                    parts.append(
                        "- " + label + ": " + str(len(items))
                        + "  (first: " + str(items[0])[:80] + ")"
                    )
            parts.append("")

        _bh_result = tools.get("behavior_heuristics") or tools.get("behavior") or {}
        if _bh_result.get("status") == "success":
            bh        = _bh_result.get("data", {})
            sev       = bh.get("severity", "unknown").upper()
            behaviors = bh.get("behaviors", [])
            parts += [
                "**Behavioral Heuristics:**",
                "- Overall severity: " + sev,
                "- Score: " + str(bh.get("total_score", 0)),
            ]
            for b in behaviors:
                cat  = b.get("category", "?")
                bsev = b.get("severity", "?").upper()
                inds = b.get("indicators", [])
                parts.append("- [" + bsev + "] " + cat + ": " + ", ".join(inds[:3]))
            parts.append("")

        return "\n".join(parts)

    # -------------------------------------------------------------------------
    # Analyst brief — pre-digested signal for the LLM (not raw JSON)
    # -------------------------------------------------------------------------

    def _build_analyst_brief(self, analysis_results: Dict[str, Any]) -> str:
        """
        Produce a compact, human-readable brief that highlights the most
        analytically relevant signals BEFORE the raw JSON context.
        This dramatically improves local-model accuracy on family/intent questions.
        """
        tools = analysis_results.get("tools", {})
        if not tools and "tool_results" in analysis_results:
            tools = analysis_results["tool_results"].get("tools", {})

        lines: List[str] = []

        # --- File identity ---
        fi = tools.get("fileinfo", {}).get("data", {})
        if fi:
            lines.append("### File Identity")
            lines.append(f"- Name:    {fi.get('file_name', 'Unknown')}")
            lines.append(f"- SHA-256: {fi.get('sha256', 'Unknown')}")
            lines.append(f"- MD5:     {fi.get('md5', 'Unknown')}")
            lines.append(f"- Type:    {fi.get('file_type', 'Unknown')}")
            entropy = fi.get("entropy", 0)
            entropy_note = ""
            if entropy > 7.5:
                entropy_note = " ⚠ VERY HIGH — strongly suggests packing/encryption"
            elif entropy > 7.0:
                entropy_note = " ⚠ HIGH — likely packed or compressed"
            elif entropy > 6.5:
                entropy_note = " (elevated — possible obfuscation)"
            lines.append(f"- Entropy: {entropy:.2f}{entropy_note}")

        # --- Packer / compiler ---
        dd = tools.get("die", {}).get("data", {})
        if dd:
            lines.append("\n### Packer / Compiler (Detect-It-Easy)")
            lines.append(f"- File type: {dd.get('file_type', 'Unknown')}")
            if dd.get("packer"):
                lines.append(f"- ⚠ PACKER DETECTED: {dd['packer']}")
            if dd.get("compiler"):
                lines.append(f"- Compiler: {dd['compiler']}")

        # --- PE imports by capability ---
        pe = tools.get("pestudio", {}).get("data", {})
        if pe:
            lines.append("\n### PE Import Analysis")
            tech = pe.get("technique_hits", {})
            sus  = pe.get("suspicious_apis", [])
            imp_by_dll = pe.get("imports_by_dll", {})
            if tech:
                lines.append("**Technique categories detected from imports:**")
                for cat, apis in tech.items():
                    lines.append(f"  - {cat}: {', '.join(apis[:8])}")
            if sus:
                lines.append(f"**Total suspicious APIs: {len(sus)}**")
                lines.append(f"  First 20: {', '.join(sus[:20])}")
            if imp_by_dll:
                lines.append("**Imports grouped by DLL (top 10 DLLs):**")
                for dll, apis in list(imp_by_dll.items())[:10]:
                    lines.append(f"  - {dll}: {', '.join(apis[:8])}")
            ps_imp = pe.get("pestudio_imports", [])
            if ps_imp:
                lines.append(f"**Pestudio blacklisted imports ({len(ps_imp)}):** "
                              + ", ".join(str(i) for i in ps_imp[:15]))
            if pe.get("anomalies"):
                lines.append(f"**PE anomalies:** {'; '.join(pe['anomalies'][:5])}")
            if pe.get("compile_time"):
                lines.append(f"**Compile timestamp:** {pe['compile_time']}")
            sections = pe.get("sections", [])
            if sections:
                lines.append("**PE Sections:**")
                for s in sections[:8]:
                    lines.append(f"  - {s.get('name','?')}: entropy={s.get('entropy','?')}, "
                                  f"size={s.get('size','?')}, {s.get('characteristics','')}")

        # --- Strings / IOCs ---
        sd = tools.get("strings", {}).get("data", {})
        if sd:
            lines.append("\n### Extracted Strings & IOCs")
            for key, label in [
                ("ips",           "IP Addresses"),
                ("domains",       "Domains"),
                ("urls",          "URLs"),
                ("registry_keys", "Registry Keys"),
                ("cmdlines",      "Command Lines"),
                ("file_paths",    "File Paths"),
                ("base64_blobs",  "Base64 Blobs"),
            ]:
                items = sd.get(key, [])
                if items:
                    lines.append(f"**{label} ({len(items)}):** "
                                  + " | ".join(str(x)[:80] for x in items[:8]))
            kw = sd.get("suspicious_keywords", [])
            if kw:
                lines.append(f"**Suspicious keywords:** {', '.join(str(k) for k in kw[:20])}")

        # --- Behavioral heuristics ---
        bh_raw = tools.get("behavior_heuristics") or tools.get("behavior") or {}
        bh = bh_raw.get("data", {})
        if bh:
            lines.append("\n### Behavioral Heuristics")
            sev = bh.get("severity", "unknown").upper()
            lines.append(f"**Overall severity: {sev}  (score: {bh.get('total_score', 0)})**")
            for b in bh.get("behaviors", []):
                cat   = b.get("category", "?")
                bsev  = b.get("severity", "?").upper()
                score = b.get("score", 0)
                inds  = b.get("indicators", [])[:6]
                lines.append(f"  [{bsev}] {cat} (score {score}): {', '.join(inds)}")

        # --- Ghidra ---
        gd = tools.get("ghidra", {}).get("data", {})
        if gd:
            lines.append("\n### Ghidra Reverse Engineering")
            lines.append(f"- Functions: {gd.get('function_count', 0)}")
            interesting = gd.get("interesting", [])
            if interesting:
                lines.append(f"- Interesting function names: {', '.join(str(i) for i in interesting[:15])}")
            crypto = gd.get("crypto_constants", [])
            if crypto:
                lines.append(f"- Crypto constants: {', '.join(str(c) for c in crypto[:10])}")
            decompiled = gd.get("decompiled", {})
            if decompiled:
                lines.append(f"- Decompiled: {', '.join(list(decompiled.keys())[:8])}")

        # --- AI analysis summary (if already run) ---
        ai = analysis_results.get("ai_analysis", {})
        if not ai and "tool_results" not in analysis_results:
            pass  # skip
        if ai and ai.get("threat_summary"):
            lines.append("\n### Prior AI Assessment")
            lines.append(f"- Threat level: {ai.get('threat_level', '?').upper()}")
            lines.append(f"- Summary: {ai.get('threat_summary', '')}")
            findings = ai.get("key_findings", [])
            if findings:
                lines.append("- Key findings:")
                for f in findings[:5]:
                    lines.append(f"  • {f}")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Rich JSON context block for LLM
    # -------------------------------------------------------------------------

    def _get_analysis_context(self, analysis_results: Dict[str, Any]) -> str:
        tools = analysis_results.get("tools", {})
        if not tools and "tool_results" in analysis_results:
            tools = analysis_results["tool_results"].get("tools", {})

        ctx: Dict[str, Any] = {}

        if "fileinfo" in tools and tools["fileinfo"].get("status") == "success":
            fi = tools["fileinfo"]["data"]
            ctx["file_info"] = {
                "name":        fi.get("file_name",       "Unknown"),
                "size_bytes":  fi.get("file_size_bytes", 0),
                "size_mb":     fi.get("file_size_mb",    0),
                "sha256":      fi.get("sha256",          "Unknown"),
                "md5":         fi.get("md5",             "Unknown"),
                "sha1":        fi.get("sha1",            "Unknown"),
                "file_type":   fi.get("file_type",       "Unknown"),
                "magic":       fi.get("magic",           "Unknown"),
                "entropy":     fi.get("entropy",         0),
                "analyzed_at": fi.get("analyzed_at",     ""),
            }

        if "die" in tools and tools["die"].get("status") == "success":
            dd = tools["die"]["data"]
            ctx["detect_it_easy"] = {
                "file_type": dd.get("file_type", ""),
                "packer":    dd.get("packer",    None),
                "compiler":  dd.get("compiler",  None),
                "raw":       dd.get("output",    ""),
            }

        if "pestudio" in tools and tools["pestudio"].get("status") == "success":
            pe = tools["pestudio"]["data"]
            ctx["pe_analysis"] = {
                "machine_type":    pe.get("machine_type",    "Unknown"),
                "imphash":         pe.get("imphash",         ""),
                "imports_total":   len(pe.get("imports",     [])),
                "imports_flat":    pe.get("imports",         [])[:50],
                "imports_by_dll":  pe.get("imports_by_dll",  {}),
                "suspicious_apis": pe.get("suspicious_apis", []),
                "technique_hits":  pe.get("technique_hits",  {}),
                "anomalies":       pe.get("anomalies",       []),
                "sections":        pe.get("sections",        []),
                "exports":         pe.get("exports",         [])[:20],
                "compile_time":    pe.get("compile_time",    ""),
                # pestudio-cli enrichment
                "pestudio_blacklisted_imports": pe.get("pestudio_imports",           []),
                "pestudio_import_summary":      pe.get("pestudio_import_summary",    {}),
                "pestudio_packers":             pe.get("pestudio_packers",           []),
                "pestudio_blacklist_strings":   pe.get("pestudio_blacklist_strings", [])[:30],
                "pestudio_urls":                pe.get("pestudio_urls",              [])[:30],
            }

        if "strings" in tools and tools["strings"].get("status") == "success":
            sd = tools["strings"]["data"]
            ctx["strings_iocs"] = {
                "urls":                sd.get("urls",                [])[:30],
                "ips":                 sd.get("ips",                 [])[:30],
                "domains":             sd.get("domains",             [])[:30],
                "registry_keys":       sd.get("registry_keys",       [])[:30],
                "file_paths":          sd.get("file_paths",          [])[:20],
                "cmdlines":            sd.get("cmdlines",            [])[:20],
                "base64_blobs":        sd.get("base64_blobs",        [])[:10],
                "suspicious_apis":     sd.get("suspicious_apis",     [])[:50],
                "suspicious_keywords": sd.get("suspicious_keywords", [])[:30],
                "total_strings":       sd.get("total_strings",       0),
            }

        _bh_ctx = tools.get("behavior_heuristics") or tools.get("behavior") or {}
        if _bh_ctx.get("status") == "success":
            bh = _bh_ctx["data"]
            ctx["behavioral_analysis"] = {
                "overall_severity": bh.get("severity",           "unknown"),
                "total_score":      bh.get("total_score",         0),
                "categories_hit":   bh.get("categories_detected", []),
                "behaviors":        bh.get("behaviors",           []),
            }


        # ---- Ghidra reverse engineering ------------------------------------ #
        if "ghidra" in tools and tools["ghidra"].get("status") == "success":
            gd = tools["ghidra"]["data"]
            # Only include decompiled code if present (it's large)
            decompiled = gd.get("decompiled", {})
            ctx["ghidra"] = {
                "function_count":  gd.get("function_count", 0),
                "functions":       gd.get("functions",      [])[:30],
                "interesting":     gd.get("interesting",    [])[:20],
                "crypto_constants":gd.get("crypto_constants",[])[:20],
                "strings":         gd.get("strings",        [])[:100],
                "summary":         gd.get("summary",        {}),
                "decompiled_functions": list(decompiled.keys()),
                # Include C pseudocode (capped per function)
                "decompiled_code": {
                    k: v[:2000] for k, v in decompiled.items()
                },
            }

        ctx_json = json.dumps(ctx, indent=2, default=str)
        print("[CONTEXT] JSON context: " + str(len(ctx_json)) + " chars")
        return ctx_json

    # -------------------------------------------------------------------------
    # Resolve analysis data (memory then disk fallback)
    # -------------------------------------------------------------------------

    def _resolve_analysis(self, session_id: str, message: str) -> Optional[Dict]:
        if session_id in self.analysis_data:
            return self.analysis_data[session_id]

        msg_lower = message.lower()

        for fname, sid in self.file_name_to_session.items():
            if fname in msg_lower and sid in self.analysis_data:
                print("[CHAT] Resolved via name map: '" + fname + "' -> " + sid)
                return self.analysis_data[sid]

        for sid, data in self.analysis_data.items():
            fi = data.get("tools", {}).get("fileinfo", {}).get("data", {})
            n  = fi.get("file_name", "").lower()
            if n and n in msg_lower:
                print("[CHAT] Resolved via scan: '" + n + "' in " + sid)
                return data

        logs_dir = os.getenv("LOGS_DIR", "analysis_logs")
        target   = os.path.join(logs_dir, session_id, "complete_analysis.json")

        def _load_json(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    d = json.load(f)
                # Keep the full document so ai_analysis is available for the brief
                # but normalise the tools key to the flat {"tools": {...}} shape
                if "tool_results" in d:
                    merged = dict(d["tool_results"])   # {"tools": {...}}
                    merged["ai_analysis"] = d.get("ai_analysis", {})
                    return merged
                return d
            except Exception:
                return None

        if os.path.exists(target):
            data = _load_json(target)
            if data:
                self.analysis_data[session_id] = data
                fi   = data.get("tools", {}).get("fileinfo", {}).get("data", {})
                name = fi.get("file_name", "")
                if name:
                    self.file_name_to_session[name.lower()] = session_id
                print("[CHAT] Loaded analysis from disk for session " + session_id)
                return data

        if os.path.isdir(logs_dir):
            for sess_dir in os.listdir(logs_dir):
                cf = os.path.join(logs_dir, sess_dir, "complete_analysis.json")
                if not os.path.isfile(cf):
                    continue
                data = _load_json(cf)
                if not data:
                    continue
                fi = data.get("tools", {}).get("fileinfo", {}).get("data", {})
                n  = fi.get("file_name", "").lower()
                if n and n in msg_lower:
                    self.analysis_data[sess_dir]        = data
                    self.file_name_to_session[n]        = sess_dir
                    print("[CHAT] Loaded from disk scan: '" + n + "' in " + sess_dir)
                    return data

        print("[CHAT] No analysis data found for session " + session_id)

        return None

    # -------------------------------------------------------------------------
    # Main chat entry point
    # -------------------------------------------------------------------------

    def chat(
        self,
        session_id:   str,
        user_message: str,
        file_name:    Optional[str] = None,
        file_hash:    Optional[str] = None,
    ) -> str:
        print("[CHAT] session=" + session_id + "  client=" + str(bool(self.client))
              + "  err=" + str(self.init_error))

        if not self.client:
            if self.init_error:
                suffix = ("Make sure Ollama is running (`ollama serve`)."
                          if self.llm_provider == "ollama"
                          else "Check OPENAI_API_KEY.")
                return "LLM client failed to initialize: " + self.init_error + ".  " + suffix
            return (
                "LLM client not initialized. "
                "Run `ollama serve` and ensure LLM_PROVIDER=ollama in your .env, "
                "or set OPENAI_API_KEY."
            )

        if session_id not in self.chat_memories:
            self.chat_memories[session_id] = [
                {"role": "system", "content": self._system_prompt()}
            ]

        analysis_data = self._resolve_analysis(session_id, user_message)

        # Direct fact resolver -- skips LLM for simple factual questions
        if analysis_data:
            direct = self._try_direct_answer(user_message, analysis_data)
            if direct:
                print("[CHAT] Answered directly (no LLM call)")
                self.chat_memories[session_id].append({"role": "user", "content": user_message})
                self.chat_memories[session_id].append({"role": "assistant", "content": direct})
                return direct

        self.chat_memories[session_id].append({"role": "user", "content": user_message})
        messages = list(self.chat_memories[session_id])

        if analysis_data:
            ctx_json = self._get_analysis_context(analysis_data)
            brief    = self._build_analyst_brief(analysis_data)
            fi       = (analysis_data.get("tools", {})
                                     .get("fileinfo", {})
                                     .get("data", {}))
            fname    = fi.get("file_name", "the analyzed file")
            context_msg = (
                "=== STATIC ANALYSIS RESULTS FOR: `" + fname + "` ===\n\n"
                "## ANALYST BRIEF (key indicators — read this first)\n"
                + brief + "\n\n"
                "## COMPLETE RAW DATA (JSON — all tool outputs)\n"
                "```json\n" + ctx_json + "\n```\n\n"
                "The data above is complete and authoritative. "
                "Answer the user's question by reasoning from these specific values. "
                "Never say the data is unavailable or incomplete."
            )
            messages.insert(-1, {"role": "system", "content": context_msg})

        elif file_name or file_hash:
            meta = "File Name: " + (file_name or "Unknown") + "\nSHA-256: " + (file_hash or "Unknown") + "\n"
            messages.insert(-1, {
                "role": "system",
                "content": "File metadata for this session:\n" + meta + "\nAnswer hash/name questions from this data directly.",
            })
        else:
            messages.insert(-1, {
                "role": "system",
                "content": "No analysis data is available for this session yet. Ask the user to upload a file first.",
            })

        # ── Family/intention questions: inject explicit reasoning scaffold ──────
        _family_keywords = (
            "family", "famil", "what is it", "what malware", "what type",
            "what kind", "intentions", "purpose", "what does it do",
            "identify", "classification", "category", "variant", "strain",
            "rat", "stealer", "ransomware", "backdoor", "loader", "dropper",
        )
        _msg_lower = user_message.lower()
        if any(kw in _msg_lower for kw in _family_keywords) and analysis_data:
            brief = self._build_analyst_brief(analysis_data)
            scaffold = (
                "The analyst is asking about malware family/type/intentions. "
                "Use the three-layer framework from your instructions:\n\n"
                "ANALYST BRIEF (pre-processed indicators):\n" + brief + "\n\n"
                "Now reason through:\n"
                "1. STRUCTURAL — what do the strings, imports, compiler, hashes tell you?\n"
                "2. OPERATIONAL — what is this sample's purpose and target platform?\n"
                "3. ATTRIBUTION — any mutex names, port numbers, or known artifact strings?\n\n"
                "Commit to a best-guess family with confidence level. "
                "Cite specific evidence values (actual API names, strings, ports). "
                "Do NOT say you cannot determine the family."
            )
            messages.insert(-1, {"role": "system", "content": scaffold})

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.2,
                max_tokens=2000,
                timeout=120,
            )
            ai_response = response.choices[0].message.content
            self.chat_memories[session_id].append({"role": "assistant", "content": ai_response})
            return ai_response
        except Exception as e:
            error_msg = (
                "I encountered an error while processing your request: " + str(e) + ". "
                "Check that Ollama is running and the model is available."
            )
            self.chat_memories[session_id].append({"role": "assistant", "content": error_msg})
            return error_msg

    # -------------------------------------------------------------------------
    # Batch analysis entry point (called by server.py after upload)
    # -------------------------------------------------------------------------

    def analyze_with_ai(self, analysis_results: Dict[str, Any], session_id: str) -> Dict[str, Any]:
        if not self.client:
            return {
                "status": "error",
                "error":  "LLM client not configured",
                "ai_analysis": {
                    "threat_level":        "unknown",
                    "threat_summary":      (
                        "AI analysis unavailable. "
                        "Start Ollama (`ollama serve`) or set OPENAI_API_KEY."
                    ),
                    "key_findings":        [],
                    "behavioral_analysis": "LLM not reachable.",
                    "iocs":                {},
                    "recommendations":     ["Run: ollama pull " + self.model],
                },
            }

        self.add_analysis_to_memory(session_id, analysis_results)

        ctx_json = self._get_analysis_context(analysis_results)
        summary  = self._create_analysis_summary(analysis_results)

        brief = self._build_analyst_brief(analysis_results)

        prompt = (
            "You are a senior malware analyst performing static analysis triage.\n\n"
            "=== ANALYST BRIEF (pre-digested indicators) ===\n"
            + brief + "\n\n"
            "=== FULL ANALYSIS DATA (JSON) ===\n"
            + ctx_json + "\n"
            "=== END ===\n\n"
            "Using ALL evidence above, identify the malware family if possible.\n"
            "Common families: AsyncRAT, NjRAT, QuasarRAT, XWorm, RedLine, AgentTesla, "
            "Emotet, Cobalt Strike, Metasploit, njRAT, DarkComet, Remcos, LokiBot, "
            "FormBook, AveMaria, BitRAT, DCRat, Nanocore, Warzone, PureLogs.\n\n"
            "Respond ONLY with a valid JSON object (no markdown, no code fences):\n"
            "{\n"
            "  \"threat_level\": \"low\" | \"medium\" | \"high\" | \"critical\",\n"
            "  \"malware_family\": \"AsyncRAT\" (or \"Unknown\" if genuinely uncertain),\n"
            "  \"malware_type\": \"RAT\" | \"Stealer\" | \"Loader\" | \"Backdoor\" | \"Ransomware\" | \"Worm\" | \"Unknown\",\n"
            "  \"threat_summary\": \"2-3 sentence description of what this sample does\",\n"
            "  \"key_findings\": [\"specific evidence string 1\", \"specific evidence string 2\"],\n"
            "  \"behavioral_analysis\": \"detailed description of capabilities and techniques\",\n"
            "  \"iocs\": {\n"
            "    \"ips\": [],\n"
            "    \"domains\": [],\n"
            "    \"urls\": [],\n"
            "    \"file_paths\": [],\n"
            "    \"registry_keys\": []\n"
            "  },\n"
            "  \"behavior_tags\": [\"C2 Communication\", \"Process Injection\"],\n"
            "  \"recommendations\": [\"actionable step 1\", \"actionable step 2\"]\n"
            "}"
        )

        try:
            api_kwargs: Dict[str, Any] = dict(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert malware analyst. Respond with valid JSON only.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
                max_tokens=4096,
                timeout=300,
            )
            if self.llm_provider == "openai":
                api_kwargs["response_format"] = {"type": "json_object"}

            response = self.client.chat.completions.create(**api_kwargs)
            raw      = response.choices[0].message.content.strip()

            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
                raw = raw.strip()
            # Strip trailing ``` if present
            if raw.endswith("```"):
                raw = raw[:-3].strip()

            ai_analysis = _parse_llm_json(raw)
            return {
                "status":      "success",
                "ai_analysis": ai_analysis,
                "timestamp":   datetime.now().isoformat(),
            }
        except Exception as e:
            print("[AI] analyze_with_ai error: " + str(e))
            return {
                "status": "error",
                "error":  str(e),
                "ai_analysis": {
                    "threat_level":        "unknown",
                    "threat_summary":      "Error during AI analysis: " + str(e),
                    "key_findings":        [],
                    "behavioral_analysis": "",
                    "iocs":                {},
                    "recommendations":     ["Check Ollama / API key configuration"],
                },
            }
