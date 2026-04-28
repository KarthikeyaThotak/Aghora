# LATAM Threat Groups & AGHORA — Speaker Notes
## ISC² Detroit Chapter Presentation | April 28, 2025
**Karthikeya Thota | Eastern Michigan University**

> **Timing Guide:** Your slot = 30 minutes (after Prof. Chris's 20 min) + 10 min Q&A
> Pace: ~1–1.5 min per content slide. Move calmly but swiftly.
> Audience: Managers, engineers, ops folks at all career levels. Mix of in-person + online.

---

## Slide 1 — Title (~30 sec)

Thanks for that introduction, Professor Chris. Good evening everyone — both those of you here in the room and those joining us online. My name is Karthikeya Thota — I'm a cybersecurity student at Eastern Michigan University, and tonight I want to take you inside the world of Latin American threat actors. We'll look at who they are, what they're building, and why it matters to every defender in this room. Then I'll demo a tool I built to automate the kind of analysis we're about to discuss.

---

## Slide 2 — $ whoami (~1.5 min)

Quick background so you know where I'm coming from. I'm on a combined BS/MS track at EMU, focused on digital forensics, malware analysis, and secure software development. I run a Proxmox-based home lab where I actually sandbox malware — so what I'm sharing tonight comes from hands-on research, not just reading papers.

I've competed in about eight hackathons and CTF competitions, mostly in AI and cybersecurity categories. The biggest output of that work is AGHORA — an AI-powered malware analysis platform I built from scratch, which we'll walk through at the end.

Proud to be part of this chapter, and excited to give something back tonight.

---

## Slide 3 — Research Objective (~1 min)

Here's the question that drove this entire research effort — and I want you to hold it in mind as we go through the threat families:

*Are LATAM actors isolated criminal groups acting independently, or are they a coordinated innovation ecosystem that shares techniques and infrastructure?*

That framing completely changes how you defend against them. I looked at groups and families active from 2024 to 2026, mapped their tactics to MITRE ATT&CK, and extracted real campaign artifacts to compare them side by side.

---

## Slide 4 — Why LATAM Matters (~1.5 min)

Why does this matter to practitioners in North America? Because these threats are no longer regional.

LATAM banking malware is now appearing in European and North American campaigns. In 2024 we saw an international law enforcement operation take down Grandoreiro — but here's the lesson: **disruption is not elimination.** The infrastructure, the knowledge, the code survived.

These actors also iterate faster than most enterprise teams can write signatures. They're abusing legitimate cloud infrastructure — Google Cloud Run, commodity VPS providers — which means traditional IP blocklists don't catch them.

The bottom line: the operational maturity of these groups is now comparable to global threat actors.

---

## Slide 5 — Blind Eagle / APT-C-36 (~1.5 min)

Blind Eagle targets Colombia and broader Latin American government and financial sectors. What makes them notable is their **speed** — they adopt new exploits extremely quickly after patches drop. That tells you they're actively monitoring vulnerability disclosures and pivoting fast.

Their delivery uses spear phishing with weaponized attachments, web-based staging, and WebDAV for payload URLs. C2 domains have very short TTLs — they burn through infrastructure to stay ahead of blocklists.

From an artifact perspective: look for phishing lure templates, WebDAV staging URLs, and registry persistence entries.

---

## Slide 6 — Grandoreiro (~1.5 min)

Grandoreiro is the one most of you have probably heard of — it was the target of the 2024 international enforcement action. But this is a critical case study: **despite the disruption, the capability didn't disappear.**

This family used a modular loader architecture, DGA-based C2 resolution, and spread itself through Outlook client abuse. The overlay attacks targeting banking UIs are sophisticated — they intercept credentials in real time.

The LNK and ZIP delivery chain it uses is still incredibly common today because it still works.

Takeaway: law enforcement action buys time. It doesn't solve the underlying ecosystem problem.

---

## Slide 7 — Mispadu & Mekotio (~1.5 min)

These two share a nearly identical delivery chain: phishing → ZIP → LNK → PowerShell → payload. Almost algorithmic at this point.

Both focus on credential harvesting, clipboard monitoring — important if you have anyone in your org handling cryptocurrency — and banking overlays that mimic major financial institution UIs.

The insight I want to highlight is at the bottom: **consistent refinement, not radical redesign.** These developers are not rewriting from scratch every few months. They have a structured development lifecycle. That's discipline you'd expect from a professional software team — not from what we typically think of as crimeware.

---

## Slide 8 — Lampion & CHAVECLOAK (~1 min)

Both of these emerged or significantly evolved in 2024. Both use DLL sideloading — a technique where a legitimate, signed Windows binary loads a malicious DLL because of how the OS resolves search paths.

CHAVECLOAK's chain is: PDF lure → ZIP → DLL sideload. Clean initial execution that looks completely benign at first glance.

For detection: look for DLL sideload file pairs, parent-child process anomalies, and consistent file path staging patterns.

---

## Slide 9 — CostaRicto (~1 min)

CostaRicto is fundamentally different from everything else on this list. It's a **hack-for-hire, mercenary espionage operation.**

Custom tooling that doesn't appear anywhere in the shared crimeware ecosystem — which makes attribution significantly harder. Multi-hop SSH tunneling for C2 to obscure operator origin.

And critically: they prioritize **long dwell time** over rapid monetization. They're not there to steal your credentials today. They're there to stay hidden for months.

That is a completely different threat model — requiring detection strategies built around behavioral anomalies over time, not fast IOC matching.

---

## Slide 10 — Infrastructure & Delivery Trends (~1.5 min)

When you look across all of these families together, five infrastructure patterns repeat consistently:

1. **Cloud abuse** — legitimate cloud platforms used for payload hosting bypasses IP-based controls
2. **Short-lived domain rotation** — blocklists can't keep up
3. **Modular loaders decoupled from payloads** — catching the loader doesn't catch the implant
4. **PowerShell with multi-layer encoding** — still the dominant living-off-the-land technique
5. **DLL sideloading via trusted signed binaries**

Key observation: these delivery innovations are **shared across families.** That's the ecosystem signal.

---

## Slide 11 — Artifact Extraction Methodology (~1 min)

For those interested in the research methodology — I organized extraction into three categories: **delivery artifacts** (email headers, lure attachments, encoded PowerShell), **host artifacts** (registry run keys, scheduled tasks, process tree anomalies), and **network artifacts** (C2 endpoints, TLS fingerprint patterns, DNS resolution timing).

This framework is repeatable — you can apply it in your own environments to build detection logic grounded in actual observed behavior, rather than vendor intelligence alone.

---

## Slide 12 — MITRE ATT&CK Mapping (~1 min)

Mapping to MITRE gives us a common vocabulary for defense. What stands out is the consistency across families — T1566 phishing, T1059 PowerShell, T1547 registry persistence, T1027 obfuscation.

But the one I want to call out specifically is **T1218 — Signed Binary Proxy Execution.** LOLBin abuse.

If you are not actively monitoring for legitimate Windows binaries being used to proxy malicious execution in your environment right now, you have a significant blind spot.

---

## Slide 13 — Evolution Signals 2024–2026 (~1.5 min)

This slide is about where these actors are heading.

Between 2024 and 2026, I documented five evolution signals: **AMSI bypass** is now standard — payloads are being engineered specifically to evade Windows' Antimalware Scan Interface. **Multi-layer encoding** is routine. **Infrastructure decentralization** across cloud, VPS, and bulletproof hosts. **Shorter iteration cycles** — the window from patch to exploit is compressing. And **loader-payload decoupling** as standard practice.

My conclusion: this is structured, professional software development. Not ad hoc crimeware.

---

## Slide 14 — Ecosystem-Level Analysis (~1.5 min)

This is the insight I'm most proud of in this research.

Instead of analyzing each family in isolation — which is the standard approach in most threat intel reports — I compared them **as an ecosystem.** The hypothesis: LATAM actors operate within a loosely connected innovation network where delivery method innovations propagate faster than malware codebases.

Think about what that means for defenders: **when you see a new delivery technique appear in one family, assume other families are testing it within weeks.** That's an actionable intelligence principle, not just an academic observation.

---

## Slide 15 — Defensive Implications (~1.5 min)

Five practical takeaways:

1. **Signature detection is losing the race** — these actors iterate faster than signatures can track
2. **Behavioral PowerShell monitoring is non-negotiable** — multi-layer encoding is standard
3. **Hunt abnormal process trees** — Office spawning scripting engines is a durable signal that doesn't go stale
4. **Build detections around shared TTPs, not malware names** — IOC-based detections expire in weeks
5. **Correlate infrastructure intelligence** — short-TTL domains, cloud provider abuse, TLS fingerprint reuse signal actor patterns that persist across campaigns

---

## Slide 16 — Strategic Conclusion (~1 min)

To close the threat research portion: LATAM actors are no longer regionally confined. They show professional development discipline. Their infrastructure is becoming more agile, not less. Delivery innovation propagates ecosystem-wide.

And your detection strategy must be **behavior-focused, not malware-brand-focused.**

The true defensive advantage comes from tracking how they evolve — not chasing their names.

Now — let me show you what I built to apply exactly this kind of analysis automatically to any binary.

---

## Slide 17 — AGHORA Demo (Section Divider) (~15 sec)

This is AGHORA — **Agentic Guided Heuristic, Orchestration, Reasoning, and Analysis.** An AI-powered malware analysis platform I built from scratch. Let me show you what it does.

---

## Slide 18 — What is AGHORA? (~2 min)

The problem I set out to solve: manual malware analysis doesn't scale. Every binary that crosses an analyst's desk needs PE analysis, string extraction, maybe decompilation, MITRE mapping, and a written report. These tools all exist — PE Studio, Ghidra, various LLMs — but they're siloed. You use them separately, correlate the results manually, then write everything up yourself.

AGHORA unifies all of that into a single agentic pipeline. Drop in a file, get a complete AI-authored threat intelligence report in minutes.

And it runs **entirely locally** — no cloud, no API keys, no sending sensitive malware samples to a third-party API. For anyone in an air-gapped or sensitive environment, that's not a nice-to-have. That's a requirement.

---

## Slide 19 — AGHORA Analysis Pipeline (~2 min)

Five stages.

**Stage 1 — File Upload:** Any binary — EXE, DLL, ZIP. Hash computed, session created, EICAR detection runs immediately.

**Stage 2 — Static Analysis:** PE Studio CLI and DIE run automatically — PE sections, imports, strings, entropy, packer detection.

**Stage 3 — Ghidra Headless Decompilation:** No GUI, no clicking through menus. AGHORA calls Ghidra from the command line, decompiles the binary, extracts suspicious functions and Win32 API calls.

**Stage 4 — AI Reasoning:** The local LLM — running on Ollama — synthesizes all evidence from stages one through three and writes an actual analyst narrative, citing specific evidence from the binary itself.

**Stage 5 — PDF Report:** MITRE-mapped, IOC appendix, AI-written assessment. One file in. Full report out.

*[If doing live demo: let me switch over and show you a real run now.]*

---

## Slide 20 — AGHORA Key Achievements (~1.5 min)

The highlights: full-stack integration — React frontend, FastAPI backend, Python analysis engine, all connected end-to-end.

The Ghidra headless integration was the hardest piece — getting automated decompilation working reliably in a pipeline without a GUI took real engineering effort.

The local LLM narrative is what I'm most excited about — the AI cites specific binary evidence: entropy values, suspicious imports, decompiled function names — not generic boilerplate text.

Real-time WebSocket tracking means you watch the analysis progress step by step in your browser as it runs.

And MITRE auto-mapping generates a visual IOC graph you can actually explore interactively.

**For everyone in this room who is looking for free, useful tooling: this runs on commodity hardware with no subscription costs.**

---

## Slide 21 — References (~15 sec)

Here are the primary sources for the research — MITRE ATT&CK, INTERPOL, CrowdStrike, Cisco Talos, Palo Alto Unit 42, Trend Micro, and Kaspersky Securelist. Happy to share any of these directly.

Professor Chris and I will both take questions now. If you have specific technical questions about the tool or the research methodology, I'd love to dig into those.

---

## Q&A Guide (~10 min, shared with Prof. Chris)

**Likely questions and talking points:**

- *"How long did AGHORA take to build?"* — Several months of evenings and weekends, iterating component by component. Started with the backend pipeline, then the LLM layer, then the frontend.

- *"Is AGHORA open source / can we access it?"* — Share your contact info. It's a research project currently; you're open to conversations about it.

- *"How accurate is the MITRE mapping?"* — It's automated heuristic-based, not perfect. It's meant to surface candidates for analyst review, not replace analyst judgment.

- *"What hardware do you need?"* — Any decent workstation. The LLM runs locally via Ollama — 16GB+ RAM recommended, not GPU-dependent.

- *"How do LATAM actors compare to nation-state actors?"* — CostaRicto shows characteristics closer to nation-state tradecraft (dwell time, custom tooling). Banking groups are more crimeware-grade but closing the gap operationally.

- *"What's next for your research?"* — Publishable paper on the ecosystem-level analysis. More automation in AGHORA. Potentially extending to dynamic analysis.

---

*Good luck — you've got this. Move calmly, make eye contact, and enjoy it.*
