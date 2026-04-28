# Full Speaker Transcript — Bullet Point Format
## ISC² Detroit Chapter | April 28, 2025
**Karthikeya Thota | Eastern Michigan University**

> **Your slot:** 30 minutes + 10 min Q&A (shared with Prof. Chris)
> **How to use this:** Each bullet is a talking point, not a line to read verbatim. Glance, speak naturally, move on.

---

## Slide 1 — Title
### *~30 seconds*

- Good evening — welcome to everyone in the room and online
- Name: Karthikeya Thota, cybersecurity student at Eastern Michigan University
- Tonight: inside the Latin American threat landscape — groups more sophisticated than most people realize
- Then: live demo of a tool I built that automates this exact kind of analysis
- Let's get into it

---

## Slide 2 — $ whoami
### *~1.5 minutes*

- BS/MS combined track at EMU — malware analysis and offensive security
- GDSC (Google Developer Student Club) Vice President — if you're going to Google I/O, you'll see me there
- Home lab: Proxmox setup where I actually sandbox and run malware in a controlled environment — this comes from hands-on research, not just papers
- 8x hackathon and CTF winner across Michigan — mostly AI and cybersecurity categories
- Biggest project: **AGHORA** — AI-powered malware analysis platform, built from scratch — we'll get to it at the end
- Happy to be part of this chapter — excited to share what I've been working on

---

## Slide 3 — Research Objective
### *~1 minute*

- The question driving this research: **Are LATAM threat actors isolated criminal gangs — or a connected ecosystem sharing techniques and infrastructure?**
- That framing completely changes how you defend against them
- Scope: groups active 2024–2026
- Methodology: pulled real campaign artifacts, mapped to MITRE ATT&CK, compared families side by side
- Hold that question in mind as we walk through the groups

---

## Slide 4 — Why LATAM Matters
### *~1.5 minutes*

- **Not regional threats anymore** — LATAM banking malware is showing up in North American and European campaigns
- **Grandoreiro as the case study:** 2024 international law enforcement takedown — and the capability survived
  - Infrastructure survived. Knowledge survived. People adapted.
  - Lesson: disruption ≠ elimination
- **Faster iteration than defenders:** these groups update tools faster than enterprise teams can write signatures
- **Cloud abuse:** abusing Google Cloud Run and commodity VPS — traffic looks clean, controls give it a pass
- **Bottom line:** operational maturity now comparable to global threat actors — not script kiddies

---

## Slide 5 — Blind Eagle (APT-C-36)
### *~1.5 minutes*

Okay, first group — Blind Eagle, also tracked as APT-C-36.

- **Who they are:** Target Colombian and broader Latin American government and financial sectors
- **What sets them apart — speed:** When a new vulnerability drops, they move fast. Very short window between a patch release and a weaponized exploit. They're actively watching vulnerability disclosures — this isn't opportunistic, it's deliberate.
- **Delivery chain:** Spear phishing with weaponized attachments → web-based staging infrastructure → WebDAV for payload URLs
- **C2 infrastructure:** Very short TTLs on domains — constantly burning through infrastructure to stay ahead of blocklists
- **Artifact signals to hunt for:** Phishing lure templates, WebDAV staging URLs, registry persistence entries

---

## Slide 6 — Grandoreiro
### *~1.5 minutes*

- **Who they are:** Probably the most well-known LATAM banking trojan — targeted by 2024 international law enforcement action
- **The lesson from the takedown:** capability didn't disappear
  - Modular architecture — loader separate from payload
  - Knowledge is still out there; not everyone was arrested
- **Technical profile:**
  - DGA-based C2 — you can't block a static domain list
  - Spread via Outlook client abuse
  - Banking overlay attacks — fake login page rendered over real bank site, credentials intercepted in real time
- **Delivery:** LNK files inside ZIPs — still one of the most common techniques in the wild today, because it still works
- **Takeaway:** Law enforcement buys time. It doesn't solve the ecosystem problem.

---

## Slide 7 — Mispadu & Mekotio
### *~1.5 minutes*

- **Origins:** Both originate from Brazil, active since ~2019, significant evolution through 2024–2025
- **Mispadu targets:** Brazil, Mexico, Chile — financial sector users and everyday banking customers
- **Mekotio targets:** Same region, plus expansion into Spanish-speaking Europe (particularly Spain)
- **Why cover together — nearly identical delivery chain:**
  - Phishing email → ZIP → malicious LNK → PowerShell → payload
  - Consistent, repeatable, keeps working because users keep clicking
- **Capabilities:**
  - Credential harvesting
  - Clipboard monitoring — if anyone in your org handles crypto, wallet addresses get captured
  - Banking overlay attacks — fake login pages on top of real bank sites
- **Key insight:** Codebases are not rewritten — they are *refined*. Regular update cycles, consistent structure across versions. That is a professional software development lifecycle — not ad hoc crimeware.

---

## Slide 8 — Lampion & CHAVECLOAK
### *~1 minute*

- **Lampion:** Active since 2019, operates in Portugal and Brazil, targets banking customers with Portuguese-language lures
- **CHAVECLOAK:** Newer — emerged 2023, evolved through 2024, targeting Brazilian users and financial institutions
- **Both made a significant technical pivot: DLL sideloading**
  - Windows apps sometimes load DLLs from the same folder as the executable
  - Attacker drops a malicious DLL with the right name → signed, trusted app loads it for them
  - No unsigned code running directly. No obvious alert. Malicious execution behind a trusted binary.
- **CHAVECLOAK's full chain:** PDF lure → ZIP → DLL sideload setup — initial execution looks completely benign
- **Detection signals:** DLL sideload file pairs (signed EXE next to unexpected DLL), unusual parent-child process relationships, consistent file path staging patterns

---

## Slide 9 — CostaRicto
### *~1 minute*

- **Fundamentally different from everything else on this list**
- **Who they are:** Hack-for-hire — mercenary cyber espionage operation. Someone pays them to get in, they get in.
- **Custom tooling** — doesn't appear anywhere in the shared crimeware ecosystem; makes attribution significantly harder
- **C2:** Multi-hop SSH tunneling to obscure operator origin
- **Priority: dwell time, not speed** — not there to steal credentials today; there to stay hidden for months
- **Why this matters:** Completely different threat model
  - Requires detection strategies built around behavioral anomalies over time
  - IOC matching won't find them — they're not reusing known tools
- **Contrast:** Banking groups are crimeware-grade in objectives; CostaRicto looks more like nation-state tradecraft

---

## Slide 10 — Infrastructure & Delivery Trends
### *~1.5 minutes*

Five patterns that repeat consistently across all groups:

- **Cloud abuse** — legitimate platforms (Google Cloud Run, VPS) used to host payloads; network controls give it a pass because it looks clean
- **Short-lived domain rotation** — TTLs so short that blocklists can't keep up
- **Modular loaders decoupled from payloads** — catching the loader doesn't mean you have the full picture
- **Multi-layer encoded PowerShell** — still the dominant living-off-the-land technique; it survives everything
- **DLL sideloading via signed trusted binaries**

- **The signal:** These innovations are spreading *across* families — not coincidence. That's the ecosystem at work.

---

## Slide 11 — Artifact Extraction Methodology
### *~1 minute*

Three extraction categories — repeatable framework you can apply in your own environment:

- **Delivery artifacts:** Email headers, lure attachments, encoded PowerShell commands
- **Host artifacts:** Registry run keys, scheduled tasks, process tree anomalies
- **Network artifacts:** C2 endpoints, TLS fingerprint patterns, DNS resolution timing

- **Why this matters:** You're building detection logic from observed behavior — not waiting for a vendor IOC list

---

## Slide 12 — MITRE ATT&CK Mapping
### *~1 minute*

- **Common techniques across all families:**
  - T1566 — Phishing
  - T1059 — PowerShell
  - T1547 — Registry persistence
  - T1027 — Obfuscation
- **The one to call out: T1218 — Signed Binary Proxy Execution (LOLBins)**
  - Shows up in almost every family covered tonight
  - If you're not actively monitoring legitimate Windows binaries being used to proxy malicious execution — **that is a genuine blind spot**

---

## Slide 13 — Evolution Signals (2024–2026)
### *~1.5 minutes*

Five documented evolution signals — where these actors are heading:

- **AMSI bypass is now standard** — payloads engineered specifically to evade Windows' Antimalware Scan Interface; built in, not an afterthought
- **Multi-layer encoding is routine** — stacking encoding on encoding to defeat static analysis
- **Infrastructure decentralization** — spread across cloud providers and bulletproof hosts; no single disruption point
- **Shorter iteration cycles** — window from patch release to exploit in the wild is compressing
- **Loader-payload decoupling by default**

- **Conclusion:** This is structured software engineering with release cycles and deliberate iteration — not ad hoc crimeware

---

## Slide 14 — Ecosystem-Level Analysis
### *~1.5 minutes*

- **Standard approach:** Analyze each family in isolation — here's what Grandoreiro does, here's what Mekotio does
- **This research:** Compared them *as an ecosystem* — delivery chain similarities, infrastructure overlap, timing of technique adoption
- **Finding:** Delivery method innovations propagate across groups **faster than malware codebases do**
- **What that means practically:**
  - New delivery technique appears in one LATAM family → others are testing it within weeks
  - Don't assume a new technique is isolated to one group
- **This is actionable:** Changes how you prioritize detection work — build for the technique, not the family name

---

## Slide 15 — Defensive Implications
### *~1.5 minutes*

Five practical takeaways:

- **Signature detection is losing the race** — these groups iterate faster than signatures can track; by the time a sig is deployed, they've moved
- **Behavioral PowerShell monitoring is non-negotiable** — multi-layer encoding is standard; static detection won't catch it
- **Hunt abnormal process trees** — Office spawning PowerShell spawning wscript is a durable behavioral signal; doesn't depend on any specific IOC
- **Build detections around TTPs, not malware names** — IOCs expire in weeks; behavioral detections last years
- **Correlate infrastructure intelligence** — short-TTL domains, cloud provider abuse, TLS fingerprint reuse are actor-level patterns that persist across campaigns and across groups

---

## Slide 16 — Strategic Conclusion
### *~1 minute*

- LATAM actors are no longer regionally confined
- They show professional development discipline
- Infrastructure is getting more agile, not less
- Delivery innovation spreads ecosystem-wide
- **Your detection strategy must be behavior-focused, not malware-brand-focused**
- The real advantage: tracking *how* they evolve — not chasing what they've already done

- *Transition:* Now let me show you what I built to apply exactly this kind of analysis automatically to any binary.

---

## Slide 17 — AGHORA (Section Divider)
### *~15 seconds*

- **AGHORA** — Agentic Guided Heuristic, Orchestration, Reasoning, and Analysis
- AI-powered malware analysis platform, built from scratch
- Let me show you what it does

---

## Slide 18 — What is AGHORA?
### *~2 minutes*

- **The problem:** Proper malware analysis is multi-tool and manual
  - PE structure, imports, packer detection, string extraction, decompilation, MITRE mapping, written report
  - All the tools exist — PE Studio, Ghidra, LLMs — but they're siloed
  - Context-switching between five tools, manual correlation, write-up yourself. For one sample. Then do it again.
- **That doesn't scale**
- **AGHORA's solution:** Single automated pipeline — drop in a file, get a complete AI-authored threat intelligence report in minutes
  - MITRE-mapped, IOC appendix, full analyst narrative
- **Runs completely locally** — no cloud, no API keys, no sending malware samples to third-party services
  - For air-gapped or sensitive environments, that's not a nice-to-have — it's a hard requirement

---

## Slide 19 — DEMO
### *[ === SHOW THE DEMO === ]*

---

## Slide 20 — AGHORA Key Achievements
### *~1.5 minutes*

- **Full-stack integration:** React frontend + FastAPI backend + Python analysis engine — connected and communicating in real time
- **Ghidra headless integration** — biggest technical challenge
  - Automated decompilation inside a pipeline, no GUI, no manual steps
  - Took significant iteration to get reliable
- **LLM narrative quality** — not a template with values filled in
  - Model reasons about the evidence and explains what it means
  - Cites specific entropy values, suspicious imports, decompiled function names from the actual sample
- **Real-time WebSocket tracking** — watch the analysis pipeline step by step in your browser as it runs
- **MITRE auto-mapping + interactive IOC graph** — explore indicator relationships visually
- **Runs on commodity hardware** — no GPU required, 16GB+ RAM, zero subscription or cloud costs

---

## Slide 21 — References
### *~15 seconds*

- Sources: MITRE ATT&CK, INTERPOL, CrowdStrike, Cisco Talos, Palo Alto Unit 42, Trend Micro, Kaspersky Securelist
- Happy to share any of these directly
- Prof. Chris and I will both take questions — go ahead

---

## Q&A Guide
### *~10 minutes, shared with Prof. Chris*

> Fine to say "great question, I'd need to think about that more" — honesty lands better than overconfidence.

---

**"How long did AGHORA take to build?"**
- Several months of evenings and weekends
- Built component by component — backend first, then Ghidra, then LLM layer, then frontend
- Lots of small iterations, not one big sprint

---

**"Is this open source? Can we get access?"**
- Research project right now — open to conversations
- Grab my contact info after and we'll talk
- Happy to demo one-on-one for anyone who wants to dig in

---

**"How accurate is the MITRE mapping?"**
- Automated and heuristic-based — not perfect
- Surfaces candidates for analyst review, not a replacement for analyst judgment
- Force multiplier, not an oracle

---

**"What hardware do you need?"**
- Any decent workstation — not GPU-dependent
- LLM runs locally via Ollama — 16GB+ RAM comfortable
- Not a supercomputer requirement

---

**"How do LATAM groups compare to nation-state actors?"**
- It's a spectrum
- CostaRicto: long dwell times, custom tooling, multi-hop infrastructure — closer to nation-state tradecraft
- Banking groups: crimeware-grade objectives, but operationally closing the gap
- The professionalism of their development cycles is the tell

---

**"What are you working on next?"**
- Research: ecosystem-level analysis toward a publishable paper
- Tool: extend AGHORA into dynamic analysis — run sample in sandbox, feed behavioral data back into the pipeline alongside static analysis

---

*You've put the work in. Go have fun with it.*
