# SOCint User Manual

**This manual teaches security analysts how to use SOCint to find and track threats.**

SOCint is a **threat intelligence search engine**. Think of it as Google for security threats:
- Type in an IP address → find everything known about it
- Type in a domain → see which hackers use it
- Paste a file hash → check if it's malware
- Search for a ransomware gang name → see their recent activities

SOCint helps you answer questions like:
- "Is this IP malicious?"
- "What's known about this hacker group?"
- "Which of our systems might be vulnerable to this CVE?"
- "Did this ransomware group claim a victim from our industry?"

---

## Getting Started (First 5 Minutes)

### Open SOCint

In your web browser:
```
http://your-server:3000
```

### Login

**Username:** `admin`  
**Password:** (ask your administrator)

### You See the Dashboard

The main screen shows:
- **Search bar** (top) — search for anything
- **Recent indicators** (middle) — recently added threats
- **Statistics** (right) — total indicators tracked
- **Navigation** (left) — different sections

---

## Part 1: Searching for Threats

### The Search Bar

Click the search box and type:

| What to Search | Examples | What You Find |
|---|---|---|
| **IP address** | `1.2.3.4` `192.168.1.100` | Malicious activity from that IP |
| **Domain** | `evil.com` `phishing-site.net` | Where the domain appears in threats |
| **URL** | `http://malware.com/payload` | URLs hosting malware |
| **File hash** | `d41d8cd98f00b204e9800998ecf8427e` (MD5) | Check if file is known malware |
| **Hacker group** | `Lazarus` `LockBit` `Conti` | Gang's recent activity |
| **CVE** | `CVE-2021-44228` | Vulnerability details + patches |

### Search Results

After searching, you see a **results page** with:

**Indicators** (left side):
- Each result is an "indicator" — a piece of threat data
- **Severity badge** (red/orange/yellow) shows how dangerous
- **Source** shows where the data came from

**Indicator Detail** (right side):
- Click any indicator to see full details
- Shows: type, value, confidence score, when it was seen, which feeds found it

### Severity Levels

Each indicator has a color:

| Color | Level | Meaning |
|-------|-------|---------|
| 🔴 Red | CRITICAL | Definitely malicious, immediate threat |
| 🟠 Orange | HIGH | Very likely malicious |
| 🟡 Yellow | MEDIUM | Suspicious, needs investigation |
| 🟢 Green | LOW | Probably harmless or informational |

**How it's calculated:**
- Multiple sources report it as bad → higher severity
- Older threat → lower severity
- Recent sightings in your environment → higher severity

---

## Part 2: Understanding Indicators

### What Is an Indicator?

An indicator is **a piece of malicious data**. Examples:

| Type | Example | Means |
|------|---------|-------|
| **IP** | `203.0.113.42` | This IP is known to send malware |
| **Domain** | `c2.malware.com` | Hackers use this to control botnets |
| **URL** | `evil.site/download/trojan.exe` | This URL hosts malware |
| **Hash** | `abc123def456...` | This file is malware (MD5/SHA256) |
| **Email** | `attacker@phishing.com` | Email address used in phishing attacks |

### Indicator Confidence Score

Each indicator has a score from 0–100:

- **0–20:** Probably not malicious (might be false positive)
- **20–50:** Somewhat suspicious
- **50–80:** Likely malicious
- **80–100:** Very likely malicious

**Example:**
- VirusTotal reports: 45 malware detections → score 85
- Single report from unknown source → score 30

---

## Part 3: The Intel Browser

### Overview

The **Intel** section is the main threat database. It shows all indicators SOCint is tracking.

**Left panel:** Filters (narrow down what you see)  
**Middle panel:** List of indicators  
**Right panel:** Details of selected indicator

### Filtering

**By Type:**
- IPs only
- Domains only
- URLs only
- File hashes only
- Email addresses only

**By Severity:**
- Only CRITICAL threats
- Only HIGH or worse
- Only new (< 24h old)

**By Source:**
- Which feed found it (OTX, MISP, CISA, NVD, etc.)
- Different feeds have different reliability

**Example filter:**
```
Type: IP
Severity: HIGH or CRITICAL
Age: Last 7 days
Source: CISA KEV
```

Result: Show me recently added critical IPs from US government's vulnerability list.

### Search Within Results

Most result lists have a search box. Use it to find specific threats in the filtered results.

---

## Part 4: Detailed Indicator View

Click any indicator to see everything SOCint knows about it.

**Information shown:**

| Section | What You See |
|---------|------------|
| **Header** | The indicator (IP/domain/etc), severity, confidence score |
| **Summary** | What this threat does, why it's dangerous |
| **Related Objects** | Other threats linked to this one |
| **Sightings** | Times and places this threat was seen |
| **MITRE ATT&CK** | What attack techniques this threat uses |
| **Intelligence** | Details from each feed |
| **Source Timeline** | When each feed added/updated information |

**Example IP indicator:**

```
IP: 203.0.113.42
Severity: HIGH (78/100)
ASN: AS1234 (Evil ISP)
Country: RU
Reverse DNS: none

Known Activity:
- Botnet command & control server (Emotet)
- Malware distribution point
- Phishing mail relay

Sightings:
- 2026-04-18: GreyNoise (noise)
- 2026-04-15: AbuseIPDB (14 reports of malicious activity)
- 2026-04-10: OTX (botnet C&C)

Related Indicators:
- malware.com (domain) - C&C domain for this botnet
- 203.0.113.50 - Similar IP, same subnet, likely same attacker
```

### Relationships (Knowledge Graph)

At the bottom of the indicator detail, you see a **graph** showing connections:

```
   Domain
     ↑
     |
    IP ----→ Malware Hash
     |
     ↓
  Email
```

This shows: "The IP hosts a domain, which delivers malware, controlled by this email."

Click any connected node to jump to that indicator.

---

## Part 5: Cases (Investigations)

### What Is a Case?

A case is a **long-term investigation**. Use cases to track:
- A ransomware gang's activities
- A specific vulnerability affecting your company
- An APT group's infrastructure
- A phishing campaign

### Creating a Case

**In web UI: Cases → New Case**

| Field | Example |
|-------|---------|
| **Name** | "LockBit attacks on healthcare" |
| **Description** | "Tracking LockBit ransomware gang targeting US hospitals" |
| **Severity** | 1–10 scale |
| **Tags** | `ransomware`, `healthcare`, `apt` |

### Adding Indicators to Cases

Once a case is created, you can add indicators to it:

1. Find an indicator (search, browse, etc.)
2. Click it to open details
3. Click **Add to Case**
4. Select the case

The indicator is now linked to the case. You can see all indicators in a case on the case detail page.

### Case Workflow

Typical lifecycle:
1. **Create** — define what you're investigating
2. **Add indicators** — collect relevant threats
3. **Add observables** — note indicators YOUR systems detected
4. **Create tasks** — assign work to team members
5. **Close** — when investigation complete

---

## Part 6: Rule Management

### What Are Rules?

Rules are **detection patterns** — code that identifies threats. Examples:
- **Yara rule:** "If file contains 'WannaCry' string, it's WannaCry malware"
- **Snort rule:** "If network traffic comes from known C&C IP, alert"
- **Sigma rule:** "If Windows event log shows 10 failed logins, alert"

SOCint imports 500+ detection rules automatically from Sigma HQ, abuse.ch, and others.

### Finding Useful Rules

**In web UI: Rules → Browse**

Filter by:
- **Platform:** Windows, Linux, network, cloud
- **Type:** Yara, Snort, Suricata, Sigma
- **Severity:** Critical, High, Medium, Low
- **Technique:** Which MITRE ATT&CK technique it detects

### Using a Rule

**Export to your SIEM:**
1. Find a rule
2. Click "Export"
3. Choose format (Snort, Suricata, Yara, etc.)
4. Copy into your detection tool

Example: Export a Sigma rule to Splunk, ELK, or a SIEM to detect threats.

---

## Part 7: CVE (Vulnerability) Tracker

### What's a CVE?

A **CVE** (Common Vulnerabilities and Exposures) is an ID for a known security bug.

Example: `CVE-2021-44228` = Log4Shell, critical bug in Java logging library. Affects millions of servers worldwide.

### Searching CVEs

**Search box → type CVE ID or keyword:**

```
CVE-2021-44228              → Find specific CVE
"remote code execution"     → Find all RCE vulnerabilities
"log4j"                     → Find all Log4j bugs
```

### CVE Details

Each CVE shows:

| Field | What It Means |
|-------|--------------|
| **CVSS Score** | 1–10 scale of severity (10 = critical) |
| **CVEP Score** | Probability it's being actively exploited (0–1) |
| **Affected Software** | Products with this bug |
| **Patch Available** | Yes/no, version number |
| **Exploit Public** | Is exploit code available online? |

**Example:**
```
CVE-2024-1234 (Critical, CVSS 9.8)
Title: "Remote Code Execution in Popular Web Framework"
EPSS: 0.92 (92% likely to be exploited)
Affected: Apache Tomcat 9.0.0 - 9.0.70
Patch: Upgrade to 9.0.71
Public Exploit: Yes (on GitHub)

Translation: This is very serious. Hackers probably know about it. 
You need to patch all Tomcat servers immediately.
```

### Building a Vulnerability Dashboard

Use cases to track vulnerabilities affecting your company:

1. Create case: "Java Deserialization Vulnerabilities"
2. Add all CVEs with "deserialization" in the description
3. Add observables from YOUR network (which systems have vulnerable Java?)
4. Track remediation progress

---

## Part 8: Dark Web Monitoring

### What Is Dark Web Monitoring?

SOCint automatically checks dark web forums, ransomware leak sites, and credential markets for:
- Your company name in breach announcements
- Your domain in phishing campaigns
- Your customers' data in dark web markets
- Ransomware gang threats

### Viewing Dark Web Intelligence

**In web UI: Dark Web → Search**

Filter by:
- **Type:** Ransomware leak, credential market, forum, breach announcement
- **Your company:** Search for your org name
- **Date range:** Last 7 days, last month, all time
- **Severity:** Only critical threats

**Example results:**
```
LockBit Claims Victim: "Company XYZ — 2.3TB leaked"
Date: 2026-04-18
Severity: CRITICAL
Description: LockBit ransomware gang claims they breached Company XYZ 
             and are extorting them. Posted full proof of access.
Action: Create case, notify leadership immediately.
```

### Alert on Threats to Your Organization

Set up alerts (in Settings) so you're notified when:
- Your company name appears on dark web
- Your domain is mentioned in forums
- Your customers are in breach data

---

## Part 9: MITRE ATT&CK Heatmap

### What Is MITRE ATT&CK?

A framework listing all known attack techniques. Organized by:
- **Tactics:** What the attacker wants (initial access, persistence, exfiltration, etc.)
- **Techniques:** How they achieve it

### The Heatmap

**In web UI: Intelligence → MITRE ATT&CK**

A grid showing:
- **Columns:** Attack techniques (T1234, T5678, etc.)
- **Rows:** Tactics (Reconnaissance, Execution, etc.)
- **Color:** Intensity (dark = many indicators for this technique)

### Using the Heatmap

**To answer:** "Which attack techniques are we detecting most?"

**To understand:** "Attackers are focusing on credential access. Are we detecting credential theft?"

**To improve:** "Defense evasion is dark. We need more detection rules for that tactic."

Click any technique to see all indicators tagged with it.

---

## Part 10: Enrichment (On-Demand Lookups)

### What Is Enrichment?

Enrichment means **looking up extra information** about a threat.

Example: You have an IP address. Enrichment tells you:
- Is it a known botnet?
- How many reports say it's malicious?
- Where is it located?
- Who owns it?
- Is a celebrity hacker using it?

### Running Enrichment

**In UI: Find indicator → Click "Enrich" button**

SOCint queries multiple threat intel feeds and returns:

| Source | Returns |
|--------|---------|
| **AbuseIPDB** | Abuse reports, confidence score |
| **GreyNoise** | Tag (malicious/benign/unknown) |
| **VirusTotal** | How many antivirus detections |
| **OTX** | Community threat pulse data |

---

## Part 11: Case Management

### Creating Investigation Tasks

In a case, create tasks to organize work:

| Task | Assigned To | Status | Deadline |
|------|------------|--------|----------|
| Check if we're vulnerable to CVE-2024-1234 | Alice | In Progress | 2026-04-25 |
| Review all indicators related to LockBit | Bob | Pending | 2026-04-28 |
| Notify customers if their data leaked | Charlie | Not Started | 2026-04-30 |

### Tracking Progress

**In case detail:**
- See all indicators collected
- See all tasks and who's working them
- Add notes about findings
- Update case status (Open → In Progress → Resolved → Closed)

---

## Part 12: Common Workflows

### Workflow 1: "I Found a Suspicious IP"

1. **Search:** Paste the IP in the search box
2. **Review results:** What feeds know about it?
3. **Check severity:** How bad is it?
4. **Look at related indicators:** What else is connected?
5. **Decide:** Is it malicious? A false positive?
6. **Take action:** If malicious, block it. If FP, mark it.

### Workflow 2: "We Got Ransomware'd"

1. **Create case:** "Ransomware Incident XYZ"
2. **Identify:** Which ransomware? (Search hashes, C&C IP)
3. **Find gang profile:** Who did this? (Search gang name on dark web)
4. **Check demands:** Are we in their leak site?
5. **Collect IOCs:** All IP/domain/hash indicators for this attack
6. **Export rules:** Download detection rules for your SIEM
7. **Block & remediate:** Share IOCs with network team

### Workflow 3: "Check Our Exposure to This CVE"

1. **Search CVE:** Type `CVE-2024-XXXX`
2. **Review:** Affected products, severity, patches
3. **Create case:** "CVE-2024-XXXX Remediation"
4. **Check your environment:** Which of OUR systems have the affected software?
5. **Add observables:** Add those systems to the case
6. **Track remediation:** Assign patches to teams, track progress

---

## Part 13: Exporting Data

### Export Indicators

**Use case:** Send threat data to your SIEM, firewall, or other tools.

**In UI: Intelligence → Export**

Formats:
- **CSV:** Spreadsheet format (easy to process)
- **JSON:** Machine-readable format
- **STIX 2.1:** Industry standard threat format
- **Firewall format:** IP blocklists, domain blocklists

### Export Rules

**Use case:** Deploy detection rules to your environment.

**In UI: Rules → [Select rules] → Export**

Formats:
- **Snort/Suricata:** For network IDS
- **Yara:** For malware scanning
- **Sigma:** For SIEM conversion tools

---

## Part 14: Tips & Tricks

### Fast Searching

- Type `type:ip` for IP-only results
- Type `severity:high` for high severity only
- Type `source:otx` for OTX-only results
- Combine: `type:domain severity:critical source:cisa`

### Keyboard Shortcuts

- `/` — Focus search box
- `e` — Expand selected indicator
- `n` — Next result
- `p` — Previous result

### Starred Indicators

Star important indicators for quick access:
1. Click indicator
2. Click star icon
3. Access starred items in sidebar

### Bulk Operations

Export multiple indicators at once:
1. Filter results (by severity, date, etc.)
2. Select all: checkbox at top
3. Click Export
4. Choose format

---

## Part 15: Daily Workflow

### Start of Day

1. **Check alerts:** Any new high-severity indicators matching your company?
2. **Review cases:** Are there open investigations?
3. **Check dark web:** Was your organization mentioned?

### Regular Tasks

- **Monitor CVEs:** New critical vulnerabilities might need immediate patching
- **Track campaigns:** Any new phishing or ransomware campaigns targeting your industry?
- **Export to SIEM:** Weekly push of new indicators to detection tools

### End of Day

- **Update cases:** Add notes to open investigations
- **Archive stale indicators:** Mark false positives
- **Prepare reports:** Export threat intel for leadership

---

**You now know how to use SOCint.** It's designed to help you find answers to security questions. When in doubt, search, read the details, and ask colleagues.

The best threat intelligence is one you actually use. Bookmark SOCint. Make searching it a daily habit. 🔍
