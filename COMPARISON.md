# ⚖️ Sentinel vs. Splunk: An Honest Junior SOC Analyst Comparison

<p align="left">
  <img src="https://img.shields.io/badge/Microsoft%20Sentinel-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white"/>
  <img src="https://img.shields.io/badge/Splunk-000000?style=for-the-badge&logo=splunk&logoColor=white"/>
  <img src="https://img.shields.io/badge/Based%20On-Real%20Attacker%20Traffic-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Detections-5%20Cross--Platform-blueviolet?style=for-the-badge"/>
</p>

> **Project Context:** This comparison is based on data collected from a live Windows Server 2022 honeypot exposed to real-world internet brute-force attacks on Azure. Over a concurrent time window, 5 identical core detections were engineered across both platforms to evaluate cloud-native vs. self-hosted SIEM operations from the perspective of a junior SOC analyst.

← [Back to Main README](README.md)

---

## ⚡ TL;DR — The 10-Second Summary

| Category | Winner | Why |
|----------|--------|-----|
| **Setup Speed** | Sentinel ✅ | DCR + AMA = zero host config |
| **Query Readability** | Sentinel ✅ | KQL pipeline is clean and structured |
| **Raw Data Correlation** | Splunk ✅ | `streamstats` is more elegant for state tracking |
| **Field Extraction (Windows)** | Sentinel ✅ | Fully automated — no `rex` needed |
| **Geo Enrichment** | Tie 🤝 | Both work; different geo-IP databases cause minor variance |
| **Automated Incident Management** | Sentinel ✅ | Built-in analytic rules + auto incidents. Splunk requires extra config |
| **Infrastructure Overhead** | Sentinel ✅ | SaaS — zero OS maintenance |
| **Cost (Software)** | Splunk ✅ | 60-day free trial vs. Sentinel pay-per-GB ingestion |
| **Multi-cloud / Hybrid Flexibility** | Splunk ✅ | Platform-agnostic by design |
| **Career Differentiator** | Both 🏆 | Query parity across both = elite portfolio signal |

---

## 1. Setup & Ingestion Experience

| Aspect | Microsoft Sentinel | Splunk Enterprise |
|:-------|:-------------------|:-----------------|
| **Time to First Log** | ~30 min (including DCR propagation delay) | ~45–60 min |
| **Infrastructure Model** | Cloud-Native, Fully Managed (SaaS) | Self-Managed IaaS (Ubuntu 24.04 VM on Azure) |
| **Log Collection Mechanism** | Azure Monitor Agent (AMA) + Data Collection Rules (DCR) | Splunk Universal Forwarder 10.4.0 via port 9997 |
| **Configuration Style** | Portal GUI — zero touch to target OS | Config files (`inputs.conf` / `outputs.conf`) edited directly on VM via SSH |
| **Firewall Config Required** | None (Azure-native traffic) | Yes — NSG rules for ports 8000 and 9997 on `vm-splunk` |
| **Agent on Honeypot** | Azure Monitor Agent (auto-deployed via DCR) | Splunk Universal Forwarder (manual MSI install + restart) |

> **Analyst Verdict:** Sentinel wins on operational simplicity. The AMA connector deploys via an Azure DCR with zero local configuration on the host — click, deploy, done. Splunk requires managing local config files, a manual agent installer, and correctly configuring cloud NSG firewall rules to accept incoming receiver traffic. More moving parts means more troubleshooting surface.

---

## 2. Query Language & Data Engineering

| Aspect | KQL (Microsoft Sentinel) | SPL (Splunk Enterprise) |
|:-------|:------------------------|:------------------------|
| **Data Architecture** | **Schema-on-Write** — data is parsed and strongly typed upon ingestion | **Schema-on-Read** — data stored raw; fields extracted dynamically at search time |
| **Readability** | Highly structured, clean tabular pipeline syntax | High-density, powerful string-processing syntax |
| **Temporal Correlation** | Native `join` with explicit time window predicates | `streamstats` — elegant, stateful, computationally light |
| **Field Extraction (Windows Events)** | Fully automated out-of-the-box via native Windows Security tables | Required custom `rex` statements against `_raw` payload to resolve field mapping conflicts |
| **Geo Enrichment** | `geo_info_from_ip_address()` — built-in, returns structured object | `iplocation` — fast, single command |
| **String Cleaning** | `replace_string()` for domain prefix stripping | `coalesce()` + `eval` for multi-field fallback resolution |
| **Schema Resilience** | `column_ifexists()` for cross-EventID field variance | `coalesce()` across multiple possible field names |

> **Key Observation on Correlation:** When building Detection 2 (Account Lockout), Splunk's `streamstats` felt more natural and computationally lighter than KQL's inner `join`. It tracked the last seen attacker IP immediately before the EventID 4740 lockout fired — a stateful window operation without needing to define two separate data sets. KQL's `join` approach is more explicit and readable, but `streamstats` is genuinely elegant for this class of problem.

---

## 3. Detection Quality & Cross-Platform Parity

| Detection | Sentinel (KQL) | Splunk (SPL) | Engineering Notes |
|:----------|:--------------|:-------------|:-----------------|
| **1. Brute Force** | Good ✅ | Good ✅ | Both caught identical high-frequency attacker IPs — `163.47.70.77` (14 attempts/5min) confirmed on both platforms |
| **2. Account Lockout** | Good ✅ | Excellent 🌟 | `streamstats` made the IP-to-lockout correlation cleaner in Splunk; same result (`labadmin` locked out by `163.47.70.77`) confirmed cross-platform |
| **3. Geo-Anomaly** | Good ✅ Sydney, AU | Good ✅ Adelaide, AU | **Critical Finding:** Real geo-IP database variance — Azure uses its own database, Splunk uses MaxMind. Same IP resolves to different cities. Same country confirmed. Document as expected cross-platform behaviour, not a bug |
| **4. Priv Escalation** | Good Baseline ✅ | Good Baseline ✅ | Required tuning to exclude `NT SERVICE\SplunkForwarder` noise — a real-world SOC tuning decision. SPL logic successfully validated; visual artifact omitted for brevity |
| **5. New User Persistence** | Good ✅ | Good ✅ | Both cleanly tracked the creation of backdoor account `attacker` and its immediate promotion to `Administrators` — full persistence chain captured on both platforms |

---

## 4. Alerting & Incident Management

This is where the platforms diverge most significantly for operational SOC use.

| Capability | Microsoft Sentinel | Splunk Enterprise |
|:-----------|:-------------------|:-----------------|
| **Automated Incident Creation** | ✅ Built-in via Analytics Rules | ❌ Requires additional Splunk ES or custom alerting config |
| **Rule Scheduling** | Run every 5 minutes, configurable | Not configured in this lab |
| **Incident Queue** | Native — 4 incidents auto-generated (IDs 31–34) | Not available without Enterprise Security add-on |
| **Severity Classification** | Automatic — Medium, mapped to MITRE | Manual |
| **Out-of-Box Triage UI** | ✅ Full incident investigation panel | ❌ Base Splunk requires additional configuration |

> **Verdict:** For a SOC that needs zero-friction automated incident creation and triage queues out of the box, Sentinel wins decisively. In this lab, 4 real incidents were auto-generated with zero manual steps after the analytic rule was deployed. Splunk Enterprise requires the **Enterprise Security (ES)** premium add-on to reach equivalent native incident management — a significant cost and complexity consideration.

---

## 5. Cost & Operational Overhead

*All figures based on a 7-day lab run with both VMs active.*

| Cost Item | Microsoft Sentinel | Splunk Enterprise |
|:----------|:-------------------|:-----------------|
| **Software License** | Pay-per-GB ingestion (Log Analytics) | Free — 60-day developer trial (500 MB/day indexing limit) |
| **Ingestion Cost (7-day lab)** | ~$3–8 AUD (low volume honeypot data) | $0 — within free tier limit for targeted honeypot |
| **Underlying VM Compute** | Standard D2als v6 — `vm-honeypot` (shared source for both SIEMs) | Standard D2als v6 — `vm-splunk` (additional VM required) |
| **Combined VM Cost** | ~$5–10 AUD/day (both VMs running simultaneously) | Included in combined figure |
| **OS Maintenance** | None — fully managed SaaS | Ubuntu 24.04 — disk monitoring, service uptime, patching |
| **Total 7-day Estimate** | ~$40–75 AUD | ~$35–70 AUD (compute only) |

> **Verdict:** At low honeypot data volumes, both platforms cost roughly the same over a 7-day lab. The real operational cost difference is **engineering time** — Sentinel requires zero OS upkeep while Splunk requires actively managing an Ubuntu Linux instance, monitoring host disk capacity, and ensuring the Splunk service stays running after VM reboots. Note: Splunk's free tier 500 MB/day indexing cap is sufficient for a targeted honeypot but requires strict `inputs.conf` filtering to avoid license violations — a real constraint any SOC team running Splunk on a budget must manage.

---

## 6. When to Choose Which

### ✅ Choose Microsoft Sentinel if:
- Your infrastructure is anchored in **Microsoft Azure / M365**
- The SOC wants to eliminate infrastructure administration and focus on detection development
- You need **native automated incident routing** and triage queues without additional licensing
- Your log sources are primarily Windows and Azure-native

### ✅ Choose Splunk Enterprise if:
- The environment is **multi-cloud, hybrid, or on-premise** — Splunk is platform-agnostic
- You need **highly granular string manipulation** and raw data parsing across messy, non-standard application logs
- The team relies on structural statistical commands like `streamstats`, `transaction`, or `eventstats`
- Licensing costs are constrained and infrastructure management capability exists

---

## 🎯 My Final Verdict

Mastering query parity across both platforms is the real differentiator for a junior analyst trying to break into the Australian cyber security industry.

Sentinel provides a clean, fast entry point for cloud-native detection engineering within Azure-dominant enterprise environments. Splunk is an enterprise heavyweight with unrivalled data manipulation flexibility — and the market reality is that both platforms appear on job descriptions constantly.

What this lab proved to me personally: writing the same detection logic in KQL and then rebuilding it in SPL forces a deeper understanding of *why* the detection works — not just *that* it works. The `streamstats` vs `join` decision for Detection 2 isn't a stylistic preference; it reflects fundamentally different mental models for stateful event correlation.

Building cross-platform detection parity on real attacker traffic gave me more practical detection engineering insight than any certification course I have taken.

---

<p align="center">
  ← <a href="README.md">Back to Main README</a>
</p>

<p align="center">
  <b>Shankar Baral — Junior Cyber Security Analyst | Canberra, ACT</b><br/>
  <i>Master of Information Technology (Cyber Security), Charles Sturt University — GPA 4.92</i>
</p>
