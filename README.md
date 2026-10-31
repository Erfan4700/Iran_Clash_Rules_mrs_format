<div align="center">

# 🇮🇷 Iran Universal Routing & Cyber Defense Suite
### Enterprise Automated Multi-Platform RuleSets & Clean Profile Processors for Mihomo, Sing-box, V2Ray/Xray & Surge

[![Automated Build Pipeline](https://img.shields.io/github/actions/workflow/status/Erfan4700/iran-routing-rules/build-iran.yml?branch=main&label=Build%20Pipeline&style=flat-square&logo=github-actions&logoColor=white)](https://github.com/Erfan4700/iran-routing-rules/actions)
[![Direct Release](https://img.shields.io/badge/Release-GitHub%20Direct%20(Zero--Cache)-blue?style=flat-square&logo=github&logoColor=white)](https://github.com/Erfan4700/iran-routing-rules/releases/latest)
[![Edge CDN Active](https://img.shields.io/badge/CDN-jsDelivr%20Purged-orange?style=flat-square&logo=jsdelivr&logoColor=white)](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/)
[![Coverage](https://img.shields.io/badge/Coverage-%2B120%2C000%20Domains-success?style=flat-square&logo=internet-explorer&logoColor=white)](#-macro-vs-modular-architectural-taxonomy)
[![HaGeZi Integrated](https://img.shields.io/badge/Threat%20Intel-HaGeZi%20MRS%20Native-purple?style=flat-square&logo=adguard&logoColor=white)](https://github.com/Erfan4700/HaGeZi_BlockLists_mrs_format)
[![Security Specs](https://img.shields.io/badge/Security-Phishing%20%7C%20AdBlock%20%7C%20Zero--Trust-emerald?style=flat-square&logo=shield&logoColor=white)](#-cyber-threat-mitigation--whitelist-integrity)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

An industrial-grade routing engine and cyber defense framework compiled natively into optimized binary and classical text rule-sets across **Mihomo (`.mrs`)**, **Sing-box (`.srs`)**, **V2Ray/Xray (`.dat`)**, and **Surge/Shadowrocket (`.list`)**. Powered by mathematical CIDR supernetting, Mozilla PSL root pruning, disjoint zero-overlap modular categorization, dynamic app tracker exceptions, and integration of the official **Enamad commercial database (~13MB)**, **Cloudflare Iranian Web registry (CF-Web)**, and **V2Fly Community categories**.

[Architecture](#-macro-vs-modular-architectural-taxonomy) • [Merge Scripts](#-clash-verge-merge-scripts-javascript-runtime) • [Catalog & Endpoints](#-ruleset-catalog--distribution-endpoints) • [Client Setup](#-client--platform-integration) • [Telemetry Sources](#-telemetry-sources--upstream-feeds) • [راهنمای جامع فارسی](#-راهنمای-جامع-به-زبان-فارسی)

</div>

---

## 🌐 Multi-Platform Client Matrix

This repository acts as an authoritative, single source of truth, compiling unified network telemetry into native runtime formats:

| Platform / Client Application | Target Core Engine | Native Binary Rule-Set | Classical / Text Source |
| :--- | :--- | :---: | :---: |
| **Clash Verge Rev, Mihomo Party, FlClash** | Mihomo / Clash.Meta | **`.mrs`** (Radix Tree) | `.txt` / `.yaml` |
| **Hiddify, NekoBox, Karing, Box4Proxy** | Sing-box Core (v1.8+) | **`.srs`** (Compiled Protobuf) | `.json` (Headless Rule-Set) |
| **Marzban, 3X-UI, v2rayN, v2rayNG, V2Box** | Xray-core / V2Fly Core | **`geosite.dat` / `geoip.dat` / `iran.dat`** | — |
| **Shadowrocket, Surge, Loon, Stash, Egern** | Surge Rule Engine | — | **`.list`** |

---

## 📐 Macro vs. Modular Architectural Taxonomy

Users and network administrators can select between two architectural designs tailored for different operational requirements:

```text
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                  1. MACRO SUITE (Comprehensive All-In-One)                            │
├────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ • Designed for maximum speed, simplicity, and zero-configuration domestic bypass.                      │
│ • iran-all-domains       : +120,000 verified domestic domains (Enamad, CF-Web, V2Fly, Roots).          │
│ • iran-all-domains-lite  : Curated set of ultra-high-traffic domestic portals for constrained devices. │
│ • iran-all-ip            : Full aggregated RIPE IPv4/IPv6 country delegations (Supernetted).          │
│ • iran-all-ads           : Unified domestic banner, SDK, and tracker blocking feed (+category-ads-ir). │
│ • iran-all-security      : Domestic phishing, banking trojans, and smishing portals.                   │
│ • iran-all-apps          : Native Android package names and desktop process names.                     │
│ • iran-app-exceptions    : Dedicated classical ruleset allowing domestic app analytics (Metrix, etc.). │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘

                                                   VS

┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              2. MODULAR SUITE (Zero-Overlap Disjoint Routing)                          │
├────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ • Designed for precision traffic control, granular policy routing, and zero memory redundancy.         │
│ • iran-modular-banking   : Certified banking portals, Shaparak infrastructure, bourse, & crypto.       │
│ • iran-modular-gov       : State, judiciary (Sana/Adliran), tax, and municipal services.               │
│ • iran-modular-media     : Video on demand, Aparat, Filimo, Telewebion, and national CDN broadcasters. │
│ • iran-modular-gaming    : Domestic game matchmaking, Radar Game subnets, and low-latency servers.     │
│ • iran-modular-download  : High-throughput software mirrors, Linux repositories, and Soft98.          │
│ • iran-modular-cloud     : Domestic cloud datacenters (ArvanCloud, Derak, ParsPack) IP-CIDRs.         │
│ • iran-modular-isp       : Direct domestic ISP infrastructure subnets (MCI, Irancell, Shatel, etc.).  │
│ • iran-modular-gambling  : Domestic online casinos, betting networks, and illegal payment scripts.    │
│ • iran-modular-other     : The mathematical remainder set (+100k Enamad shops, Startups, News).       │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### The Disjoint Mathematical Guarantee:
Specialized sub-categories are strictly isolated using automated set difference operations:
$$\text{iran-modular-other} = \text{iran-all-domains} \setminus (\text{banking} \cup \text{gov} \cup \text{media} \cup \text{gaming} \cup \text{download})$$

$$\text{banking} \cap \text{gov} \cap \text{media} \cap \text{gaming} \cap \text{download} \cap \text{other} = \emptyset$$

> **Zero Log Pollution & Zero RAM Waste:** No domain existing in `banking`, `gov`, `media`, `gaming`, or `download` is replicated in `iran-modular-other`. This completely prevents duplicate memory allocation inside the client radix tree and guarantees strict mutual exclusivity.

---

## ⚡ Clash Verge Merge Scripts (JavaScript Runtime)

This repository includes **three specialized production-hardened JavaScript merge processors** in the root directory for **Clash Verge Rev**, **Mihomo Party**, and **FlClash**. All scripts feature native integration with the **[HaGeZi MRS Blocklists](https://github.com/Erfan4700/HaGeZi_BlockLists_mrs_format)**, automated domestic DNS policy injection, zero-latency domestic white-listing, and UDP/QUIC leak suppression.

```text
├── clash-verge-merge-Macro.js       # [Ultra-Light] Full Macro: Iran Macro + HaGeZi Macro Bundles (Lowest RAM/CPU)
├── clash-verge-merge-IranMacro.js   # [Hybrid] Macro Iran (iran-all-*) + Granular Modular HaGeZi Lists
└── clash-verge-merge-modular.js     # [Full Granular] Per-category toggles for Iran (Banking, Media, Gov, etc.)
```

### Key Architectural Upgrades in Runtime Processors:
* **Sniffer Bypass for Domestic Rulesets:** TLS/HTTP sniffing is automatically bypassed for all domestic Iranian domains (`rule-set:iran-all-domains` or modular equivalents). This completely eliminates TLS handshake latency and prevents 403 Forbidden / Cloudflare Captcha loops on Iranian websites.
* **Offloaded Static Evaluation:** Over 120,000 domestic domains (including the full Enamad directory) are pre-compiled into binary `.mrs`, completely removing memory bloat and loops from client JavaScript engines.
* **Emergency Slot (`EMERGENCY_MANUAL_DOMAINS`):** A dedicated, zero-delay array at the top of the scripts allowing users to unblock any newly launched domestic domain immediately without waiting for pipeline builds.
* **Decoupled Tracker Routing (`iran-app-exceptions`):** Analytics endpoints utilized by essential domestic transport services (Metrix SDK used by Snapp, Tapsi, SnappFood) are dynamically routed via clean classical rulesets, eliminating ride-hailing crashes when domestic adblockers are active.

---

## 🛡️ Cyber Threat Mitigation & Whitelist Integrity

* **Targeted Threat Elimination (`iran-all-security` & `iran-all-security-ip`):** Intercepts cloned phishing portals mimicking judiciary services (`sana` / `adliran`), fraudulent subsidy pages, card-to-card traps, and malicious C2 IPs.
* **Adblock Isolation (`category-ads-ir`):** Domestic ad networks from V2Fly Community (`category-ads-ir`) are strictly routed to `iran-all-ads` (`REJECT`) and isolated from bypass datasets to prevent domestic ads from bypassing adblockers.
* **Cloudflare Anycast IP Safety Isolation:** From the `CF-Web` database, **only validated domain names are extracted**. Cloudflare Anycast IP addresses (`104.21.x.x`, `172.67.x.x`) are discarded, ensuring global internet CDN routing remains unpolluted.
* **Deterministic Financial Protection (`UNBREAK_WHITELIST`):** Enforces an immutable exemption layer during Python compilation (`build.py`) for central payment infrastructure (`*.shaparak.ir`), all licensed Payment Service Providers (Behpardakht, Sadad, Asan Pardakht, Saman Kish, Parsian, ZarinPal, etc.), core Iranian banks, crypto platforms (Nobitex, Wallex), and critical SMS notification endpoints (`kavenegar.com`, `ghasedak.me`).

---

## 🔄 Resilience & User Customization (`data/baseline/`)

To prevent build failures, cache corruption, or upstream network disruptions during GitHub Actions execution, the build pipeline incorporates a **Golden Baseline Resilience Database (`data/baseline/`)**:
* **Automated Fallback:** If an upstream source fails or returns insufficient entries, the pipeline automatically falls back to verified local baseline snapshots (`load_baseline`).
* **Manual Additions (`custom-domains.txt`):** Users can manually add unindexed, private, or local enterprise domains to `data/baseline/custom-domains.txt`.
  - Domains added to this file are automatically deduplicated, pruned against Mozilla PSL, and categorized into both Macro and Modular rulesets.
  - The file is **never overwritten** by automated snapshot bots.
  - Committing to `custom-domains.txt` triggers an automatic, immediate release build via GitHub Actions.

---

## 📦 Ruleset Catalog & Distribution Endpoints

All release assets are rebuilt automatically twice daily (03:00 and 15:00 UTC) or upon manual push via parallelized compilation and distributed via both zero-cache GitHub direct links and purged jsDelivr edge mirrors:

* **Direct GitHub Releases URL (Recommended - Real-time & Zero Cache Lag):**  
  `https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/`
* **Edge CDN URL (Failover):**  
  `https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/`

### 1. Macro Datasets (All-In-One Suite)
| Ruleset Identifier | Scope / Content | Action | Supported Formats |
| :--- | :--- | :---: | :---: |
| **`iran-all-domains`** | +120k validated Iranian domains (Enamad, CF-Web, V2Fly) | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.list) |
| **`iran-all-domains-lite`** | Essential high-traffic domestic domains | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains-lite.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains-lite.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains-lite.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains-lite.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains-lite.list) |
| **`iran-all-ip`** | Full supernetted RIPE IPv4/IPv6 subnets | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.list) |
| **`iran-all-ads`** | Domestic ad servers, SDKs, and trackers (+v2fly ads) | `REJECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.list) |
| **`iran-all-security`** | Phishing portals, fake banks, and malware | `REJECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.list) |
| **`iran-all-security-ip`**| Malicious IP addresses, C2 nodes, and bots | `REJECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security-ip.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security-ip.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security-ip.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security-ip.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security-ip.list) |
| **`iran-app-exceptions`** | Tracker exceptions for Snapp/Tapsi/Metrix | `DIRECT` | [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-app-exceptions.txt) \| [yaml](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-app-exceptions.yaml) |
| **`iran-all-apps`** | Android package IDs & Windows processes | `DIRECT` | [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-apps.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-apps.txt) \| [yaml](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-apps.yaml) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-apps.json) |
| **`iran-asn`** | Autonomous System Numbers of Iranian ISPs | `DIRECT` | [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-asn.txt) \| [yaml](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-asn.yaml) |
| **`iran-unified`** | Single classical master file for legacy clients | `DIRECT` | [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-unified.txt) \| [yaml](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-unified.yaml) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-unified.list) |

### 2. Modular Datasets (Zero-Overlap Granular Suite)
| Ruleset Identifier | Specific Scope | Action | Supported Formats |
| :--- | :--- | :---: | :---: |
| **`iran-modular-banking`** | Banks, Shaparak gateways, crypto, bourse, insurance | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.list) |
| **`iran-modular-gov`** | State portals, Sana, judiciary, tax services | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gov.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gov.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gov.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gov.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gov.list) |
| **`iran-modular-media`** | VOD, streaming platforms, Aparat, Filimo, news | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-media.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-media.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-media.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-media.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-media.list) |
| **`iran-modular-gaming`** | Domestic game matchmaking & Radar Game | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gaming.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gaming.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gaming.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gaming.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gaming.list) |
| **`iran-modular-download`** | High-speed software mirrors, ISOs, Soft98 | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-download.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-download.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-download.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-download.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-download.list) |
| **`iran-modular-cloud`** | National cloud CIDRs (Arvan, Derak, ParsPack) | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-cloud.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-cloud.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-cloud.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-cloud.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-cloud.list) |
| **`iran-modular-isp`** | Supernetted ISP allocations (IP-CIDR) | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-isp.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-isp.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-isp.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-isp.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-isp.list) |
| **`iran-modular-gambling`** | Online gambling portals & betting scripts | `REJECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gambling.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gambling.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gambling.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gambling.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gambling.list) |
| **`iran-modular-other`** | Remainder set (+100k Enamad shops, Startups, CF-Web) | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.list) |

### 3. Unified V2Ray / Xray Protobuf Datasets
* **`geosite.dat`**: Full tags (`geosite:iran-all-domains`, `geosite:iran-modular-banking`, `geosite:iran-modular-gov`, `geosite:iran-modular-media`, `geosite:iran-modular-gaming`, `geosite:iran-modular-download`, `geosite:iran-modular-other`, `geosite:iran-all-ads`, `geosite:iran-all-security`, `geosite:iran-modular-gambling`, `geosite:ir`) ➔ [Download geosite.dat](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/geosite.dat)
* **`geoip.dat`**: Country tags (`geoip:ir`, `geoip:iran-modular-cloud`, `geoip:iran-modular-isp`, `geoip:iran-all-security-ip`) ➔ [Download geoip.dat](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/geoip.dat)
* **`iran.dat`**: Drop-in unified replacement for Marzban and traditional Xray server deployments ➔ [Download iran.dat](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran.dat)

---

## 🚀 Client & Platform Integration

### 1. Mihomo / Clash Meta (`config.yaml`) - Production Ready Setup

```yaml
rule-providers:
  iran-app-exceptions:
    type: http
    behavior: classical
    format: text
    url: "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-app-exceptions.txt"
    path: ./ruleset/iran-app-exceptions.txt
    interval: 172800

  iran-all-security:
    type: http
    behavior: domain
    format: mrs
    url: "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.mrs"
    path: ./ruleset/iran-all-security.mrs
    interval: 86400

  iran-all-ads:
    type: http
    behavior: domain
    format: mrs
    url: "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.mrs"
    path: ./ruleset/iran-all-ads.mrs
    interval: 172800

  iran-modular-banking:
    type: http
    behavior: domain
    format: mrs
    url: "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.mrs"
    path: ./ruleset/iran-modular-banking.mrs
    interval: 172800

  iran-modular-other:
    type: http
    behavior: domain
    format: mrs
    url: "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.mrs"
    path: ./ruleset/iran-modular-other.mrs
    interval: 172800

  iran-all-ip:
    type: http
    behavior: ipcidr
    format: mrs
    url: "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.mrs"
    path: ./ruleset/iran-all-ip.mrs
    interval: 172800

rules:
  - GEOIP,private,DIRECT,no-resolve
  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT
  - RULE-SET,iran-app-exceptions,DIRECT
  - RULE-SET,iran-all-security,REJECT
  - RULE-SET,iran-all-ads,REJECT
  - DOMAIN-SUFFIX,ir,DIRECT
  - RULE-SET,iran-modular-banking,DIRECT
  - RULE-SET,iran-modular-other,DIRECT
  - RULE-SET,iran-all-ip,DIRECT,no-resolve
  - MATCH,PROXY
```

---

### 2. Sing-box Core (`config.json`)

```json
{
  "route": {
    "rule_set": [
      {
        "tag": "iran-all-ads",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.srs",
        "download_detour": "direct"
      },
      {
        "tag": "iran-all-security",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.srs",
        "download_detour": "direct"
      },
      {
        "tag": "iran-all-domains",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.srs",
        "download_detour": "direct"
      },
      {
        "tag": "iran-all-ip",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.srs",
        "download_detour": "direct"
      }
    ],
    "rules": [
      { "rule_set": "iran-all-ads", "outbound": "block" },
      { "rule_set": "iran-all-security", "outbound": "block" },
      { "rule_set": "iran-all-domains", "outbound": "direct" },
      { "rule_set": "iran-all-ip", "outbound": "direct" }
    ]
  }
}
```

---

### 3. V2Ray / Xray / Marzban Outbound Server Routing

```json
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "outboundTag": "blocked",
        "domain": [
          "ext:iran.dat:iran-all-ads",
          "ext:iran.dat:iran-all-security",
          "ext:iran.dat:iran-modular-gambling"
        ]
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "domain": [
          "ext:iran.dat:ir",
          "ext:iran.dat:iran-all-domains"
        ],
        "ip": [
          "geoip:ir"
        ]
      }
    ]
  }
}
```

---

## 📡 Telemetry Sources & Upstream Feeds

The automated pipeline (`build.py`) aggregates telemetry from authorized registries and vetted sources:

### 1. Commercial & E-Commerce Registries (Enamad):
* **Official Enamad Mirror Database:** `@bootmortis/enamad-mirror` (`domains.csv` ~13MB) – Over 100,000 verified Iranian businesses, e-commerce platforms, and domestic startups.

### 2. Cloudflare-Fronted Domestic Infrastructure:
* **CF-Web Registry:** `@hossein-mohseni/CF-Web` (`domains.json`) – Iranian websites utilizing Cloudflare edge proxies, sanitized to extract root domain names and avoid Cloudflare WAF bot-challenges.

### 3. V2Fly Community Categorization:
* **V2Fly Domain Community Feeds:** `@v2fly/domain-list-community` (15 direct categories: `category-bank-ir`, `category-gov-ir`, `category-media-ir`, `category-news-ir`, `category-tech-ir`, `category-bourse-ir`, `category-payment-ir`, `category-shopping-ir`, `category-scholar-ir`, `category-insurance-ir`, etc. + `category-ads-ir` strictly isolated into `iran-all-ads`).

### 4. Official IP & ASN Allocations:
* **RIPE NCC Delegated Statistics:** `ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest`.
* **APNIC Mirror Delegation:** `ftp.apnic.net/stats/ripe-ncc/delegated-ripencc-latest`.
* **Domestic Datacenters:** `ygbkm/resources` (`ipv4.txt` & `ipv6.txt`).
* **Meta Rules Datasets:** `MetaCubeX/meta-rules-dat`.
* **Chocolate4U Routing Feeds:** `Chocolate4U/Iran-clash-rules` (`ircidr.txt` & `irasn.txt`).

### 5. Cloud Datacenters:
* Subnets for ArvanCloud (`arvancloud.txt`), Derak (`derakcloud.txt`), Iranserver (`iranserver.txt`), and ParsPack (`parspack.txt`).

### 6. Domestic & Government Domains:
* **Hosted Domains Catalog:** `@bootmortis/iran-hosted-domains` (`domains.txt` & `clash_rules_other.txt`).
* **Information Technology Organization (ITO):** `@bootmortis/ito-gov-mirror` (`domains.csv`).
* **Domestic Heuristics:** `@ygbkm/clash-rules-iran`.
* **Sanitized CitizenLab / OONI Feeds:** `citizenlab/test-lists` (Domestic unblocked subset only).

### 7. Security, Phishing, & Adblocking:
* **PersianBlocker Feeds:** `@MasterKia/PersianBlocker` (`PersianBlockerHosts.txt`, `PersianBlockerAds-Hosts.txt`, `PersianBlockerPhishing.txt`, `PersianBlockerGambling.txt`).
* **Global Phishing Filters:** `@curbengh/phishing-filter`.
* **Threat Intelligence Sets:** `Chocolate4U` (`phishing.txt`, `malware.txt`, `phishing-ip.txt`, `malware-ip.txt`).

### 8. Applications & Processes:
* **Iranian Android Packages:** `@SamadiPour/iran-android-apps` (`packages.json`).
* **Desktop Windows Binaries:** Curated list (`Bale.exe`, `Eitaa.exe`, `Rubika.exe`, `Soroush.exe`, `IDMan.exe`, etc.).

---

## 🇮🇷 راهنمای جامع به زبان فارسی

<details>
<summary><b>برای مطالعه نکات تخصصی، نحوه افزودن دامنه‌های دستی و معماری ارتقایافته کلیک کنید</b></summary>
<br>

### چه چیزی این نسخه را متفاوت می‌کند؟ (پوشش بیش از ۱۲۰ هزار دامنه)
در بیشتر رول‌ست‌های عمومی، تنها دامنه‌های ختم‌شده به `.ir` شناسایی می‌شوند. این در حالی است که هزاران کسب‌وکار، صرافی، وب‌سایت دانشگاهی و ارائه‌دهنده خدمات داخلی در ایران از دامنه‌های بین‌المللی مانند `.com`، `.net`، `.org` یا سرویس‌های CDN کلودفلر استفاده می‌کنند.  
با اضافه شدن پایگاه جامع **اینماد (Enamad Mirror با حجم ۱۳ مگابایت)** و مخزن **CF-Web**، تمامی این دامنه‌ها اکنون شناسایی و به صورت مستقیم (`DIRECT`) روت می‌شوند؛ در نتیجه:
* **پینگ دامنه‌های تجاری داخلی** از ۲۰۰ الی ۴۰۰ میلی‌ثانیه (عبور از فیلترشکن) به ۱۰ الی ۳۰ میلی‌ثانیه کاهش می‌یابد.
* مشکل مسدود شدن با خطای **Access Denied 403** (به دلیل ورود با آی‌پی خارجی به سایت‌های داخلی) به‌طور کامل ریشه‌کن می‌شود.
* خطاهای اعصاب‌خردکن **Cloudflare Captcha / Turnstile** روی سایت‌های ایرانی لود نخواهند شد.

### نحوه افزودن دامنه اختصاصی کاربر (`data/baseline/custom-domains.txt`)
اگر دامنه شخصی، شرکتی یا پورتال سازمانی دارید که در هیچ لیستی نیست:
1. کافی است وارد پوشه `data/baseline/` در گیت‌هاب خود شوید.
2. فایل `custom-domains.txt` را باز کرده و دامنه‌های مورد نظر را خط‌به‌خط وارد کنید.
3. با زدن دکمه Commit، گیت‌هاب اکشن به‌صورت خودکار اجرا شده، دامنه‌ها را پالایش، ضد همپوشانی و کامپایل کرده و نسخه جدید را منتشر می‌کند. بات‌های به‌روزرسانی بیس‌لاین هرگز این فایل را بازنویسی نخواهند کرد.

### چرا اسنیفر (Sniffer) برای دامنه‌های ایران غیرفعال است؟
اسنیفر در کلاینت‌های هسته کلش (Mihomo) تلاش می‌کند تا با تحلیل Handshake پکت‌های TLS نام دامنه را حدس بزند. وقتی ترافیک داخلی از قبل با رول‌ست‌های باینری شناسایی شده باشد، عبور دادن صدها هزار دامنه از اسنیفر فقط بار پردازشی CPU را بالا برده و لود اولیه سایت‌های داخلی را کند می‌کند. اسکریپت‌های مرج این پروژه با تنظیم هوشمند `skip-domain`، بار اسنیفر را برای ترافیک ایران به صفر می‌رسانند.

### ایزولاسیون کامل تبلیغات ایرانی (`category-ads-ir`)
در پایپ‌لاین‌های استاندارد، اگر دامنه‌های v2fly بدون تفکیک اضافه شوند، فایل تبلیغات ایران (`category-ads-ir`) به اشتباه وارد رول‌های بای‌پس مستقیم می‌شود و تبلیغات یکتانت و تپسل از سد ادبلاکر فرار می‌کنند. در این پروژه، دسته تبلیغات v2fly به صورت ایزوله فقط وارد **`iran-all-ads`** شده و با اکشن `REJECT` مسدود می‌شود.

### راهنمای انتخاب بین ۳ اسکریپت Merge موجود در مخزن:
1. **`clash-verge-merge-Macro.js` (پیشنهادی برای مصرف عمومی و موبایل):**  
   سبک‌ترین حالت ممکن؛ هم ترافیک ایران و هم پکیج‌های هاگزی را به‌صورت ماکروهای تجمیعی لود می‌کند تا مصرف رم گوشی به حداقل برسد.
2. **`clash-verge-merge-IranMacro.js` (پیشنهادی برای سیستم‌های با رم کافی):**  
   ترافیک ایران به‌صورت ماکرو و یکپارچه است، اما گزینه‌های امنیتی و محتوایی هاگزی به‌صورت تک‌به‌تک و ماژولار قابل انتخاب هستند.
3. **`clash-verge-merge-modular.js` (کنترل کامل بر ترافیک داخلی):**  
   تمامی دسته‌بندی‌های ایران (بانک، رسانه، دولت، بازی، ابر، دانلود و سایر) دارای کلیدهای مستقل هستند و می‌توان هر کدام را جداگانه خاموش یا روشن کرد.

### چرا تپسی، اسنپ و اسنپ‌فود با ادبلاکرها به مشکل نمی‌خورند؟
بسیاری از اپلیکیشن‌های سفارش غذا و تاکسی اینترنتی از SDKهای تحلیلی مثل `metrix.ir` استفاده می‌کنند. در بلاک‌لیست‌های تبلیغاتی معمولاً کل دامنه‌ی متریکس مسدود می‌شود که منجر به اختلال در اسنپ و تپسی می‌گردد.  
در این پروژه یک رول‌ست اختصاصی به نام **`iran-app-exceptions`** طراحی شده که **قبل از قوانین ادبلاکر** لود می‌شود و بررسی می‌کند که اگر پکت از سمت اپلیکیشن‌های رسمی نظیر `cab.snapp.passenger` به سمت متریکس ارسال شد، بلافاصله مستقیم (`DIRECT`) شود و سایر ترافیک‌های تبلیغاتی متفرقه مسدود بماند.

### پالایش ریشه‌ای با استاندارد Mozilla PSL:
در وب‌سایت‌های ایرانی پسوندهای مرتبه دوم زیادی نظیر `.co.ir`، `.gov.ir`، `.ac.ir` وجود دارد. اسکریپت‌های سنتی معمولاً بخش آخر دامنه‌ها را جدا می‌کنند و با دامنه‌هایی مثل `ir` یا `co.ir` رفتار یک دامنه مستقل را انجام می‌دهند که باعث خرابی کل رول‌ست می‌شود.  
این پروژه از کتابخانه رسمی `tldextract` و پایگاه داده موزیلا (Mozilla Public Suffix List) استفاده می‌کند تا ریشه ثبت‌شده (Registered Domain) استخراج شود. بدین ترتیب زیردامنه‌های زائد حذف شده و حجم کل فایل‌ها بین ۴۰ الی ۶۰ درصد کاهش می‌یابد بدون آنکه حتی یک دامنه از دست برود.

### نحوه استفاده از اسکریپت‌های ادغام در Clash Verge Rev
1. وارد نرم‌افزار **Clash Verge Rev** شوید.
2. به بخش **Profiles** رفته و روی پروفایل اشتراک فعال خود راست‌کلیک کرده و گزینه **Edit Rules** یا **Merge Scripts** را باز کنید.
3. کد یکی از سه فایل اسکریپت بالا را کپی کرده و در تب مربوطه جای‌گذاری کنید.
4. تغییرات را ذخیره نموده و پروفایل را فعال کنید.

</details>

---

## 📄 License

This repository is licensed under the **[MIT License](LICENSE)**. Network routing telemetry and domain datasets remain under the intellectual rights of their respective official registries and maintainers.
