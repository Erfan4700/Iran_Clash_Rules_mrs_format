<div align="center">

# 🇮🇷 Iran Universal Routing & Cyber Defense Suite
### Enterprise Automated Multi-Platform RuleSets & Clean Profile Processors for Mihomo, Sing-box, V2Ray/Xray & Surge

[![Automated Build Pipeline](https://img.shields.io/github/actions/workflow/status/Erfan4700/iran-routing-rules/build-iran.yml?branch=main&label=Build%20Pipeline&style=flat-square&logo=github-actions&logoColor=white)](https://github.com/Erfan4700/iran-routing-rules/actions)
[![Direct Release](https://img.shields.io/badge/Release-GitHub%20Direct%20(Zero--Cache)-blue?style=flat-square&logo=github&logoColor=white)](https://github.com/Erfan4700/iran-routing-rules/releases/latest)
[![Edge CDN Active](https://img.shields.io/badge/CDN-jsDelivr%20Purged-orange?style=flat-square&logo=jsdelivr&logoColor=white)](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/)
[![HaGeZi Integrated](https://img.shields.io/badge/Threat%20Intel-HaGeZi%20MRS%20Native-purple?style=flat-square&logo=adguard&logoColor=white)](https://github.com/Erfan4700/HaGeZi_BlockLists_mrs_format)
[![Security Specs](https://img.shields.io/badge/Security-Phishing%20%7C%20AdBlock%20%7C%20Zero--Trust-emerald?style=flat-square&logo=shield&logoColor=white)](#-cyber-threat-mitigation--whitelist-integrity)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

An industrial-grade routing engine and cyber defense framework compiled natively into optimized binary and classical text rule-sets across **Mihomo (`.mrs`)**, **Sing-box (`.srs`)**, **V2Ray/Xray (`.dat`)**, and **Surge/Shadowrocket (`.list`)**. Powered by prefix-level CIDR mathematical supernetting, Mozilla PSL root pruning, strictly disjoint modular categorization, and ready-to-use **Macro** and **Modular** Clash Verge JavaScript processors.

[Architecture](#-macro-vs-modular-architectural-taxonomy) • [Merge Scripts](#-clash-verge-merge-scripts-javascript-runtime) • [Catalog & Endpoints](#-ruleset-catalog--distribution-endpoints) • [Client Setup](#-client--platform-integration) • [Threat Mitigation](#-cyber-threat-mitigation--whitelist-integrity) • [راهنمای جامع فارسی](#-راهنمای-جامع-به-زبان-فارسی)

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
│ • Designed for simplicity and zero-configuration bypass.                                               │
│ • iran-all-domains       : 100% of verified domestic domains consolidated into a single dataset.        │
│ • iran-all-ip            : Full aggregated RIPE IPv4/IPv6 country delegations.                         │
│ • iran-all-ads           : Unified domestic banner, SDK, and tracker blocking feed.                   │
│ • iran-all-security      : Domestic phishing, banking trojans, and smishing portals.                   │
│ • iran-all-apps          : Native Android package names and desktop process names.                     │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘

                                                   VS

┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              2. MODULAR SUITE (Zero-Overlap Disjoint Routing)                          │
├────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ • Designed for precision traffic control, granular policy routing, and zero memory redundancy.         │
│ • iran-modular-banking   : Certified banking portals, Shaparak infrastructure, and crypto exchanges.  │
│ • iran-modular-gov       : State, judiciary (Sana/Adliran), tax, and municipal services.               │
│ • iran-modular-media     : Video on demand, Aparat, Filimo, Telewebion, and national CDN broadacsters. │
│ • iran-modular-gaming    : Domestic game matchmaking, Radar Game subnets, and low-latency servers.     │
│ • iran-modular-download  : High-throughput software mirrors, Linux repositories, and Soft98.          │
│ • iran-modular-cloud     : Domestic cloud datacenters (ArvanCloud, Derak, ParsPack) IP-CIDRs.         │
│ • iran-modular-isp       : Direct domestic ISP infrastructure subnets (MCI, Irancell, Shatel, etc.).  │
│ • iran-modular-gambling  : Domestic online casinos, betting networks, and illegal payment scripts.    │
│ • iran-modular-other     : The mathematical remainder set (E-commerce, Snapp, Digikala, News).        │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### The Disjoint Mathematical Guarantee:
Specialized sub-categories are strictly isolated using automated set difference operations:
$$\text{iran-modular-other} = \text{iran-all-domains} \setminus (\text{banking} \cup \text{gov} \cup \text{media} \cup \text{gaming} \cup \text{download})$$

> **Zero Log Pollution & Zero RAM Waste:** No domain existing in `banking`, `gov`, `media`, `gaming`, or `download` is replicated in `iran-modular-other`. This completely prevents duplicate memory allocation inside the client radix tree.

---

## ⚡ Clash Verge Merge Scripts (JavaScript Runtime)

This repository includes two production-hardened JavaScript merge processors in the root directory for **Clash Verge Rev**, **Mihomo Party**, and **FlClash**. Both scripts feature native integration with the **[HaGeZi MRS Blocklists](https://github.com/Erfan4700/HaGeZi_BlockLists_mrs_format)**, automated domestic DNS policy injection, zero-latency domestic white-listing, and UDP/QUIC leak suppression.

```text
├── clash-verge-merge-macro.js    # For users who prefer a single macro switch for all Iran traffic
└── clash-verge-merge-modular.js  # For users demanding per-category toggles (Banking, Media, Gaming, etc.)
```

### Features Shared by Both Scripts:
1. **Dynamic HaGeZi Integration:** Supports all HaGeZi tiers (`light`, `normal`, `pro`, `promini`, `proplus`, `proplusmini`, `ultimate`, `ultimatemini`) plus modular add-ons (NSFW, Gambling, TIF IP/Mini, and Device Trackers: Apple, Samsung, Xiaomi, Microsoft, Amazon, LG, Roku, and TikTok).
2. **Deterministic Domestic DNS Isolation:** Injects domestic DoH and unpoisoned bootstrap resolvers (`193.186.32.32`, `223.5.5.5`, `119.29.29.29`) with dedicated `nameserver-policy` and `fake-ip-filter` entries to eliminate DNS leaks.
3. **Automated Proxy Group Resolution:** Dynamically traverses configuration proxy groups and attaches the primary egress group without hardcoded names.
4. **QUIC Censorship Bypass:** Enforces UDP 443 rejection (`AND,((NETWORK,UDP),(DST-PORT,443)),REJECT`) to force instantaneous TCP fallback, preventing ISP UDP-throttling.

---

## 📦 Ruleset Catalog & Distribution Endpoints

All release assets are rebuilt automatically twice daily (03:00 and 15:00 UTC) and distributed via both zero-cache GitHub direct links and purged jsDelivr edge mirrors:

* **Direct GitHub Releases URL (Recommended - Real-time & Zero Cache Lag):**  
  `https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/`
* **Edge CDN URL (Failover):**  
  `https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/`

### 1. Macro Datasets (All-In-One Suite)
| Ruleset Identifier | Scope / Content | Action | Supported Formats |
| :--- | :--- | :---: | :---: |
| **`iran-all-domains`** | 100% of validated Iranian domains | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.list) |
| **`iran-all-domains-lite`** | Essential high-traffic domestic domains | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains-lite.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains-lite.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains-lite.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains-lite.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains-lite.list) |
| **`iran-all-ip`** | Full supernetted RIPE IPv4/IPv6 subnets | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.list) |
| **`iran-all-ads`** | Domestic ad servers, SDKs, and trackers | `REJECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.list) |
| **`iran-all-security`** | Phishing portals, fake banks, and malware | `REJECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.list) |
| **`iran-all-security-ip`**| Malicious IP addresses, C2 nodes, and bots | `REJECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security-ip.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security-ip.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security-ip.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security-ip.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security-ip.list) |
| **`iran-all-apps`** | Android package IDs & Windows processes | `DIRECT` | [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-apps.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-apps.txt) \| [yaml](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-apps.yaml) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-apps.json) |
| **`iran-asn`** | Autonomous System Numbers of Iranian ISPs | `DIRECT` | [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-asn.txt) \| [yaml](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-asn.yaml) |
| **`iran-unified`** | Single classical master file for legacy clients | `DIRECT` | [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-unified.txt) \| [yaml](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-unified.yaml) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-unified.list) |

### 2. Modular Datasets (Zero-Overlap Granular Suite)
| Ruleset Identifier | Specific Scope | Action | Supported Formats |
| :--- | :--- | :---: | :---: |
| **`iran-modular-banking`** | Banks, Shaparak gateways, crypto, bourse | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.list) |
| **`iran-modular-gov`** | State portals, Sana, judiciary, tax services | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gov.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gov.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gov.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gov.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gov.list) |
| **`iran-modular-media`** | VOD, streaming platforms, Aparat, Filimo | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-media.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-media.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-media.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-media.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-media.list) |
| **`iran-modular-gaming`** | Domestic game matchmaking & Radar Game | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gaming.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gaming.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gaming.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gaming.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gaming.list) |
| **`iran-modular-download`** | High-speed software mirrors, ISOs, Soft98 | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-download.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-download.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-download.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-download.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-download.list) |
| **`iran-modular-cloud`** | National cloud CIDRs (Arvan, Derak, ParsPack) | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-cloud.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-cloud.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-cloud.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-cloud.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-cloud.list) |
| **`iran-modular-isp`** | Supernetted ISP allocations (IP-CIDR) | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-isp.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-isp.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-isp.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-isp.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-isp.list) |
| **`iran-modular-gambling`** | Online gambling portals & betting scripts | `REJECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gambling.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gambling.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gambling.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gambling.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gambling.list) |
| **`iran-modular-other`** | Remainder set (E-commerce, Snapp, Digikala) | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.list) |

### 3. Unified V2Ray / Xray Protobuf Datasets
* **`geosite.dat`**: Full tags (`geosite:iran-all-domains`, `geosite:iran-modular-banking`, `geosite:iran-modular-gov`, `geosite:iran-modular-media`, `geosite:iran-modular-gaming`, `geosite:iran-modular-download`, `geosite:iran-modular-other`, `geosite:iran-all-ads`, `geosite:iran-all-security`, `geosite:iran-modular-gambling`, `geosite:ir`) ➔ [Download geosite.dat](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/geosite.dat)
* **`geoip.dat`**: Country tags (`geoip:ir`, `geoip:iran-modular-cloud`, `geoip:iran-modular-isp`, `geoip:iran-all-security-ip`) ➔ [Download geoip.dat](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/geoip.dat)
* **`iran.dat`**: Drop-in unified replacement for Marzban and traditional Xray server deployments ➔ [Download iran.dat](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran.dat)

---

## 🚀 Client & Platform Integration

### 1. Mihomo / Clash Meta (`config.yaml`) - Modular Setup

```yaml
rule-providers:
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

Configure the outbound routing to prevent server-side loopbacks and protect the server egress IP:

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

## 🇮🇷 راهنمای جامع به زبان فارسی

<details>
<summary><b>برای مطالعه معماری مهندسی داده و راهنمای دو اسکریپت کلیک کنید</b></summary>
<br>

این پروژه یک اکوسیستم مسیریابی و امنیت سایبری چندسکویی است که به‌صورت بلادرنگ داده‌های اینترنتی کشور را از مراکز رسمی ثبت اینترنت منطقه‌ای (**RIPE NCC**) و میرورهای اعتبارسنجی‌شده استخراج کرده و به فرمت‌های باینری و سبک کامپایل می‌کند.

### ۱. انتخاب میان دو اسکریپت ادغام (Merge Scripts):
در پوشه ریشه مخزن دو اسکریپت جاوااسکریپت قرار دارد:
* **`clash-verge-merge-macro.js`:**  
  ویژه کاربرانی که می‌خواهند با کمترین تنظیمات و به صورت یکپارچه تمام ترافیک داخلی را مستقیم (Direct) کنند و دغدغه‌ای برای تفکیک دسته‌ها ندارند.
* **`clash-verge-merge-modular.js`:**  
  ویژه کاربرانی که خواهان کنترل دقیق، صفر درصد تداخل دامنه‌ها و امکان روشن/خاموش کردن دسته‌های مجزا (بانک‌ها، رسانه‌ها، سامانه‌های دولتی، گیمینگ و هاست‌های دانلود) هستند.

### ۲. ادغام قدرتمند با فیلترهای جهانی HaGeZi:
هر دو اسکریپت شامل پنل کاربری (`0. USER CONTROL PANEL`) با برچسب‌های راهنما هستند:
* تنظیم سطوح استاندارد مسدودسازی تبلیغات از **Light** تا **Ultimate** و نسخه‌های کم‌مصرف **Mini**.
* فیدهای امنیت سایبری **TIF** (تهدیدات سروری و بدافزار) و انسداد درگاه‌های جعلی.
* ترکرهای اختصاصی تجهیزات هوشمند شامل سامسونگ، شیائومی، اپل، مایکروسافت، تلویزیون‌های ال‌جی، روکو و تیک‌تاک.
* مسدودسازی قمار و محتوای بزرگسالان (NSFW) به‌صورت کاملاً ماژولار.

### ۳. چرا لینک‌های GitHub Direct به جای jsDelivr؟
سرویس‌های CDN واسط نظیر jsDelivr تغییرات ریلیز را با تاخیرهای چند روزه کَش (Cache Lag) می‌کنند. آدرس‌های مستقیم `releases/latest/download` بدون هیچ‌گونه تاخیر و به‌محض اتمام فرایند ساخت خودکار، آخرین نسخه فایل‌های فشرده کامپایل‌شده را به کلاینت تحویل می‌دهند.

</details>

---

## 📡 Data Sources & Attribution

* **Official Regional Internet Registries (RIRs):** Delegated allocations directly parsed from [RIPE NCC](https://ftp.ripe.net/) and [APNIC](https://ftp.apnic.net/).
* **National Domain Catalogs:** Verified domestic domains from [@bootmortis/iran-hosted-domains](https://github.com/bootmortis/iran-hosted-domains) and official ITO registries.
* **Threat & Adblock Feeds:** Heuristic phishing datasets and domestic mobile ad patterns from [@MasterKia/PersianBlocker](https://github.com/MasterKia/PersianBlocker).
* **Compilers & Tooling:** [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) (MRS format), [SagerNet/sing-box](https://github.com/SagerNet/sing-box) (SRS format), and [v2fly/geoip](https://github.com/v2fly/geoip) (DAT format).

---

## 📄 License

This repository is licensed under the **[MIT License](LICENSE)**. Network routing telemetry and domain datasets remain under the intellectual rights of their respective official registries and maintainers.
