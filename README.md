<div align="center">

# 🇮🇷 Iran Universal Routing & Cyber Defense Suite
### Automated Multi-Platform RuleSets for Mihomo, Sing-box, V2Ray/Xray & Shadowrocket

[![Automated Build](https://img.shields.io/github/actions/workflow/status/Erfan4700/iran-routing-rules/build-iran.yml?branch=main&label=Build%20Pipeline&style=flat-square&logo=github-actions&logoColor=white)](https://github.com/Erfan4700/iran-routing-rules/actions)
[![Release Branch](https://img.shields.io/badge/CDN-jsDelivr%20Active-orange?style=flat-square&logo=jsdelivr&logoColor=white)](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/)
[![Multi-Platform](https://img.shields.io/badge/Platform-Mihomo%20%7C%20Sing--box%20%7C%20V2Ray%20%7C%20Surge-blue?style=flat-square&logo=airplayvideo&logoColor=white)](#-multi-platform-matrix)
[![Security Specs](https://img.shields.io/badge/Security-Phishing%20%7C%20AdBlock%20%7C%20Zero--Break-emerald?style=flat-square&logo=shield&logoColor=white)](#-cyber-threat-mitigation--whitelist-integrity)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

An enterprise-grade, high-performance routing and security engine designed for the Iranian network ecosystem. Compiled natively into binary and text rule-sets across **Mihomo (`.mrs`)**, **Sing-box (`.srs`)**, **V2Ray/Xray (`.dat`)**, and **Surge/Shadowrocket (`.list`)**, with prefix-level CIDR aggregation, Mozilla PSL-compliant domain pruning, and disjoint modular categories.

[Ruleset Catalog](#-ruleset-catalog--cdn-endpoints) • [Platform Setup](#-client--platform-integration) • [Architecture](#-system-architecture) • [Security & Whitelist](#-cyber-threat-mitigation--whitelist-integrity) • [Granular Modules](#-modular-granularity--disjoint-routing) • [Sources](#-data-sources--attribution) • [راهنمای فارسی](#-راهنمای-جامع-به-زبان-فارسی)

</div>

---

## 🌐 Multi-Platform Matrix

This repository acts as a single source of truth, compiling identical telemetry into native formats for every major networking client:

| Platform / Client | Target Engine | Binary Format | Source / Text Format |
| :--- | :--- | :---: | :---: |
| **Clash Verge Rev, Mihomo Party, FlClash** | Mihomo / Clash.Meta | `.mrs` | `.txt` / `.yaml` |
| **Hiddify, NekoBox, Karing, Box4Proxy** | Sing-box Core | `.srs` | `.json` (Headless v1) |
| **Marzban, 3X-UI, v2rayN, v2rayNG, V2Box** | Xray-core / V2Ray | `geosite.dat` / `geoip.dat` / `iran.dat` | — |
| **Shadowrocket, Surge, Loon, Stash, Egern** | Surge Rule Engine | — | `.list` |

---

## 📐 System Architecture

Telemetry is ingested from authoritative RIR mirrors and vetted open datasets, hardened through a Python pipeline, and compiled using native binaries:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                           UPSTREAM TELEMETRY FEEDS                          │
├─────────────────────┬──────────────────────┬────────────────────────────────┤
│  RIPE NCC / APNIC   │ Bootmortis & Gov ITO │ PersianBlocker & Curated Feeds │
│ (Official IP & ASN) │ (Verified IR Domains)│ (Ads, Threats, Gaming, Apps)   │
└──────────┬──────────┴──────────┬───────────┴───────────────┬────────────────┘
           │                     │                           │
           ▼                     ▼                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DATA HARDENING & REFINING PIPELINE                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  • Mathematical Supernetting (ipaddress.collapse_addresses)                 │
│  • Mozilla Public Suffix List (PSL) Root Pruning via tldextract             │
│  • Strictly Disjoint Granular Classification (Zero-Overlap Remainder Set)   │
│  • Deterministic Zero-Trust Exemption (Shaparak, Sheba, PSPs, SMS APIs)     │
│  • Strict Separation: PACKAGE-NAME (Android) vs PROCESS-NAME (Desktop)      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
            ┌──────────────────────────┼──────────────────────────┐
            ▼                          ▼                          ▼
┌──────────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐
│     MIHOMO CORE      │   │    SING-BOX CORE     │   │   V2FLY COMPILER     │
│  convert-ruleset     │   │  rule-set compile    │   │  Protobuf Generators │
│  ===> Binary .mrs    │   │  ===> Binary .srs    │   │  ===> Binary .dat    │
└──────────┬───────────┘   └──────────┬───────────┘   └──────────┬───────────┘
           │                          │                          │
           └──────────────────────────┼──────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     GLOBAL EDGE DISTRIBUTION & CDN                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  Branch: `release` | Automated jsDelivr CDN Purge | Re-tagged Zero-Cache    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Core Engineering Highlights

* **Mozilla Public Suffix List (PSL) Domain Pruning:** Domain deduplication uses the official Mozilla PSL database via `tldextract`. Multi-part ccTLDs (`.co.ir`, `.gov.ir`, `.sch.ir`, `.ac.ir`) are parsed with absolute boundary accuracy, stripping redundant subdomains (`api.aparat.com` ➔ `aparat.com`) without breaking multi-tenant hosts.
* **Mathematical Supernetting:** Contiguous CIDRs from official **RIPE NCC** delegates are mathematically folded. This reduces table lookup overhead and memory footprint in memory-constrained devices (routers, mobile clients).
* **Strict Application Taxonomy:** Eliminates log pollution and unnecessary CPU cycle consumption by splitting application rules: Android packages strictly use `PACKAGE-NAME`, while desktop binaries use `PROCESS-NAME`.
* **Zero-Overlap Granular Partitioning:** Granular sub-modules are generated as disjoint mathematical sets. The remainder file (`iran-other`) has exactly **0% overlap** with specialized categories.

---

## 🛡️ Cyber Threat Mitigation & Whitelist Integrity

* **Targeted Threat Elimination (`iran-security`):** Intercepts cloned phishing portals mimicking judiciary services (`sana` / `adliran`), fraudulent subsidy pages, and card-to-card traps without sweeping unrelated global domains.
* **Deterministic Financial Protection (`UNBREAK_WHITELIST`):** Enforces an immutable exemption layer for central payment infrastructure (`*.shaparak.ir`), all licensed Payment Service Providers (Behpardakht, Sadad, Asan Pardakht, Saman Kish, Parsian, ZarinPal), and critical SMS notification endpoints (`kavenegar.com`, `ghasedak.me`). Legitimate payment callbacks are guaranteed never to drop.
* **Ad & Telemetry Suppression (`iran-ads`):** Neutralizes domestic mobile ad SDKs, banner trackers, and analytics telemetry without breaking host applications.
* **Domestic Betting & Casino Blocking (`iran-gambling`):** Blocks domestic gambling portals and payment routing scripts.

---

## 🧩 Modular Granularity & Disjoint Routing

Users can choose between a single all-inclusive list or fine-grained routing policies:

```text
               ┌────────────────────────────────────────────────────────┐
               │        iran-domains (Master Set: 100% of Domains)      │
               └──────────────────────────┬─────────────────────────────┘
                                          │
            ┌──────────────┬──────────────┼──────────────┬──────────────┬────────────────────────┐
            │              │              │              │              │                        │
       iran-media     iran-banking     iran-gov     iran-gaming   iran-download             iran-other
        (Streams)       (Finance)       (State)       (Gaming)       (Soft/DL)            (Disjoint Rest)
                                                                                  [0% Overlap with left 5]
```

$$\text{iran-other} = \text{iran-domains} \setminus (\text{media} \cup \text{banking} \cup \text{gov} \cup \text{gaming} \cup \text{download})$$

---

## 📦 Ruleset Catalog & CDN Endpoints

All files are rebuilt twice daily (03:00 and 15:00 UTC) and deployed directly to CDN edge caches:

```text
Base CDN URL: https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/
```

| Ruleset Identifier | Content Scope | Default Action | Supported Formats | CDN Direct Download |
| :--- | :--- | :---: | :---: | :---: |
| **`iran-domains`** | Master list: All verified Iranian domains | `DIRECT` | `.mrs` `.srs` `.txt` `.json` `.list` | [mrs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-domains.mrs) \| [srs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-domains.srs) \| [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-domains.txt) |
| **`iran-domains-lite`**| Essential high-traffic domestic services | `DIRECT` | `.mrs` `.srs` `.txt` `.json` `.list` | [mrs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-domains-lite.mrs) \| [srs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-domains-lite.srs) \| [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-domains-lite.txt) |
| **`iran-media`** | VOD, Video Streaming, Aparat, Filimo, CDNs | `DIRECT` | `.mrs` `.srs` `.txt` `.json` `.list` | [mrs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-media.mrs) \| [srs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-media.srs) \| [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-media.txt) |
| **`iran-banking`** | Banks, Shaparak, PSPs, Crypto, Bourse | `DIRECT` | `.mrs` `.srs` `.txt` `.json` `.list` | [mrs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-banking.mrs) \| [srs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-banking.srs) \| [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-banking.txt) |
| **`iran-gov`** | State portals, Sana, Tax, Judiciary | `DIRECT` | `.mrs` `.srs` `.txt` `.json` `.list` | [mrs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-gov.mrs) \| [srs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-gov.srs) \| [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-gov.txt) |
| **`iran-gaming`** | Domestic game servers, low-latency radar | `DIRECT` | `.mrs` `.srs` `.txt` `.json` `.list` | [mrs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-gaming.mrs) \| [srs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-gaming.srs) \| [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-gaming.txt) |
| **`iran-download`** | Software download portals, Linux mirrors | `DIRECT` | `.mrs` `.srs` `.txt` `.json` `.list` | [mrs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-download.mrs) \| [srs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-download.srs) \| [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-download.txt) |
| **`iran-other`** | Remainder set (E-commerce, Snapp, News) | `DIRECT` | `.mrs` `.srs` `.txt` `.json` `.list` | [mrs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-other.mrs) \| [srs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-other.srs) \| [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-other.txt) |
| **`iran-ip`** | RIPE official IPv4 & IPv6 subnets | `DIRECT` | `.mrs` `.srs` `.txt` `.json` `.list` | [mrs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-ip.mrs) \| [srs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-ip.srs) \| [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-ip.txt) |
| **`iran-cloud`** | Domestic cloud CIDRs (Arvan, Derak, ParsPack) | `DIRECT` | `.mrs` `.srs` `.txt` `.json` `.list` | [mrs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-cloud.mrs) \| [srs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-cloud.srs) \| [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-cloud.txt) |
| **`iran-ads`** | Domestic in-app mobile ads & analytics | `REJECT` | `.mrs` `.srs` `.txt` `.json` `.list` | [mrs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-ads.mrs) \| [srs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-ads.srs) \| [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-ads.txt) |
| **`iran-security`** | Cloned bank portals, smishing & malware | `REJECT` | `.mrs` `.srs` `.txt` `.json` `.list` | [mrs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-security.mrs) \| [srs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-security.srs) \| [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-security.txt) |
| **`iran-security-ip`**| Malicious C2 servers & smishing host IPs | `REJECT` | `.mrs` `.srs` `.txt` `.json` `.list` | [mrs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-security-ip.mrs) \| [srs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-security-ip.srs) \| [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-security-ip.txt) |
| **`iran-gambling`** | Online casinos & betting networks | `REJECT` | `.mrs` `.srs` `.txt` `.json` `.list` | [mrs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-gambling.mrs) \| [srs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-gambling.srs) \| [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-gambling.txt) |
| **`iran-apps`** | Domestic Android packages & Windows apps | `DIRECT` | `.srs` `.txt` `.yaml` `.json` | [srs](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-apps.srs) \| [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-apps.txt) \| [yaml](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-apps.yaml) |
| **`iran-asn`** | Autonomous System Numbers of Iranian ISPs | `DIRECT` | `.txt` `.yaml` | [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-asn.txt) \| [yaml](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-asn.yaml) |
| **`iran-unified`** | Single-file complete classical routing rule | `DIRECT` | `.txt` `.yaml` `.list` | [txt](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-unified.txt) \| [yaml](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-unified.yaml) \| [list](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-unified.list) |

### V2Ray / Xray Unified Binary Datasets
* **`geosite.dat`**: Full tags (`geosite:iran-domains`, `geosite:iran-media`, `geosite:iran-banking`, `geosite:iran-gov`, `geosite:iran-gaming`, `geosite:iran-download`, `geosite:iran-other`, `geosite:iran-ads`, `geosite:iran-security`, `geosite:iran-gambling`, `geosite:ir`, `geosite:other`) ➔ [Download](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/geosite.dat)
* **`geoip.dat`**: Country tag (`geoip:ir`, `geoip:iran-cloud`, `geoip:iran-security-ip`) ➔ [Download](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/geoip.dat)
* **`iran.dat`**: Drop-in replacement for traditional Marzban/Xray setups ➔ [Download](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran.dat)

---

## 🚀 Client & Platform Integration

### 1. Mihomo / Clash Meta (`config.yaml`)

```yaml
rule-providers:
  iran_ads:
    type: http
    behavior: domain
    format: mrs
    url: "https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-ads.mrs"
    path: ./ruleset/iran-ads.mrs
    interval: 86400

  iran_security:
    type: http
    behavior: domain
    format: mrs
    url: "https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-security.mrs"
    path: ./ruleset/iran-security.mrs
    interval: 86400

  iran_banking:
    type: http
    behavior: domain
    format: mrs
    url: "https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-banking.mrs"
    path: ./ruleset/iran-banking.mrs
    interval: 86400

  iran_other:
    type: http
    behavior: domain
    format: mrs
    url: "https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-other.mrs"
    path: ./ruleset/iran-other.mrs
    interval: 86400

  iran_ip:
    type: http
    behavior: ipcidr
    format: mrs
    url: "https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-ip.mrs"
    path: ./ruleset/iran-ip.mrs
    interval: 86400

rules:
  - RULE-SET,iran_ads,REJECT
  - RULE-SET,iran_security,REJECT
  - RULE-SET,iran_banking,DIRECT
  - RULE-SET,iran_other,DIRECT
  - RULE-SET,iran_ip,DIRECT,no-resolve
  - MATCH,PROXY
```

*(For automated profiles with HaGeZi integration and DNS leak prevention, use our [`clash-verge-merge.js`](./clash-verge-merge.js)).*

---

### 2. Sing-box / Hiddify / NekoBox (`config.json`)

```json
{
  "route": {
    "rule_set": [
      {
        "tag": "iran-ads",
        "type": "remote",
        "format": "binary",
        "url": "https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-ads.srs",
        "download_detour": "direct"
      },
      {
        "tag": "iran-domains",
        "type": "remote",
        "format": "binary",
        "url": "https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-domains.srs",
        "download_detour": "direct"
      },
      {
        "tag": "iran-ip",
        "type": "remote",
        "format": "binary",
        "url": "https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-ip.srs",
        "download_detour": "direct"
      }
    ],
    "rules": [
      { "rule_set": "iran-ads", "outbound": "block" },
      { "rule_set": "iran-domains", "outbound": "direct" },
      { "rule_set": "iran-ip", "outbound": "direct" }
    ]
  }
}
```

---

### 3. V2Ray / Xray / Marzban Server Routing

On outbound servers (Marzban / 3X-UI), block domestic traffic to prevent proxy loops; on user clients (v2rayNG/N), route domestic traffic to `direct`:

```json
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "outboundTag": "blocked",
        "domain": [
          "ext:iran.dat:ads",
          "ext:iran.dat:iran-security",
          "ext:iran.dat:iran-gambling"
        ]
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "domain": [
          "ext:iran.dat:ir",
          "ext:iran.dat:other"
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

### 4. Shadowrocket / Surge / Loon

Add as an external Rule-Set URL and assign the policy to `DIRECT`:

```text
https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/iran-unified.list
```

---

## 🇮🇷 راهنمای جامع به زبان فارسی

<details>
<summary><b>برای مطالعه مشخصات فنی، معماری داده و راهنمای تفکیک کلیک کنید</b></summary>
<br>

این پروژه یک پایپ‌لاین مهندسی‌شده و چندسکویی برای تفکیک ترافیک شبکه، مسدودسازی تهدیدات بومی و کنترل دسترسی اینترنت است که به صورت کاملاً خودکار برای تمامی کلاینت‌های شناخته‌شده جهان فایل‌های اختصاصی تولید می‌کند.

### ۱. ویژگی‌های فنی برجسته
* **پالایش دامنه‌ها بر مبنای Mozilla PSL:** دامنه‌ها با استاندارد رسمی شرکت موزیلا و کتابخانه `tldextract` اعتبارسنجی می‌شوند. برخلاف روش‌های سنتی، پسوندهای چندبخشی کشور (`.co.ir`, `.gov.ir`, `.sch.ir`, `.ac.ir`) به درستی پردازش شده و زیردامنه‌های زائد بدون از بین رفتن عملکرد دامنه ریشه حذف می‌شوند.
* **سوپرنتینگ ریاضی IPها:** تمامی رنج‌های IPv4 و IPv6 مستقیماً از **RIPE NCC** استخراج و فشرده‌سازی ریاضی می‌شوند تا تعداد سطرهای جداول روتینگ کلاینت به حداقل برسد.
* **تفکیک بدون همپوشانی (Disjoint Sets):** دسته‌بندی‌های فیلم و رسانه، بانک و پرداخت، سامانه‌های دولتی، گیمینگ و دانلود به عنوان مجموعه‌های مجزا استخراج شده‌اند. دامنه‌های باقی‌مانده کشور (فروشگاه‌ها، تاکسی‌های اینترنتی و اخبار) در ماژول **`iran-other`** قرار دارند که دقیقاً **صفر درصد همپوشانی** با دسته‌های تخصصی دارد.
* **سفیدلیست تضمینی پرداخت (Zero-Trust):** زیرساخت‌های شاپرک، تمام پی‌اس‌پی‌ها (به‌پرداخت، سداد، سامان‌کیش، آسان‌پردخت و...) و سرورهای پیامک رمز یکبار مصرف در لایه‌ای نفوذناپذیر از مسدودسازی محافظت شده‌اند تا هیچ خرید اینترنتی با خطا مواجه نشود.

### ۲. پلتفرم‌های پشتیبانی‌شده
* **Mihomo / Clash:** باینری‌های سبک و پیش‌ایندکس‌شده `.mrs` در رم.
* **Sing-box (Hiddify / NekoBox / Karing):** باینری‌های فوق‌سریع فشرده `.srs` همراه با سورس JSON.
* **Xray / V2Ray / Marzban:** دیتابیس‌های رسمی پروتوباف `geosite.dat` و `geoip.dat` و فایل سازگاری `iran.dat`.
* **iOS (Shadowrocket / Surge / Loon):** فایل‌های متنی استاندارد `.list`.

</details>

---

## 📡 Data Sources & Attribution

Data processing relies strictly on authoritative registries, official mirrors, and targeted threat intelligence feeds:

* **Official Regional Internet Registries (RIRs):**
  * IPv4, IPv6, and ASN allocations directly parsed from [RIPE NCC](https://ftp.ripe.net/) and [APNIC](https://ftp.apnic.net/) official delegated daily telemetry.
* **Domestic Domain & Infrastructure Catalog:**
  * National hosted domains sourced from [@bootmortis/iran-hosted-domains](https://github.com/bootmortis/iran-hosted-domains).
  * Infrastructure data from the Information Technology Organization of Iran (ITO) mirror.
* **Routing & Datacenter Rules:**
  * Domestic routing heuristics from [@ygbkm/clash-rules-iran](https://github.com/ygbkm/clash-rules-iran).
  * GeoIP lists from [@MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat).
* **Adblocking & Threat Feeds:**
  * Domestic advertising and smishing patterns from [@MasterKia/PersianBlocker](https://github.com/MasterKia/PersianBlocker).
  * Heuristic phishing datasets from [@curbengh/phishing-filter](https://github.com/curbengh/phishing-filter).
* **Application Package Telemetry:**
  * Android package catalog from [@SamadiPour/iran-android-apps](https://github.com/SamadiPour/iran-android-apps).
* **Compiler Engines:**
  * [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) (Mihomo MRS Compiler)
  * [SagerNet/sing-box](https://github.com/SagerNet/sing-box) (Sing-box RuleSet Compiler)
  * [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) & [v2fly/geoip](https://github.com/v2fly/geoip) (V2Ray Protobuf DAT Compilers)

---

## 📄 License

This repository is licensed under the **[MIT License](LICENSE)**. Network telemetry and domain telemetry remain under the respective intellectual rights of their upstream regional registries and maintainers.
