<div align="center">

# 🇮🇷 Iran Routing, Cyber Defense & Family Safety Suite
### High-Performance Binary Rule-Sets (`.mrs`) for Mihomo & Clash.Meta

[![Automated Build](https://img.shields.io/github/actions/workflow/status/Erfan4700/Iran_Clash_Rules_mrs_format/build-iran.yml?branch=main&label=CI%2FCD%20Build&style=flat-square&logo=github-actions&logoColor=white)](https://github.com/Erfan4700/Iran_Clash_Rules_mrs_format/actions)
[![Release Branch](https://img.shields.io/badge/CDN-jsDelivr%20Active-orange?style=flat-square&logo=jsdelivr&logoColor=white)](https://www.jsdelivr.com/)
[![Security Specs](https://img.shields.io/badge/Security-Phishing%20%7C%20AdBlock%20%7C%20Zero--Break-blue?style=flat-square&logo=shield&logoColor=white)](#-cyber-threat-mitigation--financial-defense)
[![Parental Control](https://img.shields.io/badge/Protection-Gambling%20%26%20Family%20Filter-emerald?style=flat-square&logo=adguard&logoColor=white)](#-parental-control--family-safety)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

A high-efficiency, multi-tier traffic engineering and protection suite for Iranian network infrastructure. Provides pre-compiled **Mihomo Rule-Set (`.mrs`)** binaries covering domestic split-tunneling, automated RIPE prefix aggregation, regional anti-phishing, payment gateway safety layers, and granular parental control filters.

[Ruleset Catalog](#-ruleset-catalog--cdn-endpoints) • [Security Specs](#-cyber-threat-mitigation--financial-defense) • [Family Safety](#-parental-control--family-safety) • [Client Setup](#-client-integration) • [Attributions](#-upstream-attribution--acknowledgements) • [راهنمای فارسی](#-راهنمای-جامع-به-زبان-فارسی)

</div>

---

## 📐 System Architecture

The pipeline refines raw upstream network and threat telemetry into hardened binary bytecode through a multi-stage validation process:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                           UPSTREAM DATA SOURCES                             │
├─────────────────────┬──────────────────────┬────────────────────────────────┤
│  RIPE NCC / APNIC   │  Bootmortis Project  │ PersianBlocker & Curated Feeds │
│ (Official IP & ASN) │ (Verified IR Domains)│ (Ads, Smishing, Casinos, Apps) │
└──────────┬──────────┴──────────┬───────────┴───────────────┬────────────────┘
           │                     │                           │
           ▼                     ▼                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PYTHON HARDENING & REFINING PIPELINE                     │
├─────────────────────────────────────────────────────────────────────────────┤
│  • Mathematical Supernet Folding (ipaddress.collapse_addresses)             │
│  • Strict Sub-Domain Whitelisting (Shaparak, Sheba, SMS OTP, Payment APIs)  │
│  • Targeted Keyword Heuristics for Fake Portals & Smishing Domains          │
│  • Domestic Betting, Casino & Adult Content Isolation                       │
│  • Android Package Identifier Extraction (PACKAGE-NAME)                     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MIHOMO COMPILATION ENGINE                           │
├──────────────────────────────────────┬──────────────────────────────────────┤
│  Domain & IP Threat Lists            │  Classical Metadata Rules            │
│  ===> [mihomo convert-ruleset]       │  ===> Passthrough (.txt)             │
│  ===> Binary Memory-Mapped (.mrs)    │  ===> ASN & Android Package Routing  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     GLOBAL DISTRIBUTION & EDGE CACHING                      │
├─────────────────────────────────────────────────────────────────────────────┤
│  Branch: `release` | Auto-Purge Cache via Webhook | High-Speed CDN Edges    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Cyber Threat Mitigation & Financial Defense

Unlike broad global blacklists that overlook domestic fraud, this suite provides targeted defenses engineered specifically for the Iranian threat landscape:

### 1. Domestic Smishing & Fake Gateway Defense (`phishing.mrs`)
* **Fake Judicial (Sana) Portals:** Proactively intercepts domains impersonating the judiciary notice system (`adliran` / `sana`), fake subsidy registrations, and fraudulent government traffic allocation campaigns.
* **Cloned Banking Portals:** Inspects hostnames mimicking Shaparak payment switches and major commercial banks (Saman, Melli, Mellat, Tejarat, Sadad).
* **SNI-Level Interception:** Operates at the DNS and TLS Server Name Indication layer, rejecting malicious connections before the TLS handshake completes.

### 2. Zero-Break Payment Integrity Layer (`UNBREAK_WHITELIST`)
* **Strict Subdomain Validation:** Standard adblockers often trigger false positives by matching broad domain substrings, inadvertently breaking payment callbacks.
* **Deterministic Exemption:** Ensures official payment infrastructure (`shaparak.ir`, `asanpardakht.ir`, `sadadpsp.ir`, `sepehrpay.com`, `sep.ir`, `zarinpal.com`) and verification SMS delivery endpoints (`kavenegar.com`, `ghasedak.me`) remain immune from blocking.

---

## 👨‍👩‍👧‍👦 Parental Control & Family Safety

Designed to create a sanitized, predictable browsing environment for home networks and shared family devices without degrading network performance:

### 1. Domestic Gambling & Casino Network Blocking (`nsfw.mrs`)
* **Unlicensed Betting Networks:** Blocks illegal online betting infrastructure, localized card-to-card casinos, and online gambling scripts tailored to domestic users.
* **Lightweight Binary Footprint:** Targets domestic betting platforms directly rather than bundling hundreds of thousands of unrelated foreign domains, preserving device RAM and startup times.

### 2. SafeSearch & Clean Media Enforcement
* **Enforced Search Engine VIPs:** Compatible with strict SafeSearch enforcement via client hosts mapping for Google and Bing:
  * `forcesafesearch.google.com` (`216.239.38.120`)
  * `strict.bing.com` (`204.79.197.220`)
* **Zero-Leak In-App Ads (`ads.mrs`):** Suppresses intrusive mobile advertising SDKs, predatory banner networks, and in-app trackers across domestic Android apps.

---

## ⚡ Network Routing & Performance Highlights

* **Supernet CIDR Aggregation:** Contiguous IPv4 and IPv6 allocations fetched directly from **RIPE NCC** are mathematically merged into minimal supernets. This minimizes radix-tree entries in the Mihomo core, cutting routing overhead by up to **50%**.
* **Android Native App Bypass (`apps.txt`):** Provides native `PACKAGE-NAME` classical routing rules for core domestic utilities (Snapp, Tapsi, Digikala, mobile banking apps, messaging tools), bypassing tunnels regardless of dynamic IP or CDN changes.
* **Pure Binary Memory-Mapped I/O:** Eliminates text parsing delays by compiling rule trees directly into Mihomo's `.mrs` format, enabling near-zero RAM expansion and rapid cold-booting.

---

## 📦 Ruleset Catalog & CDN Endpoints

All files are recompiled twice daily and deployed via jsDelivr CDN edges:

| Ruleset File | Category | Format | Behavior | Action | Functional Scope | Fast CDN URL |
| :--- | :---: | :---: | :---: | :---: | :--- | :--- |
| **`ir.mrs`** | Routing | `mrs` | `domain` | `DIRECT` | Verified Iranian domains hosted outside the `.ir` TLD | [Download](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/ir.mrs) |
| **`ircidr.mrs`** | Routing | `mrs` | `ipcidr` | `DIRECT` | Prefix-collapsed Iranian IPv4 and IPv6 subnets (RIPE) | [Download](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/ircidr.mrs) |
| **`irasn.txt`** | Routing | `text` | `classical` | `DIRECT` | Autonomous System Numbers (ASN) of domestic ISPs | [Download](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/irasn.txt) |
| **`apps.txt`** | Routing | `text` | `classical` | `DIRECT` | Android application package identifiers for split routing | [Download](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/apps.txt) |
| **`ads.mrs`** | Adblock | `mrs` | `domain` | `REJECT` | In-app mobile trackers with payment gateway whitelist | [Download](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/ads.mrs) |
| **`phishing.mrs`** | Security | `mrs` | `domain` | `REJECT` | Domestic banking clones, fake Sana, and smishing pages | [Download](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/phishing.mrs) |
| **`nsfw.mrs`** | Family | `mrs` | `domain` | `REJECT` | Domestic gambling networks, betting sites & adult content | [Download](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/nsfw.mrs) |

---

## 🚀 Client Integration

### Method 1: Master Integration Script (Clash Verge Rev / Mihomo Party)

Our unified script, [`clash-verge-merge.js`](./clash-verge-merge.js), merges this regional repository with global security feeds into an optimized, leak-free profile:

* **Modular Feature Toggles:** Individually toggle AdBlock, Anti-Phishing, Gambling Protection, OS Telemetry, and SafeSearch.
* **Global Defense Integration:** Automatically links with [HaGeZi_BlockLists_mrs_format](https://github.com/Erfan4700/HaGeZi_BlockLists_mrs_format) for worldwide Threat Intelligence (TIF).
* **Zero Geo-Database Overhead:** Removes bulky external MMDB/Dat files; local routing is handled via hardcoded RFC 1918 CIDRs and prefix-folded RIPE rules.

👉 **[View Integration Script (`clash-verge-merge.js`)](./clash-verge-merge.js)**

---

### Method 2: Manual `config.yaml` Declaration

Add the providers directly to your client profile.

---

## 🇮🇷 راهنمای جامع به زبان فارسی

<details>
<summary><b> برای مطالعه مشخصات فنی، امنیتی، کنترل والدین و اصالت پروژه کلیک کنید</b></summary>
<br>

این پروژه یک اکوسیستم تفکیک ترافیک، دفاع سایبری و نظارت خانوادگی برای هسته Mihomo و کلاینت‌های مدرن (مانند Clash Verge Rev، Mihomo Party و FlClash) است که با هدف عملکرد فنی دقیق و دوری از تعاریف اغراق‌آمیز طراحی شده است.

### ۱. امنیت سایبری و پیشگیری از کلاهبرداری (`phishing.mrs`)
* **فیشینگ‌های پیامکی بومی:** دامنه‌های فیشینگ ابلاغیه‌های جعلی قضایی (سامانه ثنا)، کلاهبرداری‌های سهام عدالت، اینترنت هدیه دولتی و درگاه‌های پرداخت تقلبی که به طور روزمره از طریق SMS برای کاربران ارسال می‌شوند را شناسایی و مسدود می‌کند.
* **عدم تداخل با تراکنش‌های معتبر:** با بهره‌گیری از وایت‌لیست قطعی شاپرک، بانک‌های عامل و سرورهای پیامک رمز یکبار مصرف، اتصال به خریدهای اینترنتی پایدار می‌ماند و در اثر فیلترینگ قطع نمی‌شود.

### ۲. حفاظت از خانواده و کنترل والدین (`nsfw.mrs`)
* **شبکه‌های قمار و شرط‌بندی داخلی:** سایت‌های شرط‌بندی، بازی‌های انفجار و کازینوهای غیرمجازی که با روش کارت‌به‌کارت از داخل کشور اقدام به جذب سرمایه می‌کنند، در این رول‌ست فیلتر می‌شوند.
* **بهینه‌سازی منابع:** به جای اضافه کردن صدها هزار دامنه خارجی غیرمرتبط (که باعث اشغال حافظه رم و کندی کلاینت می‌شود)، تمرکز بر دامنه‌های فعال زبان فارسی قرار گرفته و وظیفه فیلتر جهانی به ادبلاکرهای مکمل (مانند HaGeZi) واگذار شده است.
* **جستجوی ایمن (SafeSearch):** با نگاشت IPهای اختصاصی موتورهای جستجو در کلاینت، دسترسی به محتوای غیراخلاقی در گوگل و بینگ روی شبکه وای‌فای خانگی مهار می‌شود.

### ۳. عملکرد شبکه و تفکیک نرم‌افزارهای اندروید (`apps.txt`)
* **بای‌پس کامل در لایه سیستم‌عامل:** برنامه‌های ضروری از جمله تاکسی‌های اینترنتی (اسنپ و تپسی)، فروشگاه‌ها، نرم‌افزارهای بانکی و پیام‌رسان‌ها با شناسه پکیج اختصاصی (`PACKAGE-NAME`) مستقیماً از تونل بای‌پس می‌شوند تا تغییرات احتمالی آی‌پی و CDN باعث کندی یا قطعی آن‌ها نشود.
* **فشرده‌سازی ریاضی رنج‌های آی‌پی:** رنج‌های شبکه ملی مستقیماً از رجیستری **RIPE NCC** استخراج و فشرده‌سازی ریاضی (Supernetting) شده‌اند تا کمترین حجم جدول روتینگ و بالاترین سرعت تطبیق بسته در هسته به دست آید.

### ۴. منابع، مراجع داده و پیشینه جامعه متن‌باز
داده‌های این پروژه به صورت کاملاً مستقل و خودکار از مراجع دست‌اول جهانی و داخلی تأمین می‌شوند:
* **رنج‌های اینترنتی:** مستقیماً از دیتابیس رسمی **RIPE NCC** و سرورهای آینه **APNIC**.
* **دامنه‌های داخلی:** با تکیه بر فهرست دامنه‌های هاست‌شده پروژه **Bootmortis**.
* **تبلیغات بومی و فیشینگ:** پالایش‌شده از پایگاه داده پروژه **PersianBlocker**.
* **قدردانی از پیشگامان:** با احترام ویژه به پروژه **Chocolate4U** که به عنوان پیشگام و تدوین‌کننده استانداردهای اولیه رول‌های کلش در ایران، الهام‌بخش شکل‌گیری این پایپ‌لاین باینری مستقل و مدرن بود.

</details>

---

## 🛡️ Upstream Attribution & Acknowledgements

This project synthesizes data from premier registry databases, threat feeds, and open-source pioneers across the Iranian networking landscape:

* **Official Regional Internet Registries (RIRs):**
  * Direct IP allocations and ASN datasets provided by the [RIPE Network Coordination Centre](https://www.ripe.net/).
  * Secondary registry mirror hosted by [APNIC (Asia-Pacific Network Information Centre)](https://www.apnic.net/).
* **Domestic Domain Intelligence:**
  * National hosted domain catalog seeded and curated by [@bootmortis](https://github.com/bootmortis/iran-hosted-domains).
* **Adblocking & Domestic Phishing Telemetry:**
  * Persian ad networks and domestic smishing feeds sourced from [@MasterKia/PersianBlocker](https://github.com/MasterKia/PersianBlocker).
  * Global heuristic patterns adapted from [@curbengh/phishing-filter](https://github.com/curbengh/phishing-filter).
* **Pioneering Foundations & Community Prior Art:**
  * Special recognition to [@Chocolate4U](https://github.com/Chocolate4U/Iran-clash-rules), whose pioneering work established the baseline architecture for Clash routing in Iran and continues to serve as an emergency fallback mirror in our automated engine.
* **Compiler & Core Runtime:**
  * Powered by the cutting-edge network engine from [MetaCubeX (Mihomo Core)](https://github.com/MetaCubeX/mihomo).

---

## 📄 License

This suite is distributed under the **MIT License**. Upstream network ranges and threat intelligence remain under the respective intellectual property and rights of their originating registries and maintainers.
