<div align="center">

# 🇮🇷 High-Performance Iran Routing & Security Suite
### Next-Gen Binary Rule-Sets (`.mrs`) & Classical Rules for Mihomo and Clash.Meta

[![Automated Build](https://img.shields.io/github/actions/workflow/status/Erfan4700/Iran_Clash_Rules_mrs_format/build-iran.yml?branch=main&label=CI%2FCD%20Build&style=flat-square&logo=github-actions&logoColor=white)](https://github.com/Erfan4700/Iran_Clash_Rules_mrs_format/actions)
[![Release Branch](https://img.shields.io/badge/CDN-jsDelivr%20Active-orange?style=flat-square&logo=jsdelivr&logoColor=white)](https://www.jsdelivr.com/)
[![Artifact Format](https://img.shields.io/badge/Artifacts-Binary%20MRS%20%2B%20Classical-blueviolet?style=flat-square&logo=webassembly&logoColor=white)](#-ruleset-catalog--cdn-endpoints)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald?style=flat-square)](LICENSE)

An enterprise-grade, memory-optimized traffic engineering and security suite for Iranian network infrastructure. Delivers pre-compiled **Mihomo Rule-Set (`.mrs`)** binaries, prefix-collapsed CIDR supernets, native Android package routing, and zero-break domestic payment protection.

[Explore Artifacts](#-ruleset-catalog--cdn-endpoints) • [Quick Setup](#-client-integration) • [Architecture](#-system-architecture) • [راهنمای فارسی](#-راهنمای-سریع-به-زبان-فارسی)

</div>

---

## 📐 System Architecture

The pipeline processes raw threat feeds and RIR registries through a multi-stage sanitization engine before compiling them into binary bytecode:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                           UPSTREAM DATA SOURCES                             │
├─────────────────────┬──────────────────────┬────────────────────────────────┤
│  RIPE NCC / APNIC   │  Bootmortis Project  │ PersianBlocker & Curated Feeds │
│ (Official IP & ASN) │ (Verified IR Domains)│   (Ads, Scams, Gambling, Apps) │
└──────────┬──────────┴──────────┬───────────┴───────────────┬────────────────┘
           │                     │                           │
           ▼                     ▼                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PYTHON HARDENING & REFINING PIPELINE                     │
├─────────────────────────────────────────────────────────────────────────────┤
│  • Mathematical Supernet Folding (ipaddress.collapse_addresses)             │
│  • Strict Sub-Domain Whitelisting (Shaparak, Sheba, SMS, Payment Switches)  │
│  • RFC 1035 Domain Parsing & Inline Comment Removal                         │
│  • Android Package Identifier Aggregation (PACKAGE-NAME)                    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MIHOMO COMPILATION ENGINE                           │
├──────────────────────────────────────┬──────────────────────────────────────┤
│  Text Domain / IP Rules              │  Android & ASN Classical Rules       │
│  ===> [mihomo convert-ruleset]       │  ===> Passthrough (.txt)             │
│  ===> Binary Memory-Mapped (.mrs)    │                                      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    GLOBAL EDGE DISTRIBUTION (jsDelivr CDN)                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  Branch: `release` | Auto-Purge Cache via Webhook | Edge-Accelerated        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Key Engineering Highlights

* **Supernet CIDR Aggregation:** Contiguous IPv4 and IPv6 allocations from RIPE NCC are mathematically merged into supernets using prefix folding. This halves routing table size in the client radix-tree, reducing memory lookups by up to **50%**.
* **Zero-Break Payment Guard (`UNBREAK_WHITELIST`):** Enforces strict subdomain evaluation preventing false-positive blocking of national payment gateways (**Shaparak, Saman, Asan Pardakht, Sadad, ZarinPal**) and SMS OTP APIs.
* **Classical Android App Routing (`apps.txt`):** Leverages `PACKAGE-NAME` matching to bypass domestic Android apps (Snapp, Tapsi, mobile banking, messaging) at the operating-system level, preventing socket leakages.
* **Targeted Regional Defense:** Focuses exclusively on domestic smishing (fake Sana, judicial notifications, gift internet scams) and Persian betting portals without polluting rules with bulky global feeds.
* **Instantaneous Binary Loading:** Compiles directly to Mihomo's proprietary `.mrs` binary bytecode, bypassing expensive runtime text/YAML parsing and significantly lowering memory footprint on routers and mobile devices.

---

## 📦 Ruleset Catalog & CDN Endpoints

All rulesets are auto-compiled every 12 hours and served globally via jsDelivr CDN edges:

| Ruleset File | Format | Behavior | Action | Coverage & Description | Fast CDN URL |
| :--- | :---: | :---: | :---: | :--- | :--- |
| **`ir.mrs`** | `mrs` | `domain` | `DIRECT` | Commercial and verified Iranian domains outside `.ir` | [Download](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/ir.mrs) |
| **`ircidr.mrs`** | `mrs` | `ipcidr` | `DIRECT` | Prefix-collapsed Iranian IPv4 and IPv6 subnets | [Download](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/ircidr.mrs) |
| **`irasn.txt`** | `text` | `classical` | `DIRECT` | Full ASN IP blocks for domestic Internet Service Providers | [Download](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/irasn.txt) |
| **`apps.txt`** | `text` | `classical` | `DIRECT` | Core Iranian Android app packages (Snapp, Banks, Divar) | [Download](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/apps.txt) |
| **`ads.mrs`** | `mrs` | `domain` | `REJECT` | Domestic trackers and ad networks with Shaparak immunity | [Download](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/ads.mrs) |
| **`phishing.mrs`**| `mrs` | `domain` | `REJECT` | Fake Shaparak gateways, fake Sana judicial scams, smishing | [Download](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/phishing.mrs) |
| **`nsfw.mrs`** | `mrs` | `domain` | `REJECT` | Persian betting networks, domestic casino portals, adult content | [Download](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/nsfw.mrs) |

---

## 🚀 Client Integration

### Method 1: All-in-One Automated Script (Recommended)

If you use **Clash Verge Rev**, **Mihomo Party**, or **FlClash**, use our unified integration script [`clash-verge-merge.js`](./clash-verge-merge.js).

This script combines:
1. **Domestic Engine (This Repo):** Routes national CIDRs, domains, and Android apps to `DIRECT`.
2. **Global Shield:** Connects with [HaGeZi_BlockLists_mrs_format](https://github.com/Erfan4700/HaGeZi_BlockLists_mrs_format) for worldwide adblocking, TIF threat defense, and telemetry pruning.
3. **Zero DNS Leaks:** Configures strict `fake-ip`, DoH resolution over proxy tunnels, and hardcoded RFC 1918 CIDRs (eliminating GeoIP dependency).

👉 **[Get the Complete Script (`clash-verge-merge.js`)](./clash-verge-merge.js)**

---

### Method 2: Manual `config.yaml` Declaration

Add the providers directly to your Mihomo configuration:

```yaml
rule-providers:
  ir:
    type: http
    behavior: domain
    format: mrs
    url: "https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/ir.mrs"
    path: ./ruleset/ir.mrs
    interval: 172800

  ircidr:
    type: http
    behavior: ipcidr
    format: mrs
    url: "https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/ircidr.mrs"
    path: ./ruleset/ircidr.mrs
    interval: 172800

  irasn:
    type: http
    behavior: classical
    format: text
    url: "https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/irasn.txt"
    path: ./ruleset/irasn.txt
    interval: 172800

  apps-ir:
    type: http
    behavior: classical
    format: text
    url: "https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/apps.txt"
    path: ./ruleset/apps.txt
    interval: 172800

  ads-ir:
    type: http
    behavior: domain
    format: mrs
    url: "https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/ads.mrs"
    path: ./ruleset/ads.mrs
    interval: 86400

rules:
  - RULE-SET,apps-ir,DIRECT,no-resolve
  - RULE-SET,ads-ir,REJECT
  - RULE-SET,ir,DIRECT
  - RULE-SET,ircidr,DIRECT,no-resolve
  - RULE-SET,irasn,DIRECT,no-resolve
  - DOMAIN-SUFFIX,ir,DIRECT
  - MATCH,PROXY
```

---

## 🇮🇷 راهنمای سریع به زبان فارسی

<details>
<summary><b>کلیک کنید برای مشاهده راهنمای فارسی و مزایای فنی</b></summary>
<br>

این پروژه مجموعه‌ای از رول‌های فوق‌العاده بهینه، سبک و باینری شده (`.mrs`) برای هسته Mihomo و کلاینت‌های مدرن (مانند Clash Verge Rev، Mihomo Party و FlClash) است که ترافیک ایران را به دقیق‌ترین شکل ممکن مدیریت می‌کند.

### چرا این مخزن بهترین انتخاب برای کاربر ایرانی است؟
1. **عدم مسدود شدن درگاه‌های بانکی:** با لایه امنیتی هوشمند، دامنه‌های شاپرک، بانک‌ها و پیامک‌های رمز یکبار مصرف به هیچ وجه در اثر فیلتر تبلیغات قطع نمی‌شوند.
2. **کاهش مصرف رم و پردازنده:** تمام فایل‌ها به صورت مستقیم به بایت‌کد باینری (`.mrs`) تبدیل شده‌اند و برخلاف فایل‌های متنی سنتی یا دیتابیس‌های حجیم GeoIP، حافظه رم دستگاه را اشغال نمی‌کنند.
3. **تفکیک اپ‌های اندرویدی (`apps.txt`):** برنامه‌هایی مثل اسنپ، تپسی، دیجی‌کالا و اپ‌های بانکی از طریق پکیج‌نیم رسمی مستقیماً از تونل بای‌پس می‌شوند تا حتی در صورت تغییر دامنه یا آی‌پی دچار قطعی نشوند.
4. **فشرده‌سازی ریاضی آی‌پی‌ها:** رنج‌های آی‌پی ایران مستقیماً از رجیستری رسمی **RIPE NCC** استخراج شده و با فرمول‌های ریاضی تجمیع (Collapse) شده‌اند تا جدول روتینگ کلاینت شما خلوت و سریع بماند.

</details>

---

## 🛡️ Upstream Attribution & Acknowledgements

* **IP Blocks & ASNs:** Provided by the [RIPE Network Coordination Centre](https://www.ripe.net/) and [APNIC Mirror](https://www.apnic.net/).
* **Domestic Domains:** Seed data curated by [@bootmortis](https://github.com/bootmortis).
* **Ad & Threat Intelligence:** Maintained by [@MasterKia/PersianBlocker](https://github.com/MasterKia/PersianBlocker) and [@curbengh/phishing-filter](https://github.com/curbengh/phishing-filter).
* **Core Engine:** Built on the cutting-edge network stack by [MetaCubeX (Mihomo Core)](https://github.com/MetaCubeX/mihomo).

---

## 📄 License

This project is licensed under the [MIT License](LICENSE). Upstream network data remains under the respective rights and intellectual property of the originating registries and maintainers.
