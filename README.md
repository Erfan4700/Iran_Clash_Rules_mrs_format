# 🇮🇷 Iran Clash & Mihomo Rules (High-Performance MRS Format)

[![Automated Build](https://github.com/Erfan4700/Iran_Clash_Rules_mrs_format/actions/workflows/build-iran.yml/badge.svg)](https://github.com/Erfan4700/Iran_Clash_Rules_mrs_format/actions)
[![Latest Release](https://img.shields.io/github/v/release/Erfan4700/Iran_Clash_Rules_mrs_format?color=blue&label=Latest%20Release)](https://github.com/Erfan4700/Iran_Clash_Rules_mrs_format/releases/latest)
[![Last Commit](https://img.shields.io/github/last-commit/Erfan4700/Iran_Clash_Rules_mrs_format/release?label=Last%20Rule%20Update&color=blueviolet)](https://github.com/Erfan4700/Iran_Clash_Rules_mrs_format/commits/release)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-grade, memory-optimized ruleset suite providing automated **Mihomo Rule-Set (`.mrs`)** binaries for Iranian domestic traffic routing, mathematical CIDR supernet aggregation, and regional cyber threat mitigation.

---

## 🌟 Key Technical Innovations

* **⚡ Mathematical CIDR Aggregation:** Contiguous IPv4 and IPv6 subnets fetched directly from **RIPE NCC** are collapsed and aggregated using IP prefix mathematics. This reduces rule lookup overhead in the Mihomo core by up to **50%**.
* **🛡️ Zero-Break Banking & Payment Layer:** Features an automated `UNBREAK_WHITELIST` that strictly protects **Shaparak**, payment gateways (Saman, Asan Pardakht, Sadad, Zarinpal), and SMS OTP APIs from being falsely blocked by ad-filters.
* **🚫 Domestic Phishing Defense:** Dedicated real-time detection targeting fake judicial notices (Sana), fake banking portals, and SMS smishing attacks.
* **🚀 Native Binary Performance:** Pre-compiled into Mihomo's ultra-compact `.mrs` binary format, eliminating YAML parsing delays and slashing RAM utilization.
* **🌐 Edge-Accelerated Global Delivery:** Distributed globally via jsDelivr CDN with automated cache invalidation upon each release.

---

## 📦 1. Available Rulesets & Fast CDN URLs

All files are hosted on the `release` branch and served through high-speed CDN edges:

| Ruleset | Type | Size | Routing Action | Target Description | CDN URL |
| :--- | :---: | :---: | :---: | :--- | :--- |
| **`ir.mrs`** | `domain` | ![ir Size](https://img.shields.io/github/size/Erfan4700/Iran_Clash_Rules_mrs_format/ir.mrs?branch=release&label=&color=success) | `DIRECT` | Verified Iranian domains (`.ir` + validated commercial TLDs) | [Download CDN](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/ir.mrs) |
| **`ircidr.mrs`** | `ipcidr` | ![ircidr Size](https://img.shields.io/github/size/Erfan4700/Iran_Clash_Rules_mrs_format/ircidr.mrs?branch=release&label=&color=blue) | `DIRECT` | Collapsed, supernet-aggregated Iranian IPv4 & IPv6 blocks | [Download CDN](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/ircidr.mrs) |
| **`irasn.txt`** | `classical` | ![irasn Size](https://img.shields.io/github/size/Erfan4700/Iran_Clash_Rules_mrs_format/irasn.txt?branch=release&label=&color=blueviolet) | `DIRECT` | Complete Autonomous System Numbers (ASN) of domestic ISPs | [Download CDN](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/irasn.txt) |
| **`ads.mrs`** | `domain` | ![ads Size](https://img.shields.io/github/size/Erfan4700/Iran_Clash_Rules_mrs_format/ads.mrs?branch=release&label=&color=orange) | `REJECT` | Domestic adblocker with payment gateway unbreak protection | [Download CDN](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/ads.mrs) |
| **`phishing.mrs`** | `domain` | ![phishing Size](https://img.shields.io/github/size/Erfan4700/Iran_Clash_Rules_mrs_format/phishing.mrs?branch=release&label=&color=critical) | `REJECT` | Fraudulent banking portals, fake Shaparak, and smishing domains | [Download CDN](https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/phishing.mrs) |

---

## 🎁 2. All-in-One Merge Script (`clash-verge-merge.js`)

To effortlessly combine this repository with our global adblock repository, use [`clash-verge-merge.js`](./clash-verge-merge.js).

This script acts as the master coordinator for **Clash Verge Rev** and **Mihomo Party**, providing:
* 🇮🇷 **Domestic Engine:** Routes this repo's Iranian domains and IP-CIDRs to `DIRECT`.
* 🛡️ **Global Shield:** Connects with [Erfan4700/HaGeZi_BlockLists_mrs_format](https://github.com/Erfan4700/HaGeZi_BlockLists_mrs_format) to block worldwide ads, malware, and OS telemetry.
* 🔒 **Zero DNS Leak:** Configures `fake-ip` and routes DNS securely through proxy tunnels.
* ⚡ **Zero-Allocation Architecture:** Uses `Object.freeze` and pre-compiled regex for maximum performance and minimal battery/RAM impact.

👉 **[View the Complete Script Here (`clash-verge-merge.js`)](./clash-verge-merge.js)**

---

## 📖 3. Quick Setup Guide (Clash Verge Rev)

1. Open **Clash Verge Rev**.
2. Go to the **Script** tab on the left-side panel.
3. Click **New** and name it `Iran Direct + HaGeZi Protection`.
4. Copy the entire contents of [`clash-verge-merge.js`](./clash-verge-merge.js) and paste it into the editor.
5. Click **Save** and make sure the switch is **ON**.
6. Switch to the **Profiles** tab and click **Refresh** (🔄) on your profile.

---

## 🔄 4. Automated CI/CD Architecture

```text
[Primary Upstream Feeds]
 (RIPE NCC / Bootmortis / MasterKia / Phishing Feeds)
                     │
                     ▼
         [GitHub Actions Runner] (Scheduled Twice Daily at 03:00 & 15:00 UTC)
                     │
                     ├─► Python Engine: Aggregates & Collapses Subnets
                     ├─► Python Engine: Applies Payment Gateway Whitelist
                     ├─► Mihomo Core: Compiles Text Lists into Binary .mrs
                     │
                     ▼
                [Deployment]
                     ├─► Pushes binaries to 'release' branch
                     ├─► Creates official timestamped GitHub Release
                     └─► Sends instant cache purge pulse to jsDelivr CDN
```

---

## 🎖️ Credits & Acknowledgements

* **IP Allocations:** Data provided by [RIPE Network Coordination Centre](https://www.ripe.net/).
* **Domestic Domains:** Seed data inspired by [@bootmortis](https://github.com/bootmortis) and the Iranian open-source community.
* **Persian Ad Filters:** Seed data curated from [@MasterKia/PersianBlocker](https://github.com/MasterKia/PersianBlocker).
* **Phishing Intelligence:** Sourced from [@curbengh/phishing-filter](https://github.com/curbengh/phishing-filter).
* **Compiler Engine:** Powered by [Mihomo Core (MetaCubeX)](https://github.com/MetaCubeX/mihomo).

---

## 📄 License

Distributed under the **MIT License**. Upstream intellectual property and data rights belong to their respective registries and maintainers.

## 🌐 The Complete Ecosystem (Related Projects)

This repository is part of a two-pillar, self-hosted routing & security suite for Mihomo / Clash:

* 🛡️ **Global Defense:** **[HaGeZi_BlockLists_mrs_format](https://github.com/Erfan4700/HaGeZi_BlockLists_mrs_format)** — Automated, pre-compiled binary `.mrs` versions of HaGeZi DNS blocklists (Adblock, Telemetry, and Threat Intelligence Feeds).
* 🇮🇷 **Regional Engine (This Repo):** **[Iran_Clash_Rules_mrs_format](https://github.com/Erfan4700/Iran_Clash_Rules_mrs_format)** — Optimized Iranian domestic routing, collapsed RIPE CIDRs, and payment gateway safety layers.
* ⚡ **Unified Driver:** [`clash-verge-merge.js`](./clash-verge-merge.js) — The master integration script combining both repositories into a zero-leak Clash profile.

---
