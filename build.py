#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
Enterprise Rule-Set Engine for Mihomo / Clash Meta
Hybrid Resilience: RIPE NCC + ygbkm + bootmortis + Chocolate4U + MetaCubeX
Text Sanitization -> Subdomain Pruning -> CIDR Collapse -> MRS Binary Compiler
================================================================================
"""

import os
import re
import sys
import json
import shutil
import zipfile
import platform
import subprocess
import ipaddress
import urllib.request
from typing import Set, List, Tuple, Optional
from pathlib import Path

# --- DIRECTORY CONFIGURATION ---
BASE_DIR = Path(__file__).resolve().parent
TEXT_DIR = BASE_DIR / "output_text"
MRS_DIR = BASE_DIR / "output_mrs"
BASELINE_DIR = BASE_DIR / "data" / "baseline"

TEXT_DIR.mkdir(parents=True, exist_ok=True)
MRS_DIR.mkdir(parents=True, exist_ok=True)
BASELINE_DIR.mkdir(parents=True, exist_ok=True)

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
HEADERS = {"User-Agent": USER_AGENT}

# ==============================================================================
# 0. ZERO-TRUST CRITICAL INFRASTRUCTURE WHITELIST
# ==============================================================================
UNBREAK_WHITELIST = {
    # PSPs & Payment Infrastructure
    "shaparak.ir", "asanpardakht.ir", "sadadpsp.ir", "behpardakht.com",
    "sepehrpay.com", "sep.ir", "pec.ir", "zarinpal.com", "zarinpal.ir",
    "payping.net", "payping.ir", "idpay.ir", "jibit.ir", "nextpay.ir",
    "vandar.ir", "zibal.ir", "rayanpay.com", "fanavakart.ir", "sayancard.ir",
    "pasargad-psp.ir", "pep.co.ir", "pna.co.ir",
    # Core Banking & Central Bank
    "cbi.ir", "bmi.ir", "bankmellat.ir", "mellatbank.ir", "tejaratbank.ir",
    "bsi.ir", "bpi.ir", "sb24.ir", "sb24.com", "parsian-bank.ir",
    "banksepah.ir", "refah-bank.ir", "keshavarzi-bank.ir", "maskan-bank.ir",
    "blubank.com", "blubank.sb24.com",
    # Essential Domestic Services & CDNs
    "sana.gov.ir", "adliran.ir", "divar.ir", "divarcdn.com", "torob.com",
    "digikala.com", "digikalacloud.com", "snapp.ir", "snapp.cab", "snapp.tech",
    "snappcloud.io", "tapsi.ir", "tapsi.cab", "kavenegar.com", "ghasedak.me",
    "raychat.io", "bale.ai", "eitaa.com", "eitaa.ir", "rubika.ir", "rubikacdn.ir",
    "soroushplus.ir", "cafebazaar.ir", "farsitel.com", "myket.ir",
    "neshan.org", "neshanmaps.ir", "balad.ir", "aparat.com", "telewebion.com",
    "mci.ir", "mtnirancell.ir", "rightel.ir", "tamin.ir"
}

PUBLIC_SUFFIX_SET = {
    "ir", "co.ir", "gov.ir", "ac.ir", "org.ir", "net.ir", "sch.ir", "id.ir",
    "com", "net", "org", "gov", "edu", "info", "biz", "io", "me", "co",
    "online", "site", "xyz", "co.uk", "org.uk", "com.tr", "edu.tr", "com.au", "net.au"
}

def is_whitelisted(domain: str) -> bool:
    """بررسی تطابق کامل یا ساب‌دامنه‌ای با سفیدلیست حیاتی"""
    domain = domain.lower()
    return any(domain == safe or domain.endswith("." + safe) for safe in UNBREAK_WHITELIST)

# ==============================================================================
# UTILITIES: NETWORK FETCHING WITH N+1 RETRY & CURL FALLBACK
# ==============================================================================
def fetch_data(urls, timeout: int = 60, min_len: int = 20) -> str:
    """دریافت داده از ماتریس منابع با فال‌بک خودکار به curl و urllib"""
    if isinstance(urls, str):
        urls = [urls]

    for url in urls:
        # ۱. تلاش با curl بومی
        try:
            cmd = ["curl", "-sSL", "--compressed", "--max-time", str(timeout), "-A", USER_AGENT, url]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if len(res.stdout.strip()) >= min_len:
                return res.stdout
        except Exception:
            pass

        # ۲. فال‌بک به کتابخانه استاندارد urllib
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
                if len(content.strip()) >= min_len:
                    return content
        except Exception:
            continue

    return ""

def load_baseline(name: str) -> Set[str]:
    """بازیابی لایه دوم: اسنپ‌شات پایدار محلی"""
    path = BASELINE_DIR / f"{name}.txt"
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip() and not line.startswith("#")}
    return set()

def save_baseline(name: str, items: Set[str]) -> None:
    """به‌روزرسانی لایه دوم: ذخیره اسنپ‌شات طلایی"""
    path = BASELINE_DIR / f"{name}.txt"
    with open(path, "w", encoding="utf-8") as f:
        for item in sorted(items):
            f.write(f"{item}\n")

# ==============================================================================
# DOMAIN PURIFICATION & SUBDOMAIN PRUNING ENGINE
# ==============================================================================
DOMAIN_REGEX = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

def clean_domain(line: str) -> Optional[str]:
    """استخراج، پاکسازی و اعتبارسنجی دقیق نام دامنه"""
    line = line.split("#")[0].split(";")[0].strip().lower()
    if not line or line.startswith(("!", "//", "/*")):
        return None

    line = re.sub(r"^(?:domain:|full:|keyword:|regexp:|\|\|?|@@)", "", line)
    line = re.sub(r"^(?:domain-suffix|domain|domain-keyword),", "", line, flags=re.IGNORECASE)

    parts = line.split()
    target = parts[1] if (len(parts) >= 2 and re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^::[0-9a-f]?$", parts[0])) else parts[0]

    target = re.sub(r"^https?://", "", target)
    target = re.sub(r"[\^/:].*$", "", target)
    target = re.sub(r"^\*\.?", "", target)
    target = re.sub(r"^\+\.?", "", target)
    target = target.strip(".")

    if target in PUBLIC_SUFFIX_SET:
        return None

    if DOMAIN_REGEX.match(target) and ".." not in target:
        return target
    return None

def prune_subdomains(domains: Set[str]) -> Set[str]:
    """
    هرس هوشمند زیردامنه‌ها:
    اگر aparat.com در لیست باشد، api.aparat.com بدون افت عملکرد حذف می‌شود.
    """
    sorted_domains = sorted(domains, key=lambda d: (len(d.split(".")), len(d), d))
    retained_roots = set()

    for domain in sorted_domains:
        parts = domain.split(".")
        is_redundant = False
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in PUBLIC_SUFFIX_SET:
                continue
            if parent in retained_roots:
                is_redundant = True
                break

        if not is_redundant:
            retained_roots.add(domain)

    return retained_roots

# ==============================================================================
# IP / CIDR PURIFICATION & COLLAPSING ENGINE
# ==============================================================================
def collapse_cidrs(raw_cidrs: List[str]) -> Tuple[List[ipaddress.IPv4Network], List[ipaddress.IPv6Network]]:
    """تجمیع و ادغام رنج‌های IP با الگوریتم Supernetting"""
    v4_nets, v6_nets = [], []
    for entry in raw_cidrs:
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        entry = re.sub(r"^(?:IP-CIDR|IP-CIDR6),", "", entry, flags=re.IGNORECASE)
        try:
            net = ipaddress.ip_network(entry, strict=False)
            if net.version == 4:
                v4_nets.append(net)
            else:
                v6_nets.append(net)
        except Exception:
            continue

    collapsed_v4 = sorted(list(ipaddress.collapse_addresses(v4_nets)), key=lambda n: (int(n.network_address), n.prefixlen))
    collapsed_v6 = sorted(list(ipaddress.collapse_addresses(v6_nets)), key=lambda n: (int(n.network_address), n.prefixlen))
    return collapsed_v4, collapsed_v6

# ==============================================================================
# MIHOMO MRS COMPILER INTEGRATION
# ==============================================================================
def find_or_download_mihomo() -> Optional[str]:
    """یافتن باینری میهومو یا دریافت نسخه رسمی برای کامپایل MRS"""
    for name in ["mihomo", "mihomo.exe"]:
        cmd_path = shutil.which(name) or (BASE_DIR / name)
        if cmd_path and os.path.exists(cmd_path) and os.access(cmd_path, os.X_OK):
            return str(cmd_path)

    print("[*] Mihomo core not found locally. Attempting automatic bootstrap...")
    uname = platform.system().lower()
    machine = platform.machine().lower()

    os_map = {"linux": "linux", "darwin": "darwin", "windows": "windows"}
    arch_map = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}

    target_os = os_map.get(uname)
    target_arch = arch_map.get(machine)

    if not target_os or not target_arch:
        print(f"[!] Unsupported architecture for auto Mihomo bootstrap: {uname}-{machine}")
        return None

    try:
        api_url = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
        api_headers = dict(HEADERS)
        github_token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
        if github_token:
            api_headers["Authorization"] = f"Bearer {github_token}"

        req = urllib.request.Request(api_url, headers=api_headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            release_data = json.loads(r.read().decode())

        target_asset = None
        for asset in release_data.get("assets", []):
            aname = asset["name"].lower()
            if target_os in aname and target_arch in aname and "compatible" not in aname:
                if (target_os == "windows" and aname.endswith(".zip")) or (target_os != "windows" and aname.endswith(".gz")):
                    target_asset = asset["browser_download_url"]
                    break

        if target_asset:
            dest_file = BASE_DIR / ("mihomo.zip" if target_os == "windows" else "mihomo.gz")
            urllib.request.urlretrieve(target_asset, dest_file)

            if target_os != "windows":
                import gzip
                bin_path = BASE_DIR / "mihomo"
                with gzip.open(dest_file, "rb") as f_in, open(bin_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
                bin_path.chmod(0o755)
                dest_file.unlink()
                return str(bin_path)
            else:
                with zipfile.ZipFile(dest_file, "r") as zip_ref:
                    zip_ref.extractall(BASE_DIR)
                dest_file.unlink()
                for p in BASE_DIR.glob("*.exe"):
                    if "mihomo" in p.name.lower():
                        return str(p)

    except Exception as e:
        print(f"[!] Auto-download failed: {e}. MRS will be generated if Mihomo is in PATH.")

    return None

def compile_to_mrs(mihomo_bin: Optional[str], behavior: str, text_file: Path, mrs_file: Path) -> bool:
    """تبدیل فایل متنی پالایش‌شده به فرمت باینری MRS بوسیله هسته رسمی Mihomo"""
    if not mihomo_bin or not text_file.exists() or text_file.stat().st_size == 0:
        return False
    try:
        cmd = [mihomo_bin, "convert-ruleset", behavior, "text", str(text_file), str(mrs_file)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0 and mrs_file.exists() and mrs_file.stat().st_size > 50:
            return True
        else:
            print(f"[!] MRS compiler notice for {text_file.name}: {res.stderr.strip()}")
            return False
    except Exception as e:
        print(f"[!] Failed to run MRS compiler: {e}")
        return False

# ==============================================================================
# MAIN PIPELINE EXECUTION
# ==============================================================================
def main():
    print("=" * 78)
    print("🚀 STARTING PRODUCTION COMPILATION PIPELINE (IRAN CLASH / MIHOMO RULES)")
    print("=" * 78)

    # --------------------------------------------------------------------------
    # STEP 1: IRAN IP-CIDRS & ASNS (RIPE NCC AUTHORITATIVE + MULTI-UPSTREAM)
    # --------------------------------------------------------------------------
    print("\n[+] STEP 1: Processing Iranian IPv4/IPv6 CIDRs & ASNs...")
    ripe_raw = fetch_data([
        "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
        "https://ftp.apnic.net/stats/ripe-ncc/delegated-ripencc-latest"
    ], timeout=90)

    raw_ip_list = []
    asns = set()

    if ripe_raw:
        for line in ripe_raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) >= 7 and parts[1] == "IR":
                if parts[2] == "ipv4":
                    try:
                        first_ip = ipaddress.IPv4Address(parts[3])
                        last_ip = first_ip + (int(parts[4]) - 1)
                        for cidr in ipaddress.summarize_range(first_ip, last_ip):
                            raw_ip_list.append(str(cidr))
                    except Exception:
                        pass
                elif parts[2] == "ipv6":
                    raw_ip_list.append(f"{parts[3]}/{parts[4]}")
                elif parts[2] == "asn":
                    asns.add(f"IP-ASN,{parts[3]}")

    extra_ip_sources = [
        "https://raw.githubusercontent.com/ygbkm/resources/refs/heads/main/resources/iran-datacenters/ipv4.txt",
        "https://raw.githubusercontent.com/ygbkm/resources/refs/heads/main/resources/iran-datacenters/ipv6.txt",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/ir.list",
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ircidr.txt"
    ]
    for url in extra_ip_sources:
        content = fetch_data(url, timeout=30)
        for line in content.splitlines():
            d = line.strip()
            if d and not d.startswith("#"):
                raw_ip_list.append(d)

    fallback_asns = fetch_data("https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/irasn.txt", timeout=30)
    for line in fallback_asns.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            asns.add(line if line.startswith("IP-ASN,") else f"IP-ASN,{line}")

    if len(raw_ip_list) < 500:
        print("[!] Upstream IP list degraded. Merging with internal Baseline...")
        raw_ip_list.extend(load_baseline("ircidr"))
    else:
        save_baseline("ircidr", set(raw_ip_list))

    if len(asns) < 100:
        asns.update(load_baseline("irasn"))
    else:
        save_baseline("irasn", asns)

    collapsed_v4, collapsed_v6 = collapse_cidrs(raw_ip_list)
    all_cidrs = [str(n) for n in collapsed_v4] + [str(n) for n in collapsed_v6]

    with open(TEXT_DIR / "ircidr.txt", "w", encoding="utf-8") as f:
        for net in all_cidrs:
            f.write(f"{net}\n")

    with open(TEXT_DIR / "irasn.txt", "w", encoding="utf-8") as f:
        for asn in sorted(asns):
            f.write(f"{asn}\n")

    with open(TEXT_DIR / "irasn.yaml", "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for asn in sorted(asns):
            f.write(f"  - '{asn}'\n")

    print(f"[✓] Compiled {len(all_cidrs)} collapsed CIDRs (IPv4: {len(collapsed_v4)}, IPv6: {len(collapsed_v6)}) | ASNs: {len(asns)}")

    # --------------------------------------------------------------------------
    # STEP 2: IRAN DOMAINS (BOOTMORTIS + YGBKM + CHOCOLATE4U + ITO)
    # --------------------------------------------------------------------------
    print("\n[+] STEP 2: Processing Iranian Domains with Subdomain Pruning...")
    raw_iran_domains = {
        "digikala.com", "torob.com", "divar.ir", "snapp.ir", "snapp.cab", "tapsi.cab",
        "neshan.org", "balad.ir", "bale.ai", "eitaa.com", "rubika.ir", "shaparak.ir",
        "asanpardakht.ir", "zarinpal.com", "aparat.com", "telewebion.com", "varzesh3.com"
    }

    domain_upstreams = [
        "https://github.com/ygbkm/clash-rules-iran/releases/latest/download/rules.txt",
        "https://raw.githubusercontent.com/bootmortis/iran-hosted-domains/release/domains.txt",
        "https://raw.githubusercontent.com/bootmortis/iran-hosted-domains/release/clash_rules_other.txt",
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.txt",
        "https://raw.githubusercontent.com/bootmortis/ito-gov-mirror/main/out/domains.csv"
    ]

    for url in domain_upstreams:
        content = fetch_data(url, timeout=40)
        for line in content.splitlines():
            if "," in line and not line.startswith("DOMAIN"):
                parts = line.split(",")
                if len(parts) >= 2:
                    line = parts[1]
            d = clean_domain(line)
            if d:
                raw_iran_domains.add(d)

    if len(raw_iran_domains) < 2000:
        print("[!] Iran domain list below health threshold. Engaging Local Baseline...")
        raw_iran_domains.update(load_baseline("ir"))
    else:
        save_baseline("ir", raw_iran_domains)

    initial_count = len(raw_iran_domains)
    pruned_iran_domains = prune_subdomains(raw_iran_domains)
    print(f"[*] Pruned redundant subdomains: {initial_count} -> {len(pruned_iran_domains)} root entities (-{initial_count - len(pruned_iran_domains)})")

    with open(TEXT_DIR / "ir.txt", "w", encoding="utf-8") as f:
        for d in sorted(pruned_iran_domains):
            f.write(f"{d}\n")

    ir_lite_raw = fetch_data("https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir-lite.txt", timeout=30)
    lite_domains = set()
    for line in ir_lite_raw.splitlines():
        d = clean_domain(line)
        if d:
            lite_domains.add(d)
    pruned_lite = prune_subdomains(lite_domains if len(lite_domains) > 100 else pruned_iran_domains)
    with open(TEXT_DIR / "ir-lite.txt", "w", encoding="utf-8") as f:
        for d in sorted(pruned_lite):
            f.write(f"{d}\n")

    # --------------------------------------------------------------------------
    # STEP 3: PERSIAN ADS WITH ZERO-TRUST WHITELIST
    # --------------------------------------------------------------------------
    print("\n[+] STEP 3: Compiling Persian Ads & Trackers...")
    ads_sources = [
        "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerHosts.txt",
        "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerAds-Hosts.txt",
        "https://raw.githubusercontent.com/bootmortis/iran-hosted-domains/release/clash_rules_ads.txt",
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ads.txt"
    ]
    raw_ads = {"yektanet.com", "sabavision.com", "mediaad.org", "najva.com"}
    for url in ads_sources:
        content = fetch_data(url, timeout=30)
        for line in content.splitlines():
            d = clean_domain(line)
            if d and not is_whitelisted(d):
                raw_ads.add(d)

    pruned_ads = prune_subdomains(raw_ads)
    with open(TEXT_DIR / "ads.txt", "w", encoding="utf-8") as f:
        for d in sorted(pruned_ads):
            f.write(f"{d}\n")
    print(f"[✓] Compiled {len(pruned_ads)} verified Persian ad domains")

    # --------------------------------------------------------------------------
    # STEP 4: DOMESTIC PHISHING & SMISHING
    # --------------------------------------------------------------------------
    print("\n[+] STEP 4: Compiling Domestic Phishing & Fake Portals...")
    phishing_sources = [
        "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerPhishing.txt",
        "https://raw.githubusercontent.com/curbengh/phishing-filter/master/phishing-filter-hosts.txt",
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing.txt"
    ]
    KEYWORD_PATTERN = re.compile(r"(?:^|[.-])(?:shaparak|sana|divar|sadad|sep|mellat|melli|sheba|tejarat|saderat|pasargad|blubank)(?:[.-]|$)")
    raw_phishing = {"phishing-fake-shaparak.top", "ir-sana-gov.com"}

    for url in phishing_sources:
        content = fetch_data(url, timeout=30)
        for line in content.splitlines():
            d = clean_domain(line)
            if d and KEYWORD_PATTERN.search(d) and not is_whitelisted(d):
                raw_phishing.add(d)

    pruned_phishing = prune_subdomains(raw_phishing)
    with open(TEXT_DIR / "phishing.txt", "w", encoding="utf-8") as f:
        for d in sorted(pruned_phishing):
            f.write(f"{d}\n")

    phishing_ip_raw = fetch_data("https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing-ip.txt", timeout=25)
    p_v4, p_v6 = collapse_cidrs(phishing_ip_raw.splitlines())
    with open(TEXT_DIR / "phishing-ip.txt", "w", encoding="utf-8") as f:
        for net in (p_v4 + p_v6):
            f.write(f"{net}\n")
    print(f"[✓] Compiled {len(pruned_phishing)} phishing domains & {len(p_v4 + p_v6)} malicious IPs")

    # --------------------------------------------------------------------------
    # STEP 5: DOMESTIC GAMBLING & CASINOS (PERSIAN BET ONLY)
    # --------------------------------------------------------------------------
    print("\n[+] STEP 5: Compiling Domestic Gambling blocklist...")
    gambling_sources = [
        "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerGambling.txt",
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/nsfw.txt"
    ]
    raw_nsfw = {"betcart.com", "takbet.com", "wolfbet.info", "cannonbet.org", "hazarat.org"}
    for url in gambling_sources:
        content = fetch_data(url, timeout=30)
        for line in content.splitlines():
            d = clean_domain(line)
            if d and not is_whitelisted(d):
                raw_nsfw.add(d)

    pruned_nsfw = prune_subdomains(raw_nsfw)
    with open(TEXT_DIR / "nsfw.txt", "w", encoding="utf-8") as f:
        for d in sorted(pruned_nsfw):
            f.write(f"{d}\n")
    print(f"[✓] Compiled {len(pruned_nsfw)} targeted gambling/nsfw domains")

    # --------------------------------------------------------------------------
    # STEP 6: DOMESTIC MALWARE (DOMAINS & IPS)
    # --------------------------------------------------------------------------
    print("\n[+] STEP 6: Compiling Malware Rules...")
    malware_raw = fetch_data("https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware.txt", timeout=30)
    raw_malware = set()
    for line in malware_raw.splitlines():
        d = clean_domain(line)
        if d and not is_whitelisted(d):
            raw_malware.add(d)
    pruned_malware = prune_subdomains(raw_malware)
    with open(TEXT_DIR / "malware.txt", "w", encoding="utf-8") as f:
        for d in sorted(pruned_malware):
            f.write(f"{d}\n")

    malware_ip_raw = fetch_data("https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware-ip.txt", timeout=30)
    m_v4, m_v6 = collapse_cidrs(malware_ip_raw.splitlines())
    with open(TEXT_DIR / "malware-ip.txt", "w", encoding="utf-8") as f:
        for net in (m_v4 + m_v6):
            f.write(f"{net}\n")
    print(f"[✓] Compiled {len(pruned_malware)} malware domains & {len(m_v4 + m_v6)} malware IPs")

    # --------------------------------------------------------------------------
    # STEP 7: IRANIAN APPS & PROCESSES
    # --------------------------------------------------------------------------
    print("\n[+] STEP 7: Compiling 5,000+ Domestic Applications (Android + Windows)...")
    ESSENTIAL_PACKAGES = {
        "cab.snapp.passenger", "cab.snapp.driver", "cab.snapp.biker", "cab.snapp.delivery",
        "taxi.tap30.passenger", "taxi.tap30.driver", "taxi.tap30.food", "com.alopeyk.customer",
        "neshan.maps", "ir.balad.maps", "com.digikala", "ir.divar", "ir.torob", "com.emalls",
        "market.nobitex", "net.nobitex", "ir.wallex.app", "com.abantether", "com.ramzinex.app",
        "ir.bitpin", "ir.tejaratbank.mobile", "com.bmi.mobilebank", "com.bmi.bam", "ir.sep.sesame",
        "ir.banksepah.mobilebank", "ir.omidbank", "com.bsi.mobilebank", "ir.bpi.mobilebank",
        "ir.blu.banking", "ir.resalat.mb", "com.aparat.android", "com.saba.filimo",
        "ir.shatel.namava", "ir.filmnet.android", "com.zoodfood.android", "org.bale.messenger",
        "ir.eitaa.messenger", "ir.resaneh1.iptv", "org.soroushplus.messenger", "com.farsitel.bazaar",
        "ir.mservices.myket", "ir.mci.ecareapp", "com.mtnirancell.myirancell", "ir.rightel.myrightel"
    }
    GLOBAL_EXCLUDES = {
        "org.telegram.messenger", "com.whatsapp", "com.instagram.android", "com.facebook.katana",
        "com.twitter.android", "com.google.android.youtube", "com.google.android.gms",
        "com.android.chrome", "org.mozilla.firefox", "com.spotify.music", "com.netflix.mediaclient",
        "com.valvesoftware.android.steam.community"
    }
    WINDOWS_PROCESSES = [
        "Bale.exe", "Eitaa.exe", "EitaaDesktop.exe", "Rubika.exe", "Soroush.exe",
        "Gap.exe", "IDMan.exe", "Digikala.exe", "Aparat.exe"
    ]

    compiled_packages = set(ESSENTIAL_PACKAGES)
    app_sources = [
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/apps.txt",
        "https://raw.githubusercontent.com/SamadiPour/iran-android-apps/master/packages.json",
        "https://raw.githubusercontent.com/bootmortis/iran-hosted-domains/main/apps/apps.txt"
    ]
    PKG_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+$")

    for url in app_sources:
        raw = fetch_data(url, timeout=30)
        matches = re.findall(r"([a-zA-Z][a-zA-Z0-9_]+(?:\.[a-zA-Z][a-zA-Z0-9_]+)+)", raw)
        for pkg in matches:
            pkg = pkg.strip()
            if (pkg not in GLOBAL_EXCLUDES and
                not pkg.startswith(("PROCESS-NAME", "PACKAGE-NAME", "payload", "rules")) and
                PKG_REGEX.match(pkg) and len(pkg) < 85):
                compiled_packages.add(pkg)

    with open(TEXT_DIR / "apps.txt", "w", encoding="utf-8") as f:
        for pkg in sorted(compiled_packages):
            f.write(f"PACKAGE-NAME,{pkg}\n")
        for pkg in sorted(compiled_packages):
            f.write(f"PROCESS-NAME,{pkg}\n")
        for proc in sorted(WINDOWS_PROCESSES):
            f.write(f"PROCESS-NAME,{proc}\n")

    with open(TEXT_DIR / "apps.yaml", "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for pkg in sorted(compiled_packages):
            f.write(f"  - 'PACKAGE-NAME,{pkg}'\n")
        for pkg in sorted(compiled_packages):
            f.write(f"  - 'PROCESS-NAME,{pkg}'\n")
        for proc in sorted(WINDOWS_PROCESSES):
            f.write(f"  - 'PROCESS-NAME,{proc}'\n")
    print(f"[✓] Compiled {len(compiled_packages)} unique apps ({len(compiled_packages)*2 + len(WINDOWS_PROCESSES)} rules)")

    # --------------------------------------------------------------------------
    # STEP 8: DOMESTIC CLOUDS & DATACENTERS
    # --------------------------------------------------------------------------
    print("\n[+] STEP 8: Compiling Domestic Cloud Providers...")
    cloud_files = ["arvancloud", "derakcloud", "iranserver", "parspack"]
    for cname in cloud_files:
        c_raw = fetch_data(f"https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/{cname}.txt", timeout=25)
        c_v4, c_v6 = collapse_cidrs(c_raw.splitlines())
        with open(TEXT_DIR / f"{cname}.txt", "w", encoding="utf-8") as f:
            for net in (c_v4 + c_v6):
                f.write(f"{net}\n")

    # --------------------------------------------------------------------------
    # STEP 9: UNIFIED CLASSICAL RULES (YGBKM MERGED SPECIFICATION)
    # --------------------------------------------------------------------------
    print("\n[+] STEP 9: Compiling Unified Classical Rules (rules.txt & rules.yaml)...")
    non_ir_domains = [d for d in pruned_iran_domains if not d.endswith(".ir")]

    classical_rules = [
        "GEOIP,ir",
        "DOMAIN-SUFFIX,ir"
    ]
    for d in sorted(non_ir_domains):
        classical_rules.append(f"DOMAIN-SUFFIX,{d}")
    for n in collapsed_v4:
        classical_rules.append(f"IP-CIDR,{n}")
    for n in collapsed_v6:
        classical_rules.append(f"IP-CIDR6,{n}")

    with open(TEXT_DIR / "rules.txt", "w", encoding="utf-8") as f:
        for r in classical_rules:
            f.write(f"{r}\n")

    with open(TEXT_DIR / "rules.yaml", "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for r in classical_rules:
            f.write(f"  - '{r}'\n")
    print(f"[✓] Unified classical rules built: {len(classical_rules)} rules")

    # --------------------------------------------------------------------------
    # STEP 10: SYNCHRONIZATION & BINARY MRS COMPILATION
    # --------------------------------------------------------------------------
    print("\n" + "=" * 78)
    print("⚙️ STEP 10: SYNCHRONIZING ARTIFACTS & COMPILING MRS")
    print("=" * 78)

    # ۱. کپی بدون قید و شرط تمام فایل‌های متنی و یمل برای تضمین خالی نماندن مخزن
    print("[*] Performing mandatory synchronization of text/yaml to output_mrs/...")
    for f in TEXT_DIR.glob("*.txt"):
        shutil.copy(f, MRS_DIR / f.name)
    for f in TEXT_DIR.glob("*.yaml"):
        shutil.copy(f, MRS_DIR / f.name)

    # ۲. کامپایل باینری‌های MRS در صورت وجود هسته میهومو
    mihomo_bin = find_or_download_mihomo()
    if not mihomo_bin:
        print("[!] Mihomo binary not available. Plain-text artifacts are fully prepared.")
    else:
        print(f"[+] Using Mihomo compiler binary: {mihomo_bin}")

        # فقط رفتارهای مجاز domain و ipcidr کامپایل می‌شوند
        domain_targets = ["ir", "ir-lite", "ads", "phishing", "nsfw", "malware"]
        for target in domain_targets:
            in_txt = TEXT_DIR / f"{target}.txt"
            out_mrs = MRS_DIR / f"{target}.mrs"
            if in_txt.exists():
                success = compile_to_mrs(mihomo_bin, "domain", in_txt, out_mrs)
                status = "✓ Compiled" if success else "✗ Failed"
                size_kb = out_mrs.stat().st_size / 1024 if out_mrs.exists() else 0
                print(f"  [{status}] {target}.mrs ({size_kb:.1f} KB)")

        ip_targets = ["ircidr", "phishing-ip", "malware-ip"] + cloud_files
        for target in ip_targets:
            in_txt = TEXT_DIR / f"{target}.txt"
            out_mrs = MRS_DIR / f"{target}.mrs"
            if in_txt.exists():
                success = compile_to_mrs(mihomo_bin, "ipcidr", in_txt, out_mrs)
                status = "✓ Compiled" if success else "✗ Failed"
                size_kb = out_mrs.stat().st_size / 1024 if out_mrs.exists() else 0
                print(f"  [{status}] {target}.mrs ({size_kb:.1f} KB)")

    total_artifacts = len(list(MRS_DIR.iterdir()))
    print("\n" + "=" * 78)
    print(f"🏁 ALL TASKS COMPLETED. Total Artifacts in ./output_mrs/: {total_artifacts}")
    print("=" * 78)

if __name__ == "__main__":
    main()
