#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
Universal Multi-Platform & Modular Rule-Set Suite
Repository: Erfan4700/iran-routing-rules
Includes: Master Lists + Granular Modules (Media, Banking, Gov, Gaming, Download)
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

# --- BOOTSTRAP TLDEXTRACT (MOZILLA PSL) ---
try:
    import tldextract
except ImportError:
    print("[*] Installing 'tldextract' for Mozilla PSL parsing...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "tldextract", "--quiet"])
        import tldextract
    except Exception as e:
        print(f"[!] Warning: Could not auto-install tldextract ({e}).")
        tldextract = None

EXTRACTOR = tldextract.TLDExtract(cache_dir=str(Path(__file__).resolve().parent / ".tld_cache")) if tldextract else None

# --- DIRECTORY CONFIGURATION ---
BASE_DIR = Path(__file__).resolve().parent
TEXT_DIR = BASE_DIR / "output_text"
MRS_DIR = BASE_DIR / "output_mrs"
BASELINE_DIR = BASE_DIR / "data" / "baseline"

V2RAY_GEOSITE_DIR = TEXT_DIR / "v2ray_geosite"
V2RAY_GEOIP_DIR = TEXT_DIR / "v2ray_geoip" / "data"

TEXT_DIR.mkdir(parents=True, exist_ok=True)
MRS_DIR.mkdir(parents=True, exist_ok=True)
BASELINE_DIR.mkdir(parents=True, exist_ok=True)
V2RAY_GEOSITE_DIR.mkdir(parents=True, exist_ok=True)
V2RAY_GEOIP_DIR.mkdir(parents=True, exist_ok=True)

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
HEADERS = {"User-Agent": USER_AGENT}

# ==============================================================================
# 0. ZERO-TRUST CRITICAL INFRASTRUCTURE WHITELIST
# ==============================================================================
UNBREAK_WHITELIST = {
    # PSPs & Payment Gateways
    "shaparak.ir", "asanpardakht.ir", "sadadpsp.ir", "behpardakht.com",
    "sepehrpay.com", "sep.ir", "pec.ir", "zarinpal.com", "zarinpal.ir",
    "payping.net", "payping.ir", "idpay.ir", "jibit.ir", "nextpay.ir",
    "vandar.ir", "zibal.ir", "rayanpay.com", "fanavakart.ir", "sayancard.ir",
    "pasargad-psp.ir", "pep.co.ir", "pna.co.ir",
    # Core Banking & Regulators
    "cbi.ir", "bmi.ir", "bankmellat.ir", "mellatbank.ir", "tejaratbank.ir",
    "bsi.ir", "bpi.ir", "sb24.ir", "sb24.com", "parsian-bank.ir",
    "banksepah.ir", "refah-bank.ir", "keshavarzi-bank.ir", "maskan-bank.ir",
    "blubank.com", "blubank.sb24.com",
    # Essential Domestic Infra & Platforms
    "sana.gov.ir", "adliran.ir", "divar.ir", "divarcdn.com", "torob.com",
    "digikala.com", "digikalacloud.com", "snapp.ir", "snapp.cab", "snapp.tech",
    "snappcloud.io", "tapsi.ir", "tapsi.cab", "kavenegar.com", "ghasedak.me",
    "raychat.io", "bale.ai", "eitaa.com", "eitaa.ir", "rubika.ir", "rubikacdn.ir",
    "soroushplus.ir", "cafebazaar.ir", "farsitel.com", "myket.ir",
    "neshan.org", "neshanmaps.ir", "balad.ir", "aparat.com", "telewebion.com",
    "mci.ir", "mtnirancell.ir", "rightel.ir", "tamin.ir"
}

def is_whitelisted(domain: str) -> bool:
    domain = domain.lower()
    return any(domain == safe or domain.endswith("." + safe) for safe in UNBREAK_WHITELIST)

# ==============================================================================
# UTILITIES: FETCHING & BASELINE RESILIENCE
# ==============================================================================
def fetch_data(urls, timeout: int = 60, min_len: int = 20) -> str:
    if isinstance(urls, str):
        urls = [urls]

    for url in urls:
        try:
            cmd = ["curl", "-sSL", "--compressed", "--max-time", str(timeout), "-A", USER_AGENT, url]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if len(res.stdout.strip()) >= min_len:
                return res.stdout
        except Exception:
            pass

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
    path = BASELINE_DIR / f"{name}.txt"
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip() and not line.startswith("#")}
    return set()

def save_baseline(name: str, items: Set[str]) -> None:
    path = BASELINE_DIR / f"{name}.txt"
    with open(path, "w", encoding="utf-8") as f:
        for item in sorted(items):
            f.write(f"{item}\n")

# ==============================================================================
# DOMAIN PURIFICATION & MOZILLA PSL PRUNING
# ==============================================================================
DOMAIN_REGEX = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

def clean_domain(line: str) -> Optional[str]:
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

    if not DOMAIN_REGEX.match(target) or ".." in target:
        return None

    if EXTRACTOR:
        ext = EXTRACTOR(target)
        if not ext.domain or not ext.suffix:
            return None
    else:
        if target in {"ir", "co.ir", "gov.ir", "ac.ir", "org.ir", "com", "net", "org"}:
            return None

    return target

def prune_subdomains(domains: Set[str]) -> Set[str]:
    sorted_domains = sorted(domains, key=lambda d: (len(d.split(".")), len(d), d))
    retained_roots = set()

    for domain in sorted_domains:
        if EXTRACTOR:
            ext = EXTRACTOR(domain)
            registered_root = ext.registered_domain

            if registered_root and registered_root != domain and registered_root in retained_roots:
                continue

            parts = ext.subdomain.split(".") if ext.subdomain else []
            is_redundant = False
            for i in range(len(parts)):
                parent = ".".join(parts[i:] + [ext.domain, ext.suffix])
                if parent in retained_roots:
                    is_redundant = True
                    break

            if not is_redundant:
                retained_roots.add(domain)
        else:
            parts = domain.split(".")
            is_redundant = False
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:])
                if parent in retained_roots:
                    is_redundant = True
                    break
            if not is_redundant:
                retained_roots.add(domain)

    return retained_roots

# ==============================================================================
# IP / CIDR COLLAPSER (SUPERNETTING)
# ==============================================================================
def collapse_cidrs(raw_cidrs: List[str]) -> Tuple[List[ipaddress.IPv4Network], List[ipaddress.IPv6Network]]:
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
# MULTI-PLATFORM EXPORTERS
# ==============================================================================
def save_singbox_domain_json(domains: Set[str], out_path: Path):
    data = {"version": 1, "rules": [{"domain_suffix": sorted(domains)}]}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def save_singbox_ip_json(cidrs: List[str], out_path: Path):
    data = {"version": 1, "rules": [{"ip_cidr": cidrs}]}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def save_singbox_apps_json(packages: Set[str], processes: List[str], out_path: Path):
    data = {"version": 1, "rules": [{"package_name": sorted(packages), "process_name": sorted(processes)}]}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def save_surge_domain_list(domains: Set[str], out_path: Path):
    with open(out_path, "w", encoding="utf-8") as f:
        for d in sorted(domains):
            f.write(f"DOMAIN-SUFFIX,{d}\n")

def save_surge_ip_list(cidrs: List[str], out_path: Path):
    with open(out_path, "w", encoding="utf-8") as f:
        for c in cidrs:
            f.write(f"IP-CIDR,{c},no-resolve\n")

def write_v2ray_domain_tag(domains: Set[str], tag_name: str):
    tag_file = V2RAY_GEOSITE_DIR / tag_name
    with open(tag_file, "w", encoding="utf-8") as f:
        for d in sorted(domains):
            f.write(f"{d}\n")

# ==============================================================================
# BINARY COMPILERS INTEGRATION
# ==============================================================================
def compile_to_mrs(mihomo_bin: Optional[str], behavior: str, text_file: Path, mrs_file: Path) -> bool:
    if not mihomo_bin or not text_file.exists() or text_file.stat().st_size == 0:
        return False
    try:
        cmd = [mihomo_bin, "convert-ruleset", behavior, "text", str(text_file), str(mrs_file)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        return (res.returncode == 0 and mrs_file.exists() and mrs_file.stat().st_size > 50)
    except Exception:
        return False

def compile_to_srs(singbox_bin: Optional[str], json_file: Path, srs_file: Path) -> bool:
    if not singbox_bin or not json_file.exists() or json_file.stat().st_size == 0:
        return False
    try:
        cmd = [singbox_bin, "rule-set", "compile", "--output", str(srs_file), str(json_file)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        return (res.returncode == 0 and srs_file.exists() and srs_file.stat().st_size > 50)
    except Exception:
        return False

# ==============================================================================
# MAIN PIPELINE EXECUTION
# ==============================================================================
def main():
    print("=" * 78)
    print("🚀 IRAN ROUTING RULES: ENTERPRISE MODULAR & UNIVERSAL PIPELINE")
    print("=" * 78)

    # --------------------------------------------------------------------------
    # 1. IRAN IP & ASN
    # --------------------------------------------------------------------------
    print("\n[+] 1/8: Processing Iranian IP-CIDRs & ASNs...")
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
        raw_ip_list.extend(load_baseline("iran-ip"))
    else:
        save_baseline("iran-ip", set(raw_ip_list))

    if len(asns) < 100:
        asns.update(load_baseline("iran-asn"))
    else:
        save_baseline("iran-asn", asns)

    collapsed_v4, collapsed_v6 = collapse_cidrs(raw_ip_list)
    all_cidrs = [str(n) for n in collapsed_v4] + [str(n) for n in collapsed_v6]

    with open(TEXT_DIR / "iran-ip.txt", "w", encoding="utf-8") as f:
        for net in all_cidrs:
            f.write(f"{net}\n")
    save_surge_ip_list(all_cidrs, TEXT_DIR / "iran-ip.list")
    save_singbox_ip_json(all_cidrs, TEXT_DIR / "iran-ip.json")

    with open(V2RAY_GEOIP_DIR / "ir", "w", encoding="utf-8") as f:
        for net in all_cidrs:
            f.write(f"{net}\n")
    with open(V2RAY_GEOIP_DIR / "iran-ip", "w", encoding="utf-8") as f:
        for net in all_cidrs:
            f.write(f"{net}\n")

    with open(TEXT_DIR / "iran-asn.txt", "w", encoding="utf-8") as f:
        for asn in sorted(asns):
            f.write(f"{asn}\n")
    with open(TEXT_DIR / "iran-asn.yaml", "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for asn in sorted(asns):
            f.write(f"  - '{asn}'\n")

    print(f"[✓] iran-ip: {len(all_cidrs)} CIDRs | iran-asn: {len(asns)} ASNs")

    # --------------------------------------------------------------------------
    # 2. DOMESTIC CLOUDS MERGED
    # --------------------------------------------------------------------------
    print("\n[+] 2/8: Aggregating Domestic Clouds (Arvan, Derak, ParsPack, IranServer)...")
    cloud_sources = ["arvancloud", "derakcloud", "iranserver", "parspack"]
    raw_cloud_cidrs = []
    for cname in cloud_sources:
        c_raw = fetch_data(f"https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/{cname}.txt", timeout=25)
        raw_cloud_cidrs.extend(c_raw.splitlines())

    cloud_v4, cloud_v6 = collapse_cidrs(raw_cloud_cidrs)
    all_cloud_cidrs = [str(n) for n in (cloud_v4 + cloud_v6)]
    with open(TEXT_DIR / "iran-cloud.txt", "w", encoding="utf-8") as f:
        for net in all_cloud_cidrs:
            f.write(f"{net}\n")
    save_surge_ip_list(all_cloud_cidrs, TEXT_DIR / "iran-cloud.list")
    save_singbox_ip_json(all_cloud_cidrs, TEXT_DIR / "iran-cloud.json")

    with open(V2RAY_GEOIP_DIR / "iran-cloud", "w", encoding="utf-8") as f:
        for net in all_cloud_cidrs:
            f.write(f"{net}\n")
    print(f"[✓] iran-cloud: {len(all_cloud_cidrs)} cloud CIDRs")

    # --------------------------------------------------------------------------
    # 3. MASTER IRANIAN DOMAINS (ALL-INCLUSIVE)
    # --------------------------------------------------------------------------
    print("\n[+] 3/8: Processing Master Iranian Domains (PSL Pruning)...")
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
        raw_iran_domains.update(load_baseline("iran-domains"))
    else:
        save_baseline("iran-domains", raw_iran_domains)

    pruned_iran_domains = prune_subdomains(raw_iran_domains)
    with open(TEXT_DIR / "iran-domains.txt", "w", encoding="utf-8") as f:
        for d in sorted(pruned_iran_domains):
            f.write(f"{d}\n")
    save_surge_domain_list(pruned_iran_domains, TEXT_DIR / "iran-domains.list")
    save_singbox_domain_json(pruned_iran_domains, TEXT_DIR / "iran-domains.json")

    write_v2ray_domain_tag(pruned_iran_domains, "iran-domains")
    write_v2ray_domain_tag(pruned_iran_domains, "ir")
    non_ir = {d for d in pruned_iran_domains if not d.endswith(".ir")}
    write_v2ray_domain_tag(non_ir, "other")

    ir_lite_raw = fetch_data("https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir-lite.txt", timeout=30)
    lite_domains = set()
    for line in ir_lite_raw.splitlines():
        d = clean_domain(line)
        if d:
            lite_domains.add(d)
    pruned_lite = prune_subdomains(lite_domains if len(lite_domains) > 100 else pruned_iran_domains)
    with open(TEXT_DIR / "iran-domains-lite.txt", "w", encoding="utf-8") as f:
        for d in sorted(pruned_lite):
            f.write(f"{d}\n")
    save_surge_domain_list(pruned_lite, TEXT_DIR / "iran-domains-lite.list")
    save_singbox_domain_json(pruned_lite, TEXT_DIR / "iran-domains-lite.json")
    write_v2ray_domain_tag(pruned_lite, "iran-domains-lite")
    print(f"[✓] Master Database: {len(pruned_iran_domains)} root domains preserved without loss.")

    # --------------------------------------------------------------------------
    # 4. GRANULAR MODULES (MEDIA, BANKING, GOV, GAMING, DOWNLOAD)
    # --------------------------------------------------------------------------
    print("\n[+] 4/8: Extracting High-Demand Granular Sub-Modules (>100 Rules Each)...")

    MEDIA_PATTERNS = re.compile(r"(?:aparat|filimo|namava|filmnet|telewebion|gapfilm|cinematicket|tiwall|tamasha|namasha|antenn|lenz|mayaa|irib|seevid|ammarfilm|radio|video|music|tv|vod|stream)")
    BANKING_PATTERNS = re.compile(r"(?:bank|shaparak|sadad|mellat|melli|tejarat|saderat|pasargad|sb24|blubank|sepah|refah|keshavarzi|maskan|postbank|zarinpal|payping|idpay|jibit|nextpay|vandar|zibal|nobitex|wallex|bitpin|ramzinex|abantether|exir|bourse|seham|tsetmc|codal|emofid|agah|fipiran)")
    GOV_PATTERNS = re.compile(r"(?:\.gov\.ir$|\.jud\.ir$|\.police\.ir$|sana\.gov|adliran|my\.gov|mardom|tax\.gov|tamin|post\.ir|dolat\.ir|majlis\.ir|sabteahval|moi\.ir|medu\.ir)")
    GAMING_PATTERNS = re.compile(r"(?:gameup|shecan|electro|radar\.game|parshub|asiagame|vmp|fivem|gamefa|vgmag|zoomg|bazicenter|baziato|csgo|samp|bazi|game)")
    DOWNLOAD_PATTERNS = re.compile(r"(?:soft98|yasdl|downloadha|p30download|asandl|sarzamindownload|p30world|shahrsakhtafzar|zoomit|digiato|download|mirror|tarfandestan)")

    media_domains = set()
    banking_domains = set()
    gov_domains = set()
    gaming_domains = set()
    download_domains = set()

    for d in pruned_iran_domains:
        if MEDIA_PATTERNS.search(d):
            media_domains.add(d)
        if BANKING_PATTERNS.search(d):
            banking_domains.add(d)
        if GOV_PATTERNS.search(d) or d.endswith(".gov.ir"):
            gov_domains.add(d)
        if GAMING_PATTERNS.search(d):
            gaming_domains.add(d)
        if DOWNLOAD_PATTERNS.search(d):
            download_domains.add(d)

    def export_sub_module(domains: Set[str], mod_name: str, min_thresh: int = 100):
        pruned_sub = prune_subdomains(domains)
        if len(pruned_sub) >= min_thresh:
            with open(TEXT_DIR / f"{mod_name}.txt", "w", encoding="utf-8") as f:
                for d in sorted(pruned_sub):
                    f.write(f"{d}\n")
            save_surge_domain_list(pruned_sub, TEXT_DIR / f"{mod_name}.list")
            save_singbox_domain_json(pruned_sub, TEXT_DIR / f"{mod_name}.json")
            write_v2ray_domain_tag(pruned_sub, mod_name)
            print(f"  [✓] Module '{mod_name}': {len(pruned_sub)} unique domains.")
            return True
        return False

    export_sub_module(media_domains, "iran-media", min_thresh=100)
    export_sub_module(banking_domains, "iran-banking", min_thresh=100)
    export_sub_module(gov_domains, "iran-gov", min_thresh=100)
    export_sub_module(gaming_domains, "iran-gaming", min_thresh=80)
    export_sub_module(download_domains, "iran-download", min_thresh=100)

    # --------------------------------------------------------------------------
    # 5. PERSIAN ADS & TRACKERS
    # --------------------------------------------------------------------------
    print("\n[+] 5/8: Compiling Persian Ads (Zero-Trust Protected)...")
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
    with open(TEXT_DIR / "iran-ads.txt", "w", encoding="utf-8") as f:
        for d in sorted(pruned_ads):
            f.write(f"{d}\n")
    save_surge_domain_list(pruned_ads, TEXT_DIR / "iran-ads.list")
    save_singbox_domain_json(pruned_ads, TEXT_DIR / "iran-ads.json")
    write_v2ray_domain_tag(pruned_ads, "iran-ads")
    write_v2ray_domain_tag(pruned_ads, "ads")
    print(f"[✓] iran-ads: {len(pruned_ads)} domains")

    # --------------------------------------------------------------------------
    # 6. UNIFIED SECURITY (PHISHING + MALWARE)
    # --------------------------------------------------------------------------
    print("\n[+] 6/8: Compiling Unified Security (Targeted Threat-Intel)...")
    DOMESTIC_THREAT_REGEX = re.compile(
        r"(?:^|[.-])(?:shaparak|sana[-_.]?gov|adliran|divar|sadad|"
        r"mellat|melli|tejarat|saderat|pasargad|blubank|keshavarzi|refah|maskan|"
        r"sep[-_.]?(?:ir|pay|epay|shaparak)|shaparak[-_.]?sep|sheba[-_.]?bank)(?:[.-]|$)"
    )

    threat_domain_sources = [
        "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerPhishing.txt",
        "https://raw.githubusercontent.com/curbengh/phishing-filter/master/phishing-filter-hosts.txt",
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing.txt",
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware.txt"
    ]

    raw_threat_domains = set()
    for url in threat_domain_sources:
        content = fetch_data(url, timeout=30)
        for line in content.splitlines():
            d = clean_domain(line)
            if d and not is_whitelisted(d):
                if DOMESTIC_THREAT_REGEX.search(d) or "malware" in url:
                    raw_threat_domains.add(d)

    pruned_threats = prune_subdomains(raw_threat_domains)
    with open(TEXT_DIR / "iran-security.txt", "w", encoding="utf-8") as f:
        for d in sorted(pruned_threats):
            f.write(f"{d}\n")
    save_surge_domain_list(pruned_threats, TEXT_DIR / "iran-security.list")
    save_singbox_domain_json(pruned_threats, TEXT_DIR / "iran-security.json")
    write_v2ray_domain_tag(pruned_threats, "iran-security")

    threat_ip_sources = [
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing-ip.txt",
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware-ip.txt"
    ]
    raw_threat_ips = []
    for url in threat_ip_sources:
        content = fetch_data(url, timeout=25)
        raw_threat_ips.extend(content.splitlines())

    t_v4, t_v6 = collapse_cidrs(raw_threat_ips)
    all_threat_cidrs = [str(n) for n in (t_v4 + t_v6)]
    with open(TEXT_DIR / "iran-security-ip.txt", "w", encoding="utf-8") as f:
        for net in all_threat_cidrs:
            f.write(f"{net}\n")
    save_surge_ip_list(all_threat_cidrs, TEXT_DIR / "iran-security-ip.list")
    save_singbox_ip_json(all_threat_cidrs, TEXT_DIR / "iran-security-ip.json")

    with open(V2RAY_GEOIP_DIR / "iran-security-ip", "w", encoding="utf-8") as f:
        for net in all_threat_cidrs:
            f.write(f"{net}\n")
    print(f"[✓] iran-security: {len(pruned_threats)} domains | iran-security-ip: {len(all_threat_cidrs)} CIDRs")

    # --------------------------------------------------------------------------
    # 7. DOMESTIC GAMBLING & CASINOS
    # --------------------------------------------------------------------------
    print("\n[+] 7/8: Compiling Domestic Gambling & Betting...")
    gambling_sources = [
        "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerGambling.txt",
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/nsfw.txt"
    ]
    raw_gambling = {"betcart.com", "takbet.com", "wolfbet.info", "cannonbet.org", "hazarat.org"}
    for url in gambling_sources:
        content = fetch_data(url, timeout=30)
        for line in content.splitlines():
            d = clean_domain(line)
            if d and not is_whitelisted(d):
                raw_gambling.add(d)

    pruned_gambling = prune_subdomains(raw_gambling)
    with open(TEXT_DIR / "iran-gambling.txt", "w", encoding="utf-8") as f:
        for d in sorted(pruned_gambling):
            f.write(f"{d}\n")
    save_surge_domain_list(pruned_gambling, TEXT_DIR / "iran-gambling.list")
    save_singbox_domain_json(pruned_gambling, TEXT_DIR / "iran-gambling.json")
    write_v2ray_domain_tag(pruned_gambling, "iran-gambling")
    print(f"[✓] iran-gambling: {len(pruned_gambling)} domains")

    # --------------------------------------------------------------------------
    # 8. APPS & UNIFIED CLASSICAL
    # --------------------------------------------------------------------------
    print("\n[+] 8/8: Compiling Applications & Unified Classical...")
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

    with open(TEXT_DIR / "iran-apps.txt", "w", encoding="utf-8") as f:
        for pkg in sorted(compiled_packages):
            f.write(f"PACKAGE-NAME,{pkg}\n")
        for proc in sorted(WINDOWS_PROCESSES):
            f.write(f"PROCESS-NAME,{proc}\n")

    with open(TEXT_DIR / "iran-apps.yaml", "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for pkg in sorted(compiled_packages):
            f.write(f"  - 'PACKAGE-NAME,{pkg}'\n")
        for proc in sorted(WINDOWS_PROCESSES):
            f.write(f"  - 'PROCESS-NAME,{proc}'\n")

    save_singbox_apps_json(compiled_packages, WINDOWS_PROCESSES, TEXT_DIR / "iran-apps.json")

    # Unified Classical
    classical_rules = ["GEOIP,ir", "DOMAIN-SUFFIX,ir"]
    for d in sorted(non_ir):
        classical_rules.append(f"DOMAIN-SUFFIX,{d}")
    for n in collapsed_v4:
        classical_rules.append(f"IP-CIDR,{n}")
    for n in collapsed_v6:
        classical_rules.append(f"IP-CIDR6,{n}")

    with open(TEXT_DIR / "iran-unified.txt", "w", encoding="utf-8") as f:
        for r in classical_rules:
            f.write(f"{r}\n")

    with open(TEXT_DIR / "iran-unified.yaml", "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for r in classical_rules:
            f.write(f"  - '{r}'\n")

    with open(TEXT_DIR / "iran-unified.list", "w", encoding="utf-8") as f:
        for d in sorted(pruned_iran_domains):
            f.write(f"DOMAIN-SUFFIX,{d}\n")
        for n in all_cidrs:
            f.write(f"IP-CIDR,{n},no-resolve\n")

    geoip_config = {
        "input": [{"type": "text", "action": "add", "args": {"inputDir": str(V2RAY_GEOIP_DIR.resolve())}}],
        "output": [{"type": "v2rayGeoIPDat", "action": "output", "args": {"outputDir": str(MRS_DIR.resolve()), "outputName": "geoip.dat"}}]
    }
    with open(TEXT_DIR / "v2ray_geoip_config.json", "w", encoding="utf-8") as f:
        json.dump(geoip_config, f, indent=2)

    # --------------------------------------------------------------------------
    # 9. DUAL COMPILATION (MIHOMO .MRS & SING-BOX .SRS)
    # --------------------------------------------------------------------------
    print("\n" + "=" * 78)
    print("⚙️ COMPILATION: MIHOMO (MRS) & SING-BOX (SRS)")
    print("=" * 78)

    for f in TEXT_DIR.glob("*.*"):
        if f.is_file():
            shutil.copy(f, MRS_DIR / f.name)

    mihomo_bin = shutil.which("mihomo") or shutil.which("mihomo.exe") or (BASE_DIR / "mihomo")
    if mihomo_bin and os.path.exists(mihomo_bin):
        print(f"[+] Mihomo Core Active: {mihomo_bin}")
        domain_targets = [
            "iran-domains", "iran-domains-lite", "iran-ads", "iran-security", "iran-gambling",
            "iran-media", "iran-banking", "iran-gov", "iran-gaming", "iran-download"
        ]
        for target in domain_targets:
            in_txt = TEXT_DIR / f"{target}.txt"
            out_mrs = MRS_DIR / f"{target}.mrs"
            if in_txt.exists():
                success = compile_to_mrs(str(mihomo_bin), "domain", in_txt, out_mrs)
                print(f"  [{'✓' if success else '✗'}] Mihomo MRS: {target}.mrs ({out_mrs.stat().st_size/1024:.1f} KB)")

        ip_targets = ["iran-ip", "iran-cloud", "iran-security-ip"]
        for target in ip_targets:
            in_txt = TEXT_DIR / f"{target}.txt"
            out_mrs = MRS_DIR / f"{target}.mrs"
            if in_txt.exists():
                success = compile_to_mrs(str(mihomo_bin), "ipcidr", in_txt, out_mrs)
                print(f"  [{'✓' if success else '✗'}] Mihomo MRS: {target}.mrs ({out_mrs.stat().st_size/1024:.1f} KB)")

    singbox_bin = shutil.which("sing-box") or shutil.which("sing-box.exe") or (BASE_DIR / "sing-box")
    if singbox_bin and os.path.exists(singbox_bin):
        print(f"[+] Sing-box Core Active: {singbox_bin}")
        srs_targets = [
            "iran-domains", "iran-domains-lite", "iran-ip", "iran-cloud",
            "iran-ads", "iran-security", "iran-security-ip", "iran-gambling", "iran-apps",
            "iran-media", "iran-banking", "iran-gov", "iran-gaming", "iran-download"
        ]
        for target in srs_targets:
            in_json = TEXT_DIR / f"{target}.json"
            out_srs = MRS_DIR / f"{target}.srs"
            if in_json.exists():
                success = compile_to_srs(str(singbox_bin), in_json, out_srs)
                print(f"  [{'✓' if success else '✗'}] Sing-box SRS: {target}.srs ({out_srs.stat().st_size/1024:.1f} KB)")

    print("\n" + "=" * 78)
    print(f"🏁 PIPELINE COMPLETED: Ready for V2Ray Go Compiler.")
    print("=" * 78)

if __name__ == "__main__":
    main()
