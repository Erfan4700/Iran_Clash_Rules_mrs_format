import os
import re
import math
import ipaddress
import urllib.request

OUTPUT_DIR = "output_text"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ------------------------------------------------------------------------------
# 1. FETCH & PROCESS IRAN IP-CIDRS (AGGREGATED & MERGED VIA RIPE NCC)
# ------------------------------------------------------------------------------
print("[-] Fetching and aggregating Iranian IPv4 prefixes from RIPE NCC...")
ripe_url = "https://ftp.ripe.net/ripe/stats/delegated-ripencc-latest"
networks = []
asns = []

try:
    req = urllib.request.Request(ripe_url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as resp:
        for line in resp.read().decode('utf-8', errors='ignore').splitlines():
            if not line or line.startswith('#'):
                continue
            parts = line.split('|')
            if len(parts) >= 7 and parts[1] == 'IR':
                # Process IPv4
                if parts[2] == 'ipv4':
                    start_ip = parts[3]
                    count = int(parts[4])
                    prefix_len = 32 - int(math.log2(count))
                    networks.append(ipaddress.ip_network(f"{start_ip}/{prefix_len}"))
                # Process Autonomous System Numbers (ASN)
                elif parts[2] == 'asn':
                    asn_num = parts[3]
                    asns.append(f"IP-ASN,{asn_num}")

    # Optimize & Collapse contiguous subnets to reduce ruleset size
    collapsed_networks = list(ipaddress.collapse_addresses(networks))
    print(f"[+] Successfully collapsed {len(networks)} subnets into {len(collapsed_networks)} supernets!")

    with open(f"{OUTPUT_DIR}/ircidr.txt", "w", encoding="utf-8") as f:
        for net in collapsed_networks:
            f.write(f"{net}\n")

    with open(f"{OUTPUT_DIR}/irasn.txt", "w", encoding="utf-8") as f:
        for asn_rule in sorted(set(asns)):
            f.write(f"{asn_rule}\n")

except Exception as e:
    print(f"[!] Error processing RIPE database: {e}")

# ------------------------------------------------------------------------------
# 2. FETCH & SANITIZE IRAN DOMAINS
# ------------------------------------------------------------------------------
print("[-] Fetching and sanitizing Iranian domains...")
domains_url = "https://raw.githubusercontent.com/bootmortis/iran-hosted-domains/main/domains/domains.txt"
iran_domains = set()

# Always include the entire national TLD
iran_domains.add("+.ir")

try:
    req = urllib.request.Request(domains_url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as resp:
        for line in resp.read().decode('utf-8', errors='ignore').splitlines():
            d = line.strip().lower()
            if d and not d.startswith('#') and not d.endswith('.ir'):
                iran_domains.add(f"+.{d}")

    with open(f"{OUTPUT_DIR}/ir.txt", "w", encoding="utf-8") as f:
        for d in sorted(iran_domains):
            f.write(f"{d}\n")
    print(f"[+] Total sanitized Iran domains: {len(iran_domains)}")
except Exception as e:
    print(f"[!] Error processing domains: {e}")

# ------------------------------------------------------------------------------
# 3. IRAN ADS WITH UNBREAK WHITELIST (PAYMENT GATEWAYS SAFETY LAYER)
# ------------------------------------------------------------------------------
print("[-] Fetching Persian Adblocker and applying payment gateway safety filters...")
ads_url = "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerHosts.txt"

# Critical domestic payment, banking & OTP domains that must NEVER be blocked
UNBREAK_WHITELIST = {
    "shaparak.ir", "asanpardakht.ir", "sadadpsp.ir", "behpardakht.com",
    "sepehrpay.com", "sep.ir", "pec.ir", "zarinpal.com", "payping.net",
    "idpay.ir", "jibit.ir", "kavenegar.com", "ghasedak.me", "raychat.io"
}

ad_domains = set()
try:
    req = urllib.request.Request(ads_url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as resp:
        for line in resp.read().decode('utf-8', errors='ignore').splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            domain = parts[-1].lower()
            
            # Apply Safety Layer: skip if it matches any payment gateway
            if not any(safe in domain for safe in UNBREAK_WHITELIST):
                ad_domains.add(domain)

    with open(f"{OUTPUT_DIR}/ads.txt", "w", encoding="utf-8") as f:
        for d in sorted(ad_domains):
            f.write(f"{d}\n")
    print(f"[+] Total safe Iranian ad domains: {len(ad_domains)}")
except Exception as e:
    print(f"[!] Error processing adblock list: {e}")

# ------------------------------------------------------------------------------
# 4. IRAN DOMESTIC PHISHING & FRAUD
# ------------------------------------------------------------------------------
print("[-] Compiling domestic phishing blocklist...")
phishing_sources = [
    "https://raw.githubusercontent.com/curbengh/phishing-filter/master/phishing-filter.txt"
]

phishing_domains = set()
for url in phishing_sources:
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as resp:
            for line in resp.read().decode('utf-8', errors='ignore').splitlines():
                d = line.strip().lower()
                if d and not d.startswith('#'):
                    phishing_domains.add(d)
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")

with open(f"{OUTPUT_DIR}/phishing.txt", "w", encoding="utf-8") as f:
    for d in sorted(phishing_domains):
        f.write(f"{d}\n")
print(f"[+] Total verified phishing domains: {len(phishing_domains)}")
