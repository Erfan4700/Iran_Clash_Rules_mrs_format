import os
import re
import ipaddress
import urllib.request

OUTPUT_DIR = "output_text"
os.makedirs(OUTPUT_DIR, exist_ok=True)

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

def fetch_data(urls):
    """Try fetching data from multiple URLs with fallback."""
    if isinstance(urls, str):
        urls = [urls]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=25) as resp:
                content = resp.read().decode('utf-8', errors='ignore')
                if len(content.strip()) > 100:
                    return content
        except Exception as e:
            print(f"[!] Warning fetching {url}: {e}")
    return ""

def clean_domain(line):
    line = line.strip().lower()
    if not line or line.startswith(('#', '!', ';', '//')):
        return None
    line = re.sub(r'^[\|]+', '', line)
    line = re.sub(r'[\^/].*$', '', line)
    line = re.sub(r'^https?://', '', line)
    line = re.sub(r'^\+\.?', '', line)
    line = re.sub(r'^\*\.?', '', line)
    line = re.sub(r'^\.', '', line)
    line = line.strip()
    if re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', line):
        return line
    return None

# ==============================================================================
# 1. IRAN IP-CIDRS & ASNS (SEPARATE IPV4 & IPV6 COLLAPSE)
# ==============================================================================
print("[-] Step 1: Fetching Iranian IP-CIDRs...")
ripe_urls = [
    "http://ftp.ripe.net/ripe/stats/delegated-ripencc-latest",
    "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ircidr.txt"
]

ipv4_nets = []
ipv6_nets = []
asns = []

ripe_raw = fetch_data(ripe_urls[0])
if ripe_raw:
    for line in ripe_raw.splitlines():
        if not line or line.startswith('#'):
            continue
        parts = line.split('|')
        if len(parts) >= 7 and parts[1] == 'IR':
            if parts[2] == 'ipv4':
                try:
                    first_ip = ipaddress.IPv4Address(parts[3])
                    last_ip = first_ip + (int(parts[4]) - 1)
                    ipv4_nets.extend(ipaddress.summarize_range(first_ip, last_ip))
                except Exception:
                    pass
            elif parts[2] == 'ipv6':
                try:
                    ipv6_nets.append(ipaddress.IPv6Network(f"{parts[3]}/{parts[4]}", strict=False))
                except Exception:
                    pass
            elif parts[2] == 'asn':
                asns.append(f"IP-ASN,{parts[3]}")

# If primary RIPE failed, parse from fallback mirror
if not ipv4_nets:
    print("[!] Using fallback mirror for Iran CIDRs...")
    mirror_raw = fetch_data(ripe_urls[1])
    for line in mirror_raw.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            try:
                net = ipaddress.ip_network(line, strict=False)
                if net.version == 4:
                    ipv4_nets.append(net)
                else:
                    ipv6_nets.append(net)
            except Exception:
                pass

# Separate collapse prevents TypeError: IPv4 vs IPv6
collapsed_v4 = list(ipaddress.collapse_addresses(ipv4_nets)) if ipv4_nets else []
collapsed_v6 = list(ipaddress.collapse_addresses(ipv6_nets)) if ipv6_nets else []
all_collapsed = collapsed_v4 + collapsed_v6

print(f"[+] Total CIDRs: {len(all_collapsed)} (IPv4: {len(collapsed_v4)}, IPv6: {len(collapsed_v6)}) | Total ASNs: {len(asns)}")

with open(f"{OUTPUT_DIR}/ircidr.txt", "w", encoding="utf-8") as f:
    for net in all_collapsed:
        f.write(f"{net}\n")

# Fallback ASNs if RIPE was empty
if not asns:
    asn_raw = fetch_data("https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/irasn.txt")
    for line in asn_raw.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            asns.append(line if line.startswith("IP-ASN,") else f"IP-ASN,{line}")

with open(f"{OUTPUT_DIR}/irasn.txt", "w", encoding="utf-8") as f:
    for asn in sorted(set(asns)) if asns else ["IP-ASN,58224", "IP-ASN,197207"]:
        f.write(f"{asn}\n")

# ==============================================================================
# 2. IRAN DOMAINS
# ==============================================================================
print("[-] Step 2: Fetching Iranian domains...")
domains_urls = [
    "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.txt",
    "https://raw.githubusercontent.com/bootmortis/iran-hosted-domains/main/domains/domains.txt"
]

iran_domains = {
    "digikala.com", "torob.com", "divar.ir", "snapp.cab", "tapsi.cab",
    "neshan.org", "balad.ir", "bale.ai", "eitaa.com", "rubika.ir",
    "shaparak.ir", "asanpardakht.ir", "zarinpal.com", "aparat.com"
}

raw_domains = fetch_data(domains_urls)
for line in raw_domains.splitlines():
    d = clean_domain(line)
    if d:
        iran_domains.add(d)

print(f"[+] Total Iran domains: {len(iran_domains)}")
with open(f"{OUTPUT_DIR}/ir.txt", "w", encoding="utf-8") as f:
    for d in sorted(iran_domains):
        f.write(f"{d}\n")

# ==============================================================================
# 3. IRAN ADS WITH UNBREAK WHITELIST
# ==============================================================================
print("[-] Step 3: Fetching Persian ads with safety layer...")
ads_urls = [
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerHosts.txt",
    "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ads.txt"
]

UNBREAK_WHITELIST = {
    "shaparak.ir", "asanpardakht.ir", "sadadpsp.ir", "behpardakht.com",
    "sepehrpay.com", "sep.ir", "pec.ir", "zarinpal.com", "payping.net",
    "idpay.ir", "jibit.ir", "kavenegar.com", "ghasedak.me", "raychat.io"
}

ad_domains = {"yektanet.com", "sabavision.com", "mediaad.org"}
raw_ads = fetch_data(ads_urls)
for line in raw_ads.splitlines():
    parts = line.split()
    if parts:
        d = clean_domain(parts[-1])
        if d and not any(safe in d for safe in UNBREAK_WHITELIST):
            ad_domains.add(d)

print(f"[+] Total safe ad domains: {len(ad_domains)}")
with open(f"{OUTPUT_DIR}/ads.txt", "w", encoding="utf-8") as f:
    for d in sorted(ad_domains):
        f.write(f"{d}\n")

# ==============================================================================
# 4. PHISHING BLOCKLIST
# ==============================================================================
print("[-] Step 4: Fetching phishing blocklist...")
phishing_urls = [
    "https://raw.githubusercontent.com/curbengh/phishing-filter/master/phishing-filter-hosts.txt",
    "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing.txt"
]

phishing_domains = {"phishing-fake-shaparak.top"}
raw_phishing = fetch_data(phishing_urls)
for line in raw_phishing.splitlines():
    parts = line.split()
    if parts:
        d = clean_domain(parts[-1])
        if d:
            phishing_domains.add(d)

print(f"[+] Total phishing domains: {len(phishing_domains)}")
with open(f"{OUTPUT_DIR}/phishing.txt", "w", encoding="utf-8") as f:
    for d in sorted(phishing_domains):
        f.write(f"{d}\n")
