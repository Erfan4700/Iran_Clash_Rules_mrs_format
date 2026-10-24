import os
import re
import ipaddress
import urllib.request

OUTPUT_DIR = "output_text"
os.makedirs(OUTPUT_DIR, exist_ok=True)

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

def fetch_data(url):
    """Safely fetch data from URL with timeout."""
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[!] Warning fetching {url}: {e}")
        return ""

def clean_domain(line):
    """Sanitize lines to extract pure domain names for Mihomo."""
    line = line.strip().lower()
    if not line or line.startswith(('#', '!', ';')):
        return None
    line = re.sub(r'^[\|]+', '', line)
    line = re.sub(r'[\^/].*$', '', line)
    line = re.sub(r'^https?://', '', line)
    line = re.sub(r'^\+\.?', '', line)
    line = re.sub(r'^\*\.?', '', line)
    line = re.sub(r'^\.', '', line)
    if re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', line):
        return line
    return None

# ==============================================================================
# 1. IRAN IP-CIDRS & ASNS (RIPE NCC WITH SAFE RANGE SUMMARIZATION)
# ==============================================================================
print("[-] Step 1: Fetching and aggregating Iranian IPv4 prefixes from RIPE NCC...")
ripe_url = "https://ftp.ripe.net/ripe/stats/delegated-ripencc-latest"
ripe_raw = fetch_data(ripe_url)

networks = []
asns = []

for line in ripe_raw.splitlines():
    if not line or line.startswith('#'):
        continue
    parts = line.split('|')
    if len(parts) >= 7 and parts[1] == 'IR':
        if parts[2] == 'ipv4':
            start_ip = parts[3]
            count = int(parts[4])
            try:
                first_ip = ipaddress.IPv4Address(start_ip)
                last_ip = first_ip + (count - 1)
                # Break non-standard ranges into valid CIDR blocks
                networks.extend(ipaddress.summarize_range(first_ip, last_ip))
            except Exception as e:
                pass
        elif parts[2] == 'asn':
            asns.append(f"IP-ASN,{parts[3]}")

# Collapse contiguous subnets into supernets
collapsed_networks = list(ipaddress.collapse_addresses(networks)) if networks else []
print(f"[+] Successfully aggregated {len(collapsed_networks)} supernets and {len(asns)} ASNs.")

with open(f"{OUTPUT_DIR}/ircidr.txt", "w", encoding="utf-8") as f:
    for net in collapsed_networks:
        f.write(f"{net}\n")

with open(f"{OUTPUT_DIR}/irasn.txt", "w", encoding="utf-8") as f:
    for asn_rule in sorted(set(asns)):
        f.write(f"{asn_rule}\n")

# ==============================================================================
# 2. IRAN DOMAINS (BOOTMORTIS RELEASE + TLD)
# ==============================================================================
print("[-] Step 2: Fetching and sanitizing Iranian domains...")
domains_urls = [
    "https://raw.githubusercontent.com/bootmortis/iran-hosted-domains/release/domains.txt",
    "https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/domains.txt"
]

iran_domains = set()
iran_domains.add("+.ir")

for url in domains_urls:
    raw = fetch_data(url)
    if raw:
        for line in raw.splitlines():
            domain = clean_domain(line)
            if domain and not domain.endswith('.ir'):
                iran_domains.add(f"+.{domain}")
        break

with open(f"{OUTPUT_DIR}/ir.txt", "w", encoding="utf-8") as f:
    for d in sorted(iran_domains):
        f.write(f"{d}\n")
print(f"[+] Guaranteed ir.txt created with {len(iran_domains)} domains.")

# ==============================================================================
# 3. IRAN ADS WITH PAYMENT GATEWAY UNBREAK WHITELIST
# ==============================================================================
print("[-] Step 3: Fetching Persian Adblocker with payment safety filters...")
ads_url = "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerHosts.txt"
ads_raw = fetch_data(ads_url)

UNBREAK_WHITELIST = {
    "shaparak.ir", "asanpardakht.ir", "sadadpsp.ir", "behpardakht.com",
    "sepehrpay.com", "sep.ir", "pec.ir", "zarinpal.com", "payping.net",
    "idpay.ir", "jibit.ir", "kavenegar.com", "ghasedak.me", "raychat.io"
}

ad_domains = set()
for line in ads_raw.splitlines():
    if not line or line.startswith('#'):
        continue
    parts = line.split()
    domain = clean_domain(parts[-1])
    if domain and not any(safe in domain for safe in UNBREAK_WHITELIST):
        ad_domains.add(domain)

with open(f"{OUTPUT_DIR}/ads.txt", "w", encoding="utf-8") as f:
    for d in sorted(ad_domains):
        f.write(f"{d}\n")
print(f"[+] Guaranteed ads.txt created with {len(ad_domains)} ad domains.")

# ==============================================================================
# 4. PHISHING & THREAT BLOCKLIST
# ==============================================================================
print("[-] Step 4: Compiling verified phishing blocklist...")
phishing_url = "https://curben.gitlab.io/malware-filter/phishing-filter-hosts.txt"
phishing_raw = fetch_data(phishing_url)

phishing_domains = set()
for line in phishing_raw.splitlines():
    if not line or line.startswith('#'):
        continue
    parts = line.split()
    domain = clean_domain(parts[-1])
    if domain:
        phishing_domains.add(domain)

with open(f"{OUTPUT_DIR}/phishing.txt", "w", encoding="utf-8") as f:
    for d in sorted(phishing_domains):
        f.write(f"{d}\n")
print(f"[+] Guaranteed phishing.txt created with {len(phishing_domains)} domains.")
