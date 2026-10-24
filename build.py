import os
import re
import ipaddress
import urllib.request

OUTPUT_DIR = "output_text"
os.makedirs(OUTPUT_DIR, exist_ok=True)

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

# Fallback baseline domestic domains (Guarantees rule-set is never empty)
FALLBACK_DOMAINS = {
    "digikala.com", "torob.com", "divar.ir", "snapp.cab", "tapsi.cab",
    "neshan.org", "balad.ir", "bale.ai", "eitaa.com", "rubika.ir",
    "shaparak.ir", "asanpardakht.ir", "zarinpal.com", "aparat.com",
    "telewebion.com", "filmnet.ir", "filimo.com", "varzesh3.com"
}

def fetch_data(url):
    """Safely fetch text data from URL with timeout."""
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[!] Warning fetching {url}: {e}")
        return ""

def clean_domain(line):
    """Extract pure, clean domain names compatible with Mihomo MRS."""
    line = line.strip().lower()
    if not line or line.startswith(('#', '!', ';', '//')):
        return None
    # Strip protocol, path, and adblock syntax
    line = re.sub(r'^[\|]+', '', line)
    line = re.sub(r'[\^/].*$', '', line)
    line = re.sub(r'^https?://', '', line)
    line = re.sub(r'^\+\.?', '', line)
    line = re.sub(r'^\*\.?', '', line)
    line = re.sub(r'^\.', '', line)
    line = line.strip()
    # Must contain at least one dot and valid domain characters
    if re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', line):
        return line
    return None

# ==============================================================================
# 1. IRAN IP-CIDRS & ASNS (RIPE NCC)
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
                networks.extend(ipaddress.summarize_range(first_ip, last_ip))
            except Exception:
                pass
        elif parts[2] == 'asn':
            asns.append(f"IP-ASN,{parts[3]}")

collapsed_networks = list(ipaddress.collapse_addresses(networks)) if networks else []
print(f"[+] Successfully aggregated {len(collapsed_networks)} supernets and {len(asns)} ASNs.")

with open(f"{OUTPUT_DIR}/ircidr.txt", "w", encoding="utf-8") as f:
    for net in collapsed_networks:
        f.write(f"{net}\n")

with open(f"{OUTPUT_DIR}/irasn.txt", "w", encoding="utf-8") as f:
    for asn_rule in sorted(set(asns)):
        f.write(f"{asn_rule}\n")

# ==============================================================================
# 2. IRAN DOMAINS (PURE DOMAINS ONLY)
# ==============================================================================
print("[-] Step 2: Fetching and sanitizing Iranian domains...")
domains_urls = [
    "https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/text/ir.txt",
    "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.txt"
]

iran_domains = set(FALLBACK_DOMAINS)

for url in domains_urls:
    raw = fetch_data(url)
    if raw:
        for line in raw.splitlines():
            domain = clean_domain(line)
            if domain:
                iran_domains.add(domain)
        break

with open(f"{OUTPUT_DIR}/ir.txt", "w", encoding="utf-8") as f:
    for d in sorted(iran_domains):
        f.write(f"{d}\n")
print(f"[+] Guaranteed ir.txt created with {len(iran_domains)} pure domains.")

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

# Fallback ad domain if upstream fails
if not ad_domains:
    ad_domains.add("yektanet.com")

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

if not phishing_domains:
    phishing_domains.add("phishing-example-domain.com")

with open(f"{OUTPUT_DIR}/phishing.txt", "w", encoding="utf-8") as f:
    for d in sorted(phishing_domains):
        f.write(f"{d}\n")
print(f"[+] Guaranteed phishing.txt created with {len(phishing_domains)} domains.")
