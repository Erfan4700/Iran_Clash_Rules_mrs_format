import os
import re
import sys
import subprocess
import ipaddress
import urllib.request
import xml.etree.ElementTree as ET

OUTPUT_DIR = "output_text"
os.makedirs(OUTPUT_DIR, exist_ok=True)

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'}

def fetch_data(urls, timeout=60):
    """Safely fetch text data over HTTPS with native curl handling redirects and compression."""
    if isinstance(urls, str):
        urls = [urls]
    for url in urls:
        # روش اول: استفاده از curl برای مدیریت دیتای فشرده و ریدایرکت‌ها
        try:
            cmd = ["curl", "-sSL", "--compressed", "--max-time", str(timeout), "-A", HEADERS['User-Agent'], url]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if len(result.stdout.strip()) > 50:
                return result.stdout
        except Exception as e:
            print(f"[!] curl notice for {url}: {e}. Retrying via urllib...")

        # روش دوم: فال‌بک با urllib
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                content = resp.read().decode('utf-8', errors='ignore')
                if len(content.strip()) > 50:
                    return content
        except Exception as e:
            print(f"[!] urllib notice for {url}: {e}")

    return ""

def clean_domain(line):
    """Extract strictly valid, normalized domain names safe for Mihomo MRS."""
    line = line.split('#')[0].split(';')[0].strip().lower()
    if not line or line.startswith(('!', '//')):
        return None

    parts = line.split()
    target = parts[1] if (len(parts) >= 2 and re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^::[0-9a-f]?$', parts[0])) else parts[0]

    target = re.sub(r'^[\|]+', '', target)
    target = re.sub(r'[\^/].*$', '', target)
    target = re.sub(r'^https?://', '', target)
    target = re.sub(r'^\+\.?', '', target)
    target = re.sub(r'^\*\.?', '', target)
    target = re.sub(r'^\.', '', target)
    target = target.strip('.')

    domain_regex = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    if re.match(domain_regex, target) and '..' not in target:
        return target
    return None

# ==============================================================================
# 0. ZERO-TRUST CRITICAL INFRASTRUCTURE WHITELIST
# ==============================================================================
UNBREAK_WHITELIST = {
    "shaparak.ir", "asanpardakht.ir", "sadadpsp.ir", "behpardakht.com",
    "sepehrpay.com", "sep.ir", "pec.ir", "zarinpal.com", "payping.net",
    "idpay.ir", "jibit.ir", "kavenegar.com", "ghasedak.me", "raychat.io",
    "divar.ir", "torob.com", "digikala.com", "sana.gov.ir"
}

def is_whitelisted(domain):
    return any(domain == safe or domain.endswith("." + safe) for safe in UNBREAK_WHITELIST)

# ==============================================================================
# 1. IRAN IP-CIDRS & ASNS (RIPE NCC & APNIC OFFICIAL MIRRORS)
# ==============================================================================
print("[-] Step 1: Fetching Iranian IP-CIDRs from Authoritative RIRs...")
ripe_urls = [
    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
    "https://ftp.apnic.net/stats/ripe-ncc/delegated-ripencc-latest",
    "http://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest"
]

ripe_raw = fetch_data(ripe_urls, timeout=90)

ipv4_nets = []
ipv6_nets = []
asns = []

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

# فال‌بک اضطراری با دیتای معتبر
if not ipv4_nets:
    print("[!] Primary RIR mirrors delayed. Engaging backup mirror...")
    fallback_cidrs = fetch_data("https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ircidr.txt", timeout=30)
    for line in fallback_cidrs.splitlines():
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

if not asns:
    fallback_asns = fetch_data("https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/irasn.txt", timeout=30)
    for line in fallback_asns.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            asns.append(line if line.startswith("IP-ASN,") else f"IP-ASN,{line}")

if not ipv4_nets or not asns:
    print("[X] FATAL ERROR: Unable to acquire IP/ASN data. Aborting.")
    sys.exit(1)

collapsed_v4 = list(ipaddress.collapse_addresses(ipv4_nets))
collapsed_v6 = list(ipaddress.collapse_addresses(ipv6_nets))
all_collapsed = collapsed_v4 + collapsed_v6

print(f"[+] Total CIDRs: {len(all_collapsed)} (IPv4: {len(collapsed_v4)}, IPv6: {len(collapsed_v6)}) | ASNs: {len(asns)}")

with open(f"{OUTPUT_DIR}/ircidr.txt", "w", encoding="utf-8") as f:
    for net in all_collapsed:
        f.write(f"{net}\n")

with open(f"{OUTPUT_DIR}/irasn.txt", "w", encoding="utf-8") as f:
    for asn in sorted(set(asns)):
        f.write(f"{asn}\n")

# ==============================================================================
# 2. IRAN DOMAINS (BOOTMORTIS WITH INTEGRITY CHECK)
# ==============================================================================
print("[-] Step 2: Fetching Iranian domains from Bootmortis...")
iran_domains = {
    "digikala.com", "torob.com", "divar.ir", "snapp.cab", "tapsi.cab",
    "neshan.org", "balad.ir", "bale.ai", "eitaa.com", "rubika.ir",
    "shaparak.ir", "asanpardakht.ir", "zarinpal.com", "aparat.com"
}

bootmortis_urls = [
    "https://raw.githubusercontent.com/bootmortis/iran-hosted-domains/release/domains.txt",
    "https://raw.githubusercontent.com/bootmortis/iran-hosted-domains/main/domains/domains.txt"
]
raw_domains = fetch_data(bootmortis_urls, timeout=35)

if raw_domains:
    for line in raw_domains.splitlines():
        d = clean_domain(line)
        if d:
            iran_domains.add(d)

if len(iran_domains) < 1000:
    print("[X] FATAL ERROR: Bootmortis dataset corrupted or unreachable. Aborting.")
    sys.exit(1)

print(f"[+] Total verified Iran domains: {len(iran_domains)}")
with open(f"{OUTPUT_DIR}/ir.txt", "w", encoding="utf-8") as f:
    for d in sorted(iran_domains):
        f.write(f"{d}\n")

# ==============================================================================
# 3. IRAN ADS WITH ZERO-TRUST PAYMENT GATEWAY WHITELIST
# ==============================================================================
print("[-] Step 3: Fetching Persian ads with strict sub-domain whitelist...")
ads_urls = [
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerHosts.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerAds-Hosts.txt"
]
ads_raw = fetch_data(ads_urls, timeout=35)

ad_domains = {"yektanet.com", "sabavision.com", "mediaad.org"}
if ads_raw:
    for line in ads_raw.splitlines():
        d = clean_domain(line)
        if d and not is_whitelisted(d):
            ad_domains.add(d)

print(f"[+] Total safe ad domains: {len(ad_domains)}")
with open(f"{OUTPUT_DIR}/ads.txt", "w", encoding="utf-8") as f:
    for d in sorted(ad_domains):
        f.write(f"{d}\n")

# ==============================================================================
# 4. DOMESTIC PHISHING (IRANIAN SMISHING & FAKE BANK PORTALS WITH WHITELIST)
# ==============================================================================
print("[-] Step 4: Fetching domestic phishing & fake portals...")
phishing_domains = {
    "phishing-fake-shaparak.top", "ir-sana-gov.com", "sep-shaparak.org"
}

phishing_urls = [
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerPhishing.txt",
    "https://raw.githubusercontent.com/curbengh/phishing-filter/master/phishing-filter-hosts.txt"
]
phishing_raw = fetch_data(phishing_urls, timeout=35)

KEYWORD_PATTERN = re.compile(r'(?:^|[.-])(?:shaparak|sana|divar|sadad|sep|mellat|melli|sheba)(?:[.-]|$)')

if phishing_raw:
    for line in phishing_raw.splitlines():
        d = clean_domain(line)
        if d and KEYWORD_PATTERN.search(d) and not is_whitelisted(d):
            phishing_domains.add(d)

print(f"[+] Total verified domestic phishing domains: {len(phishing_domains)}")
with open(f"{OUTPUT_DIR}/phishing.txt", "w", encoding="utf-8") as f:
    for d in sorted(phishing_domains):
        f.write(f"{d}\n")

# ==============================================================================
# 5. DOMESTIC GAMBLING & CASINOS (PERSIAN BET SITES ONLY)
# ==============================================================================
print("[-] Step 5: Compiling Domestic Gambling blocklist...")
gambling_domains = {
    "betcart.com", "1xbet.com", "takbet.com", "tinbet.info", "hottbet.com",
    "pokeriranian.com", "wolfbet.info", "cannonbet.org", "shartbandi.com",
    "tinybet.info", "hotbet.info", "hazarat.org", "pablobet.info"
}

gambling_urls = [
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerGambling.txt"
]
gambling_raw = fetch_data(gambling_urls, timeout=35)
if gambling_raw:
    for line in gambling_raw.splitlines():
        d = clean_domain(line)
        if d and not is_whitelisted(d):
            gambling_domains.add(d)

print(f"[+] Total targeted domestic gambling domains: {len(gambling_domains)}")
with open(f"{OUTPUT_DIR}/nsfw.txt", "w", encoding="utf-8") as f:
    for d in sorted(gambling_domains):
        f.write(f"{d}\n")

# ==============================================================================
# 6. IRANIAN APPS (AUTONOMOUS MASSIVE CRAWLER & CURATED CORE)
# ==============================================================================
print("[-] Step 6: Scraping and compiling massive domestic Android & Windows database...")

# ۱. هسته تضمین‌شده اپلیکیشن‌های حیاتی (بانک‌ها، تاکسی‌ها، صرافی‌ها، پیام‌رسان‌ها)
CURATED_ANDROID_SEED = {
    # تاکسی و لجستیک
    "cab.snapp.passenger", "cab.snapp.driver", "cab.snapp.biker", "cab.snapp.delivery",
    "taxi.tap30.passenger", "taxi.tap30.driver", "taxi.tap30.food", "com.alopeyk.customer", "com.alopeyk.courier",
    "com.taxsee.taxsee", "neshan.maps", "ir.balad.maps",
    # فروشگاه و خدمات
    "com.digikala", "com.digikala.seller", "ir.divar", "com.sheypoor.mobile", "ir.torob",
    "com.emalls", "com.basalam.app", "com.snappmarket", "com.zoodfood.android",
    # مالی، بانکی و رمزارز
    "market.nobitex", "net.nobitex", "ir.wallex.app", "com.abantether", "com.ramzinex.app", "ir.bitpin", "io.exir",
    "ir.tejaratbank.mobile", "com.bmi.mobilebank", "com.bmi.bam", "ir.sep.sesame", "ir.banksepah.mobilebank",
    "ir.omidbank", "com.bsi.mobilebank", "ir.bpi.mobilebank", "com.bki.mobilebank", "ir.refah.mobilebank",
    "com.maskan.mobilebank", "ir.samanpr.mobillet", "ir.sinabank.mobilebank", "com.ayandeh.kilid",
    "ir.blu.banking", "ir.resalat.mb", "ir.zarinpal.android", "ir.payping.app", "com.asanpardakht",
    # رسانه، فیلم و سرگرمی
    "com.aparat.android", "com.saba.filimo", "ir.shatel.namava", "ir.filmnet.android", "ir.cinematicket.app",
    "com.alibaba.android", "ir.flytoday", "com.pintapin", "com.jabama",
    # پیام‌رسان و اپراتورها
    "org.bale.messenger", "ir.eitaa.messenger", "ir.resaneh1.iptv", "org.soroushplus.messenger", "ir.gap.im", "com.iGap",
    "ir.mci.ecareapp", "com.mtnirancell.myirancell", "ir.rightel.myrightel", "com.farsitel.bazaar", "ir.mservices.myket"
}

# پکیج‌هایی که هرگز نباید دایرکت شوند (برنامه‌های خارجی موجود در کافه‌بازار)
GLOBAL_EXCLUDES = {
    "org.telegram.messenger", "com.whatsapp", "com.instagram.android",
    "com.facebook.katana", "com.twitter.android", "com.google.android.youtube",
    "com.google.android.gms", "com.android.chrome", "org.mozilla.firefox",
    "com.spotify.music", "com.netflix.mediaclient"
}

scraped_packages = set(CURATED_ANDROID_SEED)
PKG_REGEX = re.compile(r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$')

# ۲. کراولر خودکار و مستقل از سرورهای کافه‌بازار (استخراج هزاران پکیج واقعی)
try:
    print("[*] Launching autonomous crawler on CafeBazaar official sitemaps...")
    store_sitemap = "https://cafebazaar.ir/sitemap.xml"
    sitemap_index = fetch_data(store_sitemap, timeout=30)
    if sitemap_index:
        # پیدا کردن ساب‌سایت‌مپ‌های برنامه‌ها
        sub_maps = re.findall(r'https://cafebazaar\.ir/sitemaps/sitemap-app-\d+\.xml', sitemap_index)
        # کراول ۵ سایت‌مپ اول اپلیکیشن‌ها (شامل هزاران برنامه)
        for sm in sub_maps[:5]:
            try:
                sm_data = fetch_data(sm, timeout=35)
                if sm_data:
                    found = re.findall(r'/app/([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+)', sm_data)
                    for p in found:
                        if p not in GLOBAL_EXCLUDES and PKG_REGEX.match(p) and len(p) < 90:
                            scraped_packages.add(p)
            except Exception:
                pass
except Exception as e:
    print(f"[!] Live crawler notice: {e}. Falling back to extensive baseline.")

# ۳. فال‌بک تکمیلی به دیتابیس جامعه متن‌باز برای رسیدن به حداکثر جامعیت
if len(scraped_packages) < 1000:
    print("[!] Pulling massive community package baseline...")
    community_repo = "https://raw.githubusercontent.com/SamadiPour/iran-android-apps/master/packages.txt"
    comm_data = fetch_data(community_repo, timeout=30)
    if comm_data:
        for line in comm_data.splitlines():
            pkg = line.replace("PACKAGE-NAME,", "").strip()
            if pkg not in GLOBAL_EXCLUDES and PKG_REGEX.match(pkg) and len(pkg) < 90:
                scraped_packages.add(pkg)

# ۴. پروسس‌های دسکتاپ ویندوز
WINDOWS_PROCESSES = [
    "Bale.exe", "Eitaa.exe", "EitaaDesktop.exe", "Rubika.exe",
    "Soroush.exe", "Gap.exe", "IDMan.exe", "Digikala.exe", "Aparat.exe"
]

with open(f"{OUTPUT_DIR}/apps.txt", "w", encoding="utf-8") as f:
    for pkg in sorted(scraped_packages):
        f.write(f"PACKAGE-NAME,{pkg}\n")
    for proc in sorted(WINDOWS_PROCESSES):
        f.write(f"PROCESS-NAME,{proc}\n")

print(f"[+] Successfully compiled {len(scraped_packages) + len(WINDOWS_PROCESSES)} total application rules (Android: {len(scraped_packages)}, Windows: {len(WINDOWS_PROCESSES)})")
