// ==============================================================================
// 0. USER CONTROL PANEL (Macro)
// ==============================================================================

// --- CORE SYSTEM SWITCHES ---
const ENABLE_SAFE_SEARCH = false;       // [Optional] Enforce SafeSearch on Google & Bing
const ENABLE_QUIC_BLOCK = true;         // [Recommended] Force TCP fallback to prevent UDP censorship throttling

// Available Tiers:
// "light" | "normal" | "pro" | "promini" | "proplus" | "proplusmini" | "ultimate" | "ultimatemini"
// Note: "ProPlus" is optimal for most users. Mini versions reduce RAM usage on low-end hardware.
const HAGEZI_TIER = "proplus";

// --- GLOBAL CONTENT BLOCKING (Modular Add-ons) ---
const ENABLE_PORN_FILTER = true;        // [Optional | Modular] HaGeZi NSFW (Never included in main tiers)
const ENABLE_GAMBLING_FILTER = true;    // [Optional | Modular] HaGeZi Gambling + Iran Modular (Not in main tiers)
const ENABLE_POPUP_ADS = false;         // [Redundant in Pro/ProPlus] Already covered; enable only if using Light/Normal
const ENABLE_SOCIAL_BLOCK = false;      // [Optional | Modular] Blocks social networks (Strict environments only)
const ENABLE_URL_SHORTENER = false;     // [Optional | Modular] Blocks URL shorteners/trackers (May break short links)

// --- ADVANCED THREAT INTELLIGENCE & SECURITY ---
const ENABLE_HAGEZI_TIF = false;        // [High RAM/CPU] Heavy 12MB Threat Intel feed (Redundant with TIF_IP on routers)
const ENABLE_HAGEZI_TIF_MEDIUM = false; // [High RAM/CPU] Medium 3MB Threat Intel feed
const ENABLE_HAGEZI_TIF_MINI = true;   // [Moderate RAM] Lightweight 1.6MB Threat Intel feed
const ENABLE_HAGEZI_TIF_IP = true;      // [Recommended | Modular] 81KB IP-CIDR feed; blocks direct C2/malware server IPs
const ENABLE_HAGEZI_FAKE = false;       // [Partially in ProPlus] Scam/Fake shops; enable if extra e-commerce guard needed
const ENABLE_HAGEZI_BADWARE = false;    // [Redundant in Pro/ProPlus] Known malware hosting providers
const ENABLE_HAGEZI_DGA7 = false;       // [Optional | Aggressive] Blocks algorithmic dynamic domains (7-day lifecycle)
const ENABLE_HAGEZI_DGA14 = false;      // [Optional | Aggressive] Blocks algorithmic dynamic domains (14-day lifecycle)
const ENABLE_HAGEZI_DYNDNS = false;     // [Aggressive | May Break] Blocks DDNS providers; breaks dynamic IP hosting/cameras
const ENABLE_HAGEZI_SPAM_TLDS = false;  // [Aggressive | May Break] Blocks spam-heavy TLD extensions (.top, .xyz, etc.)
const ENABLE_HAGEZI_DOH_IP = false;     // [Optional | Modular] Blocks public DoH/DoT resolver IPs (Prevents DNS bypass)

// --- NATIVE OEM & APP TRACKERS (Device Specific) ---
// Note: Native lists are modular add-ons to prevent device telemetry without breaking device core features.
const ENABLE_TRACKER_XIAOMI = false;    // [Optional] Xiaomi/HyperOS tracking & ads
const ENABLE_TRACKER_SAMSUNG = true;    // [Optional] Samsung OneUI analytics & diagnostic services
const ENABLE_TRACKER_APPLE = false;     // [Optional] Apple analytics (Keep false if you use iCloud private relay)
const ENABLE_TRACKER_MICROSOFT = true;  // [Optional] Windows diagnostic, Cortana & Office telemetry
const ENABLE_TRACKER_HUAWEI = false;    // [Optional] Huawei device telemetry
const ENABLE_TRACKER_BBK = false;       // [Optional] Oppo / Realme / Vivo tracking
const ENABLE_TRACKER_AMAZON = false;    // [Optional] Amazon Echo, Alexa, & FireTV tracking
const ENABLE_TRACKER_LG = false;        // [Optional] LG Smart TV (webOS) analytics & ACR advertising
const ENABLE_TRACKER_ROKU = false;      // [Optional] Roku streaming media tracking
const ENABLE_TRACKER_TIKTOK = true;    // [Optional] TikTok app telemetry & analytics
const ENABLE_TRACKER_TIKTOK_EXT = false;// [Aggressive] Extended TikTok tracker list (May break feed/login)

// --- ANTI-PIRACY & COPYRIGHT ---
const ENABLE_ANTI_PIRACY = false;       // [Optional | Modular] Blocks torrent indexers, warez, & streaming piracy

// --- IRAN CORE SUITE ---
const ENABLE_IRAN_ADS = true;          // [Recommended] Iran-specific ads, web trackers & banners
const ENABLE_IRAN_SECURITY = true;     // [Recommended] Iran phishing banks, fake shaparak gateways & malware
const ENABLE_IRAN_DIRECT = true;       // [Recommended] Bypasses domestic servers/CDNs for zero-latency domestic traffic

const SECURITY_INTERVAL = 24 * 3600;   // 24 Hours update interval for fast-changing threat feeds
const STANDARD_INTERVAL = 48 * 3600;   // 48 Hours update interval for general adblock rules

// ==============================================================================
// 1. DATASETS & REPOSITORIES (DIRECT GITHUB RELEASES - FAST & UP-TO-DATE)
// ==============================================================================

const IRAN_RULES_BASE_URL = "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/";
const HAGEZI_RAW_URL = "https://github.com/Erfan4700/HaGeZi_BlockLists_mrs_format/releases/latest/download/";

const HAGEZI_TIERS_MAP = Object.freeze({
  light: "HageziLight",
  normal: "HageziNormal",
  pro: "HageziPro",
  promini: "HageziProMini",
  proplus: "HageziProPlus",
  proplusmini: "HageziProPlusMini",
  ultimate: "HageziUltimate",
  ultimatemini: "HageziUltimateMini"
});

const SELECTED_HAGEZI_NAME = HAGEZI_TIERS_MAP[HAGEZI_TIER.toLowerCase()] ?? "HageziProPlus";

const JUNK_RULES_REGEX = /(?:GEOIP|GEOSITE|RULE-SET),[^,\n]*(?<![a-z0-9])(?:CN|CHINA|RU|RUSSIA)(?![a-z0-9])/i;
const PROXY_KEYWORD_REGEX = /proxy|auto|select|default|fallback|internet|traffic|manual|nodes|نهایی|اینترنت|دستی|انتخاب|🚀|⚡|♻️/i;
const MATCH_RULE_REGEX = /^match(?:,|$)/i;
const DIRECT_KEYWORD_REGEX = /direct/i;
const IP_RULE_PREFIX_REGEX = /^(?:GEOIP|IP-CIDR|IP-CIDR6|IP-ASN),/i;
const NO_RESOLVE_REGEX = /,\s*no-resolve(?:\s*#.*)?$/i;

const MANUAL_DOMAINS = Object.freeze([
  "aparat.com", "filimo.com", "telewebion.com", "varzesh3.com",
  "neshan.org", "rajman.org", "cedarmaps.com", "snapp.cab", "snapp.tax",
  "snappcloud.io", "snapp.supply", "tapsi.cab", "tap33.me", "taximaxim.com",
  "torob.com", "divarcdn.com", "digikala.com", "digikalacloud.com",
  "dl150m.info", "dl175m.info", "linkulu.com", "film2media.cam",
  "zarinpal.com", "zarin.link", "payping.net", "ramzinex.com", "abantether.com",
  "nobitex.net", "exir.io", "wallex.net"
]);

const MANUAL_WILDCARDS = Object.freeze(MANUAL_DOMAINS.map(d => `+.${d}`));

const FROZEN_HOSTS = Object.freeze({
  "forcesafesearch.google.com": "216.239.38.120",
  "www.google.com": "216.239.38.120",
  "google.com": "216.239.38.120",
  "strict.bing.com": "204.79.197.220",
  "www.bing.com": "204.79.197.220",
  "bing.com": "204.79.197.220"
});

const PURE_DOMESTIC_RESOLVERS = Object.freeze([
  "193.186.32.32",
  "217.218.127.127",
  "217.218.155.155"
]);

const UNPOISONED_PROXY_RESOLVERS = Object.freeze([
  "https://223.5.5.5/dns-query",
  "223.5.5.5",
  "119.29.29.29",
  "193.186.32.32"
]);

const HYBRID_BOOTSTRAP_RESOLVERS = Object.freeze([
  "223.5.5.5",
  "119.29.29.29",
  "193.186.32.32"
]);

const DOH_ENDPOINTS = Object.freeze([
  "https://1.1.1.1/dns-query",
  "https://8.8.8.8/dns-query",
  "https://9.9.9.9/dns-query"
]);

// ==============================================================================
// 2. HELPER FUNCTIONS
// ==============================================================================

function makeProvider(name, behavior, format, url, interval) {
  return {
    type: "http",
    behavior: behavior,
    format: format,
    url: url,
    path: `./ruleset/${name}.${format === "mrs" ? "mrs" : "txt"}`,
    interval: interval
  };
}

function resolvePrimaryProxyGroup(groups) {
  if (!Array.isArray(groups) || groups.length === 0) return "PROXY";

  let matchedSelectGroup = null;
  let fallbackAutoGroup = null;

  for (let i = 0, len = groups.length; i < len; i++) {
    const group = groups[i];
    if (!group) continue;
    const { type, name } = group;

    if (DIRECT_KEYWORD_REGEX.test(name) || name.toLowerCase() === "reject") continue;

    const isMatch = PROXY_KEYWORD_REGEX.test(name);
    if (type === "select" && isMatch) return name;
    if (!matchedSelectGroup && isMatch) matchedSelectGroup = name;
    if (!fallbackAutoGroup && (type === "url-test" || type === "fallback" || type === "load-balance")) {
      fallbackAutoGroup = name;
    }
  }

  return matchedSelectGroup ?? fallbackAutoGroup ?? groups[0]?.name ?? "PROXY";
}

// ==============================================================================
// 3. MAIN RUNTIME PIPELINE
// ==============================================================================

function main(config, profileName) {
  const defaultProxyGroup = resolvePrimaryProxyGroup(config["proxy-groups"]);

  config["tcp-concurrent"] = true;
  config["unified-delay"] = true;
  config["find-process-mode"] = "strict";

  delete config["global-client-fingerprint"];

  if (Array.isArray(config.proxies)) {
    for (let i = 0, len = config.proxies.length; i < len; i++) {
      const p = config.proxies[i];
      if (p && (p.tls || p["reality-opts"] || p.type === "vless" || p.type === "trojan" || p.type === "hysteria2")) {
        p["client-fingerprint"] ??= "chrome";
      }
    }
  }

  config["geodata-mode"] = false;
  config["geo-auto-update"] = false;

  config["keep-alive-idle"] = 600;
  config["keep-alive-interval"] = 15;

  (config.experimental ??= {})["quic-go-disable-ecn"] = true;

  const profile = (config.profile ??= {});
  profile["store-fake-ip"] = true;
  profile["store-selected"] = true;

  config.sniffer = {
    enable: true,
    "force-dns-mapping": true,
    "parse-pure-ip": true,
    "override-destination": false,
    sniff: {
      TLS: { ports: [443, 8443, 2053, 2083, 2087, 2096] },
      HTTP: { ports: [80, 8080, 8880] }
    },
    "skip-dst-address": [
      "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
      "224.0.0.0/4", "255.255.255.255/32"
    ],
    "skip-domain": [
      "Mijia Cloud", "+.push.apple.com", "+.apple.com",
      "+.lan", "+.local", "+.home.arpa", "+.ir",
      ...MANUAL_WILDCARDS
    ]
  };

  if (ENABLE_SAFE_SEARCH) {
    config.hosts = Object.assign({}, config.hosts ?? {}, FROZEN_HOSTS);
  }

  const dns = (config.dns ??= {});
  dns.enable = true;
  dns["enhanced-mode"] = "fake-ip";
  dns["fake-ip-range"] = "198.18.0.1/16";
  dns["cache-algorithm"] = "arc";
  dns["cache-size"] = 4096;
  dns["respect-rules"] = false;
  dns["direct-nameserver-follow-policy"] = true;
  dns["use-system-hosts"] = true;
  dns["use-hosts"] = true;
  dns.ipv6 = false;
  dns["prefer-h3"] = false;

  dns["default-nameserver"] = HYBRID_BOOTSTRAP_RESOLVERS;
  dns["proxy-server-nameserver"] = UNPOISONED_PROXY_RESOLVERS;
  dns["direct-nameserver"] = PURE_DOMESTIC_RESOLVERS;

  const fakeIpList = [
    "+.ir",
    ...MANUAL_WILDCARDS,
    "+.lan", "+.local", "+.home.arpa",
    "captive.apple.com", "+.connectivitycheck.gstatic.com",
    "detectportal.firefox.com", "+.msftconnecttest.com", "+.msftncsi.com",
    "time.apple.com", "time.google.com", "time.windows.com", "time.nist.gov",
    "+.pool.ntp.org", "+.ntp.org",
    "+.steamcontent.com", "+.battlenet.com", "+.battle.net", "+.ea.com",
    "stun.*", "*.stun.*", "supl.google.com", "+.supl.google.com",
    "location.services.mozilla.com"
  ];
  if (ENABLE_IRAN_DIRECT) {
    fakeIpList.splice(1, 0, "rule-set:iran-all-domains");
  }
  dns["fake-ip-filter"] = fakeIpList;

  dns.nameserver = DOH_ENDPOINTS.map(url => `${url}#${defaultProxyGroup}`);

  const nsPolicy = {
    "+.ir": PURE_DOMESTIC_RESOLVERS,
    "supl.google.com": PURE_DOMESTIC_RESOLVERS,
    "+.supl.google.com": PURE_DOMESTIC_RESOLVERS
  };
  if (ENABLE_IRAN_DIRECT) {
    nsPolicy["rule-set:iran-all-domains"] = PURE_DOMESTIC_RESOLVERS;
  }
  for (let i = 0; i < MANUAL_DOMAINS.length; i++) {
    nsPolicy[`+.${MANUAL_DOMAINS[i]}`] = PURE_DOMESTIC_RESOLVERS;
  }
  dns["nameserver-policy"] = Object.assign(dns["nameserver-policy"] ?? {}, nsPolicy);

  // ============================================================================
  // RULE-PROVIDERS DEFINITION
  // ============================================================================
  const providers = {};

  // 1. Global Base Adblock (Selected via HAGEZI_TIER)
  providers["hagezi-main"] = makeProvider(
    `hagezi-${HAGEZI_TIER}`, "domain", "mrs",
    `${HAGEZI_RAW_URL}${SELECTED_HAGEZI_NAME}.mrs`, STANDARD_INTERVAL
  );

  // 2. Global Threat Intelligence & Security
  if (ENABLE_HAGEZI_TIF) {
    providers["hagezi-tif"] = makeProvider("HageziTIF", "domain", "mrs", `${HAGEZI_RAW_URL}HageziTIF.mrs`, SECURITY_INTERVAL);
  }
  if (ENABLE_HAGEZI_TIF_MEDIUM) {
    providers["hagezi-tif-medium"] = makeProvider("HageziTIFMedium", "domain", "mrs", `${HAGEZI_RAW_URL}HageziTIFMedium.mrs`, SECURITY_INTERVAL);
  }
  if (ENABLE_HAGEZI_TIF_MINI) {
    providers["hagezi-tif-mini"] = makeProvider("HageziTIFMini", "domain", "mrs", `${HAGEZI_RAW_URL}HageziTIFMini.mrs`, SECURITY_INTERVAL);
  }
  if (ENABLE_HAGEZI_TIF_IP) {
    providers["hagezi-tif-ip"] = makeProvider("HageziTIF_IP", "ipcidr", "mrs", `${HAGEZI_RAW_URL}HageziTIF_IP.mrs`, SECURITY_INTERVAL);
  }
  if (ENABLE_HAGEZI_FAKE) {
    providers["hagezi-fake"] = makeProvider("HageziFake", "domain", "mrs", `${HAGEZI_RAW_URL}HageziFake.mrs`, SECURITY_INTERVAL);
  }
  if (ENABLE_HAGEZI_BADWARE) {
    providers["hagezi-badware"] = makeProvider("HageziBadwareHoster", "domain", "mrs", `${HAGEZI_RAW_URL}HageziBadwareHoster.mrs`, SECURITY_INTERVAL);
  }
  if (ENABLE_HAGEZI_DGA7) {
    providers["hagezi-dga7"] = makeProvider("HageziDGA7", "domain", "mrs", `${HAGEZI_RAW_URL}HageziDGA7.mrs`, SECURITY_INTERVAL);
  }
  if (ENABLE_HAGEZI_DGA14) {
    providers["hagezi-dga14"] = makeProvider("HageziDGA14", "domain", "mrs", `${HAGEZI_RAW_URL}HageziDGA14.mrs`, SECURITY_INTERVAL);
  }
  if (ENABLE_HAGEZI_DYNDNS) {
    providers["hagezi-dyndns"] = makeProvider("HageziDynDNS", "domain", "mrs", `${HAGEZI_RAW_URL}HageziDynDNS.mrs`, SECURITY_INTERVAL);
  }
  if (ENABLE_HAGEZI_SPAM_TLDS) {
    providers["hagezi-spamtlds"] = makeProvider("HageziSpamTLDs", "domain", "mrs", `${HAGEZI_RAW_URL}HageziSpamTLDs.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_HAGEZI_DOH_IP) {
    providers["hagezi-doh-ip"] = makeProvider("HageziDoH_IP", "ipcidr", "mrs", `${HAGEZI_RAW_URL}HageziDoH_IP.mrs`, STANDARD_INTERVAL);
  }

  // 3. Global Content Blocking (NSFW / Gambling / Popups / Social / Shorteners)
  if (ENABLE_PORN_FILTER) {
    providers["hagezi-nsfw"] = makeProvider("HageziNSFW", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNSFW.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_GAMBLING_FILTER) {
    providers["hagezi-gambling"] = makeProvider("HageziGamblingMedium", "domain", "mrs", `${HAGEZI_RAW_URL}HageziGamblingMedium.mrs`, STANDARD_INTERVAL);
    providers["iran-modular-gambling"] = makeProvider("iran-modular-gambling", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-modular-gambling.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_POPUP_ADS) {
    providers["hagezi-popups"] = makeProvider("HageziPopUpAds", "domain", "mrs", `${HAGEZI_RAW_URL}HageziPopUpAds.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_SOCIAL_BLOCK) {
    providers["hagezi-social"] = makeProvider("HageziSocial", "domain", "mrs", `${HAGEZI_RAW_URL}HageziSocial.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_URL_SHORTENER) {
    providers["hagezi-urlshortener"] = makeProvider("HageziURLShortener", "domain", "mrs", `${HAGEZI_RAW_URL}HageziURLShortener.mrs`, STANDARD_INTERVAL);
  }

  // 4. Native Telemetry Trackers
  if (ENABLE_TRACKER_APPLE) {
    providers["hagezi-native-apple"] = makeProvider("HageziNativeApple", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeApple.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_TRACKER_MICROSOFT) {
    providers["hagezi-native-microsoft"] = makeProvider("HageziNativeMicrosoft", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeMicrosoft.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_TRACKER_XIAOMI) {
    providers["hagezi-native-xiaomi"] = makeProvider("HageziNativeXiaomi", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeXiaomi.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_TRACKER_SAMSUNG) {
    providers["hagezi-native-samsung"] = makeProvider("HageziNativeSamsung", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeSamsung.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_TRACKER_HUAWEI) {
    providers["hagezi-native-huawei"] = makeProvider("HageziNativeHuawei", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeHuawei.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_TRACKER_BBK) {
    providers["hagezi-native-oppo-realme"] = makeProvider("HageziNativeOppoRealme", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeOppoRealme.mrs`, STANDARD_INTERVAL);
    providers["hagezi-native-vivo"] = makeProvider("HageziNativeVivo", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeVivo.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_TRACKER_AMAZON) {
    providers["hagezi-native-amazon"] = makeProvider("HageziNativeAmazon", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeAmazon.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_TRACKER_LG) {
    providers["hagezi-native-lg"] = makeProvider("HageziNativeLGWebOS", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeLGWebOS.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_TRACKER_ROKU) {
    providers["hagezi-native-roku"] = makeProvider("HageziNativeRoku", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeRoku.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_TRACKER_TIKTOK) {
    providers["hagezi-native-tiktok"] = makeProvider("HageziNativeTikTok", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeTikTok.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_TRACKER_TIKTOK_EXT) {
    providers["hagezi-native-tiktok-ext"] = makeProvider("HageziNativeTikTokExtended", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeTikTokExtended.mrs`, STANDARD_INTERVAL);
  }

  // 5. Anti-Piracy
  if (ENABLE_ANTI_PIRACY) {
    providers["hagezi-antipiracy"] = makeProvider("HageziAntiPiracy", "domain", "mrs", `${HAGEZI_RAW_URL}HageziAntiPiracy.mrs`, STANDARD_INTERVAL);
  }

  // 6. Iran Domestic Security & Ads
  if (ENABLE_IRAN_ADS) {
    providers["iran-all-ads"] = makeProvider("iran-all-ads", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-all-ads.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_IRAN_SECURITY) {
    providers["iran-all-security"] = makeProvider("iran-all-security", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-all-security.mrs`, SECURITY_INTERVAL);
    providers["iran-all-security-ip"] = makeProvider("iran-all-security-ip", "ipcidr", "mrs", `${IRAN_RULES_BASE_URL}iran-all-security-ip.mrs`, SECURITY_INTERVAL);
  }

  // 7. Iran Master Direct
  if (ENABLE_IRAN_DIRECT) {
    providers["iran-all-domains"] = makeProvider("iran-all-domains", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-all-domains.mrs`, STANDARD_INTERVAL);
    providers["iran-all-ip"] = makeProvider("iran-all-ip", "ipcidr", "mrs", `${IRAN_RULES_BASE_URL}iran-all-ip.mrs`, STANDARD_INTERVAL);
    providers["iran-all-apps"] = makeProvider("iran-all-apps", "classical", "text", `${IRAN_RULES_BASE_URL}iran-all-apps.txt`, STANDARD_INTERVAL);
    providers["iran-asn"] = makeProvider("iran-asn", "classical", "text", `${IRAN_RULES_BASE_URL}iran-asn.txt`, STANDARD_INTERVAL);
  }

  config["rule-providers"] = Object.assign(config["rule-providers"] ?? {}, providers);

  // ============================================================================
  // RULES EVALUATION PIPELINE
  // ============================================================================
  const ruleSet = new Set();

  // 1. Local Network & Private IP Bypass
  ruleSet.add("DST-PORT,7275,DIRECT");
  ruleSet.add("GEOIP,private,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR,127.0.0.0/8,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR,172.16.0.0/12,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR6,fc00::/7,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR6,fe80::/10,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR,224.0.0.0/4,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR,255.255.255.255/32,DIRECT,no-resolve");

  // Torrents
  ruleSet.add("DST-PORT,6881-6889,DIRECT");
  ruleSet.add("DST-PORT,51413,DIRECT");

  // 2. High-Priority QUIC Blocking
  if (ENABLE_QUIC_BLOCK) {
    ruleSet.add("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT");
  }

  // 3. Security, Phishing, Malware & Threat Intel
  if (ENABLE_HAGEZI_TIF) ruleSet.add("RULE-SET,hagezi-tif,REJECT");
  if (ENABLE_HAGEZI_TIF_MEDIUM) ruleSet.add("RULE-SET,hagezi-tif-medium,REJECT");
  if (ENABLE_HAGEZI_TIF_MINI) ruleSet.add("RULE-SET,hagezi-tif-mini,REJECT");
  if (ENABLE_HAGEZI_TIF_IP) ruleSet.add("RULE-SET,hagezi-tif-ip,REJECT,no-resolve");
  if (ENABLE_HAGEZI_FAKE) ruleSet.add("RULE-SET,hagezi-fake,REJECT");
  if (ENABLE_HAGEZI_BADWARE) ruleSet.add("RULE-SET,hagezi-badware,REJECT");
  if (ENABLE_HAGEZI_DGA7) ruleSet.add("RULE-SET,hagezi-dga7,REJECT");
  if (ENABLE_HAGEZI_DGA14) ruleSet.add("RULE-SET,hagezi-dga14,REJECT");
  if (ENABLE_HAGEZI_DYNDNS) ruleSet.add("RULE-SET,hagezi-dyndns,REJECT");
  if (ENABLE_HAGEZI_SPAM_TLDS) ruleSet.add("RULE-SET,hagezi-spamtlds,REJECT");
  if (ENABLE_HAGEZI_DOH_IP) ruleSet.add("RULE-SET,hagezi-doh-ip,REJECT,no-resolve");

  if (ENABLE_IRAN_SECURITY) {
    ruleSet.add("RULE-SET,iran-all-security,REJECT");
    ruleSet.add("RULE-SET,iran-all-security-ip,REJECT,no-resolve");
  }

  // 4. Content Filtering: Porn, Gambling, Popups, Social, Shorteners
  if (ENABLE_PORN_FILTER) ruleSet.add("RULE-SET,hagezi-nsfw,REJECT");
  if (ENABLE_GAMBLING_FILTER) {
    ruleSet.add("RULE-SET,hagezi-gambling,REJECT");
    ruleSet.add("RULE-SET,iran-modular-gambling,REJECT");
  }
  if (ENABLE_POPUP_ADS) ruleSet.add("RULE-SET,hagezi-popups,REJECT");
  if (ENABLE_SOCIAL_BLOCK) ruleSet.add("RULE-SET,hagezi-social,REJECT");
  if (ENABLE_URL_SHORTENER) ruleSet.add("RULE-SET,hagezi-urlshortener,REJECT");

  // 5. General Ads & Base Trackers
  ruleSet.add("RULE-SET,hagezi-main,REJECT");
  if (ENABLE_IRAN_ADS) ruleSet.add("RULE-SET,iran-all-ads,REJECT");

  // Allow Metrix ONLY for Snapp Passenger app
  ruleSet.add("AND,((DOMAIN-SUFFIX,metrix.ir),(PROCESS-NAME,cab.snapp.passenger)),DIRECT");
  
  // 6. Native OEM & App Telemetry Blockers
  if (ENABLE_TRACKER_APPLE) ruleSet.add("RULE-SET,hagezi-native-apple,REJECT");
  if (ENABLE_TRACKER_MICROSOFT) ruleSet.add("RULE-SET,hagezi-native-microsoft,REJECT");
  if (ENABLE_TRACKER_XIAOMI) ruleSet.add("RULE-SET,hagezi-native-xiaomi,REJECT");
  if (ENABLE_TRACKER_SAMSUNG) ruleSet.add("RULE-SET,hagezi-native-samsung,REJECT");
  if (ENABLE_TRACKER_HUAWEI) ruleSet.add("RULE-SET,hagezi-native-huawei,REJECT");
  if (ENABLE_TRACKER_BBK) {
    ruleSet.add("RULE-SET,hagezi-native-oppo-realme,REJECT");
    ruleSet.add("RULE-SET,hagezi-native-vivo,REJECT");
  }
  if (ENABLE_TRACKER_AMAZON) ruleSet.add("RULE-SET,hagezi-native-amazon,REJECT");
  if (ENABLE_TRACKER_LG) ruleSet.add("RULE-SET,hagezi-native-lg,REJECT");
  if (ENABLE_TRACKER_ROKU) ruleSet.add("RULE-SET,hagezi-native-roku,REJECT");
  if (ENABLE_TRACKER_TIKTOK) ruleSet.add("RULE-SET,hagezi-native-tiktok,REJECT");
  if (ENABLE_TRACKER_TIKTOK_EXT) ruleSet.add("RULE-SET,hagezi-native-tiktok-ext,REJECT");

  // 7. Anti-Piracy
  if (ENABLE_ANTI_PIRACY) ruleSet.add("RULE-SET,hagezi-antipiracy,REJECT");

  // 8. Special Overrides
  ruleSet.add(`DOMAIN-SUFFIX,waze.com,${defaultProxyGroup}`);
  ruleSet.add(`DOMAIN-KEYWORD,waze,${defaultProxyGroup}`);

  // 9. Manual Zero-Delay Domestic Whitelist
  for (let i = 0; i < MANUAL_DOMAINS.length; i++) {
    ruleSet.add(`DOMAIN-SUFFIX,${MANUAL_DOMAINS[i]},DIRECT`);
  }
  ruleSet.add("DOMAIN-SUFFIX,ir,DIRECT");

  // 10. Iran Macro Direct Routing
  if (ENABLE_IRAN_DIRECT) {
    ruleSet.add("RULE-SET,iran-all-apps,DIRECT,no-resolve");
    ruleSet.add("RULE-SET,iran-all-domains,DIRECT");
    ruleSet.add("RULE-SET,iran-all-ip,DIRECT,no-resolve");
    ruleSet.add("RULE-SET,iran-asn,DIRECT,no-resolve");
  }

  // 11. Profile Existing Rules Integration
  const rawRules = config.rules;
  let capturedMatchRule = null;

  if (Array.isArray(rawRules)) {
    for (let i = 0, len = rawRules.length; i < len; i++) {
      const rule = rawRules[i];
      if (typeof rule !== "string" || rule.length === 0) continue;

      let cleanRule = rule.trim();
      if (cleanRule.length === 0) continue;

      if (IP_RULE_PREFIX_REGEX.test(cleanRule) && !NO_RESOLVE_REGEX.test(cleanRule)) {
        cleanRule = `${cleanRule},no-resolve`;
      }

      if (MATCH_RULE_REGEX.test(cleanRule)) {
        if (!capturedMatchRule && !DIRECT_KEYWORD_REGEX.test(cleanRule)) {
          capturedMatchRule = cleanRule;
        }
      } else if (!JUNK_RULES_REGEX.test(cleanRule)) {
        ruleSet.add(cleanRule);
      }
    }
  }

  // 12. Final Fallback Catch-All
  ruleSet.add(capturedMatchRule ?? `MATCH,${defaultProxyGroup}`);
  config.rules = Array.from(ruleSet);

  return config;
}
