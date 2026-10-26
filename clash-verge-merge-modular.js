// ==============================================================================
// 0. USER CONTROL PANEL (MODULAR PRO DIRECT GITHUB EDITION)
// ==============================================================================

const ENABLE_SAFE_SEARCH = false;
const ENABLE_QUIC_BLOCK = true;

// "light" | "normal" | "pro" | "proplus" | "ultimate"
const HAGEZI_TIER = "proplus";

// --- GLOBAL CONTENT BLOCKING (NOT IN PROPLUS - HIGHLY RECOMMENDED) ---
const ENABLE_PORN_FILTER = true;        // HaGeZi NSFW (100% Global Adult Content)
const ENABLE_GAMBLING_FILTER = true;    // HaGeZi Global Gambling + Iran Betting/Casinos
const ENABLE_POPUP_ADS = false;         // Optional (Most are already inside ProPlus)

// --- ADVANCED THREAT INTELLIGENCE & SECURITY ---
const ENABLE_HAGEZI_TIF = false;         // Threat Intelligence Feeds (Domains - 12MB RAM)
const ENABLE_HAGEZI_TIF_IP = true;      // Threat Intelligence Feeds (IP-CIDR - Must Have)
const ENABLE_HAGEZI_FAKE = false;       // Optional (Partially inside ProPlus)
const ENABLE_HAGEZI_BADWARE = false;    // Optional (Partially inside ProPlus)

// --- NATIVE OEM TRACKERS (NOT IN PROPLUS - MUST ENABLE MANUALLY) ---
const ENABLE_TRACKER_XIAOMI = true;     // Xiaomi / Redmi MIUI & HyperOS Telemetry
const ENABLE_TRACKER_SAMSUNG = true;    // Samsung OneUI Telemetry
const ENABLE_TRACKER_APPLE = true;      // Apple iOS / macOS Telemetry
const ENABLE_TRACKER_MICROSOFT = true;  // Windows Telemetry
const ENABLE_TRACKER_HUAWEI = false;     // Huawei EMUI / HarmonyOS Telemetry
const ENABLE_TRACKER_BBK = false;       // Oppo / Realme / Vivo Telemetry

// --- ANTI-PIRACY & COPYRIGHT ---
const ENABLE_ANTI_PIRACY = false;

// --- IRAN MODULAR SUB-CATEGORIES (ALL DISJOINT / ZERO OVERLAP) ---
const ENABLE_IRAN_ADS = true;          // Iran Ads & Trackers
const ENABLE_IRAN_SECURITY = true;     // Iran Phishing, Fake Gateways & Malware
const ENABLE_IRAN_DIRECT = true;       // Master Switch for Domestic Direct Routing

const ENABLE_MODULAR_BANKING = true;
const ENABLE_MODULAR_GOV = true;
const ENABLE_MODULAR_MEDIA = true;
const ENABLE_MODULAR_GAMING = true;
const ENABLE_MODULAR_DOWNLOAD = true;
const ENABLE_MODULAR_OTHER = true;
const ENABLE_MODULAR_ISP = true;
const ENABLE_MODULAR_CLOUD = true;
const ENABLE_MODULAR_APPS = true;

const SECURITY_INTERVAL = 24 * 3600;   
const STANDARD_INTERVAL = 48 * 3600;   

// ==============================================================================
// 1. DATASETS & REPOSITORIES (DIRECT GITHUB RAW - ZERO CDN CACHE LAG)
// ==============================================================================

// 1. Official Repository Direct Raw: Erfan4700/iran-routing-rules
const IRAN_RULES_BASE_URL = "https://raw.githubusercontent.com/Erfan4700/iran-routing-rules/release/";

// 2. Official Global Adblock Direct Raw: MiHomoer/MiHomo-Hagezi
const HAGEZI_RAW_URL = "https://raw.githubusercontent.com/MiHomoer/MiHomo-Hagezi/release/";

const HAGEZI_TIERS_MAP = Object.freeze({
  light: "HageziLight",
  normal: "HageziNormal",
  pro: "HageziPro",
  proplus: "HageziProPlus",
  ultimate: "HageziUltimate"
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
  config["find-process-mode"] = "off";

  delete config["global-client-fingerprint"];

  if (Array.isArray(config.proxies)) {
    for (let i = 0, len = config.proxies.length; i < len; i++) {
      const p = config.proxies[i];
      if (p && (p.tls || p["reality-opts"] || p.type === "vless" || p.type === "trojan" || p.type === "hysteria2")) {
        p["client-fingerprint"] ??= "chrome";
      }
    }
  }

  // Bypass heavy GeoIP/GeoSite databases to save RAM and Network bandwidth
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

  // Ultra-Fast Fake-IP Filter using Modular Sets & Core Manual Domains
  dns["fake-ip-filter"] = [
    "+.ir",
    "rule-set:iran-modular-banking",
    "rule-set:iran-modular-gov",
    "rule-set:iran-modular-media",
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

  dns.nameserver = DOH_ENDPOINTS.map(url => `${url}#${defaultProxyGroup}`);

  const nsPolicy = {
    "+.ir": PURE_DOMESTIC_RESOLVERS,
    "rule-set:iran-modular-banking": PURE_DOMESTIC_RESOLVERS,
    "rule-set:iran-modular-gov": PURE_DOMESTIC_RESOLVERS,
    "rule-set:iran-modular-media": PURE_DOMESTIC_RESOLVERS,
    "supl.google.com": PURE_DOMESTIC_RESOLVERS,
    "+.supl.google.com": PURE_DOMESTIC_RESOLVERS
  };
  for (let i = 0; i < MANUAL_DOMAINS.length; i++) {
    nsPolicy[`+.${MANUAL_DOMAINS[i]}`] = PURE_DOMESTIC_RESOLVERS;
  }
  dns["nameserver-policy"] = Object.assign(dns["nameserver-policy"] ?? {}, nsPolicy);

  // ============================================================================
  // RULE-PROVIDERS DEFINITION (DIRECT GITHUB RAW)
  // ============================================================================
  const providers = {};

  // 1. Global Base Adblock (HaGeZi Tier)
  providers["hagezi-main"] = makeProvider(
    `hagezi-${HAGEZI_TIER}`, "domain", "mrs",
    `${HAGEZI_RAW_URL}${SELECTED_HAGEZI_NAME}.mrs`, STANDARD_INTERVAL
  );

  // 2. Global Threat Intelligence & Security
  if (ENABLE_HAGEZI_TIF) {
    providers["hagezi-tif"] = makeProvider("HageziTIF", "domain", "mrs", `${HAGEZI_RAW_URL}HageziTIF.mrs`, SECURITY_INTERVAL);
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

  // 3. Global Porn & Adult Content Block
  if (ENABLE_PORN_FILTER) {
    providers["hagezi-nsfw"] = makeProvider("HageziNSFW", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNSFW.mrs`, STANDARD_INTERVAL);
  }

  // 4. Global & Domestic Gambling Block
  if (ENABLE_GAMBLING_FILTER) {
    providers["hagezi-gambling"] = makeProvider("HageziGamblingMedium", "domain", "mrs", `${HAGEZI_RAW_URL}HageziGamblingMedium.mrs`, STANDARD_INTERVAL);
    providers["iran-modular-gambling"] = makeProvider("iran-modular-gambling", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-modular-gambling.mrs`, STANDARD_INTERVAL);
  }

  // 5. Pop-up Ads
  if (ENABLE_POPUP_ADS) {
    providers["hagezi-popups"] = makeProvider("HageziPopUpAds", "domain", "mrs", `${HAGEZI_RAW_URL}HageziPopUpAds.mrs`, STANDARD_INTERVAL);
  }

  // 6. Native Telemetry Trackers
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

  // 7. Anti-Piracy (Optional)
  if (ENABLE_ANTI_PIRACY) {
    providers["hagezi-antipiracy"] = makeProvider("HageziAntiPiracy", "domain", "mrs", `${HAGEZI_RAW_URL}HageziAntiPiracy.mrs`, STANDARD_INTERVAL);
  }

  // 8. Iran Domestic Ads & Security (Your Repo)
  if (ENABLE_IRAN_ADS) {
    providers["iran-all-ads"] = makeProvider("iran-all-ads", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-all-ads.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_IRAN_SECURITY) {
    providers["iran-all-security"] = makeProvider("iran-all-security", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-all-security.mrs`, SECURITY_INTERVAL);
    providers["iran-all-security-ip"] = makeProvider("iran-all-security-ip", "ipcidr", "mrs", `${IRAN_RULES_BASE_URL}iran-all-security-ip.mrs`, SECURITY_INTERVAL);
  }

  // 9. Iran Modular Sub-Categories (Your Repo)
  if (ENABLE_IRAN_DIRECT) {
    if (ENABLE_MODULAR_BANKING) {
      providers["iran-modular-banking"] = makeProvider("iran-modular-banking", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-modular-banking.mrs`, STANDARD_INTERVAL);
    }
    if (ENABLE_MODULAR_GOV) {
      providers["iran-modular-gov"] = makeProvider("iran-modular-gov", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-modular-gov.mrs`, STANDARD_INTERVAL);
    }
    if (ENABLE_MODULAR_MEDIA) {
      providers["iran-modular-media"] = makeProvider("iran-modular-media", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-modular-media.mrs`, STANDARD_INTERVAL);
    }
    if (ENABLE_MODULAR_GAMING) {
      providers["iran-modular-gaming"] = makeProvider("iran-modular-gaming", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-modular-gaming.mrs`, STANDARD_INTERVAL);
    }
    if (ENABLE_MODULAR_DOWNLOAD) {
      providers["iran-modular-download"] = makeProvider("iran-modular-download", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-modular-download.mrs`, STANDARD_INTERVAL);
    }
    if (ENABLE_MODULAR_OTHER) {
      providers["iran-modular-other"] = makeProvider("iran-modular-other", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-modular-other.mrs`, STANDARD_INTERVAL);
    }
    if (ENABLE_MODULAR_ISP) {
      providers["iran-modular-isp"] = makeProvider("iran-modular-isp", "ipcidr", "mrs", `${IRAN_RULES_BASE_URL}iran-modular-isp.mrs`, STANDARD_INTERVAL);
    }
    if (ENABLE_MODULAR_CLOUD) {
      providers["iran-modular-cloud"] = makeProvider("iran-modular-cloud", "ipcidr", "mrs", `${IRAN_RULES_BASE_URL}iran-modular-cloud.mrs`, STANDARD_INTERVAL);
    }
    if (ENABLE_MODULAR_APPS) {
      providers["iran-all-apps"] = makeProvider("iran-all-apps", "classical", "text", `${IRAN_RULES_BASE_URL}iran-all-apps.txt`, STANDARD_INTERVAL);
    }
    providers["iran-asn"] = makeProvider("iran-asn", "classical", "text", `${IRAN_RULES_BASE_URL}iran-asn.txt`, STANDARD_INTERVAL);
  }

  config["rule-providers"] = Object.assign(config["rule-providers"] ?? {}, providers);

  // ============================================================================
  // RULES EVALUATION PIPELINE (TOP-TO-BOTTOM OPTIMIZED ORDER)
  // ============================================================================
  const ruleSet = new Set();

  // 1. Essential Local Network & Private IP Bypass (Direct)
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

  // Torrent Clients
  ruleSet.add("DST-PORT,6881-6889,DIRECT");
  ruleSet.add("DST-PORT,51413,DIRECT");

  // 2. High-Priority QUIC Blocking (Immediate Fallback to TLS/TCP)
  if (ENABLE_QUIC_BLOCK) {
    ruleSet.add("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT");
  }

  // 3. Security, Phishing, Malware & Threat Intel (Zero-Trust Top Priority)
  if (ENABLE_HAGEZI_TIF) ruleSet.add("RULE-SET,hagezi-tif,REJECT");
  if (ENABLE_HAGEZI_TIF_IP) ruleSet.add("RULE-SET,hagezi-tif-ip,REJECT,no-resolve");
  if (ENABLE_HAGEZI_FAKE) ruleSet.add("RULE-SET,hagezi-fake,REJECT");
  if (ENABLE_HAGEZI_BADWARE) ruleSet.add("RULE-SET,hagezi-badware,REJECT");

  if (ENABLE_IRAN_SECURITY) {
    ruleSet.add("RULE-SET,iran-all-security,REJECT");
    ruleSet.add("RULE-SET,iran-all-security-ip,REJECT,no-resolve");
  }

  // 4. Content Filtering: Porn, Gambling & Pop-ups
  if (ENABLE_PORN_FILTER) ruleSet.add("RULE-SET,hagezi-nsfw,REJECT");
  if (ENABLE_GAMBLING_FILTER) {
    ruleSet.add("RULE-SET,hagezi-gambling,REJECT");
    ruleSet.add("RULE-SET,iran-modular-gambling,REJECT");
  }
  if (ENABLE_POPUP_ADS) ruleSet.add("RULE-SET,hagezi-popups,REJECT");

  // 5. General Ads & Base Trackers
  ruleSet.add("RULE-SET,hagezi-main,REJECT");
  if (ENABLE_IRAN_ADS) ruleSet.add("RULE-SET,iran-all-ads,REJECT");

  // 6. Native OEM Telemetry Blockers
  if (ENABLE_TRACKER_APPLE) ruleSet.add("RULE-SET,hagezi-native-apple,REJECT");
  if (ENABLE_TRACKER_MICROSOFT) ruleSet.add("RULE-SET,hagezi-native-microsoft,REJECT");
  if (ENABLE_TRACKER_XIAOMI) ruleSet.add("RULE-SET,hagezi-native-xiaomi,REJECT");
  if (ENABLE_TRACKER_SAMSUNG) ruleSet.add("RULE-SET,hagezi-native-samsung,REJECT");
  if (ENABLE_TRACKER_HUAWEI) ruleSet.add("RULE-SET,hagezi-native-huawei,REJECT");
  if (ENABLE_TRACKER_BBK) {
    ruleSet.add("RULE-SET,hagezi-native-oppo-realme,REJECT");
    ruleSet.add("RULE-SET,hagezi-native-vivo,REJECT");
  }

  // 7. Anti-Piracy (Optional)
  if (ENABLE_ANTI_PIRACY) ruleSet.add("RULE-SET,hagezi-antipiracy,REJECT");

  // 8. Special Domain Overrides
  ruleSet.add(`DOMAIN-SUFFIX,waze.com,${defaultProxyGroup}`);
  ruleSet.add(`DOMAIN-KEYWORD,waze,${defaultProxyGroup}`);

  // 9. Manual Zero-Delay Domestic Whitelist
  for (let i = 0; i < MANUAL_DOMAINS.length; i++) {
    ruleSet.add(`DOMAIN-SUFFIX,${MANUAL_DOMAINS[i]},DIRECT`);
  }
  ruleSet.add("DOMAIN-SUFFIX,ir,DIRECT");

  // 10. Iran Modular Direct Routing (Zero-Loss / Zero-Overlap)
  if (ENABLE_IRAN_DIRECT) {
    if (ENABLE_MODULAR_APPS) ruleSet.add("RULE-SET,iran-all-apps,DIRECT,no-resolve");
    if (ENABLE_MODULAR_BANKING) ruleSet.add("RULE-SET,iran-modular-banking,DIRECT");
    if (ENABLE_MODULAR_GOV) ruleSet.add("RULE-SET,iran-modular-gov,DIRECT");
    if (ENABLE_MODULAR_MEDIA) ruleSet.add("RULE-SET,iran-modular-media,DIRECT");
    if (ENABLE_MODULAR_GAMING) ruleSet.add("RULE-SET,iran-modular-gaming,DIRECT");
    if (ENABLE_MODULAR_DOWNLOAD) ruleSet.add("RULE-SET,iran-modular-download,DIRECT");
    if (ENABLE_MODULAR_OTHER) ruleSet.add("RULE-SET,iran-modular-other,DIRECT");
    if (ENABLE_MODULAR_CLOUD) ruleSet.add("RULE-SET,iran-modular-cloud,DIRECT,no-resolve");
    if (ENABLE_MODULAR_ISP) ruleSet.add("RULE-SET,iran-modular-isp,DIRECT,no-resolve");
    ruleSet.add("RULE-SET,iran-asn,DIRECT,no-resolve");
  }

  // 11. Integration of Existing Profile Rules (Sanitized)
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
