// ==============================================================================
// 0. USER CONTROL PANEL (Macro Architecture)
// ==============================================================================

const ENABLE_SAFE_SEARCH = false;       // [Optional] Enforce SafeSearch
const ENABLE_QUIC_BLOCK = true;         // [Recommended] Force TCP fallback to prevent UDP censorship throttling

// Available Tiers: "light" | "normal" | "pro" | "proplus" | "ultimate"
const HAGEZI_TIER = "proplus";

// --- GLOBAL CONTENT & THREAT INTELLIGENCE (Macro Bundles) ---
const ENABLE_HAGEZI_SECURITY_ALL = true; // [Macro] Merges TIF-Mini, Fake, Badware & DynDNS into 1 file
const ENABLE_HAGEZI_SECURITY_IP = true;  // [Macro] Merges TIF-IP & DoH Bypass IPs into 1 file
const ENABLE_HAGEZI_CONTENT_ALL = true;  // [Macro] Merges Adult (NSFW), Gambling & Popups into 1 file

// --- ANTI-PIRACY & COPYRIGHT (Kept Standalone to Prevent Breaking Downloads/Torrents) ---
const ENABLE_ANTI_PIRACY = false;        // [Optional | Standalone] Blocks torrent trackers & warez portals

// --- NATIVE OEM & APP TRACKERS (Device Specific - Lightweight 2KB to 4KB each) ---
// Enable ONLY the brands you or your network devices actually use to prevent RAM bloat:
const ENABLE_TRACKER_SAMSUNG = false;     // Samsung OneUI telemetry
const ENABLE_TRACKER_MICROSOFT = true;  // Windows diagnostic & Cortana telemetry
const ENABLE_TRACKER_XIAOMI = false;     // Xiaomi & HyperOS tracking
const ENABLE_TRACKER_APPLE = false;      // Apple telemetry (Keep false if using iCloud Relay)
const ENABLE_TRACKER_HUAWEI = false;     // Huawei telemetry
const ENABLE_TRACKER_BBK = false;        // Oppo / Realme / Vivo tracking
const ENABLE_TRACKER_AMAZON = false;     // Amazon Echo & FireTV tracking
const ENABLE_TRACKER_LG = false;         // LG Smart TV (webOS) analytics
const ENABLE_TRACKER_ROKU = false;       // Roku streaming media tracking
const ENABLE_TRACKER_TIKTOK = true;      // TikTok analytics & tracker telemetry
const ENABLE_TRACKER_TIKTOK_EXT = false; // Aggressive TikTok tracking (May break app feed)

// Optional Master Switch (If running on a router with dozens of diverse guest devices):
const ENABLE_TRACKER_ALL_OEM = false;    // [Macro] Downloads HageziNativeAll (Not recommended for single phones)

// --- IRAN CORE SUITE (Macro All-In-One) ---
const ENABLE_IRAN_DIRECT = true;         // Master Switch for Domestic Direct Routing
const ENABLE_IRAN_SECURITY = true;       // Iran Phishing, Fake Gateways & Threat IPs
const ENABLE_IRAN_ADS = true;            // Iran Ads & Trackers

const SECURITY_INTERVAL = 36 * 3600;     
const STANDARD_INTERVAL = 72 * 3600;     

// ==============================================================================
// 1. DATASETS & REPOSITORIES (DIRECT GITHUB RELEASES)
// ==============================================================================

const IRAN_RULES_BASE_URL = "https://github.com/Erfan4700/iran-routing-rules/releases/download/latest/";
const HAGEZI_RAW_URL = "https://github.com/Erfan4700/HaGeZi_BlockLists_Compiled_format/releases/download/latest/";

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


const EMERGENCY_MANUAL_DOMAINS = Object.freeze([
  // "custom-local-bank.com",
  // "my-internal-service.ir"
]);

const EMERGENCY_WILDCARDS = Object.freeze(EMERGENCY_MANUAL_DOMAINS.map(d => `+.${d}`));

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
    path: `./ruleset/${name}.${format === "mrs" ? "mrs" : (format === "yaml" ? "yaml" : "txt")}`,
    interval: interval
  };
}

function resolvePrimaryProxyGroup(groups) {
  if (!Array.isArray(groups) || groups.length === 0) return "PROXIES";

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

  return matchedSelectGroup ?? fallbackAutoGroup ?? groups[0]?.name ?? "PROXIES";
}

// ==============================================================================
// 3. MAIN RUNTIME PIPELINE
// ==============================================================================

function main(config, profileName) {
  // --------------------------------------------------------------------------
  // [FIX 1]: Normalize proxy configurations (Strip info nodes & cast string ports)
  // --------------------------------------------------------------------------
  if (Array.isArray(config.proxies)) {
    // Filter out non-functional metadata/informational nodes (traffic balance, expiry, etc.)
    config.proxies = config.proxies.filter(p => {
      if (!p || !p.name) return false;
      return !/(مشخصات|باقی مانده|مصرف|trial|expire|traffic)/i.test(p.name);
    });

    for (let i = 0, len = config.proxies.length; i < len; i++) {
      const p = config.proxies[i];
      if (!p) continue;

      // Robust port validation: convert string to integer and ensure a valid port range
      if (typeof p.port === "string") {
        const parsed = parseInt(p.port, 10);
        if (!Number.isNaN(parsed) && parsed > 0 && parsed <= 65535) {
          p.port = parsed;
        }
      }

      if (p.tls || p["reality-opts"] || p.type === "vless" || p.type === "trojan" || p.type === "hysteria2") {
        p["client-fingerprint"] ??= "chrome";
      }
    }
  }

  // --------------------------------------------------------------------------
  // [FIX 2]: Auto-generate Proxy Groups if the profile input is empty or raw
  // --------------------------------------------------------------------------
  const validProxyNames = Array.isArray(config.proxies) && config.proxies.length > 0
    ? config.proxies.map(p => p.name)
    : ["DIRECT"];

  if (!Array.isArray(config["proxy-groups"]) || config["proxy-groups"].length === 0) {
    config["proxy-groups"] = [
      {
        name: "PROXIES",
        type: "select",
        proxies: ["AUTO", ...validProxyNames]
      },
      {
        name: "AUTO",
        type: "url-test",
        url: "http://www.gstatic.com/generate_204",
        interval: 300,
        tolerance: 50,
        proxies: [...validProxyNames]
      }
    ];
  } else {
    // If the group exists but contains no proxies, link all validated nodes
    const primary = config["proxy-groups"][0];
    if (primary && Array.isArray(primary.proxies) && primary.proxies.length === 0) {
      primary.proxies = validProxyNames;
    }
  }

  const defaultProxyGroup = resolvePrimaryProxyGroup(config["proxy-groups"]);

  config["tcp-concurrent"] = true;
  config["unified-delay"] = true;
  config["find-process-mode"] = "strict";

  delete config["global-client-fingerprint"];

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
      ...EMERGENCY_WILDCARDS
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
    ...EMERGENCY_WILDCARDS,
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
  for (let i = 0; i < EMERGENCY_MANUAL_DOMAINS.length; i++) {
    nsPolicy[`+.${EMERGENCY_MANUAL_DOMAINS[i]}`] = PURE_DOMESTIC_RESOLVERS;
  }
  dns["nameserver-policy"] = Object.assign(dns["nameserver-policy"] ?? {}, nsPolicy);

  // ============================================================================
  // RULE-PROVIDERS DEFINITION
  // ============================================================================
  const providers = {};

  // 1. Global Base Adblock Tier
  providers["hagezi-main"] = makeProvider(
    `hagezi-${HAGEZI_TIER}`, "domain", "mrs",
    `${HAGEZI_RAW_URL}${SELECTED_HAGEZI_NAME}.mrs`, STANDARD_INTERVAL
  );

  // 2. HaGeZi Macro Bundles (General Security & Pure Content)
  if (ENABLE_HAGEZI_SECURITY_ALL) {
    providers["hagezi-security-all"] = makeProvider("HageziSecurityAll", "domain", "mrs", `${HAGEZI_RAW_URL}HageziSecurityAll.mrs`, SECURITY_INTERVAL);
  }
  if (ENABLE_HAGEZI_SECURITY_IP) {
    providers["hagezi-security-ip"] = makeProvider("HageziSecurityIP", "ipcidr", "mrs", `${HAGEZI_RAW_URL}HageziSecurityIP.mrs`, SECURITY_INTERVAL);
  }
  if (ENABLE_HAGEZI_CONTENT_ALL) {
    providers["hagezi-content-all"] = makeProvider("HageziContentAll", "domain", "mrs", `${HAGEZI_RAW_URL}HageziContentAll.mrs`, STANDARD_INTERVAL);
  }

  // 3. Standalone Anti-Piracy (Never merged into Content to protect downloads)
  if (ENABLE_ANTI_PIRACY) {
    providers["hagezi-antipiracy"] = makeProvider("HageziAntiPiracy", "domain", "mrs", `${HAGEZI_RAW_URL}HageziAntiPiracy.mrs`, STANDARD_INTERVAL);
  }

  // 4. Native OEM Trackers (Granular & Zero-Bloat)
  if (ENABLE_TRACKER_ALL_OEM) {
    providers["hagezi-native-all"] = makeProvider("HageziNativeAll", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeAll.mrs`, STANDARD_INTERVAL);
  } else {
    if (ENABLE_TRACKER_SAMSUNG) providers["hagezi-native-samsung"] = makeProvider("HageziNativeSamsung", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeSamsung.mrs`, STANDARD_INTERVAL);
    if (ENABLE_TRACKER_MICROSOFT) providers["hagezi-native-microsoft"] = makeProvider("HageziNativeMicrosoft", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeMicrosoft.mrs`, STANDARD_INTERVAL);
    if (ENABLE_TRACKER_TIKTOK) providers["hagezi-native-tiktok"] = makeProvider("HageziNativeTikTok", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeTikTok.mrs`, STANDARD_INTERVAL);
    if (ENABLE_TRACKER_XIAOMI) providers["hagezi-native-xiaomi"] = makeProvider("HageziNativeXiaomi", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeXiaomi.mrs`, STANDARD_INTERVAL);
    if (ENABLE_TRACKER_APPLE) providers["hagezi-native-apple"] = makeProvider("HageziNativeApple", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeApple.mrs`, STANDARD_INTERVAL);
    if (ENABLE_TRACKER_HUAWEI) providers["hagezi-native-huawei"] = makeProvider("HageziNativeHuawei", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeHuawei.mrs`, STANDARD_INTERVAL);
    if (ENABLE_TRACKER_BBK) providers["hagezi-native-oppo-realme"] = makeProvider("HageziNativeOppoRealme", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeOppoRealme.mrs`, STANDARD_INTERVAL);
    if (ENABLE_TRACKER_AMAZON) providers["hagezi-native-amazon"] = makeProvider("HageziNativeAmazon", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeAmazon.mrs`, STANDARD_INTERVAL);
    if (ENABLE_TRACKER_LG) providers["hagezi-native-lg"] = makeProvider("HageziNativeLGWebOS", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeLGWebOS.mrs`, STANDARD_INTERVAL);
    if (ENABLE_TRACKER_ROKU) providers["hagezi-native-roku"] = makeProvider("HageziNativeRoku", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeRoku.mrs`, STANDARD_INTERVAL);
    if (ENABLE_TRACKER_TIKTOK_EXT) providers["hagezi-native-tiktok-ext"] = makeProvider("HageziNativeTikTokExtended", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeTikTokExtended.mrs`, STANDARD_INTERVAL);
  }

  // 5. Iran Core Macro Suite & Dynamic Exceptions
  if (ENABLE_IRAN_SECURITY) {
    providers["iran-all-security"] = makeProvider("iran-all-security", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-all-security.mrs`, SECURITY_INTERVAL);
    providers["iran-all-security-ip"] = makeProvider("iran-all-security-ip", "ipcidr", "mrs", `${IRAN_RULES_BASE_URL}iran-all-security-ip.mrs`, SECURITY_INTERVAL);
  }
  if (ENABLE_IRAN_ADS) {
    providers["iran-all-ads"] = makeProvider("iran-all-ads", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-all-ads.mrs`, STANDARD_INTERVAL);
  }
  if (ENABLE_IRAN_DIRECT) {
    // استثنائات تحلیلی برنامه‌ها (پیکربندی‌شده در پایتون بدون خطا)
    providers["iran-app-exceptions"] = makeProvider("iran-app-exceptions", "classical", "text", `${IRAN_RULES_BASE_URL}iran-app-exceptions.txt`, STANDARD_INTERVAL);
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

  // 1. Local Network & Private IP Bypass (پوشش کامل RFC1918 توسط رول پیش‌فرض هسته)
  ruleSet.add("GEOIP,private,DIRECT,no-resolve");
  ruleSet.add("DST-PORT,7275,DIRECT");

  // Torrents
  ruleSet.add("DST-PORT,6881-6889,DIRECT");
  ruleSet.add("DST-PORT,51413,DIRECT");

  // 2. High-Priority QUIC Blocking
  if (ENABLE_QUIC_BLOCK) {
    ruleSet.add("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT");
  }

  // 3. Global & Domestic Security (Threat Intelligence)
  if (ENABLE_HAGEZI_SECURITY_ALL) ruleSet.add("RULE-SET,hagezi-security-all,REJECT");
  if (ENABLE_HAGEZI_SECURITY_IP) ruleSet.add("RULE-SET,hagezi-security-ip,REJECT,no-resolve");
  if (ENABLE_IRAN_SECURITY) {
    ruleSet.add("RULE-SET,iran-all-security,REJECT");
    ruleSet.add("RULE-SET,iran-all-security-ip,REJECT,no-resolve");
  }

  // 4. Content Filtering (NSFW / Gambling / Popups)
  if (ENABLE_HAGEZI_CONTENT_ALL) ruleSet.add("RULE-SET,hagezi-content-all,REJECT");

  // 5. Standalone Anti-Piracy
  if (ENABLE_ANTI_PIRACY) ruleSet.add("RULE-SET,hagezi-antipiracy,REJECT");
  
  // --------------------------------------------------------------------------
  // 6. SPECIAL APP EXCEPTIONS (بسیار مهم: قبل از مسدودسازی تبلیغات)
  // متریکس برای اسنپ، تپسی و اسنپ‌فود بدون بلاک شدن مجاز می‌شود
  // --------------------------------------------------------------------------
  if (ENABLE_IRAN_DIRECT) {
    ruleSet.add("RULE-SET,iran-app-exceptions,DIRECT");
  }

  // 7. Base Adblocking & Telemetry
  ruleSet.add("RULE-SET,hagezi-main,REJECT");
  if (ENABLE_IRAN_ADS) ruleSet.add("RULE-SET,iran-all-ads,REJECT");

  // 8. Native OEM Trackers Routing
  if (ENABLE_TRACKER_ALL_OEM) {
    ruleSet.add("RULE-SET,hagezi-native-all,REJECT");
  } else {
    if (ENABLE_TRACKER_SAMSUNG) ruleSet.add("RULE-SET,hagezi-native-samsung,REJECT");
    if (ENABLE_TRACKER_MICROSOFT) ruleSet.add("RULE-SET,hagezi-native-microsoft,REJECT");
    if (ENABLE_TRACKER_TIKTOK) ruleSet.add("RULE-SET,hagezi-native-tiktok,REJECT");
    if (ENABLE_TRACKER_XIAOMI) ruleSet.add("RULE-SET,hagezi-native-xiaomi,REJECT");
    if (ENABLE_TRACKER_APPLE) ruleSet.add("RULE-SET,hagezi-native-apple,REJECT");
    if (ENABLE_TRACKER_HUAWEI) ruleSet.add("RULE-SET,hagezi-native-huawei,REJECT");
    if (ENABLE_TRACKER_BBK) ruleSet.add("RULE-SET,hagezi-native-oppo-realme,REJECT");
    if (ENABLE_TRACKER_AMAZON) ruleSet.add("RULE-SET,hagezi-native-amazon,REJECT");
    if (ENABLE_TRACKER_LG) ruleSet.add("RULE-SET,hagezi-native-lg,REJECT");
    if (ENABLE_TRACKER_ROKU) ruleSet.add("RULE-SET,hagezi-native-roku,REJECT");
    if (ENABLE_TRACKER_TIKTOK_EXT) ruleSet.add("RULE-SET,hagezi-native-tiktok-ext,REJECT");
  }
  
  // 9. Special Domain Overrides
  ruleSet.add(`DOMAIN-SUFFIX,waze.com,${defaultProxyGroup}`);
  ruleSet.add(`DOMAIN-KEYWORD,waze,${defaultProxyGroup}`);

  // 10. Manual Zero-Delay Domestic Whitelist (دامنه‌های روز مبادا در صورت پر بودن لیست)
  for (let i = 0; i < EMERGENCY_MANUAL_DOMAINS.length; i++) {
    ruleSet.add(`DOMAIN-SUFFIX,${EMERGENCY_MANUAL_DOMAINS[i]},DIRECT`);
  }
  ruleSet.add("DOMAIN-SUFFIX,ir,DIRECT");

  // 11. Iran Macro Direct Routing (رول‌ست‌های فوق سریع کامپایل‌شده)
  if (ENABLE_IRAN_DIRECT) {
    ruleSet.add("RULE-SET,iran-all-apps,DIRECT,no-resolve");
    ruleSet.add("RULE-SET,iran-all-domains,DIRECT");
    ruleSet.add("RULE-SET,iran-all-ip,DIRECT,no-resolve");
    ruleSet.add("RULE-SET,iran-asn,DIRECT,no-resolve");
  }

  // 12. Integration of Existing Profile Rules
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

  // 13. Final Fallback Catch-All
  ruleSet.add(capturedMatchRule ?? `MATCH,${defaultProxyGroup}`);
  config.rules = Array.from(ruleSet);

  return config;
}
