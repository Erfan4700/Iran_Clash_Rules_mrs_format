// ==============================================================================
// 0. USER CONTROL PANEL (MODULAR DIRECT GITHUB EDITION)
// ==============================================================================

const ENABLE_SAFE_SEARCH = false;
const ENABLE_QUIC_BLOCK = true;

// "light" | "normal" | "pro" | "proplus" | "ultimate"
const HAGEZI_TIER = "proplus";
const ENABLE_HAGEZI_TIF = false;        // HaGeZi Threat Intelligence Feeds (Active)
const ENABLE_NATIVE_TRACKERS = true;   // Apple & Windows Telemetry Trackers

const ENABLE_IRAN_ADS = true;          // Iran Domestic Ads & Trackers
const ENABLE_IRAN_SECURITY = true;     // Iran Phishing, Fake Gateways & Malware
const ENABLE_GAMBLING_FILTER = true;   // Iran Gambling & Betting Filter
const ENABLE_IRAN_DIRECT = true;       // Master Switch for Domestic Direct Routing

// Modular Iran Sub-Categories (All Disjoint / Zero Overlap)
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
const HAGEZI_MRS_URL = "https://raw.githubusercontent.com/MiHomoer/MiHomo-Hagezi/release/";

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

  // Pure Rule-Provider Mode: We bypass heavy GeoIP/GeoSite databases to save RAM and Network bandwidth
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

  // 1. Global Adblock / Trackers (Hagezi via Direct GitHub Raw)
  providers["hagezi-main"] = makeProvider(
    `hagezi-${HAGEZI_TIER}`, "domain", "mrs",
    `${HAGEZI_MRS_URL}${SELECTED_HAGEZI_NAME}.mrs`, STANDARD_INTERVAL
  );

  if (ENABLE_HAGEZI_TIF) {
    providers["hagezi-tif"] = makeProvider("HageziTIF", "domain", "mrs", `${HAGEZI_MRS_URL}HageziTIF.mrs`, SECURITY_INTERVAL);
  }

  if (ENABLE_NATIVE_TRACKERS) {
    providers["hagezi-apple"] = makeProvider("HageziApple", "domain", "mrs", `${HAGEZI_MRS_URL}HageziApple.mrs`, STANDARD_INTERVAL);
    providers["hagezi-windows"] = makeProvider("HageziWindows", "domain", "mrs", `${HAGEZI_MRS_URL}HageziWindows.mrs`, STANDARD_INTERVAL);
  }

  // 2. Iran Domestic Ads (via Direct GitHub Raw)
  if (ENABLE_IRAN_ADS) {
    providers["iran-all-ads"] = makeProvider("iran-all-ads", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-all-ads.mrs`, STANDARD_INTERVAL);
  }

  // 3. Iran Domestic Security: Phishing & Malware (via Direct GitHub Raw)
  if (ENABLE_IRAN_SECURITY) {
    providers["iran-all-security"] = makeProvider("iran-all-security", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-all-security.mrs`, SECURITY_INTERVAL);
    providers["iran-all-security-ip"] = makeProvider("iran-all-security-ip", "ipcidr", "mrs", `${IRAN_RULES_BASE_URL}iran-all-security-ip.mrs`, SECURITY_INTERVAL);
  }

  // 4. Iran Gambling Filter (via Direct GitHub Raw)
  if (ENABLE_GAMBLING_FILTER) {
    providers["iran-modular-gambling"] = makeProvider("iran-modular-gambling", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-modular-gambling.mrs`, STANDARD_INTERVAL);
  }

  // 5. Iran Modular Sub-Categories (via Direct GitHub Raw)
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
  if (ENABLE_HAGEZI_TIF) {
    ruleSet.add("RULE-SET,hagezi-tif,REJECT");
  }

  if (ENABLE_IRAN_SECURITY) {
    ruleSet.add("RULE-SET,iran-all-security,REJECT");
    ruleSet.add("RULE-SET,iran-all-security-ip,REJECT,no-resolve");
  }

  // 4. Ads & Trackers Blocking
  ruleSet.add("RULE-SET,hagezi-main,REJECT");
  if (ENABLE_IRAN_ADS) ruleSet.add("RULE-SET,iran-all-ads,REJECT");
  if (ENABLE_GAMBLING_FILTER) ruleSet.add("RULE-SET,iran-modular-gambling,REJECT");

  if (ENABLE_NATIVE_TRACKERS) {
    ruleSet.add("RULE-SET,hagezi-apple,REJECT");
    ruleSet.add("RULE-SET,hagezi-windows,REJECT");
  }

  // 5. Special Domain Overrides
  ruleSet.add(`DOMAIN-SUFFIX,waze.com,${defaultProxyGroup}`);
  ruleSet.add(`DOMAIN-KEYWORD,waze,${defaultProxyGroup}`);

  // 6. Manual Zero-Delay Domestic Whitelist
  for (let i = 0; i < MANUAL_DOMAINS.length; i++) {
    ruleSet.add(`DOMAIN-SUFFIX,${MANUAL_DOMAINS[i]},DIRECT`);
  }
  ruleSet.add("DOMAIN-SUFFIX,ir,DIRECT");

  // 7. Iran Modular Direct Routing (Zero-Loss / Zero-Overlap)
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

  // 8. Integration of Existing Profile Rules (Sanitized)
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

  // 9. Final Fallback Catch-All
  ruleSet.add(capturedMatchRule ?? `MATCH,${defaultProxyGroup}`);
  config.rules = Array.from(ruleSet);

  return config;
}
