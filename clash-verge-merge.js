// ==============================================================================
// 0. USER CONTROL SWITCHES & INTERVALS
// ==============================================================================

// 1. HaGeZi Blocklist & Adblock Tier Selection
// Valid Options: "light" | "normal" | "pro" | "proplus" | "ultimate"
const HAGEZI_TIER = "proplus";

// 2. Enable Real-Time Cyber Defense (TIF - Threat Intelligence Feeds: Malware & Phishing)
const ENABLE_HAGEZI_TIF = true;

// 3. Enforce SafeSearch on Major Search Engines (Google & Bing)
const ENABLE_SAFE_SEARCH = false;

// 4. Automated Update Intervals (in hours)
const SECURITY_UPDATE_HOURS = 24;
const STANDARD_UPDATE_HOURS = 48;
const GEO_UPDATE_HOURS = 72;

const SECURITY_UPDATE_INTERVAL = SECURITY_UPDATE_HOURS * 3600;
const STANDARD_UPDATE_INTERVAL = STANDARD_UPDATE_HOURS * 3600;

// ==============================================================================
// 1. IMMUTABLE DATASETS & SOURCES (Static Allocation Outside Runtime)
// ==============================================================================

// Self-Hosted Autonomous Repositories
const HAGEZI_MRS_URL = "https://cdn.jsdelivr.net/gh/Erfan4700/HaGeZi_BlockLists_mrs_format@release/";
const IRAN_RULES_URL = "https://cdn.jsdelivr.net/gh/Erfan4700/Iran_Clash_Rules_mrs_format@release/";
const METACUBEX_GEO_URL = "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/";

// Static mapping dictionary for HaGeZi tiers
const HAGEZI_TIERS_MAP = Object.freeze({
  light: "HageziLight",
  normal: "HageziNormal",
  pro: "HageziPro",
  proplus: "HageziProPlus",
  ultimate: "HageziUltimate"
});

const SELECTED_HAGEZI_NAME = HAGEZI_TIERS_MAP[HAGEZI_TIER.toLowerCase()] ?? "HageziProPlus";

// Precompiled Regexes for traffic sanitization and automated proxy group extraction
const JUNK_RULES_REGEX = /(?:GEOIP|GEOSITE|RULE-SET),[^,\n]*(?<![a-z0-9])(?:CN|CHINA|RU|RUSSIA)(?![a-z0-9])/i;
const PROXY_KEYWORD_REGEX = /proxy|auto|select|default|نهایی|اینترنت|دستی|انتخاب/i;
const MATCH_RULE_REGEX = /^match(?:,|$)/i;
const DIRECT_KEYWORD_REGEX = /direct/i;
const IP_RULE_PREFIX_REGEX = /^(?:GEOIP|IP-CIDR|IP-CIDR6|IP-ASN),/i;
const NO_RESOLVE_REGEX = /,\s*no-resolve(?:\s*#.*)?$/i;

// Critical domestic domains not covered by the .ir TLD
const MANUAL_DOMAINS = Object.freeze([
  // Transportation & Navigation
  "neshan.org", "rajman.org", "cedarmaps.com", "snapp.cab", "snapp.tax",
  "snappcloud.io", "snapp.supply", "tapsi.cab", "tap33.me", "taximaxim.com",
  // E-Commerce & Classifieds
  "torob.com", "divarcdn.com", "digikala.com",
  // Domestic Media & Download CDNs
  "dl150m.info", "dl175m.info", "linkulu.com", "film2media.cam",
  // Cryptocurrency Exchanges & Payment Gateways
  "zarinpal.com", "zarin.link", "payping.net", "ramzinex.com", "abantether.com",
  "nobitex.net", "exir.io", "wallex.net"
]);

const MANUAL_WILDCARDS = Object.freeze(MANUAL_DOMAINS.map(d => `+.${d}`));

// Static host mapping for SafeSearch enforcement
const FROZEN_HOSTS = Object.freeze({
  "forcesafesearch.google.com": "216.239.38.120",
  "www.google.com": "216.239.38.120",
  "google.com": "216.239.38.120",
  "strict.bing.com": "204.79.197.220",
  "www.bing.com": "204.79.197.220",
  "bing.com": "204.79.197.220"
});

// Pure domestic DNS resolvers (Iran)
const PURE_DOMESTIC_RESOLVERS = Object.freeze([
  "193.186.32.32",
  "217.218.127.127",
  "217.218.155.155"
]);

// Anti-poisoning DNS pool for proxy handshake resolution
const UNPOISONED_PROXY_RESOLVERS = Object.freeze([
  "https://223.5.5.5/dns-query",
  "223.5.5.5",
  "119.29.29.29",
  "193.186.32.32"
]);

// Bootstrap DNS resolvers
const HYBRID_BOOTSTRAP_RESOLVERS = Object.freeze([
  "223.5.5.5",
  "119.29.29.29",
  "193.186.32.32"
]);

// Encrypted international DoH endpoints routed through the proxy tunnel
const DOH_ENDPOINTS = Object.freeze([
  "https://1.1.1.1/dns-query",
  "https://8.8.8.8/dns-query",
  "https://9.9.9.9/dns-query"
]);

// Precompiled Binary MRS Rule-Providers (All Self-Hosted)
const PRECOMPILED_PROVIDERS = Object.freeze({
  // Global Protection (HaGeZi Repository)
  "hagezi-main": Object.freeze({
    type: "http",
    behavior: "domain",
    format: "mrs",
    url: `${HAGEZI_MRS_URL}${SELECTED_HAGEZI_NAME}.mrs`,
    path: `./ruleset/${SELECTED_HAGEZI_NAME}.mrs`,
    interval: STANDARD_UPDATE_INTERVAL
  }),
  ...(ENABLE_HAGEZI_TIF ? {
    "hagezi-tif": Object.freeze({
      type: "http",
      behavior: "domain",
      format: "mrs",
      url: `${HAGEZI_MRS_URL}HageziTIF.mrs`,
      path: "./ruleset/HageziTIF.mrs",
      interval: SECURITY_UPDATE_INTERVAL
    })
  } : {}),

  // Regional Iran Protection & Routing (Iran Rules Repository)
  "ads-ir": Object.freeze({
    type: "http",
    behavior: "domain",
    format: "mrs",
    url: `${IRAN_RULES_URL}ads.mrs`,
    path: "./ruleset/ads.mrs",
    interval: STANDARD_UPDATE_INTERVAL
  }),
  "phishing-ir": Object.freeze({
    type: "http",
    behavior: "domain",
    format: "mrs",
    url: `${IRAN_RULES_URL}phishing.mrs`,
    path: "./ruleset/phishing.mrs",
    interval: SECURITY_UPDATE_INTERVAL
  }),
  "ir": Object.freeze({
    type: "http",
    behavior: "domain",
    format: "mrs",
    url: `${IRAN_RULES_URL}ir.mrs`,
    path: "./ruleset/ir.mrs",
    interval: STANDARD_UPDATE_INTERVAL
  }),
  "ircidr": Object.freeze({
    type: "http",
    behavior: "ipcidr",
    format: "mrs",
    url: `${IRAN_RULES_URL}ircidr.mrs`,
    path: "./ruleset/ircidr.mrs",
    interval: STANDARD_UPDATE_INTERVAL
  }),
  "irasn": Object.freeze({
    type: "http",
    behavior: "classical",
    format: "text",
    url: `${IRAN_RULES_URL}irasn.txt`,
    path: "./ruleset/irasn.txt",
    interval: STANDARD_UPDATE_INTERVAL
  })
});

// Nameserver Policy: Route domestic queries strictly to domestic resolvers
const PRECOMPILED_NS_POLICY = Object.freeze(
  MANUAL_DOMAINS.reduce((acc, domain) => {
    acc[`+.${domain}`] = PURE_DOMESTIC_RESOLVERS;
    return acc;
  }, {
    "+.ir": PURE_DOMESTIC_RESOLVERS,
    "rule-set:ir": PURE_DOMESTIC_RESOLVERS,
    "supl.google.com": PURE_DOMESTIC_RESOLVERS,
    "+.supl.google.com": PURE_DOMESTIC_RESOLVERS
  })
);

// Fake-IP Filter (Bypasses Captive Portals, NTP, Gaming CDNs, & Domestic TLDs)
const FROZEN_FAKE_IP_FILTER = Object.freeze([
  "+.ir",
  "rule-set:ir",
  ...MANUAL_WILDCARDS,
  "+.lan", "+.local", "+.home.arpa",
  "captive.apple.com", "+.connectivitycheck.gstatic.com",
  "detectportal.firefox.com", "+.msftconnecttest.com", "+.msftncsi.com",
  "time.apple.com", "time.google.com", "time.windows.com", "time.nist.gov",
  "+.pool.ntp.org", "+.ntp.org",
  "+.steamcontent.com", "+.battlenet.com", "+.battle.net", "+.ea.com",
  "stun.*", "*.stun.*", "supl.google.com", "+.supl.google.com",
  "location.services.mozilla.com"
]);

// Official MetaCubeX GeoIP Engine
const FROZEN_GEOX_URL = Object.freeze({
  geoip: `${METACUBEX_GEO_URL}geoip.metadb`,
  mmdb: `${METACUBEX_GEO_URL}geoip.metadb`
});

// Streamlined & Stable Sniffer Configuration
const FROZEN_SNIFFER_CONFIG = Object.freeze({
  enable: true,
  "force-dns-mapping": true,
  "parse-pure-ip": true,
  "override-destination": false,
  sniff: Object.freeze({
    TLS: Object.freeze({ ports: Object.freeze([443, 8443, 2053, 2083, 2087, 2096]) }),
    HTTP: Object.freeze({ ports: Object.freeze([80, 8080, 8880]) })
  }),
  "skip-dst-address": Object.freeze([
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
  ]),
  "skip-domain": Object.freeze([
    "Mijia Cloud", "+.push.apple.com", "+.apple.com",
    "+.lan", "+.local", "+.home.arpa", "+.ir",
    ...MANUAL_WILDCARDS
  ])
});

// Immutable Core Routing Rules (Optimized for Zero GC Allocation)
const STATIC_CORE_RULES = Object.freeze([
  // 1. Local Network, Multicast, & A-GPS Geolocation
  "DST-PORT,7275,DIRECT",
  "GEOIP,private,DIRECT,no-resolve",
  "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
  "IP-CIDR,255.255.255.255/32,DIRECT,no-resolve",

  // 2. Peer-to-Peer / BitTorrent Ports
  "DST-PORT,6881-6889,DIRECT",
  "DST-PORT,51413,DIRECT",

  // 3. Global Threat Protection (HaGeZi)
  "RULE-SET,hagezi-main,REJECT",
  ...(ENABLE_HAGEZI_TIF ? ["RULE-SET,hagezi-tif,REJECT"] : []),

  // 4. Regional Ads & Domestic Phishing (Self-Hosted Iran Engine)
  "RULE-SET,ads-ir,REJECT",
  "RULE-SET,phishing-ir,REJECT",

  // 5. Direct Domestic Traffic (Manual Domains, National TLD, CIDRs, & ASNs)
  ...MANUAL_DOMAINS.map(d => `DOMAIN-SUFFIX,${d},DIRECT`),
  "DOMAIN-SUFFIX,ir,DIRECT",
  "RULE-SET,ir,DIRECT",
  "RULE-SET,ircidr,DIRECT,no-resolve",
  "RULE-SET,irasn,DIRECT,no-resolve",
  "GEOIP,IR,DIRECT,no-resolve",

  // 6. Block QUIC (UDP/443) to Prevent Censorship Throttling
  "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"
]);

// ==============================================================================
// 2. HELPER FUNCTIONS
// ==============================================================================

function resolvePrimaryProxyGroup(groups) {
  if (!Array.isArray(groups) || groups.length === 0) return "PROXY";

  let matchedSelectGroup = null;
  let fallbackAutoGroup = null;

  for (let i = 0, len = groups.length; i < len; i++) {
    const group = groups[i];
    if (!group) continue;
    const { type, name } = group;

    const isMatch = PROXY_KEYWORD_REGEX.test(name);
    if (type === "select" && isMatch) {
      return name;
    }
    if (!matchedSelectGroup && isMatch) {
      matchedSelectGroup = name;
    }
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

  config["geodata-mode"] = false;
  config["geo-auto-update"] = true;
  config["geo-update-interval"] = GEO_UPDATE_HOURS;
  config["geox-url"] = FROZEN_GEOX_URL;
  config["keep-alive-idle"] = 600;
  config["keep-alive-interval"] = 15;

  (config.experimental ??= {})["quic-go-disable-ecn"] = true;

  const profile = (config.profile ??= {});
  profile["store-fake-ip"] = true;
  profile["store-selected"] = true;

  config.sniffer = FROZEN_SNIFFER_CONFIG;

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
  dns["fake-ip-filter"] = FROZEN_FAKE_IP_FILTER;

  dns.nameserver = DOH_ENDPOINTS.map(url => `${url}#${defaultProxyGroup}`);

  Object.assign((dns["nameserver-policy"] ??= {}), PRECOMPILED_NS_POLICY);
  Object.assign((config["rule-providers"] ??= {}), PRECOMPILED_PROVIDERS);

  const ruleSet = new Set(STATIC_CORE_RULES);
  
  // Route Waze Navigation directly through the primary proxy tunnel
  ruleSet.add(`DOMAIN-SUFFIX,waze.com,${defaultProxyGroup}`);
  ruleSet.add(`DOMAIN-KEYWORD,waze,${defaultProxyGroup}`);

  const rawRules = config.rules;
  let capturedMatchRule = null;

  if (Array.isArray(rawRules)) {
    for (let i = 0, len = rawRules.length; i < len; i++) {
      const rule = rawRules[i];
      if (typeof rule !== "string" || rule.length === 0) continue;

      const firstChar = rule.charCodeAt(0);
      const lastChar = rule.charCodeAt(rule.length - 1);
      let cleanRule = (firstChar <= 32 || lastChar <= 32) ? rule.trim() : rule;

      if (cleanRule.length === 0) continue;

      // Automatically append 'no-resolve' to all IP/ASN based rules to prevent DNS leaks
      if (IP_RULE_PREFIX_REGEX.test(cleanRule) && !NO_RESOLVE_REGEX.test(cleanRule)) {
        cleanRule = `${cleanRule},no-resolve`;
      }

      const c0 = cleanRule.charCodeAt(0);
      if ((c0 === 77 || c0 === 109) && MATCH_RULE_REGEX.test(cleanRule)) {
        if (!capturedMatchRule && !DIRECT_KEYWORD_REGEX.test(cleanRule)) {
          capturedMatchRule = cleanRule;
        }
      } else if (!JUNK_RULES_REGEX.test(cleanRule)) {
        ruleSet.add(cleanRule);
      }
    }
  }

  ruleSet.add(capturedMatchRule ?? `MATCH,${defaultProxyGroup}`);
  config.rules = Array.from(ruleSet);

  return config;
}
