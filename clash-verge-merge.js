// ==============================================================================
// 0. CONTROL PANEL & CONFIGURATION MODULES
// ==============================================================================

const ENABLE_SAFE_SEARCH = false;
const ENABLE_QUIC_BLOCK = true;

// --- [A] Global HaGeZi Security & Ad-blocking Tiers ---
const HAGEZI_TIER = "proplus"; // Options: "light" | "normal" | "pro" | "proplus" | "ultimate"
const ENABLE_HAGEZI_TIF = true; // Real-time Threat Intelligence Feeds (Malware & Ransomware)
const ENABLE_DYNDNS_BLOCK = true; // Block Dynamic DNS domains
const ENABLE_NATIVE_TRACKERS = true; // Block native telemetry (Windows, Apple, Xiaomi, Android)
const ENABLE_PORN_FILTER = true; // Adult / NSFW content filtering
const ENABLE_GAMBLING_FILTER = true; // Block global betting and gambling platforms

// --- [B] Domestic Iran Security & Advertising Modules ---
const ENABLE_IRAN_ADS = true; // Persian advertising networks (Yektanet, Sabavision, etc.)
const ENABLE_IRAN_SECURITY = true; // Domestic phishing gateways and local malicious hosts
const ENABLE_IRAN_GAMBLING = true; // Iranian betting and unauthorized casino websites

// --- [C] Modular Direct Routing for Iranian Traffic (Bypasses Proxy) ---
const ENABLE_IRAN_MEDIA = true; // Aparat, Filimo, Telewebion, and domestic streaming
const ENABLE_IRAN_BANKING = true; // Banks, Shaparak network, crypto exchanges, stock market
const ENABLE_IRAN_GOV = true; // Government, judicial, and public service portals
const ENABLE_IRAN_GAMING = true; // Domestic gaming nodes and low-latency servers
const ENABLE_IRAN_DOWNLOAD = true; // Domestic software repositories and Linux mirrors
const ENABLE_IRAN_OTHER = true; // Remaining uncategorized national domain registry

// Rule-set update intervals (in seconds)
const SECURITY_INTERVAL = 24 * 3600; // 24 Hours for dynamic security feeds
const STANDARD_INTERVAL = 48 * 3600; // 48 Hours for general static lists

// ==============================================================================
// 1. DATASETS, REGEX & CONSTANTS
// ==============================================================================

const IRAN_BASE_URL = "https://cdn.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/";
const HAGEZI_BASE_URL = "https://cdn.jsdelivr.net/gh/Erfan4700/HaGeZi_BlockLists_mrs_format@release/";

const HAGEZI_TIERS_MAP = Object.freeze({
  light: "HageziLight",
  normal: "HageziNormal",
  pro: "HageziPro",
  proplus: "HageziProPlus",
  ultimate: "HageziUltimate"
});

const SELECTED_HAGEZI_NAME = HAGEZI_TIERS_MAP[HAGEZI_TIER.toLowerCase()] ?? "HageziProPlus";

// Optimized regex patterns for rule sanitization
const JUNK_RULES_REGEX = /(?:GEOIP|GEOSITE|RULE-SET),[^,\n]*(?<![a-z0-9])(?:CN|CHINA|RU|RUSSIA)(?![a-z0-9])/i;
const PROXY_KEYWORD_REGEX = /proxy|auto|select|default|fallback|internet|traffic|manual|nodes|نهایی|اینترنت|دستی|انتخاب|🚀|⚡|♻️/i;
const MATCH_RULE_REGEX = /^match(?:,|$)/i;
const DIRECT_KEYWORD_REGEX = /direct/i;
const IP_RULE_PREFIX_REGEX = /^(?:GEOIP|IP-CIDR|IP-CIDR6|IP-ASN),/i;
const NO_RESOLVE_REGEX = /,\s*no-resolve(?:\s*#.*)?$/i;

// High-frequency Iranian services outside the .ir TLD
const MANUAL_DOMAINS = Object.freeze([
  "aparat.com", "filimo.com", "telewebion.com", "varzesh3.com",
  "neshan.org", "rajman.org", "cedarmaps.com", "snapp.cab", "snapp.tax",
  "snappcloud.io", "snapp.supply", "tapsi.cab", "tap33.me", "taximaxim.com",
  "torob.com", "divarcdn.com", "digikala.com", "digikalacloud.com",
  "dl150m.info", "dl175m.info", "linkulu.com", "film2media.cam",
  "zarinpal.com", "zarin.link", "payping.net", "ramzinex.com", "abantether.com",
  "nobitex.net", "exir.io", "wallex.net"
]);

const MANUAL_WILDCARDS = Object.freeze(MANUAL_DOMAINS.map(domain => `+.${domain}`));

// SafeSearch DNS overrides
const FROZEN_HOSTS = Object.freeze({
  "forcesafesearch.google.com": "216.239.38.120",
  "www.google.com": "216.239.38.120",
  "google.com": "216.239.38.120",
  "strict.bing.com": "204.79.197.220",
  "www.bing.com": "204.79.197.220",
  "bing.com": "204.79.197.220"
});

// Domestic clean DNS resolvers
const PURE_DOMESTIC_RESOLVERS = Object.freeze([
  "193.186.32.32",
  "217.218.127.127",
  "217.218.155.155"
]);

// Anti-poisoning resolvers for proxy server host resolution
const UNPOISONED_PROXY_RESOLVERS = Object.freeze([
  "https://223.5.5.5/dns-query",
  "223.5.5.5",
  "119.29.29.29",
  "193.186.32.32"
]);

// Bootstrap resolvers for initial DNS server lookups
const HYBRID_BOOTSTRAP_RESOLVERS = Object.freeze([
  "223.5.5.5",
  "119.29.29.29",
  "193.186.32.32"
]);

// Secure DoH endpoints routed through the active proxy tunnel
const DOH_ENDPOINTS = Object.freeze([
  "https://1.1.1.1/dns-query",
  "https://8.8.8.8/dns-query",
  "https://9.9.9.9/dns-query"
]);

// ==============================================================================
// 2. HELPER FUNCTIONS
// ==============================================================================

/**
 * Builds standard rule-provider definitions without hardcoded routing restrictions.
 */
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

/**
 * Detects the primary outgoing proxy group from the client configuration.
 */
function resolvePrimaryProxyGroup(groups) {
  if (!Array.isArray(groups) || groups.length === 0) return "DIRECT";

  for (let i = 0, len = groups.length; i < len; i++) {
    const g = groups[i];
    if (g && g.type === "select" && PROXY_KEYWORD_REGEX.test(g.name)) return g.name;
  }
  for (let i = 0, len = groups.length; i < len; i++) {
    const g = groups[i];
    if (g && (g.type === "url-test" || g.type === "fallback") && PROXY_KEYWORD_REGEX.test(g.name)) return g.name;
  }
  for (let i = 0, len = groups.length; i < len; i++) {
    const g = groups[i];
    if (g && g.type === "select" && !DIRECT_KEYWORD_REGEX.test(g.name) && g.name.toLowerCase() !== "reject") return g.name;
  }
  return groups[0]?.name ?? "DIRECT";
}

// ==============================================================================
// 3. MAIN RUNTIME PIPELINE
// ==============================================================================

function main(config) {
  const defaultProxyGroup = resolvePrimaryProxyGroup(config["proxy-groups"]);

  // Core networking tuning
  config["tcp-concurrent"] = true;
  config["unified-delay"] = true;
  config["find-process-mode"] = "off";

  delete config["global-client-fingerprint"];

  // Apply TLS client fingerprinting to modern outbound protocols
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
  delete config["geox-url"];

  config["keep-alive-idle"] = 600;
  config["keep-alive-interval"] = 15;

  (config.experimental ??= {})["quic-go-disable-ecn"] = true;

  const profile = (config.profile ??= {});
  profile["store-fake-ip"] = true;
  profile["store-selected"] = true;

  // Lightweight sniffer: only inspect standard web traffic to save CPU
  config.sniffer = {
    enable: true,
    "force-dns-mapping": true,
    "parse-pure-ip": true,
    "override-destination": false,
    sniff: {
      TLS: { ports: [443, 8443] },
      HTTP: { ports: [80, 8080] }
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

  // Anti-leak DNS architecture
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

  dns["fake-ip-filter"] = [
    "+.ir",
    ...MANUAL_WILDCARDS,
    "+.lan", "+.local", "+.home.arpa",
    "captive.apple.com", "+.connectivitycheck.gstatic.com",
    "detectportal.firefox.com", "+.msftconnecttest.com", "+.msftncsi.com",
    "time.apple.com", "time.google.com", "time.windows.com", "time.nist.gov",
    "+.pool.ntp.org", "+.ntp.org",
    "+.steamcontent.com", "+.battlenet.com", "+.battle.net", "+.ea.com",
    "stun.*", "*.stun.*", "supl.google.com", "+.supl.google.com"
  ];

  dns.nameserver = DOH_ENDPOINTS.map(url => `${url}#${defaultProxyGroup}`);

  const nsPolicy = MANUAL_DOMAINS.reduce((acc, domain) => {
    acc[`+.${domain}`] = PURE_DOMESTIC_RESOLVERS;
    return acc;
  }, {
    "+.ir": PURE_DOMESTIC_RESOLVERS,
    "supl.google.com": PURE_DOMESTIC_RESOLVERS,
    "+.supl.google.com": PURE_DOMESTIC_RESOLVERS
  });
  Object.assign((dns["nameserver-policy"] ??= {}), nsPolicy);

  // Populate Rule-Providers
  const providers = {};

  // HaGeZi Global Suite
  providers["hagezi-main"] = makeProvider(SELECTED_HAGEZI_NAME, "domain", "mrs", `${HAGEZI_BASE_URL}${SELECTED_HAGEZI_NAME}.mrs`, STANDARD_INTERVAL);
  if (ENABLE_HAGEZI_TIF) providers["hagezi-tif"] = makeProvider("HageziTIF", "domain", "mrs", `${HAGEZI_BASE_URL}HageziTIF.mrs`, SECURITY_INTERVAL);
  if (ENABLE_DYNDNS_BLOCK) providers["hagezi-dyndns"] = makeProvider("HageziDynDNS", "domain", "mrs", `${HAGEZI_BASE_URL}HageziDynDNS.mrs`, SECURITY_INTERVAL);
  if (ENABLE_PORN_FILTER) providers["hagezi-nsfw"] = makeProvider("HageziNSFW", "domain", "mrs", `${HAGEZI_BASE_URL}HageziNSFW.mrs`, STANDARD_INTERVAL);
  if (ENABLE_GAMBLING_FILTER) providers["hagezi-gambling"] = makeProvider("HageziGambling", "domain", "mrs", `${HAGEZI_BASE_URL}HageziGambling.mrs`, STANDARD_INTERVAL);

  if (ENABLE_NATIVE_TRACKERS) {
    providers["hagezi-windows"] = makeProvider("HageziWindows", "domain", "mrs", `${HAGEZI_BASE_URL}HageziWindows.mrs`, STANDARD_INTERVAL);
    providers["hagezi-apple"] = makeProvider("HageziApple", "domain", "mrs", `${HAGEZI_BASE_URL}HageziApple.mrs`, STANDARD_INTERVAL);
    providers["hagezi-xiaomi"] = makeProvider("HageziXiaomi", "domain", "mrs", `${HAGEZI_BASE_URL}HageziXiaomi.mrs`, STANDARD_INTERVAL);
    providers["hagezi-android"] = makeProvider("HageziAndroid", "domain", "mrs", `${HAGEZI_BASE_URL}HageziAndroid.mrs`, STANDARD_INTERVAL);
  }

  // Domestic Iran Security & Ad-blocking
  if (ENABLE_IRAN_ADS) providers["iran-ads"] = makeProvider("iran-ads", "domain", "mrs", `${IRAN_BASE_URL}iran-ads.mrs`, STANDARD_INTERVAL);
  if (ENABLE_IRAN_SECURITY) {
    providers["iran-security"] = makeProvider("iran-security", "domain", "mrs", `${IRAN_BASE_URL}iran-security.mrs`, SECURITY_INTERVAL);
    providers["iran-security-ip"] = makeProvider("iran-security-ip", "ipcidr", "mrs", `${IRAN_BASE_URL}iran-security-ip.mrs`, SECURITY_INTERVAL);
  }
  if (ENABLE_IRAN_GAMBLING) providers["iran-gambling"] = makeProvider("iran-gambling", "domain", "mrs", `${IRAN_BASE_URL}iran-gambling.mrs`, STANDARD_INTERVAL);

  // Iran Modular Categories
  if (ENABLE_IRAN_MEDIA) providers["iran-media"] = makeProvider("iran-media", "domain", "mrs", `${IRAN_BASE_URL}iran-media.mrs`, STANDARD_INTERVAL);
  if (ENABLE_IRAN_BANKING) providers["iran-banking"] = makeProvider("iran-banking", "domain", "mrs", `${IRAN_BASE_URL}iran-banking.mrs`, STANDARD_INTERVAL);
  if (ENABLE_IRAN_GOV) providers["iran-gov"] = makeProvider("iran-gov", "domain", "mrs", `${IRAN_BASE_URL}iran-gov.mrs`, STANDARD_INTERVAL);
  if (ENABLE_IRAN_GAMING) providers["iran-gaming"] = makeProvider("iran-gaming", "domain", "mrs", `${IRAN_BASE_URL}iran-gaming.mrs`, STANDARD_INTERVAL);
  if (ENABLE_IRAN_DOWNLOAD) providers["iran-download"] = makeProvider("iran-download", "domain", "mrs", `${IRAN_BASE_URL}iran-download.mrs`, STANDARD_INTERVAL);
  if (ENABLE_IRAN_OTHER) providers["iran-other"] = makeProvider("iran-other", "domain", "mrs", `${IRAN_BASE_URL}iran-other.mrs`, STANDARD_INTERVAL);

  // Infrastructure & Application Rules
  providers["iran-ip"] = makeProvider("iran-ip", "ipcidr", "mrs", `${IRAN_BASE_URL}iran-ip.mrs`, STANDARD_INTERVAL);
  providers["iran-apps"] = makeProvider("iran-apps", "classical", "text", `${IRAN_BASE_URL}iran-apps.txt`, STANDARD_INTERVAL);

  Object.assign((config["rule-providers"] ??= {}), providers);

  // Build the unified routing table
  const ruleSet = new Set();

  // 1. Local Network & Broadcast isolation (prevents LAN leakage even without GeoIP database)
  ruleSet.add("GEOIP,private,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR,127.0.0.0/8,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR,172.16.0.0/12,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR6,fc00::/7,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR6,fe80::/10,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR,224.0.0.0/4,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR,255.255.255.255/32,DIRECT,no-resolve");

  // 2. High-speed Direct P2P & Torrent ports
  ruleSet.add("DST-PORT,7275,DIRECT");
  ruleSet.add("DST-PORT,6881-6889,DIRECT");
  ruleSet.add("DST-PORT,51413,DIRECT");

  // 3. Fast domestic threat rejection
  if (ENABLE_IRAN_SECURITY) {
    ruleSet.add("RULE-SET,iran-security,REJECT");
    ruleSet.add("RULE-SET,iran-security-ip,REJECT,no-resolve");
  }
  if (ENABLE_IRAN_ADS) ruleSet.add("RULE-SET,iran-ads,REJECT");
  if (ENABLE_IRAN_GAMBLING) ruleSet.add("RULE-SET,iran-gambling,REJECT");

  // 4. Global HaGeZi blocklists & Trackers
  ruleSet.add("RULE-SET,hagezi-main,REJECT");
  if (ENABLE_HAGEZI_TIF) ruleSet.add("RULE-SET,hagezi-tif,REJECT");
  if (ENABLE_DYNDNS_BLOCK) ruleSet.add("RULE-SET,hagezi-dyndns,REJECT");
  if (ENABLE_PORN_FILTER) ruleSet.add("RULE-SET,hagezi-nsfw,REJECT");
  if (ENABLE_GAMBLING_FILTER) ruleSet.add("RULE-SET,hagezi-gambling,REJECT");
  if (ENABLE_NATIVE_TRACKERS) {
    ruleSet.add("RULE-SET,hagezi-windows,REJECT");
    ruleSet.add("RULE-SET,hagezi-apple,REJECT");
    ruleSet.add("RULE-SET,hagezi-xiaomi,REJECT");
    ruleSet.add("RULE-SET,hagezi-android,REJECT");
  }

  // 5. Zero-latency matching for major domestic domains
  for (let i = 0; i < MANUAL_DOMAINS.length; i++) {
    ruleSet.add(`DOMAIN-SUFFIX,${MANUAL_DOMAINS[i]},DIRECT`);
  }
  ruleSet.add("DOMAIN-SUFFIX,ir,DIRECT");

  // 6. Direct routing for Iran modules
  if (ENABLE_IRAN_MEDIA) ruleSet.add("RULE-SET,iran-media,DIRECT");
  if (ENABLE_IRAN_BANKING) ruleSet.add("RULE-SET,iran-banking,DIRECT");
  if (ENABLE_IRAN_GOV) ruleSet.add("RULE-SET,iran-gov,DIRECT");
  if (ENABLE_IRAN_GAMING) ruleSet.add("RULE-SET,iran-gaming,DIRECT");
  if (ENABLE_IRAN_DOWNLOAD) ruleSet.add("RULE-SET,iran-download,DIRECT");
  if (ENABLE_IRAN_OTHER) ruleSet.add("RULE-SET,iran-other,DIRECT");

  ruleSet.add("RULE-SET,iran-apps,DIRECT,no-resolve");
  ruleSet.add("RULE-SET,iran-ip,DIRECT,no-resolve");
  ruleSet.add("GEOIP,IR,DIRECT,no-resolve");

  // 7. Protocol blocking & specific traffic exceptions
  if (ENABLE_QUIC_BLOCK) ruleSet.add("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT");
  ruleSet.add(`DOMAIN-SUFFIX,waze.com,${defaultProxyGroup}`);
  ruleSet.add(`DOMAIN-KEYWORD,waze,${defaultProxyGroup}`);

  // 8. Sanitize raw subscription rules and append at the end
  const rawRules = config.rules;
  let capturedMatchRule = null;

  if (Array.isArray(rawRules)) {
    for (let i = 0, len = rawRules.length; i < len; i++) {
      const rule = rawRules[i];
      if (typeof rule !== "string" || rule.length === 0) continue;

      let cleanRule = rule.trim();
      if (cleanRule.length === 0) continue;

      // Force no-resolve on IP-based rules to eliminate DNS leaks
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

  // Final fallback rule
  ruleSet.add(capturedMatchRule ?? `MATCH,${defaultProxyGroup}`);
  config.rules = Array.from(ruleSet);

  return config;
}
