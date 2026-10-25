// ==============================================================================
// 0. CONTROL PANEL (Module Management Control Panel)
// ==============================================================================

const ENABLE_SAFE_SEARCH = false;
const ENABLE_QUIC_BLOCK = true;

// --- [A] New HaGeZi Settings (Erfan4700 HaGeZi MRS) ---
const HAGEZI_TIER = "proplus"; // "light" | "normal" | "pro" | "proplus" | "ultimate"
const ENABLE_HAGEZI_TIF = true; // Real-time threat intelligence feeds against global ransomware and phishing
const ENABLE_DYNDNS_BLOCK = true; // Block Dynamic DNS domains
const ENABLE_NATIVE_TRACKERS = true; // Block native system trackers (Windows, Apple, Xiaomi, Samsung)
const ENABLE_PORN_FILTER = true; // Adult / NSFW content filtering
const ENABLE_GAMBLING_FILTER = true; // Block gambling and betting sites

// --- [B] Iran Security & Ad-blocking Modules ---
const ENABLE_IRAN_ADS = true; // Persian ads (Yektanet, Sabavision, etc.)
const ENABLE_IRAN_SECURITY = true; // Domestic phishing (gateways, Sana) and local malware
const ENABLE_IRAN_GAMBLING = true; // Iranian betting and casino sites

// --- [C] Categorized Iran Modules (Direct traffic bypassing proxy) ---
const ENABLE_IRAN_MEDIA = true; // Aparat, Filimo, Telewebion, etc.
const ENABLE_IRAN_BANKING = true; // Banks, Shaparak, crypto exchanges, and stock market
const ENABLE_IRAN_GOV = true; // Government, judicial, and tax portals
const ENABLE_IRAN_GAMING = true; // Game servers and ping reduction services
const ENABLE_IRAN_DOWNLOAD = true; // Soft98 and domestic Linux mirrors
const ENABLE_IRAN_OTHER = true; // Remaining Iranian domains (zero overlap)

// Rule update intervals (hours)
const SECURITY_UPDATE_HOURS = 24;
const STANDARD_UPDATE_HOURS = 48;
const SECURITY_INTERVAL = SECURITY_UPDATE_HOURS * 3600;
const STANDARD_INTERVAL = STANDARD_UPDATE_HOURS * 3600;

// ==============================================================================
// 1. DATASETS & SOURCES (Using cdn.jsdelivr for maximum stability in Iran)
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

// Compiled regular expressions
const JUNK_RULES_REGEX = /(?:GEOIP|GEOSITE|RULE-SET),[^,\n]*(?<![a-z0-9])(?:CN|CHINA|RU|RUSSIA)(?![a-z0-9])/i;
const PROXY_KEYWORD_REGEX = /proxy|auto|select|default|fallback|internet|traffic|manual|nodes|نهایی|اینترنت|دستی|انتخاب|🚀|⚡|♻️/i;
const MATCH_RULE_REGEX = /^match(?:,|$)/i;
const DIRECT_KEYWORD_REGEX = /direct/i;
const IP_RULE_PREFIX_REGEX = /^(?:GEOIP|IP-CIDR|IP-CIDR6|IP-ASN),/i;
const NO_RESOLVE_REGEX = /,\s*no-resolve(?:\s*#.*)?$/i;

// Critical domestic domains outside .ir TLD (including Aparat and Filimo for instant loading)
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

// Direct SafeSearch DNS mapping
const FROZEN_HOSTS = Object.freeze({
  "forcesafesearch.google.com": "216.239.38.120",
  "www.google.com": "216.239.38.120",
  "google.com": "216.239.38.120",
  "strict.bing.com": "204.79.197.220",
  "www.bing.com": "204.79.197.220",
  "bing.com": "204.79.197.220"
});

// Domestic DNS resolvers
const PURE_DOMESTIC_RESOLVERS = Object.freeze([
  "193.186.32.32",
  "217.218.127.127",
  "217.218.155.155"
]);

// Anti-poisoning secure DNS pool
const UNPOISONED_PROXY_RESOLVERS = Object.freeze([
  "https://223.5.5.5/dns-query",
  "223.5.5.5",
  "119.29.29.29",
  "193.186.32.32"
]);

// Bootstrap DNS pool
const HYBRID_BOOTSTRAP_RESOLVERS = Object.freeze([
  "223.5.5.5",
  "119.29.29.29",
  "193.186.32.32"
]);

// International DoH pool routed through proxy tunnel
const DOH_ENDPOINTS = Object.freeze([
  "https://1.1.1.1/dns-query",
  "https://8.8.8.8/dns-query",
  "https://9.9.9.9/dns-query"
]);

// Optimized sniffer configuration
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

// ==============================================================================
// 2. HELPER FUNCTIONS (Class-free and fully compatible with FlClash & Clash Verge)
// ==============================================================================

function makeProvider(name, behavior, format, url, interval) {
  return Object.freeze({
    type: "http",
    behavior: behavior,
    format: format,
    url: url,
    path: `./ruleset/${name}.${format === "mrs" ? "mrs" : "txt"}`,
    interval: interval
  });
}

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
  config["geo-auto-update"] = false;
  delete config["geox-url"];

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

  // --- Anti-leak DNS configuration ---
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

  dns["fake-ip-filter"] = Object.freeze([
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
  ]);

  dns.nameserver = DOH_ENDPOINTS.map(url => `${url}#${defaultProxyGroup}`);

  const nsPolicy = MANUAL_DOMAINS.reduce((acc, domain) => {
    acc[`+.${domain}`] = PURE_DOMESTIC_RESOLVERS;
    return acc;
  }, {
    "+.ir": PURE_DOMESTIC_RESOLVERS,
    "supl.google.com": PURE_DOMESTIC_RESOLVERS,
    "+.supl.google.com": PURE_DOMESTIC_RESOLVERS
  });
  Object.assign((dns["nameserver-policy"] ??= {}), Object.freeze(nsPolicy));

  // --- Build rule providers with cdn.jsdelivr endpoints ---
  const providers = {};

  // 1. New HaGeZi lists (Erfan4700/HaGeZi_BlockLists_mrs_format)
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

  // 2. Domestic security and ad-blocking
  if (ENABLE_IRAN_ADS) providers["iran-ads"] = makeProvider("iran-ads", "domain", "mrs", `${IRAN_BASE_URL}iran-ads.mrs`, STANDARD_INTERVAL);
  if (ENABLE_IRAN_SECURITY) {
    providers["iran-security"] = makeProvider("iran-security", "domain", "mrs", `${IRAN_BASE_URL}iran-security.mrs`, SECURITY_INTERVAL);
    providers["iran-security-ip"] = makeProvider("iran-security-ip", "ipcidr", "mrs", `${IRAN_BASE_URL}iran-security-ip.mrs`, SECURITY_INTERVAL);
  }
  if (ENABLE_IRAN_GAMBLING) providers["iran-gambling"] = makeProvider("iran-gambling", "domain", "mrs", `${IRAN_BASE_URL}iran-gambling.mrs`, STANDARD_INTERVAL);

  // 3. Modular Iran categories
  if (ENABLE_IRAN_MEDIA) providers["iran-media"] = makeProvider("iran-media", "domain", "mrs", `${IRAN_BASE_URL}iran-media.mrs`, STANDARD_INTERVAL);
  if (ENABLE_IRAN_BANKING) providers["iran-banking"] = makeProvider("iran-banking", "domain", "mrs", `${IRAN_BASE_URL}iran-banking.mrs`, STANDARD_INTERVAL);
  if (ENABLE_IRAN_GOV) providers["iran-gov"] = makeProvider("iran-gov", "domain", "mrs", `${IRAN_BASE_URL}iran-gov.mrs`, STANDARD_INTERVAL);
  if (ENABLE_IRAN_GAMING) providers["iran-gaming"] = makeProvider("iran-gaming", "domain", "mrs", `${IRAN_BASE_URL}iran-gaming.mrs`, STANDARD_INTERVAL);
  if (ENABLE_IRAN_DOWNLOAD) providers["iran-download"] = makeProvider("iran-download", "domain", "mrs", `${IRAN_BASE_URL}iran-download.mrs`, STANDARD_INTERVAL);
  if (ENABLE_IRAN_OTHER) providers["iran-other"] = makeProvider("iran-other", "domain", "mrs", `${IRAN_BASE_URL}iran-other.mrs`, STANDARD_INTERVAL);

  // 4. Infrastructure and applications
  providers["iran-ip"] = makeProvider("iran-ip", "ipcidr", "mrs", `${IRAN_BASE_URL}iran-ip.mrs`, STANDARD_INTERVAL);
  providers["iran-apps"] = makeProvider("iran-apps", "classical", "text", `${IRAN_BASE_URL}iran-apps.txt`, STANDARD_INTERVAL);

  Object.assign((config["rule-providers"] ??= {}), providers);

  // --- Traffic rules order ---
  const ruleSet = new Set();

  ruleSet.add("DST-PORT,7275,DIRECT");
  ruleSet.add("GEOIP,private,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR,224.0.0.0/4,DIRECT,no-resolve");
  ruleSet.add("IP-CIDR,255.255.255.255/32,DIRECT,no-resolve");
  ruleSet.add("DST-PORT,6881-6889,DIRECT");
  ruleSet.add("DST-PORT,51413,DIRECT");

  // Global HaGeZi blocklists
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

  // Domestic Iran blocklists
  if (ENABLE_IRAN_ADS) ruleSet.add("RULE-SET,iran-ads,REJECT");
  if (ENABLE_IRAN_SECURITY) {
    ruleSet.add("RULE-SET,iran-security,REJECT");
    ruleSet.add("RULE-SET,iran-security-ip,REJECT,no-resolve");
  }
  if (ENABLE_IRAN_GAMBLING) ruleSet.add("RULE-SET,iran-gambling,REJECT");

  // Manual domains (Aparat, Filimo, etc.) for guaranteed zero-delay direct routing
  for (let i = 0; i < MANUAL_DOMAINS.length; i++) {
    ruleSet.add(`DOMAIN-SUFFIX,${MANUAL_DOMAINS[i]},DIRECT`);
  }
  ruleSet.add("DOMAIN-SUFFIX,ir,DIRECT");

  // Direct routing for Iran modules
  if (ENABLE_IRAN_MEDIA) ruleSet.add("RULE-SET,iran-media,DIRECT");
  if (ENABLE_IRAN_BANKING) ruleSet.add("RULE-SET,iran-banking,DIRECT");
  if (ENABLE_IRAN_GOV) ruleSet.add("RULE-SET,iran-gov,DIRECT");
  if (ENABLE_IRAN_GAMING) ruleSet.add("RULE-SET,iran-gaming,DIRECT");
  if (ENABLE_IRAN_DOWNLOAD) ruleSet.add("RULE-SET,iran-download,DIRECT");
  if (ENABLE_IRAN_OTHER) ruleSet.add("RULE-SET,iran-other,DIRECT");

  ruleSet.add("RULE-SET,iran-apps,DIRECT,no-resolve");
  ruleSet.add("RULE-SET,iran-ip,DIRECT,no-resolve");
  ruleSet.add("GEOIP,IR,DIRECT,no-resolve");

  // Block QUIC protocol
  if (ENABLE_QUIC_BLOCK) ruleSet.add("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT");

  // Waze navigation routing
  ruleSet.add(`DOMAIN-SUFFIX,waze.com,${defaultProxyGroup}`);
  ruleSet.add(`DOMAIN-KEYWORD,waze,${defaultProxyGroup}`);

  // Sanitize and filter raw subscription rules
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
