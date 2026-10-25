// ==============================================================================
// 0. MASTER CONTROL PANEL (MODULE CONFIGURATION)
// ==============================================================================

// --- [A] Global Filtering (HaGeZi Global Adblock & Threat Defense) ---
const HAGEZI_TIER = "proplus"; // Options: "light" | "normal" | "pro" | "proplus" | "ultimate"
const ENABLE_HAGEZI_TIF = true; // Global block for malware, ransomware, and phishing (Threat Intelligence Feeds)
const ENABLE_NATIVE_TRACKERS = false; // Block native OS telemetry (Windows, Apple, Xiaomi, Android/Samsung)
const ENABLE_DYNDNS_BLOCK = false; // Block Dynamic DNS domains (DuckDNS, No-IP, C2 Trojans)
const ENABLE_PORN_FILTER = false; // Block adult and explicit content
const ENABLE_GAMBLING_FILTER = false; // Block global gambling and casino portals

// --- [B] Domestic Security & Threat Defense (Iran) ---
const ENABLE_IRAN_ADS = true; // Block domestic trackers and Persian ad networks (Yektanet, SabaVision, etc.)
const ENABLE_IRAN_SECURITY = true; // Block domestic malware, fake payment portals (Shaparak), and phishing
const ENABLE_IRAN_GAMBLING = true; // Block domestic gambling and betting portals

// --- [C] Granular Domestic Routing (Iran Modular Services) ---
const ENABLE_IRAN_BANKING = true; // Direct routing for banks, payment gateways, stock exchange, and crypto
const ENABLE_IRAN_GOV = true; // Direct routing for government and judicial portals (.gov.ir, Sana, Tax)
const ENABLE_IRAN_MEDIA = true; // Direct routing for domestic VOD and streaming (Aparat, Filimo, Namava, Telewebion)
const ENABLE_IRAN_GAMING = true; // Direct routing for domestic game servers, ping reduction, and gaming media
const ENABLE_IRAN_DOWNLOAD = true; // Direct routing for software download portals and Linux mirrors (Soft98, etc.)
const ENABLE_IRAN_OTHER = true; // Remainder of domestic domains (E-commerce, ride-hailing, news) with zero overlap
const ENABLE_IRAN_MASTER_DOMAINS = false; // Master comprehensive domain list (all-in-one domestic package)

// --- [D] Domestic Infrastructure & Applications ---
const ENABLE_IRAN_APPS = true; // Direct routing for domestic Android packages and Windows executables
const ENABLE_IRAN_IP = true; // Direct routing for all official Iranian IPv4/IPv6 CIDRs (RIPE NCC)
const ENABLE_IRAN_CLOUD = true; // Direct routing for domestic cloud and datacenter CIDRs (Arvan, Derak, ParsPack)
const ENABLE_IRAN_ASN = true; // Direct routing by Autonomous System Numbers (MCI, MTN Irancell, Shatel, etc.)

// --- [E] Network & DNS Optimization ---
const ENABLE_QUIC_BLOCK = true; // Block UDP/443 (QUIC) to prevent ISP packet loss and bandwidth throttling
const ENABLE_SAFE_SEARCH = false; // Enforce strict SafeSearch on Google and Bing

// Automated Update Intervals (in seconds)
const INTERVAL_SECURITY = 24 * 3600; // Daily (24 hours)
const INTERVAL_STANDARD = 48 * 3600; // Bi-daily (48 hours)

// ==============================================================================
// 1. IMMUTABLE CONSTANTS & DATA REGISTRY
// ==============================================================================

const CDN_HAGEZI_BASE = "https://fastly.jsdelivr.net/gh/Erfan4700/HaGeZi_BlockLists_mrs_format@release/";
const CDN_IRAN_BASE = "https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/";

const HAGEZI_TIERS_MAP = Object.freeze({
  light: "HageziLight",
  normal: "HageziNormal",
  pro: "HageziPro",
  proplus: "HageziProPlus",
  ultimate: "HageziUltimate"
});

const SELECTED_HAGEZI_NAME = HAGEZI_TIERS_MAP[HAGEZI_TIER.toLowerCase()] ?? "HageziProPlus";

// Precompiled memory-resident regular expressions
const REGEX_JUNK_RULES = /(?:GEOIP|GEOSITE|RULE-SET),[^,\n]*(?<![a-z0-9])(?:CN|CHINA|RU|RUSSIA)(?![a-z0-9])/i;
// Universal proxy group detection (supporting standard names, keywords, and unicode emojis)
const REGEX_PROXY_GROUP = /proxy|auto|select|fallback|internet|traffic|manual|nodes|default|all|🚀|⚡|♻️|🔰|🎮|🌐/i;
const REGEX_MATCH_RULE = /^match(?:,|$)/i;
const REGEX_DIRECT_RULE = /direct/i;
const REGEX_IP_RULE_PREFIX = /^(?:GEOIP|IP-CIDR|IP-CIDR6|IP-ASN),/i;
const REGEX_NO_RESOLVE = /,\s*no-resolve(?:\s*#.*)?$/i;

// Critical domestic domains outside .ir TLD
const DOMESTIC_NON_IR_DOMAINS = Object.freeze([
  "neshan.org", "rajman.org", "cedarmaps.com", "snapp.cab", "snapp.tax",
  "snappcloud.io", "snapp.supply", "tapsi.cab", "tap33.me", "taximaxim.com",
  "torob.com", "divarcdn.com", "digikala.com", "dl150m.info", "dl175m.info",
  "linkulu.com", "film2media.cam", "zarinpal.com", "zarin.link", "payping.net",
  "ramzinex.com", "abantether.com", "nobitex.net", "exir.io", "wallex.net"
]);

const DOMESTIC_NON_IR_RULES = Object.freeze(DOMESTIC_NON_IR_DOMAINS.map(d => `DOMAIN-SUFFIX,${d},DIRECT`));
const DOMESTIC_WILDCARDS = Object.freeze(DOMESTIC_NON_IR_DOMAINS.map(d => `+.${d}`));

// Static SafeSearch host mappings
const SAFE_SEARCH_HOSTS = Object.freeze({
  "forcesafesearch.google.com": "216.239.38.120",
  "www.google.com": "216.239.38.120",
  "google.com": "216.239.38.120",
  "strict.bing.com": "204.79.197.220",
  "www.bing.com": "204.79.197.220",
  "bing.com": "204.79.197.220"
});

// Domestic upstream DNS resolvers (Iran)
const DNS_DOMESTIC_RESOLVERS = Object.freeze([
  "193.186.32.32",
  "217.218.127.127",
  "217.218.155.155"
]);

// Anti-pollution proxy DNS resolvers
const DNS_PROXY_RESOLVERS = Object.freeze([
  "https://223.5.5.5/dns-query",
  "223.5.5.5",
  "119.29.29.29",
  "193.186.32.32"
]);

// Bootstrap DNS resolvers
const DNS_BOOTSTRAP_RESOLVERS = Object.freeze([
  "223.5.5.5",
  "119.29.29.29",
  "193.186.32.32"
]);

// International secure DoH endpoints
const DNS_DOH_ENDPOINTS = Object.freeze([
  "https://1.1.1.1/dns-query",
  "https://8.8.8.8/dns-query",
  "https://9.9.9.9/dns-query"
]);

// ==============================================================================
// 2. MODULAR ARCHITECTURE ENGINES
// ==============================================================================

class CoreTuner {
  static apply(config) {
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
  }
}

class SnifferEngine {
  static generate() {
    return Object.freeze({
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
        ...DOMESTIC_WILDCARDS
      ])
    });
  }
}

class ProxyClassifier {
  static resolvePrimary(groups) {
    if (!Array.isArray(groups) || groups.length === 0) return "DIRECT";

    // 1. Try finding a selector group matching standard keywords
    for (let i = 0, len = groups.length; i < len; i++) {
      const g = groups[i];
      if (g && g.type === "select" && REGEX_PROXY_GROUP.test(g.name)) {
        return g.name;
      }
    }

    // 2. Try finding an auto/url-test group
    for (let i = 0, len = groups.length; i < len; i++) {
      const g = groups[i];
      if (g && (g.type === "url-test" || g.type === "fallback") && REGEX_PROXY_GROUP.test(g.name)) {
        return g.name;
      }
    }

    // 3. Fallback to the first available selector group (not reject/direct)
    for (let i = 0, len = groups.length; i < len; i++) {
      const g = groups[i];
      if (g && g.type === "select" && !REGEX_DIRECT_RULE.test(g.name) && g.name.toLowerCase() !== "reject") {
        return g.name;
      }
    }

    // 4. Ultimate fallback to the very first group's actual name in the subscription
    return groups[0]?.name ?? "DIRECT";
  }
}

class ProviderFactory {
  static create(name, behavior, format, url, interval) {
    return Object.freeze({
      type: "http",
      behavior: behavior,
      format: format,
      url: url,
      path: `./ruleset/${name}.${format === "mrs" ? "mrs" : "txt"}`,
      interval: interval
    });
  }

  static buildRegistry() {
    const providers = {};

    // HaGeZi Global Filtering Providers
    providers["hagezi-main"] = this.create(SELECTED_HAGEZI_NAME, "domain", "mrs", `${CDN_HAGEZI_BASE}${SELECTED_HAGEZI_NAME}.mrs`, INTERVAL_STANDARD);
    if (ENABLE_HAGEZI_TIF) providers["hagezi-tif"] = this.create("HageziTIF", "domain", "mrs", `${CDN_HAGEZI_BASE}HageziTIF.mrs`, INTERVAL_SECURITY);
    if (ENABLE_DYNDNS_BLOCK) providers["hagezi-dyndns"] = this.create("HageziDynDNS", "domain", "mrs", `${CDN_HAGEZI_BASE}HageziDynDNS.mrs`, INTERVAL_SECURITY);
    if (ENABLE_PORN_FILTER) providers["hagezi-nsfw"] = this.create("HageziNSFW", "domain", "mrs", `${CDN_HAGEZI_BASE}HageziNSFW.mrs`, INTERVAL_STANDARD);
    if (ENABLE_GAMBLING_FILTER) providers["hagezi-gambling"] = this.create("HageziGambling", "domain", "mrs", `${CDN_HAGEZI_BASE}HageziGambling.mrs`, INTERVAL_STANDARD);

    if (ENABLE_NATIVE_TRACKERS) {
      providers["hagezi-windows"] = this.create("HageziWindows", "domain", "mrs", `${CDN_HAGEZI_BASE}HageziWindows.mrs`, INTERVAL_STANDARD);
      providers["hagezi-apple"] = this.create("HageziApple", "domain", "mrs", `${CDN_HAGEZI_BASE}HageziApple.mrs`, INTERVAL_STANDARD);
      providers["hagezi-xiaomi"] = this.create("HageziXiaomi", "domain", "mrs", `${CDN_HAGEZI_BASE}HageziXiaomi.mrs`, INTERVAL_STANDARD);
      providers["hagezi-android"] = this.create("HageziAndroid", "domain", "mrs", `${CDN_HAGEZI_BASE}HageziAndroid.mrs`, INTERVAL_STANDARD);
    }

    // Iran Regional Security Providers
    if (ENABLE_IRAN_ADS) providers["iran-ads"] = this.create("iran-ads", "domain", "mrs", `${CDN_IRAN_BASE}iran-ads.mrs`, INTERVAL_STANDARD);
    if (ENABLE_IRAN_SECURITY) {
      providers["iran-security"] = this.create("iran-security", "domain", "mrs", `${CDN_IRAN_BASE}iran-security.mrs`, INTERVAL_SECURITY);
      providers["iran-security-ip"] = this.create("iran-security-ip", "ipcidr", "mrs", `${CDN_IRAN_BASE}iran-security-ip.mrs`, INTERVAL_SECURITY);
    }
    if (ENABLE_IRAN_GAMBLING) providers["iran-gambling"] = this.create("iran-gambling", "domain", "mrs", `${CDN_IRAN_BASE}iran-gambling.mrs`, INTERVAL_STANDARD);

    // Iran Granular Domestic Routing Modules
    if (ENABLE_IRAN_MEDIA) providers["iran-media"] = this.create("iran-media", "domain", "mrs", `${CDN_IRAN_BASE}iran-media.mrs`, INTERVAL_STANDARD);
    if (ENABLE_IRAN_BANKING) providers["iran-banking"] = this.create("iran-banking", "domain", "mrs", `${CDN_IRAN_BASE}iran-banking.mrs`, INTERVAL_STANDARD);
    if (ENABLE_IRAN_GOV) providers["iran-gov"] = this.create("iran-gov", "domain", "mrs", `${CDN_IRAN_BASE}iran-gov.mrs`, INTERVAL_STANDARD);
    if (ENABLE_IRAN_GAMING) providers["iran-gaming"] = this.create("iran-gaming", "domain", "mrs", `${CDN_IRAN_BASE}iran-gaming.mrs`, INTERVAL_STANDARD);
    if (ENABLE_IRAN_DOWNLOAD) providers["iran-download"] = this.create("iran-download", "domain", "mrs", `${CDN_IRAN_BASE}iran-download.mrs`, INTERVAL_STANDARD);
    if (ENABLE_IRAN_OTHER) providers["iran-other"] = this.create("iran-other", "domain", "mrs", `${CDN_IRAN_BASE}iran-other.mrs`, INTERVAL_STANDARD);

    // Iran Master & Infrastructure Modules
    if (ENABLE_IRAN_MASTER_DOMAINS) providers["iran-domains"] = this.create("iran-domains", "domain", "mrs", `${CDN_IRAN_BASE}iran-domains.mrs`, INTERVAL_STANDARD);
    if (ENABLE_IRAN_APPS) providers["iran-apps"] = this.create("iran-apps", "classical", "text", `${CDN_IRAN_BASE}iran-apps.txt`, INTERVAL_STANDARD);
    if (ENABLE_IRAN_IP) providers["iran-ip"] = this.create("iran-ip", "ipcidr", "mrs", `${CDN_IRAN_BASE}iran-ip.mrs`, INTERVAL_STANDARD);
    if (ENABLE_IRAN_CLOUD) providers["iran-cloud"] = this.create("iran-cloud", "ipcidr", "mrs", `${CDN_IRAN_BASE}iran-cloud.mrs`, INTERVAL_STANDARD);
    if (ENABLE_IRAN_ASN) providers["iran-asn"] = this.create("iran-asn", "classical", "text", `${CDN_IRAN_BASE}iran-asn.txt`, INTERVAL_STANDARD);

    return Object.freeze(providers);
  }
}

class DnsEngine {
  static configure(config, defaultProxyGroup, activeProviders) {
    if (ENABLE_SAFE_SEARCH) {
      Object.assign((config.hosts ??= {}), SAFE_SEARCH_HOSTS);
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

    dns["default-nameserver"] = DNS_BOOTSTRAP_RESOLVERS;
    dns["proxy-server-nameserver"] = DNS_PROXY_RESOLVERS;
    dns["direct-nameserver"] = DNS_DOMESTIC_RESOLVERS;

    // Bulletproof Fake-IP Filters (Only include rule-set if provider is actively loaded)
    const fakeIpFilters = [
      "+.ir",
      ...DOMESTIC_WILDCARDS,
      "+.lan", "+.local", "+.home.arpa",
      "captive.apple.com", "+.connectivitycheck.gstatic.com",
      "detectportal.firefox.com", "+.msftconnecttest.com", "+.msftncsi.com",
      "time.apple.com", "time.google.com", "time.windows.com", "time.nist.gov",
      "+.pool.ntp.org", "+.ntp.org",
      "+.steamcontent.com", "+.battlenet.com", "+.battle.net", "+.ea.com",
      "stun.*", "*.stun.*", "supl.google.com", "+.supl.google.com",
      "location.services.mozilla.com"
    ];

    if (activeProviders["iran-domains"]) fakeIpFilters.push("rule-set:iran-domains");
    if (activeProviders["iran-other"]) fakeIpFilters.push("rule-set:iran-other");

    dns["fake-ip-filter"] = Object.freeze(fakeIpFilters);

    // Upstream DoH queries routed through proxy tunnel
    dns.nameserver = DNS_DOH_ENDPOINTS.map(url => `${url}#${defaultProxyGroup}`);

    // Dynamic Nameserver Policy (Zero Missing-Provider Errors)
    const nsPolicy = DOMESTIC_NON_IR_DOMAINS.reduce((acc, domain) => {
      acc[`+.${domain}`] = DNS_DOMESTIC_RESOLVERS;
      return acc;
    }, {
      "+.ir": DNS_DOMESTIC_RESOLVERS,
      "supl.google.com": DNS_DOMESTIC_RESOLVERS,
      "+.supl.google.com": DNS_DOMESTIC_RESOLVERS
    });

    if (activeProviders["iran-domains"]) nsPolicy["rule-set:iran-domains"] = DNS_DOMESTIC_RESOLVERS;
    if (activeProviders["iran-other"]) nsPolicy["rule-set:iran-other"] = DNS_DOMESTIC_RESOLVERS;

    Object.assign((dns["nameserver-policy"] ??= {}), Object.freeze(nsPolicy));
  }
}

class RulesEngine {
  static assemble(config, defaultProxyGroup, activeProviders) {
    const ruleSet = new Set();

    // 1. RFC1918 Private & Local CIDRs
    const RFC1918_RULES = [
      "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
      "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
      "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
      "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
      "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
      "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
      "IP-CIDR,255.255.255.255/32,DIRECT,no-resolve",
      "IP-CIDR6,::1/128,DIRECT,no-resolve",
      "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
      "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
      "DST-PORT,7275,DIRECT",
      "DST-PORT,6881-6889,DIRECT",
      "DST-PORT,51413,DIRECT"
    ];
    for (let i = 0; i < RFC1918_RULES.length; i++) ruleSet.add(RFC1918_RULES[i]);

    // 2. Global Threat Defense (HaGeZi)
    if (activeProviders["hagezi-main"]) ruleSet.add("RULE-SET,hagezi-main,REJECT");
    if (activeProviders["hagezi-tif"]) ruleSet.add("RULE-SET,hagezi-tif,REJECT");
    if (activeProviders["hagezi-dyndns"]) ruleSet.add("RULE-SET,hagezi-dyndns,REJECT");
    if (activeProviders["hagezi-nsfw"]) ruleSet.add("RULE-SET,hagezi-nsfw,REJECT");
    if (activeProviders["hagezi-gambling"]) ruleSet.add("RULE-SET,hagezi-gambling,REJECT");
    if (activeProviders["hagezi-windows"]) ruleSet.add("RULE-SET,hagezi-windows,REJECT");
    if (activeProviders["hagezi-apple"]) ruleSet.add("RULE-SET,hagezi-apple,REJECT");
    if (activeProviders["hagezi-xiaomi"]) ruleSet.add("RULE-SET,hagezi-xiaomi,REJECT");
    if (activeProviders["hagezi-android"]) ruleSet.add("RULE-SET,hagezi-android,REJECT");

    // 3. Regional Threat & Adblock
    if (activeProviders["iran-ads"]) ruleSet.add("RULE-SET,iran-ads,REJECT");
    if (activeProviders["iran-security"]) {
      ruleSet.add("RULE-SET,iran-security,REJECT");
      ruleSet.add("RULE-SET,iran-security-ip,REJECT,no-resolve");
    }
    if (activeProviders["iran-gambling"]) ruleSet.add("RULE-SET,iran-gambling,REJECT");

    // 4. Applications Routing
    if (activeProviders["iran-apps"]) ruleSet.add("RULE-SET,iran-apps,DIRECT,no-resolve");

    // 5. Domestic Granular Modules (Direct Traffic)
    if (activeProviders["iran-banking"]) ruleSet.add("RULE-SET,iran-banking,DIRECT");
    if (activeProviders["iran-gov"]) ruleSet.add("RULE-SET,iran-gov,DIRECT");
    if (activeProviders["iran-media"]) ruleSet.add("RULE-SET,iran-media,DIRECT");
    if (activeProviders["iran-gaming"]) ruleSet.add("RULE-SET,iran-gaming,DIRECT");
    if (activeProviders["iran-download"]) ruleSet.add("RULE-SET,iran-download,DIRECT");
    if (activeProviders["iran-other"]) ruleSet.add("RULE-SET,iran-other,DIRECT");

    // 6. Domestic Infrastructure & Fallback Master
    for (let i = 0; i < DOMESTIC_NON_IR_RULES.length; i++) ruleSet.add(DOMESTIC_NON_IR_RULES[i]);
    ruleSet.add("DOMAIN-SUFFIX,ir,DIRECT");

    if (activeProviders["iran-domains"]) ruleSet.add("RULE-SET,iran-domains,DIRECT");
    if (activeProviders["iran-cloud"]) ruleSet.add("RULE-SET,iran-cloud,DIRECT,no-resolve");
    if (activeProviders["iran-ip"]) ruleSet.add("RULE-SET,iran-ip,DIRECT,no-resolve");
    if (activeProviders["iran-asn"]) ruleSet.add("RULE-SET,iran-asn,DIRECT,no-resolve");

    // 7. Network Protections
    if (ENABLE_QUIC_BLOCK) ruleSet.add("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT");

    // 8. Dynamic Routing overrides (Waze Navigation)
    ruleSet.add(`DOMAIN-SUFFIX,waze.com,${defaultProxyGroup}`);
    ruleSet.add(`DOMAIN-KEYWORD,waze,${defaultProxyGroup}`);

    // 9. Process and Sanitize Subscription Rules
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
        const c0 = cleanRule.charCodeAt(0);

        // Fast ASCII check for IP rules ('G'/'g', 'I'/'i')
        if ((c0 === 71 || c0 === 103 || c0 === 73 || c0 === 105) &&
            REGEX_IP_RULE_PREFIX.test(cleanRule) &&
            !REGEX_NO_RESOLVE.test(cleanRule)) {
          cleanRule = `${cleanRule},no-resolve`;
        }

        // Fast ASCII check for MATCH rule ('M'/'m')
        if ((c0 === 77 || c0 === 109) && REGEX_MATCH_RULE.test(cleanRule)) {
          if (!capturedMatchRule && !REGEX_DIRECT_RULE.test(cleanRule)) {
            capturedMatchRule = cleanRule;
          }
        } else if (!REGEX_JUNK_RULES.test(cleanRule)) {
          ruleSet.add(cleanRule);
        }
      }
    }

    ruleSet.add(capturedMatchRule ?? `MATCH,${defaultProxyGroup}`);
    config.rules = Array.from(ruleSet);
  }
}

// ==============================================================================
// 3. PIPELINE ORCHESTRATOR
// ==============================================================================

function main(config, profileName) {
  // 1. Detect and resolve primary proxy group dynamically
  const defaultProxyGroup = ProxyClassifier.resolvePrimary(config["proxy-groups"]);

  // 2. Tune engine parameters and performance flags
  CoreTuner.apply(config);

  // 3. Configure packet sniffer
  config.sniffer = SnifferEngine.generate();

  // 4. Build active rule-providers dictionary
  const activeProviders = ProviderFactory.buildRegistry();
  Object.assign((config["rule-providers"] ??= {}), activeProviders);

  // 5. Configure DNS safely using only active providers
  DnsEngine.configure(config, defaultProxyGroup, activeProviders);

  // 6. Assemble and optimize routing rule hierarchy
  RulesEngine.assemble(config, defaultProxyGroup, activeProviders);

  return config;
}
