// ==============================================================================
// 0. USER CONTROL PANEL
// ==============================================================================

const ENABLE_SAFE_SEARCH = false;
const ENABLE_QUIC_BLOCK = true;

// "light" | "normal" | "pro" | "proplus" | "ultimate"
const HAGEZI_TIER = "proplus";
const ENABLE_HAGEZI_TIF = false;       
const ENABLE_PORN_FILTER = true;       
const ENABLE_GAMBLING_FILTER = true;   

const ENABLE_NATIVE_TRACKERS = false;

const ENABLE_IRAN_ADS = true;          
const ENABLE_IRAN_SECURITY = true;     
const ENABLE_IRAN_DIRECT = true;       

const SECURITY_INTERVAL = 24 * 3600;   
const STANDARD_INTERVAL = 48 * 3600;   
const GEO_UPDATE_HOURS = 72;           

// ==============================================================================
// 1. DATASETS, REGEX & CONSTANTS
// ==============================================================================

const CHOCOLATE_BASE_URL = "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-clash-rules@release/";
const HAGEZI_MRS_URL = "https://cdn.jsdelivr.net/gh/MiHomoer/MiHomo-Hagezi@release/";

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

const FROZEN_GEOX_URL = Object.freeze({
  geoip: `${CHOCOLATE_BASE_URL}geoip.metadb`,
  mmdb: `${CHOCOLATE_BASE_URL}geoip.metadb`
});

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

  dns["fake-ip-filter"] = [
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
  ];

  dns.nameserver = DOH_ENDPOINTS.map(url => `${url}#${defaultProxyGroup}`);

  const nsPolicy = MANUAL_DOMAINS.reduce((acc, domain) => {
    acc[`+.${domain}`] = PURE_DOMESTIC_RESOLVERS;
    return acc;
  }, {
    "+.ir": PURE_DOMESTIC_RESOLVERS,
    "rule-set:ir": PURE_DOMESTIC_RESOLVERS,
    "supl.google.com": PURE_DOMESTIC_RESOLVERS,
    "+.supl.google.com": PURE_DOMESTIC_RESOLVERS
  });
  Object.assign((dns["nameserver-policy"] ??= {}), nsPolicy);

  const providers = {};

  providers["hagezi-main"] = makeProvider(
    `hagezi-${HAGEZI_TIER}`, "domain", "mrs",
    `${HAGEZI_MRS_URL}${SELECTED_HAGEZI_NAME}.mrs`, STANDARD_INTERVAL
  );

  if (ENABLE_PORN_FILTER) {
    providers["nsfw"] = makeProvider("nsfw", "domain", "mrs", `${CHOCOLATE_BASE_URL}nsfw.mrs`, STANDARD_INTERVAL);
  }

  if (ENABLE_NATIVE_TRACKERS) {
    providers["hagezi-apple"] = makeProvider("HageziApple", "domain", "mrs", `${HAGEZI_MRS_URL}HageziApple.mrs`, STANDARD_INTERVAL);
    providers["hagezi-windows"] = makeProvider("HageziWindows", "domain", "mrs", `${HAGEZI_MRS_URL}HageziWindows.mrs`, STANDARD_INTERVAL);
  }

  if (ENABLE_IRAN_ADS) {
    providers["ads-ir"] = makeProvider("ads-ir", "domain", "mrs", `${CHOCOLATE_BASE_URL}ads.mrs`, STANDARD_INTERVAL);
  }

  if (ENABLE_IRAN_SECURITY) {
    providers["malware-ip"] = makeProvider("malware-ip", "ipcidr", "mrs", `${CHOCOLATE_BASE_URL}malware-ip.mrs`, SECURITY_INTERVAL);
    providers["phishing-ip"] = makeProvider("phishing-ip", "ipcidr", "mrs", `${CHOCOLATE_BASE_URL}phishing-ip.mrs`, SECURITY_INTERVAL);
  }

  if (ENABLE_IRAN_DIRECT) {
    providers["ir"] = makeProvider("ir", "domain", "mrs", `${CHOCOLATE_BASE_URL}ir.mrs`, STANDARD_INTERVAL);
    providers["ircidr"] = makeProvider("ircidr", "ipcidr", "mrs", `${CHOCOLATE_BASE_URL}ircidr.mrs`, STANDARD_INTERVAL);
    providers["irasn"] = makeProvider("irasn", "classical", "text", `${CHOCOLATE_BASE_URL}irasn.txt`, STANDARD_INTERVAL);
    providers["apps"] = makeProvider("apps", "classical", "text", `${CHOCOLATE_BASE_URL}apps.txt`, STANDARD_INTERVAL);
  }

  Object.assign((config["rule-providers"] ??= {}), providers);

  const ruleSet = new Set();

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

  ruleSet.add("DST-PORT,6881-6889,DIRECT");
  ruleSet.add("DST-PORT,51413,DIRECT");

  ruleSet.add("RULE-SET,hagezi-main,REJECT");
  if (ENABLE_IRAN_ADS) ruleSet.add("RULE-SET,ads-ir,REJECT");
  if (ENABLE_PORN_FILTER) ruleSet.add("RULE-SET,nsfw,REJECT");

  if (ENABLE_IRAN_SECURITY) {
    ruleSet.add("RULE-SET,malware-ip,REJECT,no-resolve");
    ruleSet.add("RULE-SET,phishing-ip,REJECT,no-resolve");
  }

  if (ENABLE_NATIVE_TRACKERS) {
    ruleSet.add("RULE-SET,hagezi-apple,REJECT");
    ruleSet.add("RULE-SET,hagezi-windows,REJECT");
  }

  for (let i = 0; i < MANUAL_DOMAINS.length; i++) {
    ruleSet.add(`DOMAIN-SUFFIX,${MANUAL_DOMAINS[i]},DIRECT`);
  }
  ruleSet.add("DOMAIN-SUFFIX,ir,DIRECT");

  if (ENABLE_IRAN_DIRECT) {
    ruleSet.add("RULE-SET,apps,DIRECT,no-resolve");
    ruleSet.add("RULE-SET,ir,DIRECT");
    ruleSet.add("RULE-SET,ircidr,DIRECT,no-resolve");
    ruleSet.add("RULE-SET,irasn,DIRECT,no-resolve");
    ruleSet.add("GEOIP,IR,DIRECT,no-resolve");
  }

  if (ENABLE_QUIC_BLOCK) {
    ruleSet.add("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT");
  }

  ruleSet.add(`DOMAIN-SUFFIX,waze.com,${defaultProxyGroup}`);
  ruleSet.add(`DOMAIN-KEYWORD,waze,${defaultProxyGroup}`);

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

  ruleSet.add(capturedMatchRule ?? `MATCH,${defaultProxyGroup}`);
  config.rules = Array.from(ruleSet);

  return config;
  }
