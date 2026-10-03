// ─────────────────────────────────────────────────────────────────────────────
// Split routing lists: normalization, persistent last-good cache, profile rules,
// settings validation, and Karing protocol-scoped subscriptions.
// ─────────────────────────────────────────────────────────────────────────────
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');
const routing = require(path.join(ROOT, 'panel/server/routingLists.js'));
const serverSrc = fs.readFileSync(path.join(ROOT, 'panel/server/index.js'), 'utf8');
const htmlSrc = fs.readFileSync(path.join(ROOT, 'panel/public/index.html'), 'utf8');
const appSrc = fs.readFileSync(path.join(ROOT, 'panel/public/app.js'), 'utf8');
const ru = JSON.parse(fs.readFileSync(path.join(ROOT, 'panel/public/locales/ru.json'), 'utf8'));
const en = JSON.parse(fs.readFileSync(path.join(ROOT, 'panel/public/locales/en.json'), 'utf8'));

let pass = 0, fail = 0;
const ok = (condition, message) => {
  if (condition) { pass++; console.log('  ✓ ' + message); }
  else { fail++; console.log('  ✗ ' + message); }
};

async function main() {
  console.log('\n[split-routing] domain list normalization and config validation');
  const normalized = routing.normalizeDomainList('\uFEFF# source\n.ua\n.Example.COM\n*.sub.example.com\nexample.com\n');
  ok(normalized.join(',') === 'example.com,sub.example.com,ua', 'normalizes case/suffix syntax, accepts source TLD suffixes, and removes duplicates');
  let invalidRejected = false;
  try { routing.normalizeDomainList('not a domain'); } catch { invalidRejected = true; }
  ok(invalidRejected, 'rejects malformed domain lines instead of caching a partial list');
  const splitConfig = routing.normalizeSplitRoutingConfig({
    enabled: true,
    lists: ['youtube', 'russia_inside', 'youtube'],
    customDomains: ['Example.org', '*.Sub.Example.org']
  });
  ok(!Object.hasOwn(splitConfig, 'enabled') && splitConfig.lists.join(',') === 'youtube,russia_inside', 'validates and de-duplicates selected source list ids without a global routing switch');
  ok(splitConfig.customDomains.join(',') === 'example.org,sub.example.org', 'normalizes custom domains for profile generation');
  let unknownRejected = false;
  try { routing.normalizeSplitRoutingConfig({ enabled: true, lists: ['https://attacker.invalid/list'] }); } catch { unknownRejected = true; }
  ok(unknownRejected, 'rejects arbitrary list ids, preventing SSRF source injection');

  console.log('\n[split-routing] source refresh and last-known-good cache');
  const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rixxx-routing-lists-'));
  let fetchMode = 'ok';
  const store = routing.createRoutingListStore({
    cacheDir,
    fetchImpl: async url => {
      if (fetchMode === 'down') return { ok: false, status: 503, headers: { get: () => null }, text: async () => '' };
      if (!String(url).startsWith('https://raw.githubusercontent.com/itdoginfo/allow-domains/main/'))
        throw new Error('unexpected source URL');
      const body = fetchMode === 'updated' ? 'Changed.com\nsub.example.com\n' : 'Example.com\nsub.example.com\n';
      return { ok: true, status: 200, headers: { get: () => String(Buffer.byteLength(body)) }, text: async () => body };
    }
  });
  const firstRefresh = await store.refresh('youtube');
  ok(firstRefresh.ok && firstRefresh.count === 2, 'downloads and caches a valid source list');
  ok(store.getDomains(['youtube']).join(',') === 'example.com,sub.example.com', 'profile builder can read the cached domain list');
  fetchMode = 'updated';
  const updatedRefresh = await store.refresh('youtube');
  ok(updatedRefresh.ok && store.getDomains(['youtube']).join(',') === 'changed.com,sub.example.com', 'successful refresh immediately replaces the in-memory cached domains');
  fetchMode = 'down';
  const failedRefresh = await store.refresh('youtube');
  ok(!failedRefresh.ok && failedRefresh.usingCached, 'failed source refresh reports and retains the previous cache');
  ok(store.getDomains(['youtube']).join(',') === 'changed.com,sub.example.com', 'last-known-good list remains available after upstream failure');
  fs.rmSync(cacheDir, { recursive: true, force: true });

  console.log('\n[split-routing] generated Karing profile and API/UI contracts');
  function extractFn(name) {
    const start = serverSrc.indexOf(`function ${name}(`);
    if (start < 0) throw new Error(`missing ${name}`);
    let p = serverSrc.indexOf('(', start), depth = 0, j = p;
    for (; j < serverSrc.length; j++) {
      if (serverSrc[j] === '(') depth++;
      else if (serverSrc[j] === ')' && --depth === 0) { j++; break; }
    }
    let i = serverSrc.indexOf('{', j), braces = 0;
    for (; i < serverSrc.length; i++) {
      if (serverSrc[i] === '{') braces++;
      else if (serverSrc[i] === '}' && --braces === 0) { i++; break; }
    }
    return serverSrc.slice(start, i);
  }
  const sandbox = {
    parseUserRow: user => ({
      ...user,
      protocols: user.protocols || [],
      domainRouting: user.domain_routing === true || Number(user.domain_routing) === 1,
    }),
    pickMieruPort: () => 2012,
    enabledBonusUrls: () => [],
    bonusUrlToSingboxOutbound: () => null,
    applyServerFlag: value => value,
    routingListStore: {
      getDomains: ids => ids.includes('youtube') ? ['youtube.example', 'blocked.example'] : [],
      getStatus: ids => ids.map(id => ({ id, selected: true, available: sandboxCacheReady }))
    },
    cfg: {
      domain: 'panel.example', serverIp: '203.0.113.1', naivePort: 443,
      mieruPortStart: 2012, mieruPortEnd: 2022, hy2Port: 443,
      stack: { hy2: true }, splitRouting: { lists: [], customDomains: [] },
      serverFlag: ''
    },
    parseInt, parseFloat, Number, Math, String, Array, JSON, URL, URLSearchParams,
    encodeURIComponent, decodeURIComponent, crypto: require('node:crypto'), Buffer,
  };
  sandbox.normalizeBonusLinks = () => [];
  vm.createContext(sandbox);
  vm.runInContext(extractFn('parseUserRow'), sandbox);
  let sandboxCacheReady = true;
  vm.runInContext(extractFn('buildProxyOutbounds'), sandbox);
  vm.runInContext(extractFn('buildSingboxConfig'), sandbox);
  sandbox.user = { username: 'alice', password: 'test-password', protocols: ['naive', 'mieru', 'hy2'], domain_routing: 0 };
  ok(vm.runInContext("parseUserRow({ domain_routing: 1 }).domainRouting", sandbox) === true &&
     vm.runInContext("parseUserRow({ domain_routing: 0 }).domainRouting", sandbox) === false,
     'database routing flag is normalized to a boolean for user profiles');

  const legacyProfile = vm.runInContext('buildSingboxConfig(user)', sandbox);
  ok(legacyProfile.route.final === 'select' && legacyProfile.route.rules.length === 1, 'unchecked per-user option sends all Karing traffic through the proxy');

  sandbox.cfg.splitRouting = {
    lists: ['youtube'], customDomains: ['custom.example']
  };
  const stillFullProxy = vm.runInContext('buildSingboxConfig(user)', sandbox);
  ok(stillFullProxy.route.final === 'select' && !stillFullProxy.route.rules.some(rule => rule.domain_suffix), 'global list configuration alone does not enable routing for unchecked users');
  sandbox.user.domain_routing = 1;
  const splitProfile = vm.runInContext('buildSingboxConfig(user)', sandbox);
  const proxyRule = splitProfile.route.rules.find(rule => Array.isArray(rule.domain_suffix));
  ok(splitProfile.route.final === 'direct', 'split-routing profile sends unlisted traffic direct by default');
  ok(proxyRule && proxyRule.outbound === 'select', 'selected domain list uses the proxy selector');
  ok(proxyRule && ['youtube.example', 'blocked.example', 'custom.example'].every(d => proxyRule.domain_suffix.includes(d)), 'cached and custom domains are embedded in the single profile response');
  ok(proxyRule && splitProfile.route.rules.indexOf(proxyRule) === 1 && splitProfile.route.final === 'direct', 'selected-domain proxy rule takes precedence over the direct default route');
  sandboxCacheReady = false;
  const coldCacheProfile = vm.runInContext('buildSingboxConfig(user)', sandbox);
  ok(coldCacheProfile.route.final === 'select', 'when a selected list has no cached copy, unlisted destinations retain proxy-by-default as a safe fallback');
  sandboxCacheReady = true;

  const naiveProfile = vm.runInContext("buildSingboxConfig(user, { protocol: 'naive' })", sandbox);
  const naiveTypes = naiveProfile.outbounds.map(outbound => outbound.type);
  ok(naiveTypes.includes('naive') && !naiveTypes.includes('mieru') && !naiveTypes.includes('hysteria2'), 'protocol-scoped Karing profile contains only the requested proxy protocol');
  ok(naiveProfile.route.final === 'direct' && naiveProfile.route.rules.some(rule => rule.domain_suffix && rule.outbound === 'select'), 'protocol-scoped profile retains the same split-routing policy');

  ok(/app\.get\('\/api\/routing-lists\/status', requireAuth/.test(serverSrc), 'cache status API is admin authenticated');
  ok(/app\.post\('\/api\/routing-lists\/refresh', requireAuth, async/.test(serverSrc), 'manual refresh API is admin authenticated');
  ok(/cron\.schedule\('23 4 \* \* \*'/.test(serverSrc), 'selected lists refresh on a daily UTC schedule');
  ok(/app\.get\('\/sub\/:token', subLimiter, async/.test(serverSrc) && /protocolFilter \? 'karing'/.test(serverSrc), 'protocol-specific subscription always emits Karing JSON');
  ok(/new URLSearchParams\(\{ client: 'karing' \}\)/.test(serverSrc), 'generated Karing links explicitly request JSON format even in all-protocol mode');
  ok(/domain_routing INTEGER NOT NULL DEFAULT 0/.test(serverSrc) && /domain_routing=excluded\.domain_routing/.test(serverSrc) &&
     /domain_routing: domainRouting === true \? 1 : 0/.test(serverSrc) &&
     /domainRouting: !!el\('u-domain-routing'\)\?\.checked/.test(appSrc), 'per-user opt-in is stored and sent by the user editor');
  ok(/id="u-domain-routing"/.test(htmlSrc) && /id="split-routing-lists"/.test(htmlSrc) && /data-routing-list/.test(appSrc) && /save-split-routing/.test(appSrc), 'user checkbox and shared domain-list settings are present');
  ok(ru.users.domainRoutingLabel && en.users.domainRoutingLabel && ru.settings.splitRoutingTitle && en.settings.splitRoutingTitle && ru.config.subProfileAll && en.config.subProfileAll, 'Russian and English strings exist for per-user routing/profile options');

  console.log(`\n[split-routing] ${pass} passed, ${fail} failed`);
  process.exitCode = fail ? 1 : 0;
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
