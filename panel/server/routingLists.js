'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { domainToASCII } = require('node:url');

const SOURCE_BASE = 'https://raw.githubusercontent.com/itdoginfo/allow-domains/main/';
const MAX_LIST_BYTES = 8 * 1024 * 1024;
const MAX_LIST_DOMAINS = 150000;
const FETCH_TIMEOUT_MS = 15000;

// These files are plain domain lists in allow-domains. The source URL is built
// exclusively from this fixed catalog; callers can never provide an arbitrary
// URL for the panel to fetch.
const ROUTING_LIST_CATALOG = Object.freeze([
  { id: 'russia_inside', label: 'Russia inside', labelRu: 'Россия внутри РФ', description: 'Resources blocked or restricted when accessed from Russia.', descriptionRu: 'Ресурсы, заблокированные или ограниченные при доступе из России.', sourcePath: 'Russia/inside-raw.lst' },
  { id: 'russia_outside', label: 'Russia outside', labelRu: 'Россия вне РФ', description: 'Russian services that require a Russian exit IP.', descriptionRu: 'Российские ресурсы, которым нужен выход с российского IP.', sourcePath: 'Russia/outside-raw.lst' },
  { id: 'anime', label: 'Anime', labelRu: 'Аниме', description: 'Anime category.', descriptionRu: 'Категория Anime.', sourcePath: 'Categories/anime.lst' },
  { id: 'block', label: 'Block', labelRu: 'Блокировки', description: 'Block category.', descriptionRu: 'Категория Block.', sourcePath: 'Categories/block.lst' },
  { id: 'geoblock', label: 'GeoBlock', labelRu: 'GeoBlock', description: 'GeoBlock category.', descriptionRu: 'Категория GeoBlock.', sourcePath: 'Categories/geoblock.lst' },
  { id: 'news', label: 'News', labelRu: 'Новости', description: 'News category.', descriptionRu: 'Категория News.', sourcePath: 'Categories/news.lst' },
  { id: 'porn', label: 'Porn', labelRu: 'Для взрослых', description: 'Porn category.', descriptionRu: 'Категория Porn.', sourcePath: 'Categories/porn.lst' },
  { id: 'hodca', label: 'H.O.D.C.A.', labelRu: 'H.O.D.C.A.', description: 'Hosting providers: Hetzner, OVH, DigitalOcean, Cloudflare, AWS, Akamai.', descriptionRu: 'Хостинг-провайдеры Hetzner, OVH, DigitalOcean, Cloudflare, AWS и Akamai.', sourcePath: 'Categories/hodca.lst' },
  { id: 'cloudflare', label: 'Cloudflare', labelRu: 'Cloudflare', description: 'Cloudflare domains.', descriptionRu: 'Домены сервиса Cloudflare.', sourcePath: 'Services/cloudflare.lst' },
  { id: 'discord', label: 'Discord', labelRu: 'Discord', description: 'Discord domains only; IP subnets are not included.', descriptionRu: 'Домены Discord; IP-подсети в этот список не входят.', sourcePath: 'Services/discord.lst' },
  { id: 'hdrezka', label: 'HDRezka', labelRu: 'HDRezka', description: 'HDRezka domains.', descriptionRu: 'Домены HDRezka.', sourcePath: 'Services/hdrezka.lst' },
  { id: 'meta', label: 'Meta', labelRu: 'Meta', description: 'Meta services domains.', descriptionRu: 'Домены сервисов Meta.', sourcePath: 'Services/meta.lst' },
  { id: 'telegram', label: 'Telegram', labelRu: 'Telegram', description: 'Telegram domains only; IP subnets are not included.', descriptionRu: 'Домены Telegram; IP-подсети не входят.', sourcePath: 'Services/telegram.lst' },
  { id: 'tiktok', label: 'TikTok', labelRu: 'TikTok', description: 'TikTok domains.', descriptionRu: 'Домены TikTok.', sourcePath: 'Services/tiktok.lst' },
  { id: 'twitter', label: 'Twitter / X', labelRu: 'Twitter / X', description: 'Twitter / X domains.', descriptionRu: 'Домены Twitter / X.', sourcePath: 'Services/twitter.lst' },
  { id: 'youtube', label: 'YouTube', labelRu: 'YouTube', description: 'YouTube domains.', descriptionRu: 'Домены YouTube.', sourcePath: 'Services/youtube.lst' },
  { id: 'google_meet', label: 'Google Meet', labelRu: 'Google Meet', description: 'Google Meet domains only; IP subnets are not included.', descriptionRu: 'Домены Google Meet; IP-подсети не входят.', sourcePath: 'Services/google_meet.lst' },
]);

const LIST_BY_ID = new Map(ROUTING_LIST_CATALOG.map(item => [item.id, item]));

function normalizeDomainList(input, { allowEmpty = false, maxDomains = MAX_LIST_DOMAINS } = {}) {
  const text = Array.isArray(input) ? input.join('\n') : String(input || '');
  const domains = new Set();
  const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    let raw = lines[i].trim();
    if (!raw || raw.startsWith('#')) continue;
    raw = raw.split('#', 1)[0].trim();
    if (!raw) continue;

    // Accept common suffix spellings while storing a canonical hostname.
    raw = raw.replace(/^\*\./, '').replace(/^\./, '').replace(/\.$/, '').toLowerCase();
    const ascii = domainToASCII(raw).toLowerCase();
    const labels = ascii.split('.');
    // A leading-dot entry such as `.ua` is valid in allow-domains and means
    // the whole TLD suffix, so single-label suffixes are intentionally allowed.
    const valid = ascii.length <= 253 && labels.length >= 1 && labels.every(label =>
      label.length >= 1 && label.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label));
    if (!valid) throw new Error(`Invalid domain on line ${i + 1}`);
    domains.add(ascii);
    if (domains.size > maxDomains) throw new Error(`Domain list exceeds ${maxDomains} entries`);
  }

  const result = [...domains].sort();
  if (!allowEmpty && result.length === 0) throw new Error('Domain list is empty');
  return result;
}

function createRoutingListStore({ cacheDir, fetchImpl = globalThis.fetch, timeoutMs = FETCH_TIMEOUT_MS } = {}) {
  if (!cacheDir) throw new Error('cacheDir is required');
  if (typeof fetchImpl !== 'function') throw new Error('fetchImpl must be a function');

  const attempts = new Map();
  const inflight = new Map();
  const memoryCache = new Map();

  function cachePath(id) {
    if (!LIST_BY_ID.has(id)) throw new Error('Unknown routing list');
    return path.join(cacheDir, `${id}.json`);
  }

  function read(id) {
    try {
      const target = cachePath(id);
      const stat = fs.statSync(target);
      const remembered = memoryCache.get(id);
      if (remembered && remembered.mtimeMs === stat.mtimeMs && remembered.size === stat.size) return remembered.record;
      const record = JSON.parse(fs.readFileSync(target, 'utf8'));
      if (!record || record.id !== id || !Array.isArray(record.domains) || !record.domains.length) return null;
      const domains = normalizeDomainList(record.domains);
      const normalized = { ...record, domains };
      memoryCache.set(id, { mtimeMs: stat.mtimeMs, size: stat.size, record: normalized });
      return normalized;
    } catch {
      memoryCache.delete(id);
      return null;
    }
  }

  function getDomains(ids) {
    const combined = new Set();
    for (const id of Array.isArray(ids) ? ids : []) {
      if (!LIST_BY_ID.has(id)) continue;
      const record = read(id);
      if (record) for (const domain of record.domains) combined.add(domain);
    }
    return [...combined].sort();
  }

  function getStatus(ids = [], language = 'ru') {
    const selected = new Set(Array.isArray(ids) ? ids : []);
    return ROUTING_LIST_CATALOG.map(({ id, label, labelRu, description, descriptionRu, sourcePath }) => {
      const record = read(id);
      const attempt = attempts.get(id) || {};
      return {
        id,
        label: language === 'en' ? label : labelRu,
        description: language === 'en' ? description : descriptionRu,
        selected: selected.has(id),
        available: !!record,
        count: record ? record.domains.length : 0,
        fetchedAt: record ? record.fetchedAt : null,
        revision: record ? record.revision : null,
        sourceUrl: SOURCE_BASE + sourcePath,
        lastAttemptAt: attempt.at || null,
        lastError: attempt.error || null,
      };
    });
  }

  async function refresh(id) {
    const item = LIST_BY_ID.get(id);
    if (!item) return { id, ok: false, error: 'Unknown routing list' };
    if (inflight.has(id)) return inflight.get(id);

    const work = (async () => {
      const at = new Date().toISOString();
      try {
        const response = await fetchImpl(SOURCE_BASE + item.sourcePath, {
          headers: { 'User-Agent': 'RIXXX-Panel-Routing-Lists' },
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!response || !response.ok) throw new Error(`Source returned HTTP ${response ? response.status : 'error'}`);
        const declaredLength = Number(response.headers && response.headers.get && response.headers.get('content-length'));
        if (Number.isFinite(declaredLength) && declaredLength > MAX_LIST_BYTES) throw new Error('Source list is too large');
        const text = await response.text();
        if (Buffer.byteLength(text, 'utf8') > MAX_LIST_BYTES) throw new Error('Source list is too large');
        const domains = normalizeDomainList(text);
        const payload = {
          id,
          sourceUrl: SOURCE_BASE + item.sourcePath,
          fetchedAt: at,
          revision: crypto.createHash('sha256').update(domains.join('\n')).digest('hex'),
          domains,
        };
        fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
        const target = cachePath(id);
        const tmp = `${target}.${process.pid}.new`;
        try {
          fs.writeFileSync(tmp, JSON.stringify(payload), { mode: 0o600 });
          fs.renameSync(tmp, target);
        } catch (err) {
          try { fs.unlinkSync(tmp); } catch {}
          throw err;
        }
        memoryCache.delete(id);
        attempts.set(id, { at, error: null });
        return { id, ok: true, count: domains.length, fetchedAt: at, revision: payload.revision };
      } catch (err) {
        const message = String(err && err.message || 'List update failed').slice(0, 240);
        attempts.set(id, { at, error: message });
        const cached = read(id);
        return { id, ok: false, error: message, usingCached: !!cached, count: cached ? cached.domains.length : 0 };
      } finally {
        inflight.delete(id);
      }
    })();
    inflight.set(id, work);
    return work;
  }

  async function refreshMany(ids) {
    const unique = [...new Set((Array.isArray(ids) ? ids : []).filter(id => LIST_BY_ID.has(id)))];
    return Promise.all(unique.map(refresh));
  }

  return { getDomains, getStatus, refresh, refreshMany };
}

function normalizeSplitRoutingConfig(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('splitRouting must be an object');
  // `enabled` was used by the first global prototype. Keep accepting it in old
  // configs, but routing is now enabled per user and this module stores only
  // the shared domain-list policy.
  if (value.enabled !== undefined && typeof value.enabled !== 'boolean') throw new Error('splitRouting.enabled must be a boolean');
  const listIds = value.lists === undefined ? [] : value.lists;
  if (!Array.isArray(listIds)) throw new Error('splitRouting.lists must be an array');
  const unknown = listIds.find(id => typeof id !== 'string' || !LIST_BY_ID.has(id));
  if (unknown !== undefined) throw new Error(`Unknown routing list: ${String(unknown).slice(0, 80)}`);
  const customDomains = normalizeDomainList(value.customDomains || [], { allowEmpty: true, maxDomains: 1000 });
  return { lists: [...new Set(listIds)], customDomains };
}

module.exports = {
  ROUTING_LIST_CATALOG,
  createRoutingListStore,
  normalizeDomainList,
  normalizeSplitRoutingConfig,
};
