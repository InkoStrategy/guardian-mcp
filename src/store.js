'use strict';

/**
 * Key-value store with a Redis-like command subset.
 *
 * Two adapters:
 *   - Upstash / Vercel KV over REST (persistent, shared by every function instance).
 *     Enabled by UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN, or the
 *     KV_REST_API_URL + KV_REST_API_TOKEN pair that the Vercel KV integration injects.
 *   - In-memory (per process) fallback so the service always works. It is
 *     explicitly reported as non-persistent so operators know the shared
 *     threat registry and session profiles do not survive cold starts.
 *
 * Supported commands: HINCRBY, HSET, HSETNX, HGETALL, HGET, SADD, SCARD, SMEMBERS,
 * EXPIRE, TTL, RPUSH, LTRIM, LRANGE, GET, SET (with EX), DEL, INCRBY, EXISTS, ZADD, ZRANGE, ZCARD.
 * Every adapter exposes `pipeline(commands)` returning results in order.
 */

const STORE_TIMEOUT_MS = Number.parseInt(process.env.STORE_TIMEOUT_MS || '2500', 10);

// ---------------------------------------------------------------------------
// In-memory adapter
// ---------------------------------------------------------------------------

function createMemoryStore() {
  const data = new Map(); // key -> { type, value, expiresAt }

  function now() {
    return Date.now();
  }
  function live(key) {
    const e = data.get(key);
    if (!e) return null;
    if (e.expiresAt && e.expiresAt <= now()) {
      data.delete(key);
      return null;
    }
    return e;
  }
  function ensure(key, type) {
    let e = live(key);
    if (!e) {
      e = { type, value: type === 'hash' ? new Map() : type === 'set' ? new Set() : type === 'list' ? [] : type === 'zset' ? new Map() : null, expiresAt: 0 };
      data.set(key, e);
    }
    if (e.type !== type) throw new Error('WRONGTYPE for ' + key);
    return e;
  }

  function exec(cmd) {
    const [name, key, ...args] = cmd;
    switch (String(name).toUpperCase()) {
      case 'HINCRBY': {
        const e = ensure(key, 'hash');
        const v = Number(e.value.get(args[0]) || 0) + Number(args[1]);
        e.value.set(args[0], String(v));
        return v;
      }
      case 'HSET': {
        const e = ensure(key, 'hash');
        let added = 0;
        for (let i = 0; i < args.length; i += 2) {
          if (!e.value.has(args[i])) added += 1;
          e.value.set(args[i], String(args[i + 1]));
        }
        return added;
      }
      case 'HSETNX': {
        const e = ensure(key, 'hash');
        if (e.value.has(args[0])) return 0;
        e.value.set(args[0], String(args[1]));
        return 1;
      }
      case 'HGET': {
        const e = live(key);
        return e && e.type === 'hash' && e.value.has(args[0]) ? e.value.get(args[0]) : null;
      }
      case 'HGETALL': {
        const e = live(key);
        if (!e || e.type !== 'hash') return [];
        const out = [];
        for (const [k, v] of e.value) out.push(k, v);
        return out;
      }
      case 'SADD': {
        const e = ensure(key, 'set');
        let added = 0;
        for (const m of args) if (!e.value.has(String(m))) { e.value.add(String(m)); added += 1; }
        return added;
      }
      case 'SCARD': {
        const e = live(key);
        return e && e.type === 'set' ? e.value.size : 0;
      }
      case 'SMEMBERS': {
        const e = live(key);
        return e && e.type === 'set' ? Array.from(e.value) : [];
      }
      case 'RPUSH': {
        const e = ensure(key, 'list');
        for (const m of args) e.value.push(String(m));
        return e.value.length;
      }
      case 'LTRIM': {
        const e = live(key);
        if (!e || e.type !== 'list') return 'OK';
        const start = Number(args[0]);
        const stop = Number(args[1]);
        const len = e.value.length;
        const s = start < 0 ? Math.max(len + start, 0) : start;
        const t = stop < 0 ? len + stop : Math.min(stop, len - 1);
        e.value = s > t ? [] : e.value.slice(s, t + 1);
        return 'OK';
      }
      case 'LRANGE': {
        const e = live(key);
        if (!e || e.type !== 'list') return [];
        const len = e.value.length;
        const start = Number(args[0]);
        const stop = Number(args[1]);
        const s = start < 0 ? Math.max(len + start, 0) : start;
        const t = stop < 0 ? len + stop : Math.min(stop, len - 1);
        return s > t ? [] : e.value.slice(s, t + 1);
      }
      case 'ZADD': {
        const e = ensure(key, 'zset');
        let added = 0;
        for (let i = 0; i < args.length; i += 2) {
          if (!e.value.has(String(args[i + 1]))) added += 1;
          e.value.set(String(args[i + 1]), Number(args[i]));
        }
        return added;
      }
      case 'ZRANGE': {
        const e = live(key);
        if (!e || e.type !== 'zset') return [];
        const sorted = Array.from(e.value.entries()).sort((a, b) => a[1] - b[1] || (a[0] < b[0] ? -1 : 1));
        const rev = args.includes('REV');
        const arr = rev ? sorted.reverse() : sorted;
        const len = arr.length;
        const start = Number(args[0]);
        const stop = Number(args[1]);
        const s = start < 0 ? Math.max(len + start, 0) : start;
        const t = stop < 0 ? len + stop : Math.min(stop, len - 1);
        const slice = s > t ? [] : arr.slice(s, t + 1);
        return args.includes('WITHSCORES') ? slice.flatMap(([m, sc]) => [m, String(sc)]) : slice.map(([m]) => m);
      }
      case 'ZCARD': {
        const e = live(key);
        return e && e.type === 'zset' ? e.value.size : 0;
      }
      case 'GET': {
        const e = live(key);
        return e && e.type === 'string' ? e.value : null;
      }
      case 'SET': {
        const e = { type: 'string', value: String(args[0]), expiresAt: 0 };
        const exIdx = args.findIndex((a) => String(a).toUpperCase() === 'EX');
        if (exIdx !== -1) e.expiresAt = now() + Number(args[exIdx + 1]) * 1000;
        data.set(key, e);
        return 'OK';
      }
      case 'INCRBY': {
        const e = live(key) || { type: 'string', value: '0', expiresAt: 0 };
        e.value = String(Number(e.value) + Number(args[0]));
        data.set(key, e);
        return Number(e.value);
      }
      case 'EXPIRE': {
        const e = live(key);
        if (!e) return 0;
        e.expiresAt = now() + Number(args[0]) * 1000;
        return 1;
      }
      case 'TTL': {
        const e = live(key);
        if (!e) return -2;
        return e.expiresAt ? Math.max(0, Math.round((e.expiresAt - now()) / 1000)) : -1;
      }
      case 'EXISTS':
        return live(key) ? 1 : 0;
      case 'DEL': {
        let n = 0;
        for (const k of [key].concat(args)) if (data.delete(k)) n += 1;
        return n;
      }
      default:
        throw new Error('Unsupported command ' + name);
    }
  }

  return {
    kind: 'memory',
    persistent: false,
    async command(...cmd) {
      return exec(cmd);
    },
    async pipeline(commands) {
      return commands.map((c) => exec(c));
    },
    _clear() {
      data.clear();
    },
    _size() {
      return data.size;
    },
  };
}

// ---------------------------------------------------------------------------
// Upstash / Vercel KV REST adapter
// ---------------------------------------------------------------------------

function createUpstashStore(url, token) {
  const base = url.replace(/\/+$/, '');
  async function post(path, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), STORE_TIMEOUT_MS);
    try {
      const res = await fetch(base + path, {
        method: 'POST',
        headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      const json = await res.json();
      if (!res.ok) throw new Error('store ' + res.status + ': ' + (json.error || JSON.stringify(json)));
      return json;
    } finally {
      clearTimeout(timer);
    }
  }
  return {
    kind: 'upstash',
    persistent: true,
    async command(...cmd) {
      const json = await post('', cmd.map(String));
      if (json.error) throw new Error('store: ' + json.error);
      return json.result;
    },
    async pipeline(commands) {
      const json = await post('/pipeline', commands.map((c) => c.map(String)));
      return json.map((r) => {
        if (r.error) throw new Error('store: ' + r.error);
        return r.result;
      });
    },
  };
}

// ---------------------------------------------------------------------------

let singleton = null;

function storeConfig(env) {
  env = env || process.env;
  const url = env.UPSTASH_REDIS_REST_URL || env.KV_REST_API_URL || '';
  const token = env.UPSTASH_REDIS_REST_TOKEN || env.KV_REST_API_TOKEN || '';
  return url && token ? { url, token } : null;
}

function getStore(env) {
  if (singleton) return singleton;
  const cfg = storeConfig(env);
  singleton = cfg ? createUpstashStore(cfg.url, cfg.token) : createMemoryStore();
  return singleton;
}

function hashToObject(flat) {
  const out = {};
  if (Array.isArray(flat)) {
    for (let i = 0; i < flat.length; i += 2) out[flat[i]] = flat[i + 1];
  } else if (flat && typeof flat === 'object') {
    Object.assign(out, flat);
  }
  return out;
}

module.exports = { createMemoryStore, createUpstashStore, getStore, storeConfig, hashToObject, STORE_TIMEOUT_MS };
