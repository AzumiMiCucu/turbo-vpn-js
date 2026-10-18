#!/usr/bin/env node
/**
 * Turbo VPN — API client + generator config VPN
 * ============================================================
 * Semua nilai di file ini berasal dari hasil analisis APK
 * "Turbo VPN v4.0.3.1 (Premium) (Mod).apk"
 * (sha256 edfe5c8c978960001e7ed916dc0a96900f15f6e1d046580bd0c26bfd56462cfa,
 *  package free.vpn.unblock.proxy.turbovpn, versionCode 2023121501).
 *
 * Pohon bukti (evidence) utama:
 *   co/allconnected/lib/net/y/k/c.java        -> deklarasi endpoint Retrofit
 *   co/allconnected/lib/net/y/k/d.java        -> pemanggil "/mms/serverlist/v2/servers_list"
 *   co/allconnected/lib/net/y/j/a.java        -> orkestrasi request, gzip, enkripsi, dekripsi
 *   co/allconnected/lib/w/h.java              -> AES-128-ECB/PKCS5 + base64
 *   co/allconnected/lib/w/x.java              -> header X-Auth-Token / X-Request-Digest
 *   co/allconnected/lib/w/q.java              -> daftar base URL ("proxy") + fallback
 *   co/allconnected/lib/openvpn/NativeUtils.java + libopvpnutil.so -> kunci API
 *   assets/built_in_proxy.json                -> kandidat host API
 *
 * ------------------------------------------------------------------
 * RINGKASAN PROTOKOL
 * ------------------------------------------------------------------
 * 1. Pilih satu BASE URL dari DEFAULT_BASES (asset built_in_proxy.json
 *    + fallback hardcoded https://sdk.allconnected.in/).
 * 2. POST body JSON dienkripsi AES-128-ECB/PKCS5 (kunci = 16 karakter
 *    pertama apiCipherKey) lalu di-base64. Isi > 512 byte akan digzip
 *    dulu dan diberi header X-Content-Encoding: gzip.
 * 3. Header wajib:
 *      X-Auth-Token     = SHA1(hex)  dari rantai string di authToken()
 *      X-Request-Digest = MD5(hex)   dari body plaintext
 *      X-Nonce, X-App-Type, X-App-Package-Name, X-App-Ver-Code,
 *      X-App-Ver-Name, X-Country, X-Device-Model, X-Device-Name,
 *      Accept-Language, User-Agent, X-Accept-Encoding
 * 4. Kalau response punya header X-Response-Digest, body-nya base64
 *    hasil AES (kadang digzip) -> didekripsi dengan apiCipherKey.
 *
 * Endpoint penting:
 *   POST /mms/serverlist/v2/servers_list   -> daftar server + kredensial
 *   POST /mms/config/v2/files/<template_id> -> template .ovpn / file config
 *   POST /mms/account/v2/activate          -> aktivasi user (opsional)
 *   POST /mms/account/v2/status            -> kuota / sisa
 *
 * ------------------------------------------------------------------
 * PENGGUNAAN
 * ------------------------------------------------------------------
 *   node turbovpn-api.mjs servers [CC]     daftar server (opsional filter negara)
 *   node turbovpn-api.mjs nodes  [CC]      URI siap pakai (ss:// / vless://)
 *   node turbovpn-api.mjs ovpn [host_ip]   profil OpenVPN lengkap
 *   node turbovpn-api.mjs ipsec            kredensial IPsec/IKEv1+IKEv2
 *   node turbovpn-api.mjs raw              JSON mentah dari API
 *   node turbovpn-api.mjs keytest          uji semua kombinasi base x keyset
 */

import crypto from 'node:crypto';
import process from 'node:process';
import zlib from 'node:zlib';

// ---------------------------------------------------------------------------
// 1. Konstanta aplikasi (dari AndroidManifest.xml + resources)
// ---------------------------------------------------------------------------

export const APP = {
  packageName: 'free.vpn.unblock.proxy.turbovpn',
  appType: '104',                 // meta-data "app_type"
  versionCode: '2023121501',
  versionName: '4.0.3.1',
  channel: 'google',
  authKey: 'YmxvY2twcm94eXR1cmJvdnBub25saW5l', // meta-data "auth_key"
  userAgent: 'okhttp/4.9.0',
};

/** Kandidat base URL: 2 pertama dari assets/built_in_proxy.json, terakhir fallback kode. */
export const DEFAULT_BASES = [
  'https://104.fastput.net/',
  'https://104-azure.fastput.net/',
  'https://sdk.allconnected.in/',
];

/**
 * Kunci dari libopvpnutil.so::Java_..._getCipherKey.
 * Fungsi native itu bercabang menurut (a) nama paket, (b) hash signature APK,
 * (c) installer package name. Untuk paket turbovpn ada dua himpunan kunci:
 *
 *   official : dipakai bila APK terpasang dari store resmi
 *              (signature == sertifikat asli DI DALAM lib).
 *   fallback : dipakai bila signature tidak dikenal (mis. APK mod/sideload).
 *
 * Untuk APK mod di repo ini, himpunan "official" terbukti tetap diterima
 * server (lihat `keytest`); "fallback" menghasilkan bad-decrypt.
 */
export const KEY_SETS = {
  official: {
    apiCipherKey: '7Yg3gQbUjYPF3/RHBmb421a3H/gk',
    apiHeaderKey: '7Yg3gQbUjYPF3/RHVmbO3tO3H/g=',
  },
  fallback: {
    apiCipherKey: 'UYUtVZGzZQNIFC99VmbO3tO3H/gd',
    apiHeaderKey: 'UYUtVZGzZQNIFC99VmbO3tO3H/gd',
  },
};

/** service_type -> protokol (VpnAgent.java baris ~1061). */
export const SERVICE_TYPE = {
  3: 'openvpn',
  4: 'ipsec',
  16: 'ssr',
  128: 'wireguard',
  512: 'issr',
  4096: 'unknown-4096',
  8192: 'vless-reality',
};

// ---------------------------------------------------------------------------
// 2. Primitif kripto (padanan co/allconnected/lib/w/h.java)
// ---------------------------------------------------------------------------

const aesKey = (k) => Buffer.from(k.slice(0, 16), 'utf8');

export function aesEcbEncrypt(plain, key) {
  const c = crypto.createCipheriv('aes-128-ecb', aesKey(key), null);
  return Buffer.concat([c.update(Buffer.from(plain, 'utf8')), c.final()]).toString('base64');
}

export function aesEcbDecryptBytes(b64, key) {
  const d = crypto.createDecipheriv('aes-128-ecb', aesKey(key), null);
  return Buffer.concat([d.update(Buffer.from(b64, 'base64')), d.final()]);
}

export const aesEcbDecrypt = (b64, key) => aesEcbDecryptBytes(b64, key).toString('utf8');
export const sha1Hex = (s) => crypto.createHash('sha1').update(s).digest('hex');
export const md5Hex = (s) => crypto.createHash('md5').update(s).digest('hex');
export const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
export const b64url = (s) => Buffer.from(s, 'utf8').toString('base64url');

// ---------------------------------------------------------------------------
// 3. Pembentukan request (padanan net/y/j/a.java + w/x.java)
// ---------------------------------------------------------------------------

export const randNonce = () => String(Math.floor(Math.random() * 10_000_000));

/** w/x.java -> i(): rangkaian string yang di-SHA1 jadi X-Auth-Token. */
export function authTokenSource(keys, nonce) {
  return (
    'apk_sign' + keys.apiHeaderKey +
    'app_package_name' + APP.packageName +
    'app_ver_code' + APP.versionCode +
    'app_ver_name' + APP.versionName +
    'nonce' + nonce +
    'auth_appkey' + APP.authKey
  );
}
export const authToken = (keys, nonce) => sha1Hex(authTokenSource(keys, nonce));

/** w/x.java -> k(): peta header standar. */
export function buildHeaders(keys, nonce) {
  return {
    'X-Auth-Token': authToken(keys, nonce),
    'X-App-Type': APP.appType,
    'X-App-Package-Name': APP.packageName,
    'X-App-Ver-Code': APP.versionCode,
    'X-App-Ver-Name': APP.versionName,
    'X-Nonce': nonce,
    'Accept-Language': 'en-US',
    'User-Agent': APP.userAgent,
    'X-Country': 'US',
    'X-Device-Model': 'Android',
    'X-Device-Name': 'Android',
    'X-Accept-Encoding': 'gzip',
    'Content-Type': 'text/plain',
  };
}

/** net/y/j/a.java -> b(): gzip bila >512 byte, lalu AES, lalu base64 + X-Request-Digest. */
export function encodeBody(keys, plainBody, headers) {
  headers['X-Request-Digest'] = md5Hex(plainBody);
  if (Buffer.byteLength(plainBody, 'utf8') > 512) {
    headers['X-Content-Encoding'] = 'gzip';
    return aesEcbEncrypt(zlib.gzipSync(Buffer.from(plainBody, 'utf8')).toString('latin1'), keys.apiCipherKey);
  }
  return aesEcbEncrypt(plainBody, keys.apiCipherKey);
}

/** net/y/j/a.java -> d(): dekripsi response bila ada X-Response-Digest. */
export function decodeResponse(keys, bodyText, responseHeaders) {
  if (!responseHeaders.get('x-response-digest')) return bodyText;
  const bytes = aesEcbDecryptBytes(bodyText, keys.apiCipherKey);
  return responseHeaders.get('x-content-encoding') === 'gzip'
    ? zlib.gunzipSync(bytes).toString('utf8')
    : bytes.toString('utf8');
}

// ---------------------------------------------------------------------------
// 4. Klien API
// ---------------------------------------------------------------------------

export class TurboVpnApi {
  constructor({ base = DEFAULT_BASES[0], keys = KEY_SETS.official, timeout = 20_000 } = {}) {
    this.base = base.replace(/\/+$/, '');
    this.keys = keys;
    this.timeout = timeout;
  }

  async post(path, body = '{}') {
    const plain = typeof body === 'string' ? body : JSON.stringify(body);
    const nonce = randNonce();
    const headers = buildHeaders(this.keys, nonce);
    const payload = encodeBody(this.keys, plain, headers);

    const url = `${this.base}${path}`;
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), this.timeout);
    try {
      const res = await fetch(url, { method: 'POST', headers, body: payload, signal: ac.signal });
      const text = await res.text();
      return {
        status: res.status,
        ok: res.ok,
        url,
        headers: Object.fromEntries(res.headers),
        decoded: decodeResponse(this.keys, text, res.headers),
      };
    } finally {
      clearTimeout(timer);
    }
  }

  /** net/y/k/d.java -> l(): body server list. tanpa user_id = mode anonim/free. */
  serversBody({ userId = null, isVip = true, country = 'US', activatedAt = null, protocols = [3, 4, 16, 128] } = {}) {
    const o = { country, is_vip: Boolean(isVip), os_lang: 'en_US' };
    if (userId !== null) o.user_id = String(userId);
    if (activatedAt !== null) o.activated_at = activatedAt;
    if (protocols) o.protocols = protocols;
    return o;
  }

  async serverList(opts = {}) {
    const out = await this.post('/mms/serverlist/v2/servers_list', this.serversBody(opts));
    try { out.json = JSON.parse(out.decoded); } catch { out.json = null; }
    return out;
  }

  /** net/y/k/d.java -> d(): ambil file config (mis. template .ovpn) via /mms/config/v2/files/<id>. */
  configFile(templateId) {
    return this.post(`/mms/config/v2/files/${templateId}`, '{}');
  }

  activate() {
    return this.post('/mms/account/v2/activate', '{}');
  }
}

/** Coba semua base x keyset, kembalikan hasil pertama yang mengembalikan server. */
export async function pickWorkingEndpoint({ timeout = 20_000 } = {}) {
  const tried = [];
  for (const base of DEFAULT_BASES) {
    for (const [keyName, keys] of Object.entries(KEY_SETS)) {
      const api = new TurboVpnApi({ base, keys, timeout });
      try {
        const r = await api.serverList();
        const count = (r.json?.servers?.length ?? 0) + (r.json?.vip_servers?.length ?? 0);
        tried.push({ base, keyName, status: r.status, count });
        if (count > 0) return { api, result: r, tried };
      } catch (e) {
        tried.push({ base, keyName, error: e.message });
      }
    }
  }
  return { api: null, result: null, tried };
}

/** Uji SEMUA kombinasi (untuk `keytest`), tanpa early-return. */
export async function probeAll({ timeout = 20_000 } = {}) {
  const out = [];
  for (const base of DEFAULT_BASES) {
    for (const [keyName, keys] of Object.entries(KEY_SETS)) {
      const api = new TurboVpnApi({ base, keys, timeout });
      try {
        const r = await api.serverList();
        const count = (r.json?.servers?.length ?? 0) + (r.json?.vip_servers?.length ?? 0);
        out.push({ base, keyName, status: r.status, count, ok: count > 0 });
      } catch (e) {
        out.push({ base, keyName, error: e.message, ok: false });
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// 5. Generator URI VPN
// ---------------------------------------------------------------------------

const HOST = (s) => s.host_ip || s.host || '';
const TAG = (s) => `${s.country || '??'} ${s.city || ''} [${SERVICE_TYPE[s.service_type] || s.service_type}]`.trim();

/** Shadowsocks / SSR URI. config.issr pakai field "encrypt", config.ssr pakai "authscheme". */
export function shadowsocksUri(server, cfg, { ssrProtocol = false } = {}) {
  const c = ssrProtocol ? (cfg?.ssr || {}) : (cfg?.issr || {});
  const method = c.encrypt || c.authscheme || 'rc4-md5';
  const password = c.password || '';
  const port = (c.ports && c.ports[0]) || 8080;
  const auth = b64url(`${method}:${password}`);
  const q = new URLSearchParams({
    obfs: c.obfs || 'plain',
    'obfs-param': c.obfs_param || '',
    protocol: c.protocol || 'origin',
    'protocol-param': c.protocol_param || '',
  });
  return `ss://${auth}@${HOST(server)}:${port}?${q.toString()}#${encodeURIComponent(TAG(server))}`;
}

/** SSR URI klasik (ssr://base64(host:port:proto:method:obfs:b64pass/?params)). */
export function ssrUri(server, cfg) {
  const c = cfg?.ssr || {};
  const method = c.authscheme || 'rc4-md5';
  const port = (c.ports && c.ports[0]) || 8080;
  const pass = Buffer.from(c.password || '', 'utf8').toString('base64url');
  const head = `${HOST(server)}:${port}:${c.protocol || 'origin'}:${method}:${c.obfs || 'plain'}:${pass}`;
  const params = new URLSearchParams({
    obfsparam: Buffer.from(c.obfs_param || '', 'utf8').toString('base64url'),
    protoparam: Buffer.from(c.protocol_param || '', 'utf8').toString('base64url'),
    remarks: Buffer.from(TAG(server), 'utf8').toString('base64url'),
  });
  return `ssr://${Buffer.from(`${head}/?${params.toString()}`, 'utf8').toString('base64url')}`;
}

/** VLESS + XTLS Reality URI dari config.xray.xray_plugin_outbounds[0]. */
export function vlessRealityUri(server, cfg) {
  const ob = cfg?.xray?.xray_plugin_outbounds?.[0];
  if (!ob) return null;
  const vnext = ob.settings?.vnext?.[0];
  const user = vnext?.users?.[0];
  const rs = ob.streamSettings?.realitySettings || {};
  const q = new URLSearchParams({
    type: ob.streamSettings?.network || 'tcp',
    security: ob.streamSettings?.security || 'reality',
    encryption: user?.encryption || 'none',
    flow: user?.flow || '',
    sni: rs.serverName || '',
    fp: rs.fingerprint || '',
    pbk: rs.publicKey || '',
    sid: rs.shortId || '',
    spx: rs.spiderX || '',
  });
  return `vless://${user?.id}@${HOST(server)}:${vnext?.port ?? 443}?${q.toString()}#${encodeURIComponent(TAG(server))}`;
}

/**
 * Profil OpenVPN: ambil template dari API lalu ganti baris remote &
 * tambahkan obscure-key (padanan OpenVpnServiceProxy.java:191).
 */
export async function openVpnProfile(api, cfg, serverJson = {}, hostIp = null) {
  const ov = cfg?.openvpn || {};
  const pp = ov.prior_ports || {};            // template_id/obscure-key/port ada di prior_ports
  const templateId = pp.template_id;
  if (!templateId) {
    throw new Error(`config.openvpn.prior_ports.template_id tidak ada (keys: ${Object.keys(pp).join(',') || 'kosong'})`);
  }
  const r = await api.configFile(templateId);

  // Kalau response memberi "request_digest", port & obscure-key di-obfuscate
  // (c.java -> L()/M(): XOR port dengan int(plaintext) % 1000, obscure-key AES-192).
  const digestPlain = deobfuscateDigest(api.keys, serverJson?.request_digest);
  const xor = digestPlain !== null ? (parseInt(digestPlain, 10) % 1000) : 0;
  const portOf = (arr, fallback) => (((arr && arr[0]) ?? fallback) ^ xor);
  const udp = portOf(pp.udp, 20026);
  const tcp = portOf(pp.tcp, 20025);
  const obscure = deobfuscateObscureKey(api.keys, pp['obscure-key']) ?? '';

  const host = hostIp || r.decoded.match(/^remote\s+(\S+)/m)?.[1] || '';
  let profile = r.decoded
    .replace(/^remote .*$/m, `remote ${host} ${udp} udp`)
    .replace(/^connect-retry-max .*$/m, 'connect-retry-max 1');
  if (obscure && !/^obscure-key /m.test(profile)) profile += `\nobscure-key ${obscure}\n`;
  return { templateId, host, tcp, udp, cipher: pp.cipher || null, obscure, profile };
}

/** request_digest = AES-192-ECB(base64) dengan 24 karakter pertama apiHeaderKey. */
export function deobfuscateDigest(keys, digestB64) {
  if (!digestB64) return null;
  try { return aes192Decrypt(digestB64, keys.apiHeaderKey); } catch { return null; }
}

/** obscure-key: mungkin sudah plaintext (16 char) atau AES-192-ECB base64. */
export function deobfuscateObscureKey(keys, value) {
  if (!value) return null;
  try { return aes192Decrypt(value, keys.apiHeaderKey); } catch { return value; }
}

export function aes192Decrypt(b64, key) {
  const d = crypto.createDecipheriv('aes-192-ecb', Buffer.from(key.slice(0, 24), 'utf8'), null);
  return Buffer.concat([d.update(Buffer.from(b64, 'base64')), d.final()]).toString('utf8');
}

/** Ringkasan kredensial IPsec (config.ipsec = IKEv2/EAP, config.ikev1 = PSK). */
export function ipsecProfile(cfg) {
  return { ipsec: cfg?.ipsec ?? null, ikev1: cfg?.ikev1 ?? null, remoteId: cfg?.ipsec?.remote_id ?? null };
}

// ---------------------------------------------------------------------------
// 6. CLI
// ---------------------------------------------------------------------------

const allServers = (json) => [
  ...(json?.servers || []),
  ...(json?.vip_servers || []),
  ...(json?.static_servers || []),
  ...(json?.multihop_servers || []),
];

const filterCc = (list, cc) =>
  cc ? list.filter((s) => String(s.country || '').toUpperCase() === cc.toUpperCase()) : list;

async function main() {
  const [cmd = 'servers', arg] = process.argv.slice(2);
  const { api, result, tried } = await pickWorkingEndpoint();
  if (!api) {
    console.error('Tidak ada endpoint yang berhasil. Percobaan:');
    for (const t of tried) console.error('  ', JSON.stringify(t));
    process.exitCode = 1;
    return;
  }
  const json = result.json;
  const cfg = json?.config || {};

  switch (cmd) {
    case 'raw':
      console.log(JSON.stringify(json, null, 2));
      break;

    case 'ipsec':
      console.log(JSON.stringify(ipsecProfile(cfg), null, 2));
      break;

    case 'ovpn': {
      const hostArg = arg && !arg.startsWith('-') ? arg : null;
      const { host, tcp, udp, templateId, cipher, obscure, profile } =
        await openVpnProfile(api, cfg, json, hostArg);
      console.error(`# base=${api.base} template=${templateId} host=${host} udp=${udp} tcp=${tcp} cipher=${cipher} obscure-key=${obscure}`);
      console.log(profile);
      break;
    }

    case 'nodes': {
      const list = filterCc(allServers(json), arg);
      const seen = new Set();
      let n = 0;
      for (const s of list) {
        const st = s.service_type;
        let uri = null;
        if (st === 512) uri = shadowsocksUri(s, cfg);
        else if (st === 16) uri = ssrUri(s, cfg);
        else if (st === 8192) uri = vlessRealityUri(s, cfg);
        if (!uri) continue;
        const key = `${st}|${HOST(s)}`;
        if (seen.has(key)) continue;
        seen.add(key);
        console.log(uri);
        if (++n >= 300) break;
      }
      console.error(`# base=${api.base} total_servers=${allServers(json).length} node_dicetak=${n}`);
      break;
    }

    case 'keytest': {
      console.log('hasil uji semua kombinasi base x keyset:');
      for (const t of await probeAll()) console.log('  ', JSON.stringify(t));
      break;
    }

    case 'servers':
    default: {
      const list = filterCc(allServers(json), arg);
      console.log(['country', 'city', 'host_ip', 'service_type', 'protocol', 'load', 'iload', 'vip_level'].join('\t'));
      for (const s of list.slice(0, 300)) {
        console.log([
          s.country, s.city, s.host_ip,
          s.service_type, SERVICE_TYPE[s.service_type] || '?',
          s.server_load, s.iload, s.vip_level ?? '',
        ].join('\t'));
      }
      console.error(`# base=${api.base} total=${allServers(json).length} ditampilkan=${Math.min(list.length, 300)}`);
    }
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error('Error:', e.message);
    process.exitCode = 1;
  });
}
