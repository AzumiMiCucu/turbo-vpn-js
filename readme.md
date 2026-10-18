# Turbo VPN 4.0.3.1 — API penghasil server/config VPN

Target: `Turbo VPN v4.0.3.1 (Premium) (Mod).apk`
`sha256 = edfe5c8c978960001e7ed916dc0a96900f15f6e1d046580bd0c26bfd56462cfa`
Paket: `free.vpn.unblock.proxy.turbovpn` — versionCode `2023121501`, versionName `4.0.3.1`

Skrip klien: [`turbovpn-api.mjs`](./turbovpn-api.mjs)

---

## 1. Jawaban singkat: URL API-nya

| Fungsi | Method + path | Base URL |
|---|---|---|
| **Daftar server + kredensial VPN** | `POST /mms/serverlist/v2/servers_list` | `https://104.fastput.net/` |
| Data kredensial lengkap | (bagian `config` pada response di atas) | sama |
| Template OpenVPN | `POST /mms/config/v2/files/<template_id>` | sama |
| Aktivasi user | `POST /mms/account/v2/activate` | sama |
| Sisa kuota | `POST /mms/account/v2/status` | sama |
| Log koneksi / ping / analytics | `/mms/report/v2/connection`, `/mms/report/v2/ping`, `/mms/analytics/v2/events` | sama |

Base URL **tidak** ditulis sebagai satu konstanta domain. Aplikasi memilih satu
"proxy"/fronting host dari `assets/built_in_proxy.json`, lalu fallback ke
`https://sdk.allconnected.in/` yang di-hardcode di `q.r()`.

Kandidat host hasil ekstraksi `assets/built_in_proxy.json` (per negara):
`https://104.fastput.net/`, `https://104.fastputon.net/`,
`https://104-azure.fastput.net/`, `https://104-0424.b-cdn.net/`,
`https://d8ou8y123d5vy.cloudfront.net/`, `https://1183375021.rsc.cdn77.org/`,
`https://104-oburt-niordna.b-cdn.net/`, plus beberapa IP Vultr/DigitalOcean.

Diuji dari mesin ini: `104.fastput.net` dan `104-azure.fastput.net` merespons
HTTP 200; `sdk.allconnected.in` tidak resolve/terblokir.

Contoh request yang berhasil (auth + body terenkripsi, lihat skrip):
```
POST https://104.fastput.net/mms/serverlist/v2/servers_list
X-Auth-Token: <sha1 hex>
X-Request-Digest: <md5 hex dari body plaintext>
X-Nonce, X-App-Type: 104, X-App-Package-Name, X-App-Ver-Code, X-App-Ver-Name,
X-Country, X-Device-Model, X-Device-Name, X-Accept-Encoding: gzip
Content-Type: text/plain
body: base64( AES-128-ECB( {"country":"US","is_vip":true,"os_lang":"en_US","protocols":[3,4,16,128]} ) )
→ 200, ±350–1060 server + blok "config" berisi password/PSK/UUID.
```

## 2. Kripto & header

| Item | Algoritma | Kunci |
|---|---|---|
| Body request & response | AES-128-ECB / PKCS5 + Base64 | 16 karakter pertama `apiCipherKey` |
| `X-Auth-Token` | SHA1(hex) atas rantai `apk_sign…auth_appkey…` | `apiHeaderKey` |
| `X-Request-Digest` | MD5(hex) body plaintext | — |
| `request_digest` / `obscure-key` | AES-192-ECB + Base64 | 24 karakter pertama `apiHeaderKey` |
| Body > 512 byte | digzip dulu, header `X-Content-Encoding: gzip` | — |

Kunci didapat dari JNI `libopvpnutil.so`
(`Java_co_allconnected_lib_openvpn_NativeUtils_getCipherKey`, fungsi
`getCipherKey(Context, z, z2)`), yang bercabang menurut nama paket, hash
signature APK, dan installer package name:

```
fragmen di .rodata libopvpnutil.so:
  0x2ae3 "7Yg3gQbU"   0x2aec "jYPF3/RH"
  0x2af5 "VmbO3tO3H/g="  (header key = frag1+frag2+frag3)
  0x2b02 "Bmb421a3H/gk"  (api key    = frag1+frag2+frag4)
  0x2b0f "UYUtVZGzZQNIFC99VmbO3tO3H/gd" (fallback / sideload)

apiHeaderKey  = 7Yg3gQbUjYPF3/RHVmbO3tO3H/g=
apiCipherKey  = 7Yg3gQbUjYPF3/RHBmb421a3H/gk
```

Diverifikasi lewat `keytest`: hanya himpunan kunci di atas yang diterima server;
varian fallback menghasilkan `bad decrypt`.

## 3. Isi `config` (kredensial VPN)

`POST /mms/serverlist/v2/servers_list` mengembalikan `servers`, `vip_servers`,
`static_servers`, `multihop_servers`, `ext` dan blok `config`/`vip_config`:

```json
{
  "ssr":    { "password": "...", "authscheme": "rc4-md5", "protocol": "origin",
              "obfs": "plain", "ports": [8080] },
  "issr":   { "password": "...", "encrypt": "rc4-md5", "ports": [8080] },
  "xray":   { "auth_type": 8192,
              "xray_plugin_outbounds": [{ "protocol": "vless",
                "settings": { "vnext": [{ "address": "##host_ip##", "port": 443,
                  "users": [{ "id": "<uuid>", "flow": "xtls-rprx-vision" }] }] },
                "streamSettings": { "security": "reality",
                  "realitySettings": { "publicKey": "...", "serverName": "www.youtube.com",
                                       "shortId": "01", "fingerprint": "chrome" } } }] },
  "ipsec":  { "eap_user": "user_104", "eap_passwd": "...", "remote_id": "...104",
              "template_id": "0f8bbee7901e74df" },
  "ikev1":  { "psk": "...", "remote_id": "abcedf.com" },
  "openvpn":{ "type": 1,
              "prior_ports": { "template_id": "e74ce4b304a65f0e", "cipher": "AES-128-CBC",
                               "obscure-key": "GENEE3KVH4HIPFM8" /* AES-192 opsional */,
                               "udp": [20026], "tcp": [20025] } },
  "connect_priority": [4]
}
```

`service_type` per server (dari `VpnAgent.java`):
`3=openvpn`, `4=ipsec`, `16=ssr`, `128=wireguard`, `512=issr`, `8192=vless-reality`
(`4096` muncul di response tapi tidak ada pemetaannya di kode versi ini).

Terkadang response menyertakan `request_digest`; bila ada, port & `obscure-key`
di-obfuscate (XOR port dengan `int(plaintext) % 1000`, `obscure-key` dienkripsi
AES-192). Pada response yang diuji, field itu tidak ada sehingga nilainya apa adanya.

## 4. Pemakaian skrip

```bash
node turbovpn-api.mjs servers ID     # daftar server (filter negara opsional)
node turbovpn-api.mjs nodes          # URI siap tempel: ss:// dan vless://
node turbovpn-api.mjs ovpn [host_ip] # profil OpenVPN lengkap (.ovpn)
node turbovpn-api.mjs ipsec          # kredensial IPsec/IKEv1
node turbovpn-api.mjs raw            # JSON mentah API
node turbovpn-api.mjs keytest        # uji semua kombinasi base x kunci
```

Skrip memilih otomatis base+keyset yang berhasil (`pickWorkingEndpoint`), lalu
membangun body terenkripsi, header auth, dan mendekripsi response — semua murni
dengan modul `node:crypto`/`node:zlib`, tanpa dependensi eksternal.

## 5. Bukti & batasan

- Ekstraksi APK & decode manifest: REA `extract_artifact` +
  `decode_android_resources` (evidence `ev_3ced1d33ffb409e734e8bd3ead3c4fb6e0baa9c4ba0e985af1272887a9adec41`,
  coverage `complete`). Fakta dari manifest: `app_type=104`,
  `auth_key=YmxvY2twcm94eXR1cmJvdnBub25saW5l`, channel `google`.
- Dekompilasi Java: jadx 1.x ke `work/turbovpn-jadx/` (40 error dari 12.158 kelas,
  sisanya lengkap). Kelas kunci: `co/allconnected/lib/net/y/k/c.java`,
  `.../k/d.java`, `.../y/j/a.java`, `co/allconnected/lib/w/{h,x,q}.java`.
- Disassembly native: `llvm-objdump` pada `work/turbovpn/lib/arm64-v8a/libopvpnutil.so`
  + inspeksi byte langsung pada `.rodata` (offset di atas). Provider native REA
  (Ghidra/Hopper/IDA) tidak tersedia di mesin ini.
- Runtime device tidak dijalankan; semua kesimpulan bersifat statis + verifikasi
  jaringan langsung terhadap endpoint yang sama.
- Nilai kredensial (`password`, `psk`, UUID) berlaku selama server API
  mengembalikannya; token tidak permanen. Kredensial bersifat rotasi dari sisi
  backend.
- Yang masih belum pasti: pemetaan `service_type 4096`, dan arti `##passphrase##`
  pada template xray (tidak ada kode yang menggantinya di DEX versi ini; kemungkinan
  diisi oleh plugin/native di luar DEX).
