// Decrypts the protected files of this site in the browser (see index.html). No password is stored here.
const SCOPE = self.registration.scope;
const BASE = new URL(SCOPE).pathname;
const TYPES = { html: "text/html; charset=utf-8", js: "text/javascript; charset=utf-8", json: "application/json",
                css: "text/css", png: "image/png", jpg: "image/jpeg", mp4: "video/mp4", svg: "image/svg+xml" };
let META = null, KEY = null;
const plain = new Map();

function db() {
  return new Promise((res, rej) => {
    const r = indexedDB.open("deck-lock", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("k");
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
}
async function store(mode, op) {
  const d = await db();
  return new Promise((res, rej) => {
    const q = op(d.transaction("k", mode).objectStore("k"));
    q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error);
  });
}
async function meta() {
  if (!META) {
    META = await (await fetch(SCOPE + "lock.json", { cache: "no-cache" })).json();
    META.set = new Set(META.files);
  }
  return META;
}
async function key() {
  if (KEY) return KEY;
  const saved = await store("readonly", (s) => s.get("key"));
  const m = await meta();
  if (!saved || saved.salt !== m.salt) return null;     // a rebuilt site has a new salt: ask again
  KEY = await crypto.subtle.importKey("raw", saved.raw, "AES-GCM", false, ["decrypt"]);
  return KEY;
}

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("message", (e) => {
  const d = e.data || {};
  e.waitUntil((async () => {
    if (d.type === "key") await store("readwrite", (s) => s.put({ raw: d.raw, salt: d.salt }, "key"));
    if (d.type === "lock") await store("readwrite", (s) => s.delete("key"));
    KEY = null; META = null; plain.clear();
    if (e.ports[0]) e.ports[0].postMessage("ok");
  })());
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith(BASE) || e.request.method !== "GET") return;
  e.respondWith(serve(e.request, decodeURIComponent(url.pathname.slice(BASE.length))));
});

async function serve(req, rel) {
  const m = await meta();
  if (!m.set.has(rel)) return fetch(req);
  const k = await key();
  if (!k) return req.mode === "navigate" ? Response.redirect(SCOPE, 302) : new Response("locked", { status: 403 });
  let buf = plain.get(rel);
  if (!buf) {
    const r = await fetch(SCOPE + rel + ".enc");
    if (!r.ok) return new Response("not found", { status: 404 });
    const b = new Uint8Array(await r.arrayBuffer());
    buf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.slice(0, 12) }, k, b.slice(12));
    plain.set(rel, buf);
  }
  const type = TYPES[rel.split(".").pop()] || "application/octet-stream";
  const n = buf.byteLength;
  const range = /bytes=(\d*)-(\d*)/.exec(req.headers.get("range") || "");
  if (range && (range[1] !== "" || range[2] !== "")) {
    let a, z;
    if (range[1] === "") { a = Math.max(0, n - parseInt(range[2], 10)); z = n - 1; }
    else { a = parseInt(range[1], 10); z = range[2] === "" ? n - 1 : Math.min(parseInt(range[2], 10), n - 1); }
    if (a >= n || a > z) return new Response(null, { status: 416, headers: { "Content-Range": "bytes */" + n } });
    return new Response(buf.slice(a, z + 1), { status: 206, headers: {
      "Content-Type": type, "Content-Range": "bytes " + a + "-" + z + "/" + n, "Content-Length": String(z - a + 1),
      "Accept-Ranges": "bytes", "Cache-Control": "no-store" } });
  }
  return new Response(buf, { status: 200, headers: { "Content-Type": type, "Content-Length": String(n),
                                                     "Accept-Ranges": "bytes", "Cache-Control": "no-store" } });
}
