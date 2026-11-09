// Decrypts the protected files of this site in the browser (see index.html). No password or key is stored here.
const SCOPE = self.registration.scope;
const BASE = new URL(SCOPE).pathname;
const TYPES = { html: "text/html; charset=utf-8", js: "text/javascript; charset=utf-8", json: "application/json",
                css: "text/css", png: "image/png", jpg: "image/jpeg", mp4: "video/mp4", svg: "image/svg+xml" };
let META = null, KEY = null, TICKET = 0;
const plain = new Map();
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function meta() {
  if (!META) {
    META = await (await fetch(SCOPE + "lock.json", { cache: "no-cache" })).json();
    META.set = new Set(META.files);
  }
  return META;
}
async function setKey(raw) { KEY = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]); plain.clear(); }

// After a restart the worker has no key: ask the deck window that made the request (it holds the key in its session).
async function keyFor(client) {
  if (KEY) return KEY;
  const v = await new Promise((res) => {
    const ch = new MessageChannel(), t = setTimeout(() => res(null), 3000);
    ch.port1.onmessage = (e) => { clearTimeout(t); res(e.data); };
    client.postMessage({ type: "need-key" }, [ch.port2]);
  });
  if (!v) return null;
  const [raw, salt] = v.split("|");
  if (salt !== (await meta()).salt) return null;
  await setKey(b64(raw));
  return KEY;
}

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil((async () => {
  try { indexedDB.deleteDatabase("deck-lock"); } catch (err) {}   // key stored by the first version (D-107)
  await self.clients.claim();
})()));
self.addEventListener("message", (e) => {
  const d = e.data || {};
  e.waitUntil((async () => {
    if (d.type === "key") { await setKey(d.raw); TICKET = Date.now() + 15000; META = null; }
    if (e.ports[0]) e.ports[0].postMessage("ok");
  })());
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith(BASE) || e.request.method !== "GET") return;
  e.respondWith(serve(e, decodeURIComponent(url.pathname.slice(BASE.length))));
});

async function serve(e, rel) {
  const req = e.request, m = await meta();
  if (!m.set.has(rel)) return fetch(req);
  if (req.mode === "navigate") {                       // only the login page may open the deck, once per ticket
    if (rel !== "deck.html" || !KEY || Date.now() > TICKET) return Response.redirect(SCOPE, 302);
    TICKET = 0;
  } else {                                             // files of the deck only for a deck window
    const client = e.clientId ? await self.clients.get(e.clientId) : null;
    if (!client || !new URL(client.url).pathname.endsWith("/deck.html")) return new Response("locked", { status: 403 });
    if (!(await keyFor(client))) return new Response("locked", { status: 403 });
  }
  let buf = plain.get(rel);
  if (!buf) {
    const r = await fetch(SCOPE + rel + ".enc");
    if (!r.ok) return new Response("not found", { status: 404 });
    const b = new Uint8Array(await r.arrayBuffer());
    buf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.slice(0, 12) }, KEY, b.slice(12));
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
