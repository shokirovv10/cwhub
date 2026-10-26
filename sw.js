// CWhub PWA: telefonga o'rnatish uchun. Sahifalar har doim tarmoqdan olinadi; internet bo'lmasa — oxirgi bosh sahifa.
const C = "cw-shell-v1";
self.addEventListener("install", e => { self.skipWaiting(); e.waitUntil(caches.open(C).then(c => c.addAll(["/", "/icon-192.png", "/logo.png"])).catch(() => {})); });
self.addEventListener("activate", e => e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== C).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener("fetch", e => {
  const r = e.request;
  if (r.method !== "GET" || r.mode !== "navigate") return;
  e.respondWith(fetch(r).then(res => { if (res.ok && new URL(r.url).pathname === "/") { const cp = res.clone(); caches.open(C).then(c => c.put("/", cp)); } return res; }).catch(() => caches.match("/")));
});
