/* ══════════════════════════════════════════════════
   NEXPROX — SERVICE WORKER v2.1
   Enables PWA install and basic offline shell.
══════════════════════════════════════════════════ */
const CACHE_NAME  = 'nexprox-v2';
const SHELL_FILES = [
    '/',
    '/index.html',
    '/login.html',
    '/style.css',
    '/app.js',
    '/logo.png',
    '/manifest.json',
    '/world.geo.json'
];

/* ── Install: cache app shell ── */
self.addEventListener('install', (e) => {
    e.waitUntil(
        caches.open(CACHE_NAME).then(cache => {
            return cache.addAll(SHELL_FILES).catch(err => {
                console.warn('[SW] Could not cache some files:', err);
            });
        })
    );
    self.skipWaiting();
});

/* ── Activate: remove old caches ── */
self.addEventListener('activate', (e) => {
    e.waitUntil(
        caches.keys().then(keys =>
            Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
        )
    );
    self.clients.claim();
});

/* ── Fetch: network-first for API, cache-first for assets ── */
self.addEventListener('fetch', (e) => {
    const url = new URL(e.request.url);

    // Always go to network for API calls
    if (url.pathname.startsWith('/api/')) {
        e.respondWith(fetch(e.request).catch(() =>
            new Response(JSON.stringify({ error: 'Offline — API unavailable.' }), {
                headers: { 'Content-Type': 'application/json' }
            })
        ));
        return;
    }

    // Cache-first for static assets
    e.respondWith(
        caches.match(e.request).then(cached => {
            if (cached) return cached;
            return fetch(e.request).then(resp => {
                // Cache successful GET responses for static assets
                if (resp && resp.status === 200 && e.request.method === 'GET') {
                    const clone = resp.clone();
                    caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
                }
                return resp;
            }).catch(() => {
                // Offline fallback for navigation
                if (e.request.mode === 'navigate') {
                    return caches.match('/index.html');
                }
            });
        })
    );
});
