/**
 * MYCEL Service Worker
 * Offline-First caching + bakgrundssynkronisering
 */

const CACHE_NAME = 'mycel-v1.0.0';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/app.js',
  '/manifest.json',
  'https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=Space+Mono:ital,wght@0,400;0,700;1,400&display=swap'
];

// ── Install: förcacha alla statiska resurser ──
self.addEventListener('install', event => {
  console.log('[SW] Installerar Mycel Service Worker...');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('[SW] Cachar statiska resurser');
        return cache.addAll(STATIC_ASSETS.map(url => {
          // Ignorera Google Fonts om offline (externa resurser)
          return new Request(url, { mode: url.startsWith('http') ? 'no-cors' : 'same-origin' });
        })).catch(err => console.warn('[SW] Caching-fel (icke-kritiskt):', err));
      })
      .then(() => self.skipWaiting()) // Aktivera omedelbart
  );
});

// ── Activate: rensa gamla cacher ──
self.addEventListener('activate', event => {
  console.log('[SW] Aktiverar ny version...');
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key => {
            console.log('[SW] Raderar gammal cache:', key);
            return caches.delete(key);
          })
      ))
      .then(() => self.clients.claim()) // Ta kontroll omedelbart
  );
});

// ── Fetch: Offline-First strategi ──
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Ignorera icke-GET-förfrågningar
  if (request.method !== 'GET') return;

  // Ignorera WebRTC, BroadcastChannel och andra browser-APIs
  if (url.protocol === 'chrome-extension:') return;

  event.respondWith(
    caches.match(request)
      .then(cached => {
        if (cached) {
          // Cache träff — returnera omedelbart (offline-first)
          // Uppdatera i bakgrunden om online
          if (navigator.onLine) {
            const fetchAndUpdate = fetch(request)
              .then(response => {
                if (response.ok) {
                  caches.open(CACHE_NAME)
                    .then(cache => cache.put(request, response.clone()));
                }
                return response;
              })
              .catch(() => {});
          }
          return cached;
        }

        // Inte i cache — hämta från nätverket
        return fetch(request)
          .then(response => {
            if (!response.ok) return response;

            // Cacha svaret för framtida offline-användning
            const toCache = response.clone();
            caches.open(CACHE_NAME)
              .then(cache => cache.put(request, toCache))
              .catch(() => {}); // Tyst fel (t.ex. opaque responses)

            return response;
          })
          .catch(() => {
            // Nätverksfel — försök returnera cached offline-sida
            return caches.match('/index.html');
          });
      })
  );
});

// ── Background Sync (för misslyckade gossip-meddelanden) ──
self.addEventListener('sync', event => {
  if (event.tag === 'gossip-sync') {
    console.log('[SW] Background sync: gossip-sync');
    event.waitUntil(syncPendingGossip());
  }
});

async function syncPendingGossip() {
  // I ett produktionssystem: hämta väntande meddelanden från IndexedDB
  // och skicka dem när anslutningen återupprättas
  const clients = await self.clients.matchAll();
  clients.forEach(client => {
    client.postMessage({ type: 'sw-gossip-sync-ready' });
  });
}

// ── Push Notifications (för peer-meddelanden) ──
self.addEventListener('push', event => {
  if (!event.data) return;
  const data = event.data.json();

  event.waitUntil(
    self.registration.showNotification(data.title || 'Mycel', {
      body: data.body || 'Du har ett nytt meddelande',
      icon: '/icon-192.png',
      badge: '/icon-96.png',
      data: data.url,
      actions: [
        { action: 'open', title: 'Öppna' },
        { action: 'dismiss', title: 'Avfärda' }
      ]
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  if (event.action === 'open' || !event.action) {
    event.waitUntil(
      clients.openWindow(event.notification.data || '/')
    );
  }
});

// ── Meddelanden från huvudapp ──
self.addEventListener('message', event => {
  if (event.data?.type === 'skip-waiting') {
    self.skipWaiting();
  }

  if (event.data?.type === 'cache-update') {
    // Tvinga uppdatering av specifik resurs
    const { url } = event.data;
    if (url) {
      fetch(url).then(response => {
        caches.open(CACHE_NAME)
          .then(cache => cache.put(url, response));
      });
    }
  }
});

console.log('[SW] Skrivpunkten Service Worker laddad — Offline-First är aktivt');
