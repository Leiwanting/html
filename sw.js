const CACHE_NAME = 'timedisplay-v4';
const urlsToCache = [
  '/html/timedisplay.html',
  '/html/manifest.json',
  '/html/icons/icon-192.svg',
  '/html/icons/icon-512.svg',
  '/html/js/qrcode.min.js'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        // 强制清空当前缓存再重新添加
        return cache.keys().then(keys => {
          return Promise.all(keys.map(k => cache.delete(k)));
        }).then(() => cache.addAll(urlsToCache));
      })
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Stale-While-Revalidate: 先返回缓存，后台更新
self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request).then(cachedResponse => {
      const fetchPromise = fetch(event.request).then(networkResponse => {
        if (networkResponse && networkResponse.status === 200 && networkResponse.type === 'basic') {
          const responseToCache = networkResponse.clone();
          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, responseToCache);
          });
        }
        return networkResponse;
      }).catch(() => cachedResponse);

      return cachedResponse || fetchPromise;
    })
  );
});
