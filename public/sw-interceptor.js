self.addEventListener("install", (event) => {
  console.log("[v0] Service Worker installing for network interception")
  self.skipWaiting()
})

self.addEventListener("activate", (event) => {
  console.log("[v0] Service Worker activated")
  event.waitUntil(self.clients.claim())
})

self.addEventListener("fetch", (event) => {
  // Only intercept requests from the game iframe
  if (
    event.request.url.includes("casino") ||
    event.request.url.includes("game") ||
    event.request.url.includes("slot") ||
    event.request.url.includes("api")
  ) {
    event.respondWith(
      fetch(event.request).then((response) => {
        // Clone the response to read it
        const responseClone = response.clone()

        // Send intercepted data to the main thread
        self.clients.matchAll().then((clients) => {
          clients.forEach((client) => {
            responseClone.text().then((body) => {
              client.postMessage({
                type: "INTERCEPTED_REQUEST",
                payload: {
                  method: event.request.method,
                  url: event.request.url,
                  headers: Object.fromEntries(event.request.headers.entries()),
                  response: {
                    status: response.status,
                    headers: Object.fromEntries(response.headers.entries()),
                    body: body,
                    timing: Date.now(),
                  },
                  type: "fetch",
                },
              })
            })
          })
        })

        return response
      }),
    )
  }
})
