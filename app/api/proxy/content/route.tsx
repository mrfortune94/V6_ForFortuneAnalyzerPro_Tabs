import { type NextRequest, NextResponse } from "next/server"

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const targetUrl = searchParams.get("target")

    if (!targetUrl) {
      return NextResponse.json({ error: "Target URL is required" }, { status: 400 })
    }

    console.log(`[v0] Proxying content from: ${targetUrl}`)

    // Fetch the target content
    const response = await fetch(targetUrl, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        DNT: "1",
        Connection: "keep-alive",
        "Upgrade-Insecure-Requests": "1",
      },
    })

    if (!response.ok) {
      return NextResponse.json({ error: "Failed to fetch target content" }, { status: response.status })
    }

    let content = await response.text()

    // Inject network interception script
    const injectionScript = `
      <script>
        // Network interception for penetration testing
        (function() {
          const originalFetch = window.fetch;
          const originalXHR = window.XMLHttpRequest;
          
          // Intercept fetch requests
          window.fetch = function(...args) {
            const startTime = Date.now();
            return originalFetch.apply(this, args).then(response => {
              const endTime = Date.now();
              
              // Send intercepted data to parent window
              if (window.parent !== window) {
                window.parent.postMessage({
                  type: 'INTERCEPTED_REQUEST',
                  payload: {
                    method: args[1]?.method || 'GET',
                    url: args[0],
                    headers: args[1]?.headers || {},
                    body: args[1]?.body,
                    response: {
                      status: response.status,
                      headers: Object.fromEntries(response.headers.entries()),
                      timing: endTime - startTime
                    },
                    type: 'fetch'
                  }
                }, '*');
              }
              
              return response;
            });
          };
          
          // Intercept XMLHttpRequest
          const originalOpen = originalXHR.prototype.open;
          const originalSend = originalXHR.prototype.send;
          
          originalXHR.prototype.open = function(method, url, ...args) {
            this._method = method;
            this._url = url;
            this._startTime = Date.now();
            return originalOpen.apply(this, [method, url, ...args]);
          };
          
          originalXHR.prototype.send = function(body) {
            this.addEventListener('loadend', () => {
              const endTime = Date.now();
              
              if (window.parent !== window) {
                window.parent.postMessage({
                  type: 'INTERCEPTED_REQUEST',
                  payload: {
                    method: this._method,
                    url: this._url,
                    body: body,
                    response: {
                      status: this.status,
                      headers: this.getAllResponseHeaders(),
                      body: this.responseText,
                      timing: endTime - this._startTime
                    },
                    type: 'xhr'
                  }
                }, '*');
              }
            });
            
            return originalSend.apply(this, [body]);
          };
          
          console.log('[v0] Network interception active for penetration testing');
        })();
      </script>
    `

    // Inject the script before closing head tag
    content = content.replace("</head>", `${injectionScript}</head>`)

    // Create response with modified headers to allow iframe embedding
    const modifiedResponse = new NextResponse(content, {
      status: 200,
      headers: {
        "Content-Type": response.headers.get("Content-Type") || "text/html",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        Pragma: "no-cache",
        Expires: "0",
        // Remove iframe-blocking headers
        "X-Frame-Options": "ALLOWALL",
        "Content-Security-Policy": "frame-ancestors *;",
      },
    })

    return modifiedResponse
  } catch (error) {
    console.error("[v0] Proxy content error:", error)
    return NextResponse.json({ error: "Failed to proxy content" }, { status: 500 })
  }
}

export async function POST(request: NextRequest) {
  try {
    const { url, method = "GET", headers = {}, body } = await request.json()

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    console.log(`[v0] Proxying ${method} request to: ${url}`)

    const fetchOptions: RequestInit = {
      method,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        Accept: "application/json, text/html, */*",
        ...headers,
      },
    }

    if (body && method !== "GET") {
      fetchOptions.body = typeof body === "string" ? body : JSON.stringify(body)
    }

    const response = await fetch(url, fetchOptions)
    const content = await response.text()

    return NextResponse.json({
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      content,
      url,
    })
  } catch (error) {
    console.error("[v0] Proxy POST error:", error)
    return NextResponse.json({ error: "Failed to proxy request" }, { status: 500 })
  }
}
