import { type NextRequest, NextResponse } from "next/server"

interface KeywordMatch {
  keyword: string
  context: string
  line: number
  url: string
  source: "html" | "javascript" | "css" | "headers" | "response"
  severity: "Critical" | "High" | "Medium" | "Low"
}

interface ScanResult {
  url: string
  matches: KeywordMatch[]
  totalMatches: number
  scannedUrls: string[]
  errors: string[]
}

export async function POST(request: NextRequest) {
  try {
    const { targetUrl, keywords = [], maxDepth = 2 } = await request.json()

    if (!targetUrl) {
      return NextResponse.json({ error: "Target URL is required" }, { status: 400 })
    }

    const sensitiveKeywords = [
      // User credentials
      { term: "password", severity: "Critical" as const },
      { term: "PASSWORD", severity: "Critical" as const },
      { term: "user", severity: "Medium" as const },
      { term: "USER", severity: "Medium" as const },
      { term: "username", severity: "High" as const },
      { term: "USERNAME", severity: "High" as const },
      { term: "admin", severity: "Critical" as const },
      { term: "ADMIN", severity: "Critical" as const },
      { term: "root", severity: "Critical" as const },

      // API keys and tokens
      { term: "api_key", severity: "Critical" as const },
      { term: "API_KEY", severity: "Critical" as const },
      { term: "secret", severity: "Critical" as const },
      { term: "SECRET", severity: "Critical" as const },
      { term: "token", severity: "High" as const },
      { term: "TOKEN", severity: "High" as const },
      { term: "jwt", severity: "High" as const },
      { term: "JWT", severity: "High" as const },

      // Database credentials
      { term: "database", severity: "Medium" as const },
      { term: "DATABASE", severity: "Medium" as const },
      { term: "db_password", severity: "Critical" as const },
      { term: "DB_PASSWORD", severity: "Critical" as const },
      { term: "mysql", severity: "Medium" as const },
      { term: "MYSQL", severity: "Medium" as const },
      { term: "postgres", severity: "Medium" as const },
      { term: "POSTGRES", severity: "Medium" as const },

      // Custom keywords from user
      ...keywords.map((k: string) => ({ term: k, severity: "High" as const })),
    ]

    const scannedUrls: string[] = []
    const allMatches: KeywordMatch[] = []
    const errors: string[] = []

    const scanUrl = async (url: string, depth: number): Promise<void> => {
      if (depth > maxDepth || scannedUrls.includes(url)) return

      try {
        console.log(`[v0] Scanning ${url} for sensitive keywords`)
        scannedUrls.push(url)

        // Use proxy to fetch content and bypass CORS
        const proxyResponse = await fetch(`${request.nextUrl.origin}/api/proxy/content`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            url,
            method: "GET",
            headers: {
              "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
              Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
          }),
        })

        if (!proxyResponse.ok) {
          errors.push(`Failed to fetch ${url}: ${proxyResponse.status}`)
          return
        }

        const { content, headers } = await proxyResponse.json()

        const headerString = JSON.stringify(headers).toLowerCase()
        sensitiveKeywords.forEach(({ term, severity }) => {
          if (headerString.includes(term.toLowerCase())) {
            allMatches.push({
              keyword: term,
              context: `Found in response headers: ${headerString.substring(headerString.indexOf(term.toLowerCase()) - 50, headerString.indexOf(term.toLowerCase()) + 50)}`,
              line: 0,
              url,
              source: "headers",
              severity,
            })
          }
        })

        const lines = content.split("\n")
        lines.forEach((line: string, index: number) => {
          sensitiveKeywords.forEach(({ term, severity }) => {
            if (line.includes(term)) {
              const contextStart = Math.max(0, line.indexOf(term) - 30)
              const contextEnd = Math.min(line.length, line.indexOf(term) + term.length + 30)
              const context = line.substring(contextStart, contextEnd)

              allMatches.push({
                keyword: term,
                context: context.trim(),
                line: index + 1,
                url,
                source: "html",
                severity,
              })
            }
          })
        })

        const scriptMatches = content.match(/<script[^>]*src=["']([^"']+)["'][^>]*>/gi)
        if (scriptMatches && depth < maxDepth) {
          for (const match of scriptMatches.slice(0, 5)) {
            // Limit to 5 JS files per page
            const srcMatch = match.match(/src=["']([^"']+)["']/)
            if (srcMatch) {
              let jsUrl = srcMatch[1]
              if (jsUrl.startsWith("/")) {
                const baseUrl = new URL(url)
                jsUrl = `${baseUrl.protocol}//${baseUrl.host}${jsUrl}`
              } else if (!jsUrl.startsWith("http")) {
                jsUrl = new URL(jsUrl, url).href
              }
              await scanUrl(jsUrl, depth + 1)
            }
          }
        }

        const cssMatches = content.match(/<link[^>]*href=["']([^"']+\.css[^"']*)["'][^>]*>/gi)
        if (cssMatches && depth < maxDepth) {
          for (const match of cssMatches.slice(0, 3)) {
            // Limit to 3 CSS files per page
            const hrefMatch = match.match(/href=["']([^"']+)["']/)
            if (hrefMatch) {
              let cssUrl = hrefMatch[1]
              if (cssUrl.startsWith("/")) {
                const baseUrl = new URL(url)
                cssUrl = `${baseUrl.protocol}//${baseUrl.host}${cssUrl}`
              } else if (!cssUrl.startsWith("http")) {
                cssUrl = new URL(cssUrl, url).href
              }
              await scanUrl(cssUrl, depth + 1)
            }
          }
        }

        if (depth === 0) {
          const commonEndpoints = [
            "/admin",
            "/admin/",
            "/admin/login",
            "/admin/config",
            "/api",
            "/api/",
            "/api/config",
            "/api/users",
            "/config",
            "/config.json",
            "/config.js",
            "/.env",
            "/env",
            "/environment",
            "/backup",
            "/backup/",
            "/db",
            "/database",
            "/test",
            "/debug",
            "/dev",
          ]

          for (const endpoint of commonEndpoints) {
            const endpointUrl = new URL(endpoint, url).href
            await scanUrl(endpointUrl, depth + 1)
          }
        }
      } catch (error) {
        errors.push(`Error scanning ${url}: ${error instanceof Error ? error.message : "Unknown error"}`)
      }
    }

    // Start scanning from the target URL
    await scanUrl(targetUrl, 0)

    const result: ScanResult = {
      url: targetUrl,
      matches: allMatches,
      totalMatches: allMatches.length,
      scannedUrls,
      errors,
    }

    console.log(`[v0] Keyword scan completed. Found ${allMatches.length} matches across ${scannedUrls.length} URLs`)

    return NextResponse.json(result)
  } catch (error) {
    console.error("[v0] Keyword scan error:", error)
    return NextResponse.json({ error: "Failed to perform keyword scan" }, { status: 500 })
  }
}
