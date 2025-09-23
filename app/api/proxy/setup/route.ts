import { type NextRequest, NextResponse } from "next/server"

export async function POST(request: NextRequest) {
  try {
    const { targetUrl } = await request.json()

    if (!targetUrl) {
      console.error("[v0] Proxy setup error: Target URL is required")
      return NextResponse.json({ error: "Target URL is required" }, { status: 400 })
    }

    if (typeof targetUrl !== "string" || targetUrl.trim() === "") {
      console.error("[v0] Proxy setup error: Target URL must be a non-empty string")
      return NextResponse.json({ error: "Target URL must be a valid string" }, { status: 400 })
    }

    let validatedUrl = targetUrl.trim()
    if (!validatedUrl.startsWith("http://") && !validatedUrl.startsWith("https://")) {
      validatedUrl = "https://" + validatedUrl
    }

    let url: URL
    try {
      url = new URL(validatedUrl)
    } catch (urlError) {
      console.error("[v0] Proxy setup error: Invalid URL format:", validatedUrl)
      return NextResponse.json(
        {
          error: "Invalid URL format. Please provide a valid URL (e.g., https://example.com)",
        },
        { status: 400 },
      )
    }

    console.log(`[v0] Setting up proxy for: ${url.hostname}`)

    // Generate a proxy URL that strips problematic headers
    const proxyUrl = `/api/proxy/content?target=${encodeURIComponent(validatedUrl)}`

    return NextResponse.json({
      proxyUrl,
      message: "Proxy configured successfully",
      target: validatedUrl,
    })
  } catch (error) {
    console.error("[v0] Proxy setup error:", error)
    return NextResponse.json(
      {
        error: "Failed to setup proxy. Please check the URL format and try again.",
      },
      { status: 500 },
    )
  }
}
