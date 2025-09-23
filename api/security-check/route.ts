import { type NextRequest, NextResponse } from "next/server"

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url)
  const url = searchParams.get("url")

  if (!url) {
    return NextResponse.json({ error: "URL parameter required" }, { status: 400 })
  }

  try {
    // Perform real security header analysis
    const response = await fetch(url, {
      method: "HEAD",
      headers: {
        "User-Agent": "PenTest-Suite-Security-Scanner/1.0",
      },
    })

    const headers: Record<string, string> = {}
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value
    })

    // Analyze cookie security
    const setCookieHeaders = response.headers.getSetCookie()
    const secureCookies = setCookieHeaders.every(
      (cookie) => cookie.toLowerCase().includes("secure") && cookie.toLowerCase().includes("httponly"),
    )

    return NextResponse.json({
      headers,
      secureCookies,
      status: response.status,
      statusText: response.statusText,
    })
  } catch (error) {
    console.error("Security check failed:", error)
    return NextResponse.json(
      {
        error: "Failed to perform security check",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    )
  }
}
