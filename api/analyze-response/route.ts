import { type NextRequest, NextResponse } from "next/server"

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url)
  const url = searchParams.get("url")

  if (!url) {
    return NextResponse.json({ error: "URL parameter required" }, { status: 400 })
  }

  try {
    // Perform real response analysis
    const response = await fetch(url, {
      headers: {
        "User-Agent": "PenTest-Suite-Response-Analyzer/1.0",
      },
    })

    const headers: Record<string, string> = {}
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value
    })

    // Extract and analyze cookies
    const setCookieHeaders = response.headers.getSetCookie()
    const cookies = setCookieHeaders.map((cookieString) => {
      const [nameValue, ...attributes] = cookieString.split(";")
      const [name, value] = nameValue.split("=")

      return {
        name: name?.trim() || "unknown",
        value: value?.trim() || "",
        secure: attributes.some((attr) => attr.trim().toLowerCase() === "secure"),
        httpOnly: attributes.some((attr) => attr.trim().toLowerCase() === "httponly"),
      }
    })

    return NextResponse.json({
      headers,
      cookies,
      status: response.status,
      contentType: response.headers.get("content-type"),
    })
  } catch (error) {
    console.error("Response analysis failed:", error)
    return NextResponse.json(
      {
        error: "Failed to analyze response",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    )
  }
}
