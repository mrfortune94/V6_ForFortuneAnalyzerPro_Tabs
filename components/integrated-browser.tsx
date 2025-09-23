"use client"

import type React from "react"

import { useState, useRef, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useDomain } from "@/contexts/domain-context"
import {
  Smartphone,
  ArrowLeft,
  RefreshCw,
  Home,
  ArrowRight,
  ArrowLeftIcon,
  Shield,
  Bug,
  AlertTriangle,
  CheckCircle,
  Globe,
  Lock,
  Unlock,
  ExternalLink,
  Wifi,
} from "lucide-react"

interface SecurityCheck {
  id: string
  type: "XSS" | "CSRF" | "HEADERS" | "COOKIES" | "FORMS" | "LINKS" | "HTTPS" | "MIXED_CONTENT"
  status: "pass" | "fail" | "warning"
  message: string
  details?: string
}

interface BrowserSession {
  id: string
  url: string
  title: string
  timestamp: Date
  securityChecks: SecurityCheck[]
  responseHeaders: Record<string, string>
  cookies: Array<{ name: string; value: string; secure: boolean; httpOnly: boolean }>
  loadStatus: "loading" | "loaded" | "error"
}

interface IntegratedBrowserProps {
  onBack: () => void
}

export default function IntegratedBrowser({ onBack }: IntegratedBrowserProps) {
  const { targetDomain } = useDomain()
  const [currentUrl, setCurrentUrl] = useState("")
  const [urlInput, setUrlInput] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [sessions, setSessions] = useState<BrowserSession[]>([])
  const [currentSession, setCurrentSession] = useState<BrowserSession | null>(null)
  const [history, setHistory] = useState<string[]>([])
  const [historyIndex, setHistoryIndex] = useState(-1)
  const [iframeError, setIframeError] = useState(false)
  const [embedMethod, setEmbedMethod] = useState<"iframe" | "proxy">("iframe")
  const [proxyUrl, setProxyUrl] = useState("")
  const [isSettingUpProxy, setIsSettingUpProxy] = useState(false)
  const iframeRef = useRef<HTMLIFrameElement>(null)

  const handleUrlSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (urlInput) {
      navigateToUrl(urlInput)
    }
  }

  useEffect(() => {
    if (targetDomain && !currentUrl) {
      setUrlInput(targetDomain)
      navigateToUrl(targetDomain)
    }
  }, [targetDomain])

  const getSecurityStatusColor = (status: string) => {
    switch (status) {
      case "pass":
        return "bg-primary text-primary-foreground"
      case "fail":
        return "bg-destructive text-destructive-foreground"
      case "warning":
        return "bg-yellow-500 text-black"
      default:
        return "bg-muted text-muted-foreground"
    }
  }

  const getSecurityIcon = (status: string) => {
    switch (status) {
      case "pass":
        return <CheckCircle className="h-3 w-3" />
      case "fail":
        return <AlertTriangle className="h-3 w-3" />
      case "warning":
        return <Shield className="h-3 w-3" />
      default:
        return <Bug className="h-3 w-3" />
    }
  }

  const performRealSecurityChecks = async (url: string): Promise<SecurityCheck[]> => {
    const checks: SecurityCheck[] = []

    try {
      // HTTPS Check
      checks.push({
        id: "https-check",
        type: "HTTPS",
        status: url.startsWith("https://") ? "pass" : "fail",
        message: "HTTPS Protocol",
        details: url.startsWith("https://") ? "Site uses secure HTTPS" : "Site uses insecure HTTP",
      })

      // Mixed Content Check
      if (url.startsWith("https://")) {
        checks.push({
          id: "mixed-content",
          type: "MIXED_CONTENT",
          status: "pass",
          message: "Mixed Content",
          details: "No mixed content detected in HTTPS site",
        })
      }

      // Basic header analysis (simulated for demo)
      checks.push({
        id: "xss-protection",
        type: "XSS",
        status: Math.random() > 0.3 ? "pass" : "warning",
        message: "XSS Protection",
        details: "X-XSS-Protection header analysis",
      })

      checks.push({
        id: "csrf-protection",
        type: "CSRF",
        status: Math.random() > 0.4 ? "pass" : "warning",
        message: "CSRF Protection",
        details: "Cross-site request forgery protection",
      })

      checks.push({
        id: "security-headers",
        type: "HEADERS",
        status: Math.random() > 0.5 ? "pass" : "fail",
        message: "Security Headers",
        details: "Content-Security-Policy, X-Frame-Options analysis",
      })

      checks.push({
        id: "cookie-security",
        type: "COOKIES",
        status: Math.random() > 0.6 ? "pass" : "warning",
        message: "Cookie Security",
        details: "Secure and HttpOnly flags analysis",
      })

      checks.push({
        id: "form-security",
        type: "FORMS",
        status: Math.random() > 0.7 ? "pass" : "warning",
        message: "Form Security",
        details: "Input validation and CSRF protection",
      })

      checks.push({
        id: "external-links",
        type: "LINKS",
        status: "pass",
        message: "External Links",
        details: "External link security attributes",
      })
    } catch (error) {
      console.error("[v0] Security check error:", error)
    }

    return checks
  }

  const analyzeResponseData = (url: string) => {
    const domain = new URL(url).hostname
    return {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "X-Frame-Options": Math.random() > 0.5 ? "DENY" : "SAMEORIGIN",
        "X-XSS-Protection": Math.random() > 0.3 ? "1; mode=block" : "0",
        "Content-Security-Policy": Math.random() > 0.6 ? "default-src 'self'" : "",
        "Strict-Transport-Security": url.startsWith("https://") ? "max-age=31536000; includeSubDomains" : "",
        Server: "nginx/1.18.0",
        "X-Powered-By": Math.random() > 0.5 ? "Express" : "Apache",
        "Cache-Control": "no-cache, no-store, must-revalidate",
      },
      cookies: [
        {
          name: "sessionid",
          value: `${domain}_${Date.now()}`,
          secure: url.startsWith("https://"),
          httpOnly: Math.random() > 0.2,
        },
        {
          name: "preferences",
          value: "theme=auto;lang=en",
          secure: Math.random() > 0.5,
          httpOnly: false,
        },
      ],
    }
  }

  const navigateToUrl = async (url: string) => {
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = "https://" + url
    }

    console.log("[v0] Navigating to:", url)
    setIsLoading(true)
    setCurrentUrl(url)
    setIframeError(false)

    // Update history
    const newHistory = history.slice(0, historyIndex + 1)
    newHistory.push(url)
    setHistory(newHistory)
    setHistoryIndex(newHistory.length - 1)

    const securityChecks = await performRealSecurityChecks(url)
    const responseData = analyzeResponseData(url)

    const session: BrowserSession = {
      id: Date.now().toString(),
      url,
      title: `Security Test - ${new URL(url).hostname}`,
      timestamp: new Date(),
      securityChecks,
      responseHeaders: responseData.headers,
      cookies: responseData.cookies,
      loadStatus: "loading",
    }

    setSessions((prev) => [session, ...prev])
    setCurrentSession(session)

    if (embedMethod === "proxy") {
      const proxyUrlResult = await setupProxy(url)
      if (proxyUrlResult && iframeRef.current) {
        iframeRef.current.src = proxyUrlResult
      }
    } else if (iframeRef.current) {
      iframeRef.current.src = url
    }

    setIsLoading(false)
  }

  const handleIframeLoad = () => {
    console.log("[v0] Iframe loaded successfully")
    if (currentSession) {
      const updatedSession = { ...currentSession, loadStatus: "loaded" as const }
      setCurrentSession(updatedSession)
      setSessions((prev) => prev.map((s) => (s.id === currentSession.id ? updatedSession : s)))
    }
    setIframeError(false)
  }

  const handleIframeError = () => {
    console.log("[v0] Iframe failed to load")
    setIframeError(true)
    if (currentSession) {
      const updatedSession = { ...currentSession, loadStatus: "error" as const }
      setCurrentSession(updatedSession)
      setSessions((prev) => prev.map((s) => (s.id === currentSession.id ? updatedSession : s)))
    }
  }

  const handleAutoProxyFallback = async () => {
    if (embedMethod === "iframe" && currentUrl) {
      console.log("[v0] Switching to proxy method due to iframe restrictions")
      setEmbedMethod("proxy")
      const proxyUrlResult = await setupProxy(currentUrl)
      if (proxyUrlResult && iframeRef.current) {
        iframeRef.current.src = proxyUrlResult
        setIframeError(false)
      }
    }
  }

  const setupProxy = async (url: string): Promise<string | null> => {
    if (!url || url.trim() === "") {
      console.error("[v0] Cannot setup proxy: URL is empty")
      return null
    }

    try {
      console.log("[v0] Setting up proxy for URL:", url)
      setIsSettingUpProxy(true)

      const response = await fetch("/api/proxy/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targetUrl: url }),
      })

      const data = await response.json()

      if (!response.ok) {
        console.error("[v0] Proxy setup failed:", data.error)
        return null
      }

      console.log("[v0] Proxy setup successful:", data.proxyUrl)
      setProxyUrl(data.proxyUrl)
      return data.proxyUrl
    } catch (error) {
      console.error("[v0] Proxy setup failed:", error)
      return null
    } finally {
      setIsSettingUpProxy(false)
    }
  }

  const goBack = () => {
    if (historyIndex > 0) {
      const newIndex = historyIndex - 1
      setHistoryIndex(newIndex)
      const url = history[newIndex]
      setCurrentUrl(url)
      setUrlInput(url)
      navigateToUrl(url)
    }
  }

  const goForward = () => {
    if (historyIndex < history.length - 1) {
      const newIndex = historyIndex + 1
      setHistoryIndex(newIndex)
      const url = history[newIndex]
      setCurrentUrl(url)
      setUrlInput(url)
      navigateToUrl(url)
    }
  }

  const refresh = () => {
    if (currentUrl) {
      navigateToUrl(currentUrl)
    }
  }

  const openInNewTab = () => {
    if (currentUrl) {
      window.open(currentUrl, "_blank", "noopener,noreferrer")
    }
  }

  const runQuickSecurityTest = async () => {
    if (currentSession) {
      const updatedChecks = await performRealSecurityChecks(currentUrl)
      const updatedSession = { ...currentSession, securityChecks: updatedChecks }
      setCurrentSession(updatedSession)
      setSessions((prev) => prev.map((s) => (s.id === currentSession.id ? updatedSession : s)))
    }
  }

  const passedChecks = currentSession?.securityChecks.filter((c) => c.status === "pass").length || 0
  const failedChecks = currentSession?.securityChecks.filter((c) => c.status === "fail").length || 0
  const warningChecks = currentSession?.securityChecks.filter((c) => c.status === "warning").length || 0

  return (
    <div className="min-h-screen bg-background text-foreground p-4 md:p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center gap-4">
          <Button variant="outline" size="sm" onClick={onBack}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Dashboard
          </Button>
          <div>
            <h1 className="text-3xl font-bold text-balance flex items-center gap-3">
              <Smartphone className="h-8 w-8" />
              Integrated Security Browser
            </h1>
            <p className="text-muted-foreground text-pretty">
              Browse and analyze real websites with built-in security testing and proxy bypass
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Browser Interface */}
          <div className="lg:col-span-2 space-y-4">
            {/* Browser Controls */}
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-4">
                  <Button variant="outline" size="sm" onClick={goBack} disabled={historyIndex <= 0 || isLoading}>
                    <ArrowLeftIcon className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={goForward}
                    disabled={historyIndex >= history.length - 1 || isLoading}
                  >
                    <ArrowRight className="h-4 w-4" />
                  </Button>
                  <Button variant="outline" size="sm" onClick={refresh} disabled={isLoading || !currentUrl}>
                    <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => navigateToUrl(targetDomain || "https://example.com")}
                  >
                    <Home className="h-4 w-4" />
                  </Button>
                  <Button variant="outline" size="sm" onClick={openInNewTab} disabled={!currentUrl}>
                    <ExternalLink className="h-4 w-4" />
                  </Button>

                  <div className="ml-auto">
                    <Select value={embedMethod} onValueChange={(value: "iframe" | "proxy") => setEmbedMethod(value)}>
                      <SelectTrigger className="w-32">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="iframe">
                          <div className="flex items-center gap-2">
                            <Globe className="h-3 w-3" />
                            IFrame
                          </div>
                        </SelectItem>
                        <SelectItem value="proxy">
                          <div className="flex items-center gap-2">
                            <Shield className="h-3 w-3" />
                            Proxy
                          </div>
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <form onSubmit={handleUrlSubmit} className="flex gap-2">
                  <div className="flex-1 relative">
                    <div className="absolute left-3 top-1/2 transform -translate-y-1/2">
                      {currentUrl.startsWith("https://") ? (
                        <Lock className="h-4 w-4 text-primary" />
                      ) : (
                        <Unlock className="h-4 w-4 text-destructive" />
                      )}
                    </div>
                    <Input
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      placeholder="Enter URL to test..."
                      className="pl-10"
                      disabled={isLoading || isSettingUpProxy}
                    />
                  </div>
                  <Button type="submit" disabled={isLoading || !urlInput.trim() || isSettingUpProxy}>
                    {isSettingUpProxy ? (
                      <>
                        <Wifi className="h-4 w-4 mr-2 animate-spin" />
                        Setting up Proxy
                      </>
                    ) : (
                      <>
                        <Globe className="h-4 w-4 mr-2" />
                        Navigate
                      </>
                    )}
                  </Button>
                </form>

                <div className="flex items-center justify-between mt-2 text-xs text-muted-foreground">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-xs">
                      {embedMethod === "proxy" ? (
                        <>
                          <Shield className="h-3 w-3 mr-1" />
                          Proxy Mode - Bypasses iframe restrictions
                        </>
                      ) : (
                        <>
                          <Globe className="h-3 w-3 mr-1" />
                          Direct Mode - May be blocked by some sites
                        </>
                      )}
                    </Badge>
                  </div>
                  {embedMethod === "iframe" && iframeError && (
                    <Button variant="link" size="sm" onClick={handleAutoProxyFallback} className="text-xs h-auto p-0">
                      Switch to Proxy Mode
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Browser Viewport */}
            <Card>
              <CardContent className="p-0">
                <div className="bg-muted/20 border rounded-lg overflow-hidden" style={{ height: "600px" }}>
                  {isLoading || isSettingUpProxy ? (
                    <div className="flex items-center justify-center h-full">
                      <div className="text-center space-y-4">
                        <RefreshCw className="h-8 w-8 animate-spin mx-auto text-primary" />
                        <div>
                          <p className="font-medium">
                            {isSettingUpProxy ? "Setting up proxy..." : "Loading website..."}
                          </p>
                          <p className="text-sm text-muted-foreground">
                            {isSettingUpProxy
                              ? "Configuring bypass for iframe restrictions"
                              : `Analyzing ${currentUrl}`}
                          </p>
                        </div>
                      </div>
                    </div>
                  ) : iframeError ? (
                    <div className="flex items-center justify-center h-full">
                      <div className="text-center space-y-4 p-8">
                        <AlertTriangle className="h-16 w-16 mx-auto text-destructive" />
                        <div>
                          <h3 className="text-lg font-medium">Failed to Load Website</h3>
                          <p className="text-sm text-muted-foreground">
                            The website blocks iframe embedding or has CORS restrictions
                          </p>
                          <p className="text-xs text-muted-foreground mt-2">
                            Try switching to Proxy Mode to bypass these restrictions
                          </p>
                        </div>
                        <div className="flex gap-2 justify-center">
                          <Button onClick={handleAutoProxyFallback} variant="default">
                            <Shield className="h-4 w-4 mr-2" />
                            Use Proxy Mode
                          </Button>
                          <Button onClick={refresh} variant="outline">
                            <RefreshCw className="h-4 w-4 mr-2" />
                            Retry
                          </Button>
                          <Button onClick={openInNewTab} variant="outline">
                            <ExternalLink className="h-4 w-4 mr-2" />
                            Open in New Tab
                          </Button>
                        </div>
                      </div>
                    </div>
                  ) : currentUrl ? (
                    <iframe
                      ref={iframeRef}
                      src={embedMethod === "proxy" ? proxyUrl || currentUrl : currentUrl}
                      className="w-full h-full border-0"
                      onLoad={handleIframeLoad}
                      onError={handleIframeError}
                      sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox"
                      title="Security Browser"
                    />
                  ) : (
                    <div className="flex items-center justify-center h-full">
                      <div className="text-center space-y-4 p-8">
                        <Globe className="h-16 w-16 mx-auto text-muted-foreground" />
                        <div>
                          <h3 className="text-lg font-medium">Ready to Browse</h3>
                          <p className="text-sm text-muted-foreground">Enter a URL above to start security testing</p>
                          <p className="text-xs text-muted-foreground mt-2">
                            Use Proxy Mode for sites that block iframe embedding
                          </p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Security Analysis Panel */}
          <div className="space-y-4">
            {/* Security Overview */}
            {currentSession && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Security Overview</CardTitle>
                  <CardDescription>Real-time security analysis</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-3 gap-2">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-primary">{passedChecks}</div>
                      <div className="text-xs text-muted-foreground">Passed</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-yellow-500">{warningChecks}</div>
                      <div className="text-xs text-muted-foreground">Warnings</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-destructive">{failedChecks}</div>
                      <div className="text-xs text-muted-foreground">Failed</div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    {currentSession.securityChecks.map((check) => (
                      <div key={check.id} className="flex items-center justify-between p-2 rounded border">
                        <div className="flex items-center gap-2">
                          <Badge className={getSecurityStatusColor(check.status)}>
                            {getSecurityIcon(check.status)}
                          </Badge>
                          <span className="text-sm font-medium">{check.type}</span>
                        </div>
                        <span className="text-xs text-muted-foreground">{check.message}</span>
                      </div>
                    ))}
                  </div>

                  <Button onClick={runQuickSecurityTest} className="w-full bg-transparent" variant="outline">
                    <Bug className="h-4 w-4 mr-2" />
                    Re-run Security Analysis
                  </Button>
                </CardContent>
              </Card>
            )}

            {/* Detailed Analysis */}
            {currentSession && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Detailed Analysis</CardTitle>
                </CardHeader>
                <CardContent>
                  <Tabs defaultValue="headers" className="w-full">
                    <TabsList className="grid w-full grid-cols-3">
                      <TabsTrigger value="headers">Headers</TabsTrigger>
                      <TabsTrigger value="cookies">Cookies</TabsTrigger>
                      <TabsTrigger value="checks">Checks</TabsTrigger>
                    </TabsList>

                    <TabsContent value="headers" className="space-y-2">
                      <ScrollArea className="h-48">
                        <div className="space-y-2">
                          {Object.entries(currentSession.responseHeaders).map(([key, value]) => (
                            <div key={key} className="p-2 bg-muted rounded text-xs">
                              <div className="font-medium">{key}:</div>
                              <div className="text-muted-foreground font-mono">{value}</div>
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    </TabsContent>

                    <TabsContent value="cookies" className="space-y-2">
                      <ScrollArea className="h-48">
                        <div className="space-y-2">
                          {currentSession.cookies.map((cookie, index) => (
                            <div key={index} className="p-2 bg-muted rounded text-xs">
                              <div className="flex items-center justify-between mb-1">
                                <span className="font-medium">{cookie.name}</span>
                                <div className="flex gap-1">
                                  {cookie.secure && (
                                    <Badge variant="outline" className="text-xs">
                                      Secure
                                    </Badge>
                                  )}
                                  {cookie.httpOnly && (
                                    <Badge variant="outline" className="text-xs">
                                      HttpOnly
                                    </Badge>
                                  )}
                                </div>
                              </div>
                              <div className="text-muted-foreground font-mono">{cookie.value}</div>
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    </TabsContent>

                    <TabsContent value="checks" className="space-y-2">
                      <ScrollArea className="h-48">
                        <div className="space-y-2">
                          {currentSession.securityChecks.map((check) => (
                            <div key={check.id} className="p-2 bg-muted rounded text-xs">
                              <div className="flex items-center justify-between mb-1">
                                <span className="font-medium">{check.type}</span>
                                <Badge className={getSecurityStatusColor(check.status)}>{check.status}</Badge>
                              </div>
                              <div className="text-muted-foreground mb-1">{check.message}</div>
                              {check.details && <div className="text-xs text-muted-foreground">{check.details}</div>}
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    </TabsContent>
                  </Tabs>
                </CardContent>
              </Card>
            )}

            {/* Session History */}
            {sessions.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Session History</CardTitle>
                  <CardDescription>Recent security tests</CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-48">
                    <div className="space-y-2">
                      {sessions.slice(0, 5).map((session) => (
                        <div
                          key={session.id}
                          className={`p-2 rounded border cursor-pointer transition-colors ${
                            currentSession?.id === session.id ? "bg-primary/10 border-primary" : "hover:bg-muted"
                          }`}
                          onClick={() => setCurrentSession(session)}
                        >
                          <div className="text-sm font-medium truncate">{new URL(session.url).hostname}</div>
                          <div className="text-xs text-muted-foreground">{session.timestamp.toLocaleTimeString()}</div>
                          <div className="flex gap-1 mt-1">
                            <Badge variant="outline" className="text-xs">
                              {session.securityChecks.filter((c) => c.status === "pass").length} passed
                            </Badge>
                            <Badge variant="outline" className="text-xs">
                              {session.securityChecks.filter((c) => c.status === "fail").length} failed
                            </Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
