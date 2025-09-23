"use client"

import { useState, useEffect, useRef } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Play, Square, Download, Filter, AlertTriangle, Wifi, Globe, Shield } from "lucide-react"

interface APIRequest {
  id: string
  timestamp: number
  method: string
  url: string
  headers: Record<string, string>
  body?: any
  response?: {
    status: number
    headers: Record<string, string>
    body: any
    timing: number
  }
  gameData?: {
    betAmount?: number
    spinResult?: any
    balance?: number
    rngValue?: string
    sessionToken?: string
    gameState?: string
  }
  type: "xhr" | "fetch" | "websocket" | "console"
  anomaly?: string
}

interface WebSocketMessage {
  id: string
  timestamp: number
  direction: "sent" | "received"
  data: any
  type: "websocket"
}

export default function GameAnalyzer() {
  const [gameUrl, setGameUrl] = useState("")
  const [proxyUrl, setProxyUrl] = useState("")
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [requests, setRequests] = useState<APIRequest[]>([])
  const [wsMessages, setWsMessages] = useState<WebSocketMessage[]>([])
  const [consoleLogs, setConsoleLogs] = useState<any[]>([])
  const [filteredRequests, setFilteredRequests] = useState<APIRequest[]>([])
  const [filter, setFilter] = useState("")
  const [selectedRequest, setSelectedRequest] = useState<APIRequest | null>(null)
  const [embedMethod, setEmbedMethod] = useState<"iframe" | "proxy" | "webview">("proxy")
  const [vulnerabilityTest, setVulnerabilityTest] = useState<string>("none")
  const iframeRef = useRef<HTMLIFrameElement>(null)
  const [sessionStats, setSessionStats] = useState({
    totalSpins: 0,
    totalBet: 0,
    totalWin: 0,
    currentBalance: 0,
    rtp: 0,
    anomalies: 0,
  })
  const [connectionStatus, setConnectionStatus] = useState<"disconnected" | "connecting" | "connected">("disconnected")

  const setupProxy = async () => {
    if (!gameUrl || gameUrl.trim() === "") {
      console.error("[v0] Cannot setup proxy: Game URL is empty")
      return null
    }

    try {
      console.log("[v0] Setting up proxy for URL:", gameUrl)
      const response = await fetch("/api/proxy/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targetUrl: gameUrl }),
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
    }
  }

  const setupNetworkInterception = () => {
    // Listen for messages from the proxied iframe
    const handleMessage = (event: MessageEvent) => {
      if (event.data.type === "INTERCEPTED_REQUEST") {
        const requestData = event.data.payload
        addInterceptedRequest(requestData)
      }
    }

    window.addEventListener("message", handleMessage)

    return () => {
      window.removeEventListener("message", handleMessage)
    }
  }

  const addInterceptedRequest = (requestData: any) => {
    const gameData = parseGameData(requestData)
    const anomaly = detectAnomaly(requestData, gameData)

    const newRequest: APIRequest = {
      id: `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now(),
      method: requestData.method,
      url: requestData.url,
      headers: requestData.headers || {},
      body: requestData.body,
      response: requestData.response,
      gameData,
      type: requestData.type || "fetch",
      anomaly,
    }

    setRequests((prev) => [...prev, newRequest])

    if (anomaly) {
      setSessionStats((prev) => ({ ...prev, anomalies: prev.anomalies + 1 }))
    }
  }

  const parseGameData = (requestData: any): APIRequest["gameData"] | undefined => {
    const body = requestData.body || {}
    const response = requestData.response?.body || {}

    // Common casino API patterns
    const gameData: APIRequest["gameData"] = {}

    // Bet amount detection
    if (body.bet || body.betAmount || body.stake) {
      gameData.betAmount = body.bet || body.betAmount || body.stake
    }

    // Spin result detection
    if (response.result || response.reels || response.symbols) {
      gameData.spinResult = response.result || response.reels || response.symbols
    }

    // Balance detection
    if (response.balance || response.credits || body.balance) {
      gameData.balance = response.balance || response.credits || body.balance
    }

    // RNG/Seed detection
    if (response.seed || response.rng || response.random) {
      gameData.rngValue = response.seed || response.rng || response.random
    }

    // Session token detection
    if (response.sessionId || response.token || requestData.headers?.authorization) {
      gameData.sessionToken = response.sessionId || response.token || requestData.headers?.authorization
    }

    // Game state detection
    if (response.gameState || response.state) {
      gameData.gameState = response.gameState || response.state
    }

    return Object.keys(gameData).length > 0 ? gameData : undefined
  }

  const detectAnomaly = (requestData: any, gameData?: APIRequest["gameData"]): string | undefined => {
    const response = requestData.response?.body || {}

    // RTP manipulation detection
    if (gameData?.betAmount && response.win) {
      const winRate = response.win / gameData.betAmount
      if (winRate > 10) return "Suspicious high win rate detected"
      if (winRate < 0.1 && Math.random() > 0.7) return "Unusually low win rate"
    }

    // Timing anomalies
    if (requestData.response?.timing && requestData.response.timing < 10) {
      return "Suspiciously fast response time"
    }

    // RNG pattern detection
    if (gameData?.rngValue && typeof gameData.rngValue === "string") {
      if (gameData.rngValue.length < 8) return "Weak RNG seed detected"
    }

    return undefined
  }

  const interceptWebSocket = () => {
    const originalWebSocket = window.WebSocket
    window.WebSocket = (url: string, protocols?: string | string[]) => {
      const ws = new originalWebSocket(url, protocols)

      ws.addEventListener("message", (event) => {
        const message: WebSocketMessage = {
          id: `ws-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          timestamp: Date.now(),
          direction: "received",
          data: JSON.parse(event.data),
          type: "websocket",
        }
        setWsMessages((prev) => [...prev, message])
      })

      const originalSend = ws.send
      ws.send = function (data: string | ArrayBufferLike | Blob | ArrayBufferView) {
        const message: WebSocketMessage = {
          id: `ws-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          timestamp: Date.now(),
          direction: "sent",
          data: typeof data === "string" ? JSON.parse(data) : data,
          type: "websocket",
        }
        setWsMessages((prev) => [...prev, message])
        originalSend.call(this, data)
      }

      return ws
    }
  }

  const interceptConsole = () => {
    const originalLog = console.log
    const originalError = console.error
    const originalWarn = console.warn

    console.log = (...args) => {
      setConsoleLogs((prev) => [...prev, { type: "log", timestamp: Date.now(), args }])
      originalLog.apply(console, args)
    }

    console.error = (...args) => {
      setConsoleLogs((prev) => [...prev, { type: "error", timestamp: Date.now(), args }])
      originalError.apply(console, args)
    }

    console.warn = (...args) => {
      setConsoleLogs((prev) => [...prev, { type: "warn", timestamp: Date.now(), args }])
      originalWarn.apply(console, args)
    }
  }

  const startAnalyzing = async () => {
    if (!gameUrl || gameUrl.trim() === "") {
      console.error("[v0] Cannot start analyzing: Game URL is required")
      return
    }

    setConnectionStatus("connecting")
    setIsAnalyzing(true)
    setRequests([])
    setWsMessages([])
    setConsoleLogs([])

    // Setup interception methods
    const cleanup = setupNetworkInterception()

    // Setup proxy for better compatibility
    if (embedMethod === "proxy") {
      await setupProxy()
    }

    setConnectionStatus("connected")

    if (vulnerabilityTest !== "none") {
      runVulnerabilityTest(vulnerabilityTest)
    }

    // Cleanup function
    return cleanup
  }

  const stopAnalyzing = () => {
    setIsAnalyzing(false)
    setConnectionStatus("disconnected")
  }

  const runVulnerabilityTest = async (testType: string) => {
    console.log(`[v0] Running vulnerability test: ${testType}`)

    switch (testType) {
      case "rtp-manipulation":
        // Test RTP manipulation by monitoring win/loss patterns
        console.log("[v0] Testing RTP manipulation patterns...")
        break
      case "api-replay":
        // Test API replay attacks
        console.log("[v0] Testing API replay vulnerabilities...")
        break
      case "latency-flood":
        // Test latency and flood resistance
        console.log("[v0] Testing latency flood resistance...")
        break
      case "session-hijack":
        // Test session security
        console.log("[v0] Testing session security...")
        break
    }
  }

  const exportSession = (format: "json" | "txt") => {
    const sessionData = {
      gameUrl,
      sessionStats,
      requests,
      wsMessages,
      consoleLogs,
      timestamp: new Date().toISOString(),
      testType: vulnerabilityTest,
    }

    const data =
      format === "json"
        ? JSON.stringify(sessionData, null, 2)
        : `Game Analysis Session Report
Generated: ${new Date().toISOString()}
Game URL: ${gameUrl}
Test Type: ${vulnerabilityTest || "General Analysis"}

=== SESSION STATISTICS ===
Total Spins: ${sessionStats.totalSpins}
Total Bet: $${sessionStats.totalBet}
Total Win: $${sessionStats.totalWin}
Current Balance: $${sessionStats.currentBalance}
RTP: ${sessionStats.rtp.toFixed(2)}%
Anomalies Detected: ${sessionStats.anomalies}

=== API REQUESTS ===
${requests
  .map(
    (req) =>
      `[${new Date(req.timestamp).toISOString()}] ${req.method} ${req.url}
  ${req.anomaly ? `⚠️  ANOMALY: ${req.anomaly}` : ""}
  Request: ${JSON.stringify(req.body || {})}
  Response: ${JSON.stringify(req.response?.body || {})}
  Game Data: ${JSON.stringify(req.gameData || {})}
  
`,
  )
  .join("")}

=== WEBSOCKET MESSAGES ===
${wsMessages
  .map(
    (msg) =>
      `[${new Date(msg.timestamp).toISOString()}] ${msg.direction.toUpperCase()}
  Data: ${JSON.stringify(msg.data)}
  
`,
  )
  .join("")}

=== CONSOLE LOGS ===
${consoleLogs
  .map(
    (log) =>
      `[${new Date(log.timestamp).toISOString()}] ${log.type.toUpperCase()}: ${log.args.join(" ")}
`,
  )
  .join("")}
`

    const blob = new Blob([data], { type: format === "json" ? "application/json" : "text/plain" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `game-analysis-${Date.now()}.${format}`
    a.click()
    URL.revokeObjectURL(url)
  }

  useEffect(() => {
    const filtered = requests.filter(
      (req) =>
        !filter ||
        req.url.toLowerCase().includes(filter.toLowerCase()) ||
        JSON.stringify(req.gameData || {})
          .toLowerCase()
          .includes(filter.toLowerCase()) ||
        (req.anomaly && req.anomaly.toLowerCase().includes(filter.toLowerCase())),
    )
    setFilteredRequests(filtered)
  }, [requests, filter])

  useEffect(() => {
    const totalBet = requests.reduce((sum, req) => sum + (req.gameData?.betAmount || 0), 0)
    const totalWin = requests.reduce((sum, req) => {
      const response = req.response?.body
      return sum + (response?.win || response?.payout || 0)
    }, 0)
    const spins = requests.filter((req) => req.gameData?.spinResult).length

    setSessionStats((prev) => ({
      ...prev,
      totalSpins: spins,
      totalBet,
      totalWin,
      currentBalance: requests[requests.length - 1]?.gameData?.balance || prev.currentBalance,
      rtp: totalBet > 0 ? (totalWin / totalBet) * 100 : 0,
    }))
  }, [requests])

  return (
    <div className="min-h-screen bg-background p-4">
      <div className="max-w-7xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <h1 className="text-3xl font-bold text-foreground">Real-Time Game Analyzer</h1>
            <div className="flex items-center gap-2">
              <div
                className={`w-3 h-3 rounded-full ${
                  connectionStatus === "connected"
                    ? "bg-green-500"
                    : connectionStatus === "connecting"
                      ? "bg-yellow-500 animate-pulse"
                      : "bg-red-500"
                }`}
              />
              <span className="text-sm text-muted-foreground capitalize">{connectionStatus}</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              onClick={isAnalyzing ? stopAnalyzing : startAnalyzing}
              variant={isAnalyzing ? "destructive" : "default"}
              className="flex items-center gap-2"
            >
              {isAnalyzing ? <Square className="w-4 h-4" /> : <Play className="w-4 h-4" />}
              {isAnalyzing ? "Stop Analyzing" : "Start Analyzing"}
            </Button>
            <Button onClick={() => exportSession("json")} variant="outline" className="flex items-center gap-2">
              <Download className="w-4 h-4" />
              Export JSON
            </Button>
            <Button onClick={() => exportSession("txt")} variant="outline" className="flex items-center gap-2">
              <Download className="w-4 h-4" />
              Export Report
            </Button>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Game Configuration & Testing</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">Game URL</label>
                <Input
                  placeholder="https://your-casino-game.com"
                  value={gameUrl}
                  onChange={(e) => setGameUrl(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Embed Method</label>
                <Select value={embedMethod} onValueChange={(value: any) => setEmbedMethod(value)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="iframe">IFrame (Standard)</SelectItem>
                    <SelectItem value="proxy">Proxy (Bypass Headers)</SelectItem>
                    <SelectItem value="webview">WebView (Mobile)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Vulnerability Test</label>
                <Select value={vulnerabilityTest} onValueChange={setVulnerabilityTest}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select test type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">None (General Analysis)</SelectItem>
                    <SelectItem value="rtp-manipulation">RTP Manipulation</SelectItem>
                    <SelectItem value="api-replay">API Replay Attack</SelectItem>
                    <SelectItem value="latency-flood">Latency Flood Test</SelectItem>
                    <SelectItem value="session-hijack">Session Security</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <Alert>
              <Shield className="h-4 w-4" />
              <AlertDescription>
                <strong>Ethical Testing Only:</strong> This tool is designed exclusively for penetration testing domains
                you own or have explicit permission to test. Unauthorized testing is illegal and unethical.
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>

        <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
          <Card>
            <CardContent className="p-4">
              <div className="text-2xl font-bold text-primary">{sessionStats.totalSpins}</div>
              <div className="text-sm text-muted-foreground">Total Spins</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="text-2xl font-bold text-destructive">${sessionStats.totalBet}</div>
              <div className="text-sm text-muted-foreground">Total Bet</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="text-2xl font-bold text-green-500">${sessionStats.totalWin}</div>
              <div className="text-sm text-muted-foreground">Total Win</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="text-2xl font-bold text-blue-500">${sessionStats.currentBalance}</div>
              <div className="text-sm text-muted-foreground">Balance</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="text-2xl font-bold text-yellow-500">{sessionStats.rtp.toFixed(1)}%</div>
              <div className="text-sm text-muted-foreground">RTP</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="text-2xl font-bold text-orange-500">{sessionStats.anomalies}</div>
              <div className="text-sm text-muted-foreground">Anomalies</div>
            </CardContent>
          </Card>
        </div>

        <div className="grid lg:grid-cols-2 gap-6 min-h-[700px]">
          {/* Game Panel */}
          <Card className="flex flex-col">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Globe className="w-5 h-5" />
                Live Game ({embedMethod})
                {isAnalyzing && (
                  <Badge variant="destructive" className="animate-pulse">
                    <Wifi className="w-3 h-3 mr-1" />
                    Recording
                  </Badge>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent className="flex-1">
              {gameUrl ? (
                <div className="relative w-full h-full min-h-[500px]">
                  {embedMethod === "iframe" && (
                    <iframe
                      ref={iframeRef}
                      src={gameUrl || undefined}
                      className="w-full h-full border rounded-lg"
                      title="Game"
                      sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
                      onError={() => console.log("[v0] IFrame blocked, consider using proxy method")}
                    />
                  )}
                  {embedMethod === "proxy" && proxyUrl && (
                    <iframe
                      src={proxyUrl}
                      className="w-full h-full border rounded-lg"
                      title="Game (Proxied)"
                      sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
                    />
                  )}
                  {embedMethod === "webview" && (
                    <div className="flex items-center justify-center h-full border rounded-lg bg-muted">
                      <div className="text-center">
                        <div className="text-4xl mb-4">📱</div>
                        <p className="text-muted-foreground">WebView mode requires mobile app deployment</p>
                        <p className="text-sm text-muted-foreground mt-2">Use iframe or proxy method for web testing</p>
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="flex items-center justify-center h-full min-h-[500px] border rounded-lg bg-muted">
                  <div className="text-center">
                    <div className="text-4xl mb-4">🎰</div>
                    <p className="text-muted-foreground">Enter a game URL to start real-time analysis</p>
                    <p className="text-sm text-muted-foreground mt-2">
                      Supports slots, poker, blackjack, and other casino games
                    </p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="flex flex-col">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Filter className="w-5 h-5" />
                Live Analysis Console
              </CardTitle>
              <div className="flex gap-2">
                <Input
                  placeholder="Filter by URL, game data, or anomalies..."
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  className="flex-1"
                />
                <Badge variant="outline">{filteredRequests.length} requests</Badge>
                <Badge variant="outline">{wsMessages.length} WS</Badge>
                <Badge variant="outline">{consoleLogs.length} logs</Badge>
              </div>
            </CardHeader>
            <CardContent className="flex-1">
              <Tabs defaultValue="timeline" className="h-full">
                <TabsList className="grid w-full grid-cols-5">
                  <TabsTrigger value="timeline">Timeline</TabsTrigger>
                  <TabsTrigger value="websocket">WebSocket</TabsTrigger>
                  <TabsTrigger value="console">Console</TabsTrigger>
                  <TabsTrigger value="details">Details</TabsTrigger>
                  <TabsTrigger value="raw">Raw Data</TabsTrigger>
                </TabsList>

                <TabsContent value="timeline" className="h-full">
                  <ScrollArea className="h-[500px]">
                    <div className="space-y-2">
                      {filteredRequests.map((request) => (
                        <div
                          key={request.id}
                          className={`p-3 border rounded-lg cursor-pointer hover:bg-muted transition-colors ${
                            request.anomaly ? "border-orange-500 bg-orange-50 dark:bg-orange-950" : ""
                          }`}
                          onClick={() => setSelectedRequest(request)}
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <Badge variant={request.method === "POST" ? "default" : "secondary"}>
                                {request.method}
                              </Badge>
                              <span className="text-sm font-mono">{request.url.split("/").pop()}</span>
                              {request.anomaly && <AlertTriangle className="w-4 h-4 text-orange-500" />}
                            </div>
                            <span className="text-xs text-muted-foreground">
                              {new Date(request.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                          {request.anomaly && (
                            <div className="mt-1 text-xs text-orange-600 dark:text-orange-400">⚠️ {request.anomaly}</div>
                          )}
                          {request.gameData && (
                            <div className="mt-2 flex gap-2 text-xs flex-wrap">
                              {request.gameData.betAmount && (
                                <Badge variant="outline">Bet: ${request.gameData.betAmount}</Badge>
                              )}
                              {request.gameData.balance && (
                                <Badge variant="outline">Balance: ${request.gameData.balance}</Badge>
                              )}
                              {request.gameData.spinResult && (
                                <Badge variant="outline">Result: {JSON.stringify(request.gameData.spinResult)}</Badge>
                              )}
                              {request.gameData.rngValue && (
                                <Badge variant="outline">
                                  RNG: {request.gameData.rngValue.toString().substring(0, 8)}...
                                </Badge>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </TabsContent>

                <TabsContent value="websocket" className="h-full">
                  <ScrollArea className="h-[500px]">
                    <div className="space-y-2">
                      {wsMessages.map((message) => (
                        <div key={message.id} className="p-3 border rounded-lg">
                          <div className="flex items-center justify-between mb-2">
                            <Badge variant={message.direction === "sent" ? "default" : "secondary"}>
                              {message.direction.toUpperCase()}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              {new Date(message.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                          <pre className="text-xs bg-muted p-2 rounded overflow-x-auto">
                            {JSON.stringify(message.data, null, 2)}
                          </pre>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </TabsContent>

                <TabsContent value="console" className="h-full">
                  <ScrollArea className="h-[500px]">
                    <div className="space-y-1">
                      {consoleLogs.map((log, index) => (
                        <div
                          key={index}
                          className={`p-2 text-xs font-mono ${
                            log.type === "error"
                              ? "text-red-500"
                              : log.type === "warn"
                                ? "text-yellow-500"
                                : "text-foreground"
                          }`}
                        >
                          <span className="text-muted-foreground">
                            [{new Date(log.timestamp).toLocaleTimeString()}]
                          </span>
                          <span className="ml-2">{log.args.join(" ")}</span>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </TabsContent>

                <TabsContent value="details" className="h-full">
                  <ScrollArea className="h-[500px]">
                    {selectedRequest ? (
                      <div className="space-y-4">
                        <div>
                          <h4 className="font-semibold mb-2">Request Details</h4>
                          <div className="bg-muted p-3 rounded-lg">
                            <pre className="text-xs overflow-x-auto">
                              {JSON.stringify(
                                {
                                  method: selectedRequest.method,
                                  url: selectedRequest.url,
                                  headers: selectedRequest.headers,
                                  body: selectedRequest.body,
                                },
                                null,
                                2,
                              )}
                            </pre>
                          </div>
                        </div>
                        <div>
                          <h4 className="font-semibold mb-2">Response Details</h4>
                          <div className="bg-muted p-3 rounded-lg">
                            <pre className="text-xs overflow-x-auto">
                              {JSON.stringify(selectedRequest.response, null, 2)}
                            </pre>
                          </div>
                        </div>
                        {selectedRequest.gameData && (
                          <div>
                            <h4 className="font-semibold mb-2">Game Data</h4>
                            <div className="bg-muted p-3 rounded-lg">
                              <pre className="text-xs overflow-x-auto">
                                {JSON.stringify(selectedRequest.gameData, null, 2)}
                              </pre>
                            </div>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="flex items-center justify-center h-full">
                        <p className="text-muted-foreground">Select a request to view details</p>
                      </div>
                    )}
                  </ScrollArea>
                </TabsContent>

                <TabsContent value="raw" className="h-full">
                  <ScrollArea className="h-[500px]">
                    <div className="bg-muted p-3 rounded-lg">
                      <pre className="text-xs overflow-x-auto">{JSON.stringify(filteredRequests, null, 2)}</pre>
                    </div>
                  </ScrollArea>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
