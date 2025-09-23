"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import {
  Shield,
  Play,
  Pause,
  ArrowLeft,
  AlertTriangle,
  CheckCircle,
  Clock,
  Network,
  Lock,
  Server,
  Globe,
} from "lucide-react"

interface Port {
  number: number
  protocol: "TCP" | "UDP"
  state: "open" | "closed" | "filtered"
  service?: string
  version?: string
  banner?: string
}

interface SslInfo {
  version: string
  cipher: string
  certificate: {
    subject: string
    issuer: string
    validFrom: string
    validTo: string
    expired: boolean
  }
  vulnerabilities: string[]
}

interface NetworkScanResult {
  id: string
  target: string
  scanType: "port" | "ssl" | "service" | "full"
  status: "scanning" | "completed" | "error"
  progress: number
  startTime: Date
  endTime?: Date
  ports: Port[]
  sslInfo?: SslInfo
  vulnerabilities: NetworkVulnerability[]
  hostInfo: {
    ip: string
    hostname?: string
    os?: string
    uptime?: string
  }
}

interface NetworkVulnerability {
  id: string
  type: "OPEN_PORT" | "SSL_WEAK" | "SERVICE_VERSION" | "BANNER_GRAB" | "OS_DETECTION"
  severity: "Critical" | "High" | "Medium" | "Low" | "Info"
  port?: number
  service?: string
  description: string
  evidence: string
  recommendation: string
}

interface NetworkScannerProps {
  onBack: () => void
}

export default function NetworkScanner({ onBack }: NetworkScannerProps) {
  const [target, setTarget] = useState("")
  const [scanType, setScanType] = useState<"port" | "ssl" | "service" | "full">("port")
  const [portRange, setPortRange] = useState("1-1000")
  const [scanResults, setScanResults] = useState<NetworkScanResult[]>([])
  const [isScanning, setIsScanning] = useState(false)

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical":
        return "bg-red-600 text-white"
      case "High":
        return "bg-red-500 text-white"
      case "Medium":
        return "bg-yellow-500 text-black"
      case "Low":
        return "bg-blue-500 text-white"
      case "Info":
        return "bg-gray-500 text-white"
      default:
        return "bg-muted text-muted-foreground"
    }
  }

  const getPortStateColor = (state: string) => {
    switch (state) {
      case "open":
        return "bg-red-500 text-white"
      case "closed":
        return "bg-gray-500 text-white"
      case "filtered":
        return "bg-yellow-500 text-black"
      default:
        return "bg-muted text-muted-foreground"
    }
  }

  const simulateNetworkScan = async (targetHost: string, type: string): Promise<NetworkScanResult> => {
    const scanId = Date.now().toString()
    const result: NetworkScanResult = {
      id: scanId,
      target: targetHost,
      scanType: type as any,
      status: "scanning",
      progress: 0,
      startTime: new Date(),
      ports: [],
      vulnerabilities: [],
      hostInfo: {
        ip: "Resolving...",
        hostname: targetHost,
      },
    }

    try {
      // Real network scan via API
      const response = await fetch("/api/network-scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          target: targetHost,
          scanType: type,
          portRange: portRange,
        }),
      })

      if (response.ok) {
        const scanData = await response.json()

        // Update progress incrementally
        for (let i = 0; i <= 100; i += 10) {
          await new Promise((resolve) => setTimeout(resolve, 200))
          result.progress = i
          setScanResults((prev) => prev.map((scan) => (scan.id === scanId ? { ...result } : scan)))
        }

        result.status = "completed"
        result.endTime = new Date()
        result.ports = scanData.ports || []
        result.sslInfo = scanData.sslInfo
        result.vulnerabilities = scanData.vulnerabilities || []
        result.hostInfo = scanData.hostInfo || result.hostInfo
      } else {
        throw new Error("Network scan API failed")
      }
    } catch (error) {
      console.error("[v0] Network scan failed:", error)
      // Fallback to basic connectivity test
      result.status = "completed"
      result.endTime = new Date()
      result.progress = 100

      // Basic connectivity check
      try {
        const connectivityTest = await fetch("/api/connectivity-test", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target: targetHost }),
        })

        if (connectivityTest.ok) {
          const testResult = await connectivityTest.json()
          result.hostInfo = testResult.hostInfo || result.hostInfo
          result.ports = testResult.basicPorts || []
          result.vulnerabilities = [
            {
              id: "1",
              type: "SERVICE_VERSION",
              severity: "Info",
              description: "Basic connectivity test completed",
              evidence: `Host ${targetHost} is reachable`,
              recommendation: "Run full scan for detailed analysis",
            },
          ]
        }
      } catch (fallbackError) {
        result.vulnerabilities = [
          {
            id: "1",
            type: "OPEN_PORT",
            severity: "Info",
            description: "Unable to perform network scan",
            evidence: "Network scan API unavailable",
            recommendation: "Check network connectivity and API availability",
          },
        ]
      }
    }

    return result
  }

  const handleStartScan = async () => {
    if (!target.trim()) return

    setIsScanning(true)
    const newScan: NetworkScanResult = {
      id: Date.now().toString(),
      target,
      scanType,
      status: "scanning",
      progress: 0,
      startTime: new Date(),
      ports: [],
      vulnerabilities: [],
      hostInfo: { ip: "Resolving..." },
    }

    setScanResults((prev) => [newScan, ...prev])

    try {
      const result = await simulateNetworkScan(target, scanType)
      setScanResults((prev) => prev.map((scan) => (scan.id === newScan.id ? result : scan)))
    } catch (error) {
      setScanResults((prev) =>
        prev.map((scan) => (scan.id === newScan.id ? { ...scan, status: "error" as const } : scan)),
      )
    }

    setIsScanning(false)
  }

  const handleStopScan = () => {
    setScanResults((prev) => prev.map((scan) => (scan.status === "scanning" ? { ...scan, status: "error" } : scan)))
    setIsScanning(false)
  }

  const totalVulnerabilities = scanResults.reduce((sum, scan) => sum + scan.vulnerabilities.length, 0)
  const openPorts = scanResults.reduce((sum, scan) => sum + scan.ports.filter((p) => p.state === "open").length, 0)
  const completedScans = scanResults.filter((s) => s.status === "completed").length

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
              <Shield className="h-8 w-8" />
              Network Infrastructure Scanner
            </h1>
            <p className="text-muted-foreground text-pretty">
              Port scanning, SSL/TLS analysis, and service enumeration
            </p>
          </div>
        </div>

        {/* Scan Configuration */}
        <Card>
          <CardHeader>
            <CardTitle>Scan Configuration</CardTitle>
            <CardDescription>Configure your network infrastructure scan</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">Target Host</label>
                <Input
                  placeholder="Enter hostname or IP address"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  disabled={isScanning}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Scan Type</label>
                <Select value={scanType} onValueChange={(value) => setScanType(value as any)} disabled={isScanning}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="port">Port Scan</SelectItem>
                    <SelectItem value="ssl">SSL/TLS Analysis</SelectItem>
                    <SelectItem value="service">Service Detection</SelectItem>
                    <SelectItem value="full">Full Scan</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Port Range</label>
                <Input
                  placeholder="1-1000 or 80,443,22"
                  value={portRange}
                  onChange={(e) => setPortRange(e.target.value)}
                  disabled={isScanning}
                />
              </div>
            </div>
            <div className="flex gap-2">
              <Button onClick={handleStartScan} disabled={isScanning || !target.trim()}>
                <Play className="h-4 w-4 mr-2" />
                Start Scan
              </Button>
              {isScanning && (
                <Button variant="destructive" onClick={handleStopScan}>
                  <Pause className="h-4 w-4 mr-2" />
                  Stop Scan
                </Button>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Statistics */}
        {scanResults.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Total Scans</p>
                    <p className="text-2xl font-bold">{scanResults.length}</p>
                  </div>
                  <Network className="h-8 w-8 text-foreground" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Open Ports</p>
                    <p className="text-2xl font-bold text-destructive">{openPorts}</p>
                  </div>
                  <Server className="h-8 w-8 text-destructive" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Vulnerabilities</p>
                    <p className="text-2xl font-bold text-destructive">{totalVulnerabilities}</p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-destructive" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Completed</p>
                    <p className="text-2xl font-bold text-primary">{completedScans}</p>
                  </div>
                  <CheckCircle className="h-8 w-8 text-primary" />
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Scan Results */}
        {scanResults.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Scan Results</CardTitle>
              <CardDescription>Network infrastructure scan results and findings</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[700px]">
                <div className="space-y-6">
                  {scanResults.map((scan) => (
                    <Card key={scan.id} className="border-l-4 border-l-primary">
                      <CardHeader className="pb-3">
                        <div className="flex items-center justify-between">
                          <div>
                            <CardTitle className="text-lg flex items-center gap-2">
                              <Globe className="h-5 w-5" />
                              {scan.target}
                            </CardTitle>
                            <div className="flex items-center gap-2 mt-1">
                              <Badge
                                variant="secondary"
                                className={
                                  scan.status === "completed"
                                    ? "bg-primary text-primary-foreground"
                                    : scan.status === "scanning"
                                      ? "bg-accent text-accent-foreground"
                                      : "bg-destructive text-destructive-foreground"
                                }
                              >
                                {scan.status === "completed" && <CheckCircle className="h-3 w-3 mr-1" />}
                                {scan.status === "scanning" && <Clock className="h-3 w-3 mr-1" />}
                                {scan.status === "error" && <AlertTriangle className="h-3 w-3 mr-1" />}
                                {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                              </Badge>
                              <Badge variant="outline">{scan.scanType.toUpperCase()}</Badge>
                              <span className="text-sm text-muted-foreground">
                                {scan.startTime.toLocaleTimeString()}
                              </span>
                            </div>
                          </div>
                          <div className="text-right">
                            <p className="text-sm text-muted-foreground">Open Ports</p>
                            <p className="text-2xl font-bold text-destructive">
                              {scan.ports.filter((p) => p.state === "open").length}
                            </p>
                          </div>
                        </div>
                      </CardHeader>

                      <CardContent className="space-y-4">
                        {scan.status === "scanning" && (
                          <div className="space-y-2">
                            <div className="flex justify-between text-sm">
                              <span>Scanning Progress</span>
                              <span>{scan.progress}%</span>
                            </div>
                            <Progress value={scan.progress} className="h-2" />
                          </div>
                        )}

                        {scan.status === "completed" && (
                          <Tabs defaultValue="ports" className="w-full">
                            <TabsList className="grid w-full grid-cols-4">
                              <TabsTrigger value="ports">Ports</TabsTrigger>
                              <TabsTrigger value="host">Host Info</TabsTrigger>
                              {scan.sslInfo && <TabsTrigger value="ssl">SSL/TLS</TabsTrigger>}
                              <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
                            </TabsList>

                            <TabsContent value="ports" className="space-y-3">
                              <div className="grid gap-2">
                                {scan.ports.map((port, index) => (
                                  <Card key={index} className="p-3">
                                    <div className="flex items-center justify-between">
                                      <div className="flex items-center gap-3">
                                        <Badge className={getPortStateColor(port.state)}>{port.state}</Badge>
                                        <span className="font-medium">
                                          {port.number}/{port.protocol}
                                        </span>
                                        {port.service && (
                                          <span className="text-sm text-muted-foreground">{port.service}</span>
                                        )}
                                      </div>
                                      {port.version && (
                                        <span className="text-sm text-muted-foreground">{port.version}</span>
                                      )}
                                    </div>
                                    {port.banner && (
                                      <div className="mt-2 bg-muted p-2 rounded text-xs font-mono">{port.banner}</div>
                                    )}
                                  </Card>
                                ))}
                              </div>
                            </TabsContent>

                            <TabsContent value="host" className="space-y-3">
                              <div className="grid gap-3">
                                <div className="flex justify-between">
                                  <span className="text-sm font-medium">IP Address:</span>
                                  <span className="text-sm">{scan.hostInfo.ip}</span>
                                </div>
                                {scan.hostInfo.hostname && (
                                  <div className="flex justify-between">
                                    <span className="text-sm font-medium">Hostname:</span>
                                    <span className="text-sm">{scan.hostInfo.hostname}</span>
                                  </div>
                                )}
                                {scan.hostInfo.os && (
                                  <div className="flex justify-between">
                                    <span className="text-sm font-medium">Operating System:</span>
                                    <span className="text-sm">{scan.hostInfo.os}</span>
                                  </div>
                                )}
                                {scan.hostInfo.uptime && (
                                  <div className="flex justify-between">
                                    <span className="text-sm font-medium">Uptime:</span>
                                    <span className="text-sm">{scan.hostInfo.uptime}</span>
                                  </div>
                                )}
                              </div>
                            </TabsContent>

                            {scan.sslInfo && (
                              <TabsContent value="ssl" className="space-y-3">
                                <Card className="p-4">
                                  <div className="space-y-3">
                                    <div className="flex items-center gap-2">
                                      <Lock className="h-4 w-4" />
                                      <span className="font-medium">SSL/TLS Configuration</span>
                                    </div>
                                    <div className="grid gap-2 text-sm">
                                      <div className="flex justify-between">
                                        <span>Version:</span>
                                        <span>{scan.sslInfo.version}</span>
                                      </div>
                                      <div className="flex justify-between">
                                        <span>Cipher:</span>
                                        <span className="font-mono text-xs">{scan.sslInfo.cipher}</span>
                                      </div>
                                      <div className="flex justify-between">
                                        <span>Certificate Subject:</span>
                                        <span className="font-mono text-xs">{scan.sslInfo.certificate.subject}</span>
                                      </div>
                                      <div className="flex justify-between">
                                        <span>Valid Until:</span>
                                        <span
                                          className={
                                            scan.sslInfo.certificate.expired ? "text-destructive" : "text-primary"
                                          }
                                        >
                                          {scan.sslInfo.certificate.validTo}
                                        </span>
                                      </div>
                                    </div>
                                    {scan.sslInfo.vulnerabilities.length > 0 && (
                                      <div className="space-y-2">
                                        <span className="text-sm font-medium">SSL Issues:</span>
                                        {scan.sslInfo.vulnerabilities.map((vuln, index) => (
                                          <div key={index} className="bg-destructive/10 p-2 rounded text-sm">
                                            {vuln}
                                          </div>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                </Card>
                              </TabsContent>
                            )}

                            <TabsContent value="vulnerabilities" className="space-y-3">
                              {scan.vulnerabilities.map((vuln) => (
                                <Card key={vuln.id} className="border-l-4 border-l-destructive">
                                  <CardContent className="p-4">
                                    <div className="flex items-start justify-between mb-2">
                                      <div className="flex items-center gap-2">
                                        <AlertTriangle className="h-4 w-4" />
                                        <span className="font-medium">{vuln.type.replace("_", " ")}</span>
                                        {vuln.port && (
                                          <Badge variant="outline">
                                            Port {vuln.port}
                                            {vuln.service && ` (${vuln.service})`}
                                          </Badge>
                                        )}
                                      </div>
                                      <Badge className={getSeverityColor(vuln.severity)}>{vuln.severity}</Badge>
                                    </div>
                                    <p className="text-sm mb-2">{vuln.description}</p>
                                    <div className="bg-muted p-2 rounded text-xs font-mono mb-2">{vuln.evidence}</div>
                                    <div className="bg-primary/10 p-2 rounded text-xs">
                                      <strong>Recommendation:</strong> {vuln.recommendation}
                                    </div>
                                  </CardContent>
                                </Card>
                              ))}
                            </TabsContent>
                          </Tabs>
                        )}
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
