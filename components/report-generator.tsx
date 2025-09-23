"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Checkbox } from "@/components/ui/checkbox"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { FileText, ArrowLeft, Download, Calendar, Building, Shield, Globe, Server, Clock } from "lucide-react"

interface ReportData {
  id: string
  title: string
  client: string
  date: Date
  summary: {
    totalVulnerabilities: number
    criticalVulns: number
    highVulns: number
    mediumVulns: number
    lowVulns: number
    testedDomains: string[]
    scanTypes: string[]
  }
  findings: Finding[]
  recommendations: string[]
}

interface Finding {
  id: string
  title: string
  severity: "Critical" | "High" | "Medium" | "Low" | "Info"
  category: "Web Application" | "API" | "Network" | "Browser"
  description: string
  impact: string
  evidence: string
  recommendation: string
  affectedUrls: string[]
  cvssScore?: number
}

interface ReportGeneratorProps {
  onBack: () => void
}

export default function ReportGenerator({ onBack }: ReportGeneratorProps) {
  const [reportConfig, setReportConfig] = useState({
    title: "",
    client: "",
    tester: "",
    includeSummary: true,
    includeFindings: true,
    includeRecommendations: true,
    includeAppendix: true,
    template: "executive",
  })

  const [isGenerating, setIsGenerating] = useState(false)
  const [generatedReports, setGeneratedReports] = useState<ReportData[]>([])

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

  const collectRealFindings = (): Finding[] => {
    const findings: Finding[] = []

    // Collect findings from localStorage if available from other tools
    try {
      const webScanResults = localStorage.getItem("webScanResults")
      const apiTestResults = localStorage.getItem("apiTestResults")
      const credentialResults = localStorage.getItem("credentialResults")
      const networkResults = localStorage.getItem("networkResults")

      if (webScanResults) {
        const webFindings = JSON.parse(webScanResults)
        findings.push(
          ...webFindings.map((result: any) => ({
            id: `web-${result.id || Date.now()}`,
            title: result.vulnerability || result.title || "Web Vulnerability",
            severity: result.severity || "Medium",
            category: "Web Application" as const,
            description: result.description || "Web application vulnerability detected",
            impact: result.impact || "Potential security risk identified",
            evidence: result.evidence || result.payload || "Evidence collected during scan",
            recommendation: result.recommendation || "Review and remediate the identified vulnerability",
            affectedUrls: result.affectedUrls || [result.url || "Target URL"],
            cvssScore: result.cvssScore,
          })),
        )
      }

      if (apiTestResults) {
        const apiFindings = JSON.parse(apiTestResults)
        findings.push(
          ...apiFindings.map((result: any) => ({
            id: `api-${result.id || Date.now()}`,
            title: result.vulnerability || result.title || "API Vulnerability",
            severity: result.severity || "Medium",
            category: "API" as const,
            description: result.description || "API security vulnerability detected",
            impact: result.impact || "API security risk identified",
            evidence: result.evidence || result.payload || "Evidence from API testing",
            recommendation: result.recommendation || "Secure the API endpoint",
            affectedUrls: result.affectedUrls || [result.endpoint || "API Endpoint"],
            cvssScore: result.cvssScore,
          })),
        )
      }

      if (credentialResults) {
        const credFindings = JSON.parse(credentialResults)
        findings.push(
          ...credFindings.map((result: any) => ({
            id: `cred-${result.id || Date.now()}`,
            title: result.title || "Credential Exposure",
            severity: result.severity || "High",
            category: "Web Application" as const,
            description: result.description || "Exposed credentials detected",
            impact: result.impact || "Unauthorized access possible",
            evidence: result.evidence || "Credentials found in application",
            recommendation: result.recommendation || "Remove exposed credentials and rotate",
            affectedUrls: result.affectedUrls || ["Target Application"],
            cvssScore: result.cvssScore,
          })),
        )
      }

      if (networkResults) {
        const netFindings = JSON.parse(networkResults)
        findings.push(
          ...netFindings.map((result: any) => ({
            id: `net-${result.id || Date.now()}`,
            title: result.title || "Network Vulnerability",
            severity: result.severity || "Medium",
            category: "Network" as const,
            description: result.description || "Network security issue detected",
            impact: result.impact || "Network security risk",
            evidence: result.evidence || "Network scan results",
            recommendation: result.recommendation || "Secure network configuration",
            affectedUrls: result.affectedUrls || ["Network Target"],
            cvssScore: result.cvssScore,
          })),
        )
      }
    } catch (error) {
      console.error("[v0] Error collecting findings:", error)
    }

    return findings
  }

  const generateRealReport = (): ReportData => {
    const realFindings = collectRealFindings()

    const severityCounts = realFindings.reduce(
      (acc, finding) => {
        acc[finding.severity.toLowerCase() as keyof typeof acc]++
        return acc
      },
      { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    )

    // Get tested domains from localStorage or domain context
    const testedDomains: string[] = []
    try {
      const domainContext = localStorage.getItem("targetDomain")
      if (domainContext) testedDomains.push(domainContext)

      const apiEndpoints = localStorage.getItem("testedEndpoints")
      if (apiEndpoints) {
        const endpoints = JSON.parse(apiEndpoints)
        testedDomains.push(...endpoints)
      }
    } catch (error) {
      console.error("[v0] Error getting tested domains:", error)
    }

    return {
      id: Date.now().toString(),
      title: reportConfig.title || "Security Assessment Report",
      client: reportConfig.client,
      date: new Date(),
      summary: {
        totalVulnerabilities: realFindings.length,
        criticalVulns: severityCounts.critical,
        highVulns: severityCounts.high,
        mediumVulns: severityCounts.medium,
        lowVulns: severityCounts.low,
        testedDomains: testedDomains.length > 0 ? testedDomains : ["No domains tested yet"],
        scanTypes: ["Web Application Scan", "API Security Test", "Credential Analysis", "Network Scan"],
      },
      findings: realFindings,
      recommendations:
        realFindings.length > 0
          ? [
              "Implement a comprehensive Web Application Firewall (WAF)",
              "Establish regular security scanning and monitoring procedures",
              "Conduct security awareness training for development teams",
              "Implement proper input validation and output encoding",
              "Review and update security headers configuration",
              "Establish network segmentation and access controls",
            ]
          : [
              "No vulnerabilities found in current scan",
              "Continue regular security assessments",
              "Implement proactive security monitoring",
            ],
    }
  }

  const handleGenerateReport = async () => {
    if (!reportConfig.title.trim() || !reportConfig.client.trim()) {
      alert("Please fill in the report title and client name")
      return
    }

    setIsGenerating(true)

    const newReport = generateRealReport()
    setGeneratedReports((prev) => [newReport, ...prev])
    setIsGenerating(false)
  }

  const handleDownloadReport = (reportId: string) => {
    const report = generatedReports.find((r) => r.id === reportId)
    if (!report) return

    // Create a comprehensive report content
    const reportContent = `
SECURITY ASSESSMENT REPORT
${report.title}
Generated: ${report.date.toLocaleDateString()}
Client: ${report.client}
Tester: ${reportConfig.tester || "PenTest Suite"}

EXECUTIVE SUMMARY
================
Total Vulnerabilities Found: ${report.summary.totalVulnerabilities}
- Critical: ${report.summary.criticalVulns}
- High: ${report.summary.highVulns}
- Medium: ${report.summary.mediumVulns}
- Low: ${report.summary.lowVulns}

Tested Domains: ${report.summary.testedDomains.join(", ")}
Scan Types: ${report.summary.scanTypes.join(", ")}

DETAILED FINDINGS
================
${
  report.findings.length > 0
    ? report.findings
        .map(
          (finding, index) => `
${index + 1}. ${finding.title}
Severity: ${finding.severity}
Category: ${finding.category}
CVSS Score: ${finding.cvssScore || "N/A"}

Description: ${finding.description}

Impact: ${finding.impact}

Evidence: ${finding.evidence}

Recommendation: ${finding.recommendation}

Affected URLs: ${finding.affectedUrls.join(", ")}
`,
        )
        .join("\n")
    : "No vulnerabilities were identified during the security assessment."
}

RECOMMENDATIONS
==============
${report.recommendations.map((rec, index) => `${index + 1}. ${rec}`).join("\n")}

---
This report was generated by PenTest Suite
Generated on: ${new Date().toISOString()}
    `

    // Create and download the file
    const blob = new Blob([reportContent], { type: "text/plain" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `security-report-${report.client.replace(/\s+/g, "-").toLowerCase()}-${report.date.toISOString().split("T")[0]}.txt`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

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
              <FileText className="h-8 w-8" />
              Report Generator
            </h1>
            <p className="text-muted-foreground text-pretty">Generate comprehensive reports from real test results</p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Report Configuration */}
          <Card>
            <CardHeader>
              <CardTitle>Report Configuration</CardTitle>
              <CardDescription>Configure your security assessment report from real scan data</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="report-title">Report Title *</Label>
                  <Input
                    id="report-title"
                    value={reportConfig.title}
                    onChange={(e) => setReportConfig((prev) => ({ ...prev, title: e.target.value }))}
                    placeholder="Enter report title"
                    required
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="client-name">Client Name *</Label>
                    <Input
                      id="client-name"
                      value={reportConfig.client}
                      onChange={(e) => setReportConfig((prev) => ({ ...prev, client: e.target.value }))}
                      placeholder="Enter client/organization name"
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="tester-name">Tester Name</Label>
                    <Input
                      id="tester-name"
                      value={reportConfig.tester}
                      onChange={(e) => setReportConfig((prev) => ({ ...prev, tester: e.target.value }))}
                      placeholder="Enter tester/team name"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Report Template</Label>
                  <Select
                    value={reportConfig.template}
                    onValueChange={(value) => setReportConfig((prev) => ({ ...prev, template: value }))}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="executive">Executive Summary</SelectItem>
                      <SelectItem value="technical">Technical Report</SelectItem>
                      <SelectItem value="compliance">Compliance Report</SelectItem>
                      <SelectItem value="detailed">Detailed Analysis</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-3">
                  <Label>Include Sections</Label>
                  <div className="space-y-2">
                    <div className="flex items-center space-x-2">
                      <Checkbox
                        id="include-summary"
                        checked={reportConfig.includeSummary}
                        onCheckedChange={(checked) =>
                          setReportConfig((prev) => ({ ...prev, includeSummary: checked as boolean }))
                        }
                      />
                      <Label htmlFor="include-summary">Executive Summary</Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Checkbox
                        id="include-findings"
                        checked={reportConfig.includeFindings}
                        onCheckedChange={(checked) =>
                          setReportConfig((prev) => ({ ...prev, includeFindings: checked as boolean }))
                        }
                      />
                      <Label htmlFor="include-findings">Detailed Findings</Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Checkbox
                        id="include-recommendations"
                        checked={reportConfig.includeRecommendations}
                        onCheckedChange={(checked) =>
                          setReportConfig((prev) => ({ ...prev, includeRecommendations: checked as boolean }))
                        }
                      />
                      <Label htmlFor="include-recommendations">Recommendations</Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Checkbox
                        id="include-appendix"
                        checked={reportConfig.includeAppendix}
                        onCheckedChange={(checked) =>
                          setReportConfig((prev) => ({ ...prev, includeAppendix: checked as boolean }))
                        }
                      />
                      <Label htmlFor="include-appendix">Technical Appendix</Label>
                    </div>
                  </div>
                </div>

                <Button
                  onClick={handleGenerateReport}
                  disabled={isGenerating || !reportConfig.title.trim() || !reportConfig.client.trim()}
                  className="w-full"
                >
                  {isGenerating ? (
                    <>
                      <Clock className="h-4 w-4 mr-2 animate-spin" />
                      Generating Report...
                    </>
                  ) : (
                    <>
                      <FileText className="h-4 w-4 mr-2" />
                      Generate Report from Real Data
                    </>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Report Preview & History */}
          <Card>
            <CardHeader>
              <CardTitle>Generated Reports</CardTitle>
              <CardDescription>View and download your security reports</CardDescription>
            </CardHeader>
            <CardContent>
              {generatedReports.length === 0 ? (
                <div className="text-center py-8">
                  <FileText className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                  <p className="text-muted-foreground">No reports generated yet</p>
                  <p className="text-sm text-muted-foreground">Configure and generate your first security report</p>
                </div>
              ) : (
                <ScrollArea className="h-[600px]">
                  <div className="space-y-4">
                    {generatedReports.map((report) => (
                      <Card key={report.id} className="border-l-4 border-l-primary">
                        <CardHeader className="pb-3">
                          <div className="flex items-start justify-between">
                            <div>
                              <CardTitle className="text-lg">{report.title}</CardTitle>
                              <div className="flex items-center gap-2 mt-1 text-sm text-muted-foreground">
                                <Building className="h-4 w-4" />
                                <span>{report.client}</span>
                                <Calendar className="h-4 w-4 ml-2" />
                                <span>{report.date.toLocaleDateString()}</span>
                              </div>
                            </div>
                            <div className="flex gap-2">
                              <Button variant="outline" size="sm" onClick={() => handleDownloadReport(report.id)}>
                                <Download className="h-4 w-4" />
                              </Button>
                            </div>
                          </div>
                        </CardHeader>

                        <CardContent className="space-y-4">
                          {/* Summary Stats */}
                          <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                              <div className="flex justify-between text-sm">
                                <span>Total Vulnerabilities:</span>
                                <span className="font-medium">{report.summary.totalVulnerabilities}</span>
                              </div>
                              <div className="flex justify-between text-sm">
                                <span>Tested Domains:</span>
                                <span className="font-medium">{report.summary.testedDomains.length}</span>
                              </div>
                            </div>
                            <div className="space-y-2">
                              <div className="flex gap-1">
                                {report.summary.criticalVulns > 0 && (
                                  <Badge className="bg-red-600 text-white text-xs">
                                    {report.summary.criticalVulns} Critical
                                  </Badge>
                                )}
                                {report.summary.highVulns > 0 && (
                                  <Badge className="bg-red-500 text-white text-xs">
                                    {report.summary.highVulns} High
                                  </Badge>
                                )}
                                {report.summary.mediumVulns > 0 && (
                                  <Badge className="bg-yellow-500 text-black text-xs">
                                    {report.summary.mediumVulns} Medium
                                  </Badge>
                                )}
                              </div>
                            </div>
                          </div>

                          {/* Findings Preview */}
                          <Tabs defaultValue="findings" className="w-full">
                            <TabsList className="grid w-full grid-cols-2">
                              <TabsTrigger value="findings">Top Findings</TabsTrigger>
                              <TabsTrigger value="domains">Tested Domains</TabsTrigger>
                            </TabsList>

                            <TabsContent value="findings" className="space-y-2">
                              <ScrollArea className="h-48">
                                <div className="space-y-2">
                                  {report.findings.slice(0, 3).map((finding) => (
                                    <div key={finding.id} className="p-2 bg-muted rounded text-sm">
                                      <div className="flex items-center justify-between mb-1">
                                        <span className="font-medium truncate">{finding.title}</span>
                                        <Badge className={getSeverityColor(finding.severity)}>{finding.severity}</Badge>
                                      </div>
                                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                        {finding.category === "Web Application" && <Globe className="h-3 w-3" />}
                                        {finding.category === "API" && <Server className="h-3 w-3" />}
                                        {finding.category === "Network" && <Shield className="h-3 w-3" />}
                                        <span>{finding.category}</span>
                                        {finding.cvssScore && <span>CVSS: {finding.cvssScore}</span>}
                                      </div>
                                    </div>
                                  ))}
                                  {report.findings.length > 3 && (
                                    <div className="text-center text-sm text-muted-foreground py-2">
                                      +{report.findings.length - 3} more findings in full report
                                    </div>
                                  )}
                                </div>
                              </ScrollArea>
                            </TabsContent>

                            <TabsContent value="domains" className="space-y-2">
                              <div className="space-y-2">
                                {report.summary.testedDomains.map((domain, index) => (
                                  <div key={index} className="flex items-center gap-2 p-2 bg-muted rounded text-sm">
                                    <Globe className="h-4 w-4 text-muted-foreground" />
                                    <span>{domain}</span>
                                  </div>
                                ))}
                              </div>
                            </TabsContent>
                          </Tabs>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
