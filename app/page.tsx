"use client"

import type React from "react"
import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Input } from "@/components/ui/input"
import { useDomain } from "@/contexts/domain-context"
import WebScanner from "@/components/web-scanner"
import ApiTester from "@/components/api-tester"
import NetworkScanner from "@/components/network-scanner"
import IntegratedBrowser from "@/components/integrated-browser"
import ReportGenerator from "@/components/report-generator"
import GameAnalyzer from "@/components/game-analyzer"
import CredentialLeakAnalyzer from "@/components/credential-leak-analyzer"
import PasswordGuard from "@/components/password-guard"
import AdminCredentialExtractor from "@/components/admin-credential-extractor"
import {
  Shield,
  Globe,
  Server,
  FileText,
  Smartphone,
  Settings,
  Play,
  Pause,
  Download,
  AlertTriangle,
  CheckCircle,
  Clock,
  PaintRoller as GameController2,
  Key,
  Target,
} from "lucide-react"

interface TestModule {
  id: string
  name: string
  description: string
  icon: React.ReactNode
  status: "idle" | "running" | "completed" | "error"
  progress?: number
  lastRun?: string
  vulnerabilities?: number
}

export default function PentestDashboard() {
  const [currentView, setCurrentView] = useState<string>("dashboard")
  const { targetDomain, setTargetDomain, isValidDomain } = useDomain()
  const [modules, setModules] = useState<TestModule[]>([
    {
      id: "web-scanner",
      name: "Web Application Scanner",
      description: "Scan for XSS, SQL injection, and other web vulnerabilities",
      icon: <Globe className="h-6 w-6" />,
      status: "idle",
      lastRun: "2 hours ago",
      vulnerabilities: 3,
    },
    {
      id: "api-tester",
      name: "API Endpoint Tester",
      description: "Test REST APIs for security misconfigurations and vulnerabilities",
      icon: <Server className="h-6 w-6" />,
      status: "completed",
      lastRun: "1 hour ago",
      vulnerabilities: 1,
    },
    {
      id: "network-scanner",
      name: "Network Infrastructure Scanner",
      description: "Port scanning, SSL/TLS analysis, and service enumeration",
      icon: <Shield className="h-6 w-6" />,
      status: "running",
      progress: 65,
      lastRun: "Running now",
    },
    {
      id: "browser",
      name: "Integrated Browser",
      description: "Browse your domains with built-in security testing tools",
      icon: <Smartphone className="h-6 w-6" />,
      status: "idle",
    },
    {
      id: "game-analyzer",
      name: "Game API Analyzer",
      description: "Real-time analysis of game APIs, RNG values, and backend logic",
      icon: <GameController2 className="h-6 w-6" />,
      status: "idle",
      lastRun: "Never",
    },
    {
      id: "credential-analyzer",
      name: "Credential Leak Analyzer",
      description: "MITM-style credential monitoring and leak detection",
      icon: <Key className="h-6 w-6" />,
      status: "idle",
      lastRun: "Never",
    },
    {
      id: "reports",
      name: "Report Generator",
      description: "Generate comprehensive PDF reports of all test results",
      icon: <FileText className="h-6 w-6" />,
      status: "idle",
      lastRun: "3 hours ago",
    },
    {
      id: "settings",
      name: "Configuration",
      description: "Configure target domains, API keys, and testing parameters",
      icon: <Settings className="h-6 w-6" />,
      status: "idle",
    },
    {
      id: "admin-extractor",
      name: "Admin Credential Extractor",
      description: "Advanced 15+ attack vectors for admin credential discovery",
      icon: <Key className="h-6 w-6" />,
      status: "idle",
      lastRun: "Never",
    },
  ])

  if (currentView === "web-scanner") {
    return <WebScanner onBack={() => setCurrentView("dashboard")} />
  }

  if (currentView === "api-tester") {
    return <ApiTester onBack={() => setCurrentView("dashboard")} />
  }

  if (currentView === "network-scanner") {
    return <NetworkScanner onBack={() => setCurrentView("dashboard")} />
  }

  if (currentView === "browser") {
    return <IntegratedBrowser onBack={() => setCurrentView("dashboard")} />
  }

  if (currentView === "game-analyzer") {
    return <GameAnalyzer />
  }

  if (currentView === "credential-analyzer") {
    return <CredentialLeakAnalyzer onBack={() => setCurrentView("dashboard")} />
  }

  if (currentView === "reports") {
    return <ReportGenerator onBack={() => setCurrentView("dashboard")} />
  }

  if (currentView === "admin-extractor") {
    return <AdminCredentialExtractor onBack={() => setCurrentView("dashboard")} />
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "running":
        return "bg-accent text-accent-foreground"
      case "completed":
        return "bg-primary text-primary-foreground"
      case "error":
        return "bg-destructive text-destructive-foreground"
      default:
        return "bg-muted text-muted-foreground"
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "running":
        return <Clock className="h-4 w-4" />
      case "completed":
        return <CheckCircle className="h-4 w-4" />
      case "error":
        return <AlertTriangle className="h-4 w-4" />
      default:
        return <Pause className="h-4 w-4" />
    }
  }

  const handleModuleAction = (moduleId: string) => {
    if (moduleId === "web-scanner") {
      setCurrentView("web-scanner")
      return
    }

    if (moduleId === "api-tester") {
      setCurrentView("api-tester")
      return
    }

    if (moduleId === "network-scanner") {
      setCurrentView("network-scanner")
      return
    }

    if (moduleId === "browser") {
      setCurrentView("browser")
      return
    }

    if (moduleId === "game-analyzer") {
      setCurrentView("game-analyzer")
      return
    }

    if (moduleId === "credential-analyzer") {
      setCurrentView("credential-analyzer")
      return
    }

    if (moduleId === "reports") {
      setCurrentView("reports")
      return
    }

    if (moduleId === "admin-extractor") {
      setCurrentView("admin-extractor")
      return
    }

    setModules((prev) =>
      prev.map((module) =>
        module.id === moduleId
          ? { ...module, status: module.status === "running" ? "idle" : ("running" as any) }
          : module,
      ),
    )
  }

  const totalVulnerabilities = modules.reduce((sum, module) => sum + (module.vulnerabilities || 0), 0)
  const runningTests = modules.filter((m) => m.status === "running").length
  const completedTests = modules.filter((m) => m.status === "completed").length

  return (
    <PasswordGuard>
      <div className="min-h-screen bg-background text-foreground p-4 md:p-6">
        <div className="max-w-7xl mx-auto space-y-6">
          {/* Header */}
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div>
              <h1 className="text-3xl font-bold text-balance">PenTest Suite</h1>
              <p className="text-muted-foreground text-pretty">
                Professional penetration testing dashboard for your domains and APIs
              </p>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => setCurrentView("reports")}>
                <Download className="h-4 w-4 mr-2" />
                Export All Reports
              </Button>
              <Button size="sm" disabled={!isValidDomain}>
                <Play className="h-4 w-4 mr-2" />
                Run All Tests
              </Button>
            </div>
          </div>

          {/* Target Domain Input Section */}
          <Card className="border-2 border-primary/20">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Target className="h-5 w-5 text-primary" />
                Target Domain Configuration
              </CardTitle>
              <CardDescription>
                Enter your domain URL once - all testing tools will use this target automatically
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-4 items-end">
                <div className="flex-1">
                  <label htmlFor="domain-input" className="text-sm font-medium mb-2 block">
                    Domain URL
                  </label>
                  <Input
                    id="domain-input"
                    type="url"
                    placeholder="Enter your domain URL (e.g., https://yourdomain.com)"
                    value={targetDomain}
                    onChange={(e) => setTargetDomain(e.target.value)}
                    className="text-lg"
                  />
                </div>
                <div className="flex items-center gap-2">
                  {isValidDomain ? (
                    <Badge variant="default" className="bg-green-500/10 text-green-500 border-green-500/20">
                      <CheckCircle className="h-3 w-3 mr-1" />
                      Valid
                    </Badge>
                  ) : (
                    <Badge variant="secondary" className="bg-yellow-500/10 text-yellow-700 border-yellow-500/20">
                      <AlertTriangle className="h-3 w-3 mr-1" />
                      Enter URL
                    </Badge>
                  )}
                </div>
              </div>
              {targetDomain && (
                <p className="text-sm text-muted-foreground mt-2">
                  All testing modules will target: <span className="font-mono text-primary">{targetDomain}</span>
                </p>
              )}
            </CardContent>
          </Card>

          {/* Stats Overview */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
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
                    <p className="text-sm text-muted-foreground">Running Tests</p>
                    <p className="text-2xl font-bold text-accent">{runningTests}</p>
                  </div>
                  <Clock className="h-8 w-8 text-accent" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Completed Tests</p>
                    <p className="text-2xl font-bold text-primary">{completedTests}</p>
                  </div>
                  <CheckCircle className="h-8 w-8 text-primary" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Total Modules</p>
                    <p className="text-2xl font-bold">{modules.length}</p>
                  </div>
                  <Shield className="h-8 w-8 text-foreground" />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Testing Modules Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {modules.map((module) => (
              <Card key={module.id} className="relative overflow-hidden">
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-muted">{module.icon}</div>
                      <div>
                        <CardTitle className="text-lg">{module.name}</CardTitle>
                        <Badge variant="secondary" className={`mt-1 ${getStatusColor(module.status)}`}>
                          {getStatusIcon(module.status)}
                          <span className="ml-1 capitalize">{module.status}</span>
                        </Badge>
                      </div>
                    </div>
                  </div>
                </CardHeader>

                <CardContent className="space-y-4">
                  <CardDescription className="text-pretty">{module.description}</CardDescription>

                  {module.progress && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span>Progress</span>
                        <span>{module.progress}%</span>
                      </div>
                      <Progress value={module.progress} className="h-2" />
                    </div>
                  )}

                  <div className="flex items-center justify-between text-sm text-muted-foreground">
                    {module.lastRun && <span>Last run: {module.lastRun}</span>}
                    {module.vulnerabilities !== undefined && (
                      <span className="text-destructive font-medium">{module.vulnerabilities} vulnerabilities</span>
                    )}
                  </div>

                  <Button
                    className="w-full"
                    variant={module.status === "running" ? "destructive" : "default"}
                    onClick={() => handleModuleAction(module.id)}
                    disabled={
                      !isValidDomain &&
                      [
                        "web-scanner",
                        "api-tester",
                        "network-scanner",
                        "browser",
                        "game-analyzer",
                        "credential-analyzer",
                        "admin-extractor",
                      ].includes(module.id)
                    }
                  >
                    {module.status === "running" ? (
                      <>
                        <Pause className="h-4 w-4 mr-2" />
                        Stop Test
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4 mr-2" />
                        {[
                          "web-scanner",
                          "api-tester",
                          "network-scanner",
                          "browser",
                          "game-analyzer",
                          "credential-analyzer",
                          "reports",
                          "admin-extractor",
                        ].includes(module.id)
                          ? "Open Tool"
                          : "Start Test"}
                      </>
                    )}
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </div>
    </PasswordGuard>
  )
}
