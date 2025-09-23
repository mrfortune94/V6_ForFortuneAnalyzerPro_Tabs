"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Shield, Lock, AlertTriangle } from "lucide-react"

interface PasswordGuardProps {
  children: React.ReactNode
}

export default function PasswordGuard({ children }: PasswordGuardProps) {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [isLoading, setIsLoading] = useState(true)

  const CORRECT_PASSWORD = "187"

  useEffect(() => {
    // Check if user is already authenticated
    const authStatus = sessionStorage.getItem("pentest-auth")
    if (authStatus === "authenticated") {
      setIsAuthenticated(true)
    }
    setIsLoading(false)
  }, [])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError("")

    if (password === CORRECT_PASSWORD) {
      setIsAuthenticated(true)
      sessionStorage.setItem("pentest-auth", "authenticated")
    } else {
      setError("Invalid password. Access denied.")
      setPassword("")
    }
  }

  const handleLogout = () => {
    setIsAuthenticated(false)
    sessionStorage.removeItem("pentest-auth")
    setPassword("")
    setError("")
  }

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center space-y-4">
            <div className="mx-auto p-3 rounded-full bg-muted w-fit">
              <Shield className="h-8 w-8 text-primary" />
            </div>
            <div>
              <CardTitle className="text-2xl font-bold">Secure Access Required</CardTitle>
              <CardDescription className="text-pretty">
                This penetration testing suite is restricted to authorized personnel only.
              </CardDescription>
            </div>
          </CardHeader>

          <CardContent className="space-y-4">
            <div className="p-4 rounded-lg bg-muted/50 border border-amber-200 dark:border-amber-800">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-amber-600 dark:text-amber-400 mt-0.5 flex-shrink-0" />
                <div className="text-sm">
                  <p className="font-medium text-amber-800 dark:text-amber-200">Authorized Use Only</p>
                  <p className="text-amber-700 dark:text-amber-300 text-pretty">
                    This tool is designed exclusively for testing domains you own or have explicit permission to test.
                  </p>
                </div>
              </div>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="password">Access Code</Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter access code"
                    className="pl-10"
                    required
                  />
                </div>
              </div>

              {error && (
                <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20">
                  <p className="text-sm text-destructive font-medium">{error}</p>
                </div>
              )}

              <Button type="submit" className="w-full">
                <Shield className="h-4 w-4 mr-2" />
                Authenticate
              </Button>
            </form>

            <div className="text-center text-xs text-muted-foreground">
              <p>Session expires when browser is closed</p>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div>
      <div className="fixed top-4 right-4 z-50">
        <Button variant="outline" size="sm" onClick={handleLogout} className="bg-background/80 backdrop-blur-sm">
          <Lock className="h-4 w-4 mr-2" />
          Logout
        </Button>
      </div>
      {children}
    </div>
  )
}
