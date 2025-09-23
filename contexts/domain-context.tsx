"use client"

import { createContext, useContext, useState, type ReactNode } from "react"

interface DomainContextType {
  targetDomain: string
  setTargetDomain: (domain: string) => void
  isValidDomain: boolean
}

const DomainContext = createContext<DomainContextType | undefined>(undefined)

export function DomainProvider({ children }: { children: ReactNode }) {
  const [targetDomain, setTargetDomain] = useState<string>("")

  const isValidDomain =
    targetDomain.length > 0 &&
    (targetDomain.startsWith("http://") || targetDomain.startsWith("https://") || targetDomain.includes("."))

  return (
    <DomainContext.Provider value={{ targetDomain, setTargetDomain, isValidDomain }}>{children}</DomainContext.Provider>
  )
}

export function useDomain() {
  const context = useContext(DomainContext)
  if (context === undefined) {
    throw new Error("useDomain must be used within a DomainProvider")
  }
  return context
}
