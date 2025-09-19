"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  GitHubIcon,
  ShieldIcon,
  AlertTriangleIcon,
  CheckCircleIcon,
  ExternalLinkIcon,
  GitPullRequestIcon,
  BugIcon,
} from "@/components/icons"

interface Repository {
  id: number
  name: string
  full_name: string
  private: boolean
  language: string | null
  description: string | null
  html_url: string
  stargazers_count: number
  forks_count: number
  created_at: string
  updated_at: string
  owner: {
    login: string
    avatar_url: string
  }
}

interface SecurityIssue {
  id: string
  title: string
  severity: "critical" | "high" | "medium" | "low"
  type: string
  description: string
  file: string
  line: number
  status: "open" | "fixed"
  created_at: string
}

interface PullRequest {
  id: string
  title: string
  number: number
  status: "open" | "merged" | "closed"
  fixes_issue: string
  url: string
  created_at: string
}

// API configuration
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5173'

const mockIssues: SecurityIssue[] = [
  {
    id: "1",
    title: "Hardcoded API credentials in config file",
    severity: "critical",
    type: "Credential Exposure",
    description: "Found hardcoded API keys in configuration file that could be exploited",
    file: "config/database.js",
    line: 23,
    status: "open",
    created_at: "2024-01-15T10:30:00Z",
  },
  {
    id: "2",
    title: "SQL Injection vulnerability in user endpoint",
    severity: "high",
    type: "SQL Injection",
    description: "User input not properly sanitized in database query",
    file: "api/users.py",
    line: 45,
    status: "open",
    created_at: "2024-01-15T10:32:00Z",
  },
  {
    id: "3",
    title: "Missing CORS security headers",
    severity: "medium",
    type: "Security Headers",
    description: "Application missing important security headers for CORS protection",
    file: "server.js",
    line: 12,
    status: "open",
    created_at: "2024-01-15T10:35:00Z",
  },
]

const mockPRs: PullRequest[] = [
  {
    id: "1",
    title: "Fix: Move API credentials to environment variables",
    number: 42,
    status: "open",
    fixes_issue: "1",
    url: "https://github.com/myorg/web-app/pull/42",
    created_at: "2024-01-15T10:45:00Z",
  },
  {
    id: "2",
    title: "Security: Add parameterized queries to prevent SQL injection",
    number: 43,
    status: "open",
    fixes_issue: "2",
    url: "https://github.com/myorg/web-app/pull/43",
    created_at: "2024-01-15T10:47:00Z",
  },
]

export default function SecurityAutomationTool() {
  const [isConnected, setIsConnected] = useState(false)
  const [selectedRepo, setSelectedRepo] = useState<string>("")
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [currentStep, setCurrentStep] = useState("")
  const [results, setResults] = useState<{
    issues: SecurityIssue[]
    prs: PullRequest[]
  } | null>(null)
  
  // New state for GitHub integration
  const [githubToken, setGithubToken] = useState("")
  const [repositories, setRepositories] = useState<Repository[]>([])
  const [isLoadingRepos, setIsLoadingRepos] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [username, setUsername] = useState("")

  // Fetch repositories from the Flask API
  const fetchRepositories = async () => {
    if (!githubToken) {
      setError("Please enter a GitHub token")
      return
    }

    setIsLoadingRepos(true)
    setError(null)

    try {
      const params = new URLSearchParams({
        token: githubToken,
        per_page: '100'
      })
      
      if (username) {
        params.append('username', username)
      }

      const response = await fetch(`${API_BASE_URL}/api/repositories?${params}`)
      
      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.message || `HTTP error! status: ${response.status}`)
      }

      const data = await response.json()
      setRepositories(data.repositories || [])
      setIsConnected(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch repositories')
      setIsConnected(false)
    } finally {
      setIsLoadingRepos(false)
    }
  }

  const handleGitHubConnect = () => {
    fetchRepositories()
  }

  const handleStartScan = async () => {
    if (!selectedRepo) return

    setIsScanning(true)
    setScanProgress(0)
    setResults(null)

    // Simulate scanning process
    const steps = [
      "Connecting to repository...",
      "Running Scout Agent - Web reconnaissance...",
      "Running Pentest Agent - Vulnerability scanning...",
      "Running Triage Agent - Analyzing findings...",
      "Creating GitHub issues...",
      "Generating security fixes...",
      "Creating pull requests...",
      "Scan complete!",
    ]

    for (let i = 0; i < steps.length; i++) {
      setCurrentStep(steps[i])
      setScanProgress(((i + 1) / steps.length) * 100)
      await new Promise((resolve) => setTimeout(resolve, 1500))
    }

    setResults({
      issues: mockIssues,
      prs: mockPRs,
    })
    setIsScanning(false)
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-destructive text-destructive-foreground"
      case "high":
        return "bg-warning text-warning-foreground"
      case "medium":
        return "bg-chart-3 text-foreground"
      case "low":
        return "bg-muted text-muted-foreground"
      default:
        return "bg-muted text-muted-foreground"
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "open":
        return "bg-success text-success-foreground"
      case "merged":
        return "bg-primary text-primary-foreground"
      case "closed":
        return "bg-muted text-muted-foreground"
      default:
        return "bg-muted text-muted-foreground"
    }
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <ShieldIcon className="h-8 w-8 text-primary" />
              <div>
                <h1 className="text-xl font-semibold text-foreground">SecureBot</h1>
                <p className="text-sm text-muted-foreground">Automated Security Scanning & Remediation</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <Badge variant="secondary" className="text-xs">
                v1.0.0
              </Badge>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-8">
        <div className="grid gap-8 lg:grid-cols-3">
          {/* Configuration Panel */}
          <div className="lg:col-span-1">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <GitHubIcon className="h-5 w-5" />
                  Repository Setup
                </CardTitle>
                <CardDescription>
                  Connect your GitHub account and select a repository to scan for security vulnerabilities.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {!isConnected ? (
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="github-token">GitHub Personal Access Token</Label>
                      <Input
                        id="github-token"
                        type="password"
                        placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                        value={githubToken}
                        onChange={(e) => setGithubToken(e.target.value)}
                      />
                      <p className="text-xs text-muted-foreground">
                        Create a token at <a href="https://github.com/settings/tokens" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">github.com/settings/tokens</a>
                      </p>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="username">Username/Organization (Optional)</Label>
                      <Input
                        id="username"
                        type="text"
                        placeholder="Leave empty for your own repos"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                      />
                    </div>

                    {error && (
                      <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-md">
                        <p className="text-sm text-destructive">{error}</p>
                      </div>
                    )}

                    <Button 
                      onClick={handleGitHubConnect} 
                      disabled={!githubToken || isLoadingRepos}
                      className="w-full"
                    >
                      {isLoadingRepos ? (
                        <>
                          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary-foreground mr-2" />
                          Loading...
                        </>
                      ) : (
                        <>
                          <GitHubIcon className="h-4 w-4 mr-2" />
                          Connect GitHub
                        </>
                      )}
                    </Button>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-sm text-success">
                        <CheckCircleIcon className="h-4 w-4" />
                        GitHub connected successfully
                      </div>
                      <Button 
                        variant="outline" 
                        size="sm" 
                        onClick={fetchRepositories}
                        disabled={isLoadingRepos}
                      >
                        {isLoadingRepos ? (
                          <div className="animate-spin rounded-full h-3 w-3 border-b-2 border-current mr-1" />
                        ) : null}
                        Refresh
                      </Button>
                    </div>

                    <div className="space-y-2">
                      <label className="text-sm font-medium">Select Repository</label>
                      <Select value={selectedRepo} onValueChange={setSelectedRepo}>
                        <SelectTrigger>
                          <SelectValue placeholder="Choose a repository..." />
                        </SelectTrigger>
                        <SelectContent>
                          {repositories.map((repo) => (
                            <SelectItem key={repo.id.toString()} value={repo.full_name}>
                              <div className="flex items-center gap-2">
                                <span>{repo.name}</span>
                                {repo.language && (
                                  <Badge variant="outline" className="text-xs">
                                    {repo.language}
                                  </Badge>
                                )}
                                {repo.private && (
                                  <Badge variant="secondary" className="text-xs">
                                    Private
                                  </Badge>
                                )}
                                <Badge variant="outline" className="text-xs">
                                  ⭐ {repo.stargazers_count}
                                </Badge>
                              </div>
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      {repositories.length === 0 && (
                        <p className="text-xs text-muted-foreground">No repositories found</p>
                      )}
                    </div>

                    <Button onClick={handleStartScan} disabled={!selectedRepo || isScanning} className="w-full">
                      {isScanning ? (
                        <>
                          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary-foreground mr-2" />
                          Scanning...
                        </>
                      ) : (
                        <>
                          <ShieldIcon className="h-4 w-4 mr-2" />
                          Start Security Scan
                        </>
                      )}
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Scan Progress */}
            {isScanning && (
              <Card className="mt-6">
                <CardHeader>
                  <CardTitle className="text-lg">Scan Progress</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <Progress value={scanProgress} className="w-full" />
                  <p className="text-sm text-muted-foreground">{currentStep}</p>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Results Panel */}
          <div className="lg:col-span-2">
            {results ? (
              <div className="space-y-6">
                {/* Summary Cards */}
                <div className="grid gap-4 md:grid-cols-3">
                  <Card>
                    <CardContent className="p-6">
                      <div className="flex items-center gap-3">
                        <BugIcon className="h-8 w-8 text-destructive" />
                        <div>
                          <p className="text-2xl font-bold">{results.issues.length}</p>
                          <p className="text-sm text-muted-foreground">Issues Found</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-6">
                      <div className="flex items-center gap-3">
                        <GitPullRequestIcon className="h-8 w-8 text-success" />
                        <div>
                          <p className="text-2xl font-bold">{results.prs.length}</p>
                          <p className="text-sm text-muted-foreground">PRs Created</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-6">
                      <div className="flex items-center gap-3">
                        <CheckCircleIcon className="h-8 w-8 text-primary" />
                        <div>
                          <p className="text-2xl font-bold">
                            {Math.round((results.prs.length / results.issues.length) * 100)}%
                          </p>
                          <p className="text-sm text-muted-foreground">Auto-Fixed</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Security Issues */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <AlertTriangleIcon className="h-5 w-5" />
                      Security Issues
                    </CardTitle>
                    <CardDescription>Vulnerabilities discovered during the security scan</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {results.issues.map((issue) => (
                        <div key={issue.id} className="border border-border rounded-lg p-4">
                          <div className="flex items-start justify-between gap-4">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-2">
                                <h3 className="font-medium">{issue.title}</h3>
                                <Badge className={getSeverityColor(issue.severity)}>
                                  {issue.severity.toUpperCase()}
                                </Badge>
                                <Badge variant="outline">{issue.type}</Badge>
                              </div>
                              <p className="text-sm text-muted-foreground mb-2">{issue.description}</p>
                              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                                <span>
                                  {issue.file}:{issue.line}
                                </span>
                                <span>Created {new Date(issue.created_at).toLocaleDateString()}</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                {/* Pull Requests */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <GitPullRequestIcon className="h-5 w-5" />
                      Generated Pull Requests
                    </CardTitle>
                    <CardDescription>Automated fixes created for the discovered vulnerabilities</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {results.prs.map((pr) => (
                        <div key={pr.id} className="border border-border rounded-lg p-4">
                          <div className="flex items-start justify-between gap-4">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-2">
                                <h3 className="font-medium">{pr.title}</h3>
                                <Badge className={getStatusColor(pr.status)}>{pr.status.toUpperCase()}</Badge>
                                <Badge variant="outline">#{pr.number}</Badge>
                              </div>
                              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                                <span>Fixes issue #{pr.fixes_issue}</span>
                                <span>Created {new Date(pr.created_at).toLocaleDateString()}</span>
                              </div>
                            </div>
                            <Button variant="outline" size="sm" asChild>
                              <a href={pr.url} target="_blank" rel="noopener noreferrer">
                                <ExternalLinkIcon className="h-4 w-4 mr-1" />
                                View PR
                              </a>
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </div>
            ) : (
              <Card className="h-96 flex items-center justify-center">
                <div className="text-center space-y-4">
                  <ShieldIcon className="h-16 w-16 mx-auto text-muted-foreground" />
                  <div>
                    <h3 className="text-lg font-medium mb-2">Ready to Scan</h3>
                    <p className="text-muted-foreground max-w-md">
                      Connect your GitHub account and select a repository to start automated security scanning and
                      remediation.
                    </p>
                  </div>
                </div>
              </Card>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
