"use client"

import { useState } from "react"

interface AnalysisResult {
  score: number
  level: string
  rec: string
  subdomains: SubdomainAnalysis[]
  vulnerabilities: Vulnerability[]
  securityFeatures: SecurityFeature[]
  threatIntelligence: ThreatData
  certificateInfo: CertificateData
  dnsAnalysis: DNSAnalysis
  ipAnalysis: IPAnalysis
}

interface SubdomainAnalysis {
  subdomain: string
  status: "safe" | "warning" | "vulnerable" | "malicious"
  riskScore: number
  issues: string[]
  recommendations: string[]
  ipAddress: string
}

interface Vulnerability {
  type: string
  severity: "low" | "medium" | "high" | "critical"
  description: string
  impact: string
  remediation: string
}

interface SecurityFeature {
  feature: string
  status: "enabled" | "disabled" | "partial"
  description: string
}

interface ThreatData {
  reputation: string
  lastSeen: string
  threatTypes: string[]
  geolocation: string
  isp: string
}

interface CertificateData {
  valid: boolean
  issuer: string
  expiry: string
  algorithm: string
  keySize: number
  warnings: string[]
}

interface DNSAnalysis {
  records: DNSRecord[]
  suspicious: boolean
  issues: string[]
}

interface DNSRecord {
  type: string
  value: string
  ttl: number
  suspicious: boolean
}

interface IPAnalysis {
  primaryIP: string
  allIPs: IPInfo[]
  geolocation: GeolocationInfo
  reputation: IPReputation
  networkInfo: NetworkInfo
  securityFlags: SecurityFlag[]
}

interface IPInfo {
  address: string
  type: "IPv4" | "IPv6"
  status: "safe" | "warning" | "malicious"
  country: string
  city: string
  isp: string
  organization: string
  riskScore: number
  lastSeen: string
}

interface GeolocationInfo {
  country: string
  countryCode: string
  region: string
  city: string
  latitude: number
  longitude: number
  timezone: string
  isp: string
  organization: string
  asn: string
}

interface IPReputation {
  score: number
  status: "clean" | "suspicious" | "malicious"
  categories: string[]
  lastReported: string
  reportCount: number
  sources: string[]
}

interface NetworkInfo {
  asn: number
  asnOrg: string
  cidr: string
  hostingProvider: string
  isProxy: boolean
  isVPN: boolean
  isTor: boolean
  isDataCenter: boolean
  isResidential: boolean
}

interface SecurityFlag {
  type: string
  severity: "info" | "low" | "medium" | "high"
  description: string
  recommendation: string
}

const ENHANCED_PRESETS: Record<string, AnalysisResult> = {
  "https://google.com": {
    score: 5,
    level: "LOW",
    rec: "SAFE",
    subdomains: [
      {
        subdomain: "www.google.com",
        status: "safe",
        riskScore: 2,
        issues: [],
        recommendations: ["Continue normal usage"],
        ipAddress: "142.250.191.14",
      },
      {
        subdomain: "mail.google.com",
        status: "safe",
        riskScore: 3,
        issues: [],
        recommendations: ["Secure email service"],
        ipAddress: "142.250.191.17",
      },
    ],
    vulnerabilities: [],
    securityFeatures: [
      { feature: "HTTPS", status: "enabled", description: "Secure connection established" },
      { feature: "HSTS", status: "enabled", description: "HTTP Strict Transport Security active" },
      { feature: "CSP", status: "enabled", description: "Content Security Policy implemented" },
      { feature: "X-Frame-Options", status: "enabled", description: "Clickjacking protection active" },
    ],
    threatIntelligence: {
      reputation: "Excellent",
      lastSeen: "Never flagged",
      threatTypes: [],
      geolocation: "United States",
      isp: "Google LLC",
    },
    certificateInfo: {
      valid: true,
      issuer: "Google Trust Services",
      expiry: "2025-03-15",
      algorithm: "RSA-SHA256",
      keySize: 2048,
      warnings: [],
    },
    dnsAnalysis: {
      records: [
        { type: "A", value: "142.250.191.14", ttl: 300, suspicious: false },
        { type: "AAAA", value: "2607:f8b0:4004:c1b::71", ttl: 300, suspicious: false },
      ],
      suspicious: false,
      issues: [],
    },
    ipAnalysis: {
      primaryIP: "142.250.191.14",
      allIPs: [
        {
          address: "142.250.191.14",
          type: "IPv4",
          status: "safe",
          country: "United States",
          city: "Mountain View",
          isp: "Google LLC",
          organization: "Google Inc.",
          riskScore: 1,
          lastSeen: "Active",
        },
        {
          address: "2607:f8b0:4004:c1b::71",
          type: "IPv6",
          status: "safe",
          country: "United States",
          city: "Mountain View",
          isp: "Google LLC",
          organization: "Google Inc.",
          riskScore: 1,
          lastSeen: "Active",
        },
      ],
      geolocation: {
        country: "United States",
        countryCode: "US",
        region: "California",
        city: "Mountain View",
        latitude: 37.4056,
        longitude: -122.0775,
        timezone: "America/Los_Angeles",
        isp: "Google LLC",
        organization: "Google Inc.",
        asn: "AS15169",
      },
      reputation: {
        score: 100,
        status: "clean",
        categories: ["Search Engine", "Technology"],
        lastReported: "Never",
        reportCount: 0,
        sources: ["VirusTotal", "AbuseIPDB", "Shodan"],
      },
      networkInfo: {
        asn: 15169,
        asnOrg: "Google LLC",
        cidr: "142.250.0.0/15",
        hostingProvider: "Google Cloud",
        isProxy: false,
        isVPN: false,
        isTor: false,
        isDataCenter: true,
        isResidential: false,
      },
      securityFlags: [
        {
          type: "Legitimate Service",
          severity: "info",
          description: "IP belongs to a well-known legitimate service provider",
          recommendation: "Safe to access",
        },
      ],
    },
  },
  "http://phishing-site.com": {
    score: 95,
    level: "HIGH",
    rec: "BLOCK",
    subdomains: [
      {
        subdomain: "login.phishing-site.com",
        status: "malicious",
        riskScore: 98,
        issues: ["Mimics legitimate login page", "Harvests credentials", "No SSL certificate"],
        recommendations: ["BLOCK IMMEDIATELY", "Report to authorities"],
        ipAddress: "185.234.72.45",
      },
      {
        subdomain: "secure.phishing-site.com",
        status: "vulnerable",
        riskScore: 85,
        issues: ["Misleading subdomain name", "Suspicious redirect patterns"],
        recommendations: ["Avoid access", "High risk of data theft"],
        ipAddress: "185.234.72.46",
      },
    ],
    vulnerabilities: [
      {
        type: "Credential Harvesting",
        severity: "critical",
        description: "Site designed to steal login credentials",
        impact: "Complete account compromise",
        remediation: "Never enter credentials on this site",
      },
      {
        type: "Malware Distribution",
        severity: "high",
        description: "May serve malicious downloads",
        impact: "System infection possible",
        remediation: "Block all downloads from this domain",
      },
    ],
    securityFeatures: [
      { feature: "HTTPS", status: "disabled", description: "No secure connection" },
      { feature: "HSTS", status: "disabled", description: "No transport security" },
      { feature: "CSP", status: "disabled", description: "No content security policy" },
    ],
    threatIntelligence: {
      reputation: "Malicious",
      lastSeen: "Active threat - 2 hours ago",
      threatTypes: ["Phishing", "Credential Theft", "Malware"],
      geolocation: "Unknown/Proxy",
      isp: "Suspicious hosting provider",
    },
    certificateInfo: {
      valid: false,
      issuer: "Self-signed",
      expiry: "Expired",
      algorithm: "Weak",
      keySize: 1024,
      warnings: ["Invalid certificate", "Weak encryption", "Self-signed"],
    },
    dnsAnalysis: {
      records: [
        { type: "A", value: "185.234.72.45", ttl: 60, suspicious: true },
        { type: "MX", value: "mail.suspicious-provider.tk", ttl: 300, suspicious: true },
      ],
      suspicious: true,
      issues: ["Short TTL values", "Suspicious IP ranges", "Recently registered domain"],
    },
    ipAnalysis: {
      primaryIP: "185.234.72.45",
      allIPs: [
        {
          address: "185.234.72.45",
          type: "IPv4",
          status: "malicious",
          country: "Russia",
          city: "Moscow",
          isp: "Suspicious Hosting Ltd",
          organization: "Bulletproof Hosting",
          riskScore: 95,
          lastSeen: "2 hours ago",
        },
      ],
      geolocation: {
        country: "Russia",
        countryCode: "RU",
        region: "Moscow",
        city: "Moscow",
        latitude: 55.7558,
        longitude: 37.6176,
        timezone: "Europe/Moscow",
        isp: "Suspicious Hosting Ltd",
        organization: "Bulletproof Hosting",
        asn: "AS12345",
      },
      reputation: {
        score: 5,
        status: "malicious",
        categories: ["Phishing", "Malware", "Botnet"],
        lastReported: "2 hours ago",
        reportCount: 847,
        sources: ["VirusTotal", "AbuseIPDB", "Shodan", "Spamhaus"],
      },
      networkInfo: {
        asn: 12345,
        asnOrg: "Suspicious Hosting Ltd",
        cidr: "185.234.72.0/24",
        hostingProvider: "Bulletproof Hosting",
        isProxy: true,
        isVPN: false,
        isTor: false,
        isDataCenter: true,
        isResidential: false,
      },
      securityFlags: [
        {
          type: "Known Malicious IP",
          severity: "high",
          description: "IP address has been reported for malicious activities",
          recommendation: "Block immediately",
        },
        {
          type: "Bulletproof Hosting",
          severity: "high",
          description: "Hosted on a provider known for ignoring abuse reports",
          recommendation: "High risk - avoid access",
        },
        {
          type: "Proxy/Anonymizer",
          severity: "medium",
          description: "Traffic may be routed through anonymization services",
          recommendation: "Exercise extreme caution",
        },
      ],
    },
  },
  "https://suspicious-bank.tk": {
    score: 75,
    level: "MEDIUM",
    rec: "CAUTION",
    subdomains: [
      {
        subdomain: "online.suspicious-bank.tk",
        status: "warning",
        riskScore: 78,
        issues: ["Suspicious TLD", "Mimics banking site", "New domain registration"],
        recommendations: ["Verify legitimacy before use", "Check official bank website"],
        ipAddress: "192.168.1.100",
      },
    ],
    vulnerabilities: [
      {
        type: "Domain Spoofing",
        severity: "medium",
        description: "Domain designed to mimic legitimate banking site",
        impact: "Potential financial fraud",
        remediation: "Verify domain authenticity with official sources",
      },
    ],
    securityFeatures: [
      { feature: "HTTPS", status: "enabled", description: "Basic SSL enabled" },
      { feature: "HSTS", status: "disabled", description: "No strict transport security" },
      { feature: "CSP", status: "partial", description: "Weak content security policy" },
    ],
    threatIntelligence: {
      reputation: "Suspicious",
      lastSeen: "Flagged 1 day ago",
      threatTypes: ["Potential Phishing", "Domain Spoofing"],
      geolocation: "Tokelau",
      isp: "Free domain provider",
    },
    certificateInfo: {
      valid: true,
      issuer: "Let's Encrypt",
      expiry: "2024-12-15",
      algorithm: "RSA-SHA256",
      keySize: 2048,
      warnings: ["Recently issued certificate", "Free certificate provider"],
    },
    dnsAnalysis: {
      records: [{ type: "A", value: "192.168.1.100", ttl: 300, suspicious: true }],
      suspicious: true,
      issues: ["Suspicious TLD", "Recently registered", "Free hosting provider"],
    },
    ipAnalysis: {
      primaryIP: "192.168.1.100",
      allIPs: [
        {
          address: "192.168.1.100",
          type: "IPv4",
          status: "warning",
          country: "Tokelau",
          city: "Fakaofo",
          isp: "Free Hosting Provider",
          organization: "Cheap Hosting Co",
          riskScore: 75,
          lastSeen: "1 day ago",
        },
      ],
      geolocation: {
        country: "Tokelau",
        countryCode: "TK",
        region: "Fakaofo",
        city: "Fakaofo",
        latitude: -9.3658,
        longitude: -171.2136,
        timezone: "Pacific/Fakaofo",
        isp: "Free Hosting Provider",
        organization: "Cheap Hosting Co",
        asn: "AS54321",
      },
      reputation: {
        score: 25,
        status: "suspicious",
        categories: ["Suspicious Domain", "Free Hosting"],
        lastReported: "1 day ago",
        reportCount: 12,
        sources: ["VirusTotal", "URLVoid"],
      },
      networkInfo: {
        asn: 54321,
        asnOrg: "Free Hosting Provider",
        cidr: "192.168.1.0/24",
        hostingProvider: "Cheap Hosting Co",
        isProxy: false,
        isVPN: false,
        isTor: false,
        isDataCenter: true,
        isResidential: false,
      },
      securityFlags: [
        {
          type: "Free Hosting",
          severity: "medium",
          description: "Hosted on a free hosting provider often used by malicious actors",
          recommendation: "Verify legitimacy before trusting",
        },
        {
          type: "Suspicious TLD",
          severity: "medium",
          description: "Uses a top-level domain commonly associated with suspicious activities",
          recommendation: "Exercise caution",
        },
      ],
    },
  },
}

function getColor(score: number) {
  if (score >= 70) return "bg-red-500"
  if (score >= 40) return "bg-yellow-500"
  return "bg-green-500"
}

function getStatusColor(status: string) {
  switch (status) {
    case "safe":
    case "clean":
      return "text-green-600 bg-green-100"
    case "warning":
    case "suspicious":
      return "text-yellow-600 bg-yellow-100"
    case "vulnerable":
      return "text-orange-600 bg-orange-100"
    case "malicious":
      return "text-red-600 bg-red-100"
    default:
      return "text-gray-600 bg-gray-100"
  }
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case "info":
      return "text-blue-600 bg-blue-100"
    case "low":
      return "text-green-600 bg-green-100"
    case "medium":
      return "text-yellow-600 bg-yellow-100"
    case "high":
      return "text-red-600 bg-red-100"
    case "critical":
      return "text-red-600 bg-red-100"
    default:
      return "text-gray-600 bg-gray-100"
  }
}

export default function EnhancedDemoAnalyzer() {
  const [url, setUrl] = useState("")
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [activeTab, setActiveTab] = useState("overview")

  const analyze = (target: string) => {
    setLoading(true)
    setResult(null)
    setTimeout(() => {
      const data = ENHANCED_PRESETS[target] || generateRandomAnalysis(target)
      setResult(data)
      setLoading(false)
    }, 2000)
  }

  const generateRandomAnalysis = (target: string): AnalysisResult => {
    const score = Math.floor(Math.random() * 90) + 5
    const domain = target.replace(/^https?:\/\//, "").split("/")[0]
    const randomIP = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`

    return {
      score,
      level: score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW",
      rec: score >= 70 ? "BLOCK" : score >= 40 ? "CAUTION" : "SAFE",
      subdomains: [
        {
          subdomain: `www.${domain}`,
          status: score > 70 ? "vulnerable" : score > 40 ? "warning" : "safe",
          riskScore: score,
          issues: score > 70 ? ["High risk detected"] : score > 40 ? ["Medium risk"] : [],
          recommendations: score > 70 ? ["Avoid access"] : score > 40 ? ["Use caution"] : ["Safe to use"],
          ipAddress: randomIP,
        },
      ],
      vulnerabilities:
        score > 70
          ? [
              {
                type: "Potential Threat",
                severity: "high" as const,
                description: "Site shows suspicious characteristics",
                impact: "Potential security risk",
                remediation: "Avoid accessing this site",
              },
            ]
          : [],
      securityFeatures: [
        { feature: "HTTPS", status: target.startsWith("https") ? "enabled" : "disabled", description: "SSL status" },
      ],
      threatIntelligence: {
        reputation: score > 70 ? "Poor" : score > 40 ? "Unknown" : "Good",
        lastSeen: "Recently analyzed",
        threatTypes: score > 70 ? ["Suspicious Activity"] : [],
        geolocation: "Unknown",
        isp: "Unknown",
      },
      certificateInfo: {
        valid: target.startsWith("https"),
        issuer: "Unknown",
        expiry: "Unknown",
        algorithm: "Unknown",
        keySize: 0,
        warnings: [],
      },
      dnsAnalysis: {
        records: [{ type: "A", value: randomIP, ttl: 300, suspicious: score > 70 }],
        suspicious: score > 70,
        issues: score > 70 ? ["Suspicious patterns detected"] : [],
      },
      ipAnalysis: {
        primaryIP: randomIP,
        allIPs: [
          {
            address: randomIP,
            type: "IPv4",
            status: score > 70 ? "malicious" : score > 40 ? "warning" : "safe",
            country: "Unknown",
            city: "Unknown",
            isp: "Unknown ISP",
            organization: "Unknown Org",
            riskScore: score,
            lastSeen: "Recently scanned",
          },
        ],
        geolocation: {
          country: "Unknown",
          countryCode: "XX",
          region: "Unknown",
          city: "Unknown",
          latitude: 0,
          longitude: 0,
          timezone: "UTC",
          isp: "Unknown ISP",
          organization: "Unknown Org",
          asn: "AS00000",
        },
        reputation: {
          score: 100 - score,
          status: score > 70 ? "malicious" : score > 40 ? "suspicious" : "clean",
          categories: score > 70 ? ["Suspicious Activity"] : [],
          lastReported: score > 70 ? "Recently" : "Never",
          reportCount: score > 70 ? Math.floor(Math.random() * 100) : 0,
          sources: ["Analysis Engine"],
        },
        networkInfo: {
          asn: 0,
          asnOrg: "Unknown",
          cidr: "0.0.0.0/0",
          hostingProvider: "Unknown",
          isProxy: false,
          isVPN: false,
          isTor: false,
          isDataCenter: false,
          isResidential: true,
        },
        securityFlags:
          score > 70
            ? [
                {
                  type: "Suspicious Activity",
                  severity: "high",
                  description: "IP shows signs of suspicious activity",
                  recommendation: "Exercise caution",
                },
              ]
            : [],
      },
    }
  }

  return (
    <div className="bg-white rounded-xl shadow-lg p-8 max-w-6xl mx-auto">
      <h3 className="text-3xl font-bold text-center mb-8">🛡️ Advanced Security Analyzer</h3>

      {/* URL Input */}
      <div className="flex flex-col sm:flex-row gap-4 mb-6">
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          className="flex-1 px-4 py-3 border-2 border-gray-300 rounded-full focus:border-blue-500 outline-none text-lg"
        />
        <button
          disabled={!url || loading}
          onClick={() => analyze(url)}
          className="bg-gradient-to-r from-blue-600 to-purple-600 text-white px-8 py-3 rounded-full font-semibold disabled:opacity-50 hover:shadow-lg transition-all"
        >
          {loading ? "🔍 Analyzing..." : "🚀 Deep Scan"}
        </button>
      </div>

      {/* Presets */}
      <div className="flex flex-wrap gap-3 justify-center text-sm mb-8">
        <span className="text-gray-600 font-medium">Quick Tests:</span>
        {Object.keys(ENHANCED_PRESETS).map((preset) => (
          <button
            key={preset}
            onClick={() => {
              setUrl(preset)
              analyze(preset)
            }}
            className="px-4 py-2 rounded-full bg-gradient-to-r from-gray-100 to-gray-200 hover:from-blue-100 hover:to-blue-200 transition-all transform hover:scale-105"
          >
            {new URL(preset).hostname}
          </button>
        ))}
      </div>

      {/* Loading */}
      {loading && (
        <div className="text-center py-12">
          <div className="animate-spin rounded-full h-16 w-16 border-b-4 border-blue-500 mx-auto mb-6"></div>
          <p className="text-lg text-gray-600 mb-2">🔍 Deep scanning security layers...</p>
          <div className="max-w-md mx-auto">
            <div className="flex justify-between text-sm text-gray-500 mb-2">
              <span>Resolving IP addresses</span>
              <span>Analyzing geolocation</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div
                className="bg-gradient-to-r from-blue-500 to-purple-500 h-2 rounded-full animate-pulse"
                style={{ width: "75%" }}
              ></div>
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {result && !loading && (
        <div className="space-y-8">
          {/* Risk Score Overview */}
          <div className="text-center bg-gradient-to-r from-gray-50 to-blue-50 rounded-xl p-8">
            <div
              className={`w-32 h-32 mx-auto rounded-full flex items-center justify-center text-white text-4xl font-bold mb-4 ${getColor(result.score)} shadow-lg`}
            >
              {result.score}
            </div>
            <h4 className="text-2xl font-bold mb-2">
              {result.level} RISK - {result.rec}
            </h4>
            <p className="text-gray-600">
              Primary IP: <span className="font-mono font-bold">{result.ipAnalysis.primaryIP}</span>
            </p>
          </div>

          {/* Tabs */}
          <div className="border-b border-gray-200">
            <nav className="flex space-x-8 overflow-x-auto">
              {[
                { id: "overview", label: "📊 Overview", count: null },
                { id: "ip-analysis", label: "🌐 IP Analysis", count: result.ipAnalysis.allIPs.length },
                { id: "subdomains", label: "🔗 Subdomains", count: result.subdomains.length },
                { id: "vulnerabilities", label: "⚠️ Vulnerabilities", count: result.vulnerabilities.length },
                { id: "security", label: "🔒 Security Features", count: result.securityFeatures.length },
                { id: "intelligence", label: "🕵️ Threat Intel", count: null },
                { id: "certificate", label: "📜 Certificate", count: null },
                { id: "dns", label: "🌍 DNS Analysis", count: result.dnsAnalysis.records.length },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`py-4 px-2 border-b-2 font-medium text-sm whitespace-nowrap ${
                    activeTab === tab.id
                      ? "border-blue-500 text-blue-600"
                      : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
                  }`}
                >
                  {tab.label}
                  {tab.count !== null && (
                    <span className="ml-2 bg-gray-100 text-gray-900 py-0.5 px-2 rounded-full text-xs">{tab.count}</span>
                  )}
                </button>
              ))}
            </nav>
          </div>

          {/* Tab Content */}
          <div className="min-h-96">
            {activeTab === "overview" && (
              <div className="grid md:grid-cols-2 gap-6">
                <div className="bg-gray-50 rounded-lg p-6">
                  <h5 className="font-bold text-lg mb-4">🎯 Quick Summary</h5>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span>Overall Risk:</span>
                      <span
                        className={`px-3 py-1 rounded-full text-sm font-medium ${getColor(result.score).replace("bg-", "bg-opacity-20 text-").replace("-500", "-700")}`}
                      >
                        {result.level}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span>Primary IP:</span>
                      <span className="font-mono font-medium">{result.ipAnalysis.primaryIP}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Location:</span>
                      <span className="font-medium">
                        {result.ipAnalysis.geolocation.city}, {result.ipAnalysis.geolocation.country}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span>ISP:</span>
                      <span className="font-medium">{result.ipAnalysis.geolocation.isp}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>IP Reputation:</span>
                      <span
                        className={`px-2 py-1 rounded text-sm font-medium ${getStatusColor(result.ipAnalysis.reputation.status)}`}
                      >
                        {result.ipAnalysis.reputation.status.toUpperCase()}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="bg-gray-50 rounded-lg p-6">
                  <h5 className="font-bold text-lg mb-4">📈 Risk Breakdown</h5>
                  <div className="space-y-4">
                    {result.subdomains.slice(0, 3).map((sub, i) => (
                      <div key={i} className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-mono">{sub.subdomain}</span>
                          <span className="text-sm font-medium">{sub.riskScore}%</span>
                        </div>
                        <div className="flex items-center justify-between text-xs text-gray-600">
                          <span>IP: {sub.ipAddress}</span>
                          <div className="w-16 bg-gray-200 rounded-full h-2">
                            <div
                              className={`h-2 rounded-full ${getColor(sub.riskScore)}`}
                              style={{ width: `${sub.riskScore}%` }}
                            ></div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {activeTab === "ip-analysis" && (
              <div className="space-y-6">
                <h5 className="font-bold text-xl mb-4">🌐 IP Address Analysis</h5>

                {/* Primary IP Info */}
                <div className="bg-gradient-to-r from-blue-50 to-indigo-50 rounded-lg p-6 border-l-4 border-blue-500">
                  <h6 className="font-bold text-lg mb-4">🎯 Primary IP Address</h6>
                  <div className="grid md:grid-cols-2 gap-6">
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span>IP Address:</span>
                        <span className="font-mono font-bold text-lg">{result.ipAnalysis.primaryIP}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Status:</span>
                        <span
                          className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(result.ipAnalysis.reputation.status)}`}
                        >
                          {result.ipAnalysis.reputation.status.toUpperCase()}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span>Reputation Score:</span>
                        <span className="font-bold">{result.ipAnalysis.reputation.score}/100</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Report Count:</span>
                        <span className="font-medium">{result.ipAnalysis.reputation.reportCount}</span>
                      </div>
                    </div>
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span>Country:</span>
                        <span className="font-medium">
                          {result.ipAnalysis.geolocation.country} ({result.ipAnalysis.geolocation.countryCode})
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span>City:</span>
                        <span className="font-medium">{result.ipAnalysis.geolocation.city}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>ISP:</span>
                        <span className="font-medium">{result.ipAnalysis.geolocation.isp}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>ASN:</span>
                        <span className="font-mono">{result.ipAnalysis.geolocation.asn}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* All IP Addresses */}
                <div>
                  <h6 className="font-bold text-lg mb-4">📋 All Resolved IP Addresses</h6>
                  <div className="space-y-4">
                    {result.ipAnalysis.allIPs.map((ip, i) => (
                      <div key={i} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
                        <div className="flex items-center justify-between mb-3">
                          <span className="font-mono text-lg font-bold">{ip.address}</span>
                          <div className="flex items-center space-x-3">
                            <span className="text-sm bg-gray-100 px-2 py-1 rounded">{ip.type}</span>
                            <span className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(ip.status)}`}>
                              {ip.status.toUpperCase()}
                            </span>
                            <div
                              className={`w-12 h-12 rounded-full flex items-center justify-center text-white font-bold ${getColor(ip.riskScore)}`}
                            >
                              {ip.riskScore}
                            </div>
                          </div>
                        </div>
                        <div className="grid md:grid-cols-3 gap-4 text-sm">
                          <div>
                            <span className="text-gray-600">Location:</span>
                            <div className="font-medium">
                              {ip.city}, {ip.country}
                            </div>
                          </div>
                          <div>
                            <span className="text-gray-600">ISP:</span>
                            <div className="font-medium">{ip.isp}</div>
                          </div>
                          <div>
                            <span className="text-gray-600">Last Seen:</span>
                            <div className="font-medium">{ip.lastSeen}</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Network Information */}
                <div className="bg-gray-50 rounded-lg p-6">
                  <h6 className="font-bold text-lg mb-4">🌐 Network Information</h6>
                  <div className="grid md:grid-cols-2 gap-6">
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span>ASN:</span>
                        <span className="font-mono">AS{result.ipAnalysis.networkInfo.asn}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>ASN Organization:</span>
                        <span className="font-medium">{result.ipAnalysis.networkInfo.asnOrg}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>CIDR Block:</span>
                        <span className="font-mono">{result.ipAnalysis.networkInfo.cidr}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Hosting Provider:</span>
                        <span className="font-medium">{result.ipAnalysis.networkInfo.hostingProvider}</span>
                      </div>
                    </div>
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span>Proxy/VPN:</span>
                        <span
                          className={`font-medium ${result.ipAnalysis.networkInfo.isProxy || result.ipAnalysis.networkInfo.isVPN ? "text-yellow-600" : "text-green-600"}`}
                        >
                          {result.ipAnalysis.networkInfo.isProxy || result.ipAnalysis.networkInfo.isVPN ? "Yes" : "No"}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span>Tor Exit Node:</span>
                        <span
                          className={`font-medium ${result.ipAnalysis.networkInfo.isTor ? "text-red-600" : "text-green-600"}`}
                        >
                          {result.ipAnalysis.networkInfo.isTor ? "Yes" : "No"}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span>Data Center:</span>
                        <span className="font-medium">{result.ipAnalysis.networkInfo.isDataCenter ? "Yes" : "No"}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Residential:</span>
                        <span className="font-medium">
                          {result.ipAnalysis.networkInfo.isResidential ? "Yes" : "No"}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Security Flags */}
                <div>
                  <h6 className="font-bold text-lg mb-4">🚩 Security Flags</h6>
                  {result.ipAnalysis.securityFlags.length === 0 ? (
                    <div className="text-center py-8 bg-green-50 rounded-lg">
                      <div className="text-4xl mb-2">✅</div>
                      <p className="text-green-600 font-medium">No security flags detected</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {result.ipAnalysis.securityFlags.map((flag, i) => (
                        <div
                          key={i}
                          className={`border-l-4 p-4 rounded-r-lg ${getSeverityColor(flag.severity).includes("red") ? "border-red-500 bg-red-50" : getSeverityColor(flag.severity).includes("yellow") ? "border-yellow-500 bg-yellow-50" : "border-blue-500 bg-blue-50"}`}
                        >
                          <div className="flex items-center justify-between mb-2">
                            <h6 className="font-bold">{flag.type}</h6>
                            <span
                              className={`px-2 py-1 rounded text-sm font-medium ${getSeverityColor(flag.severity)}`}
                            >
                              {flag.severity.toUpperCase()}
                            </span>
                          </div>
                          <p className="text-gray-700 mb-2">{flag.description}</p>
                          <p className="text-sm font-medium text-blue-600">💡 {flag.recommendation}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {activeTab === "subdomains" && (
              <div className="space-y-4">
                <h5 className="font-bold text-xl mb-4">🔗 Subdomain & IP Analysis</h5>
                {result.subdomains.map((subdomain, i) => (
                  <div key={i} className="border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow">
                    <div className="flex items-center justify-between mb-4">
                      <div>
                        <h6 className="font-bold text-lg font-mono">{subdomain.subdomain}</h6>
                        <p className="text-sm text-gray-600 font-mono">IP: {subdomain.ipAddress}</p>
                      </div>
                      <div className="flex items-center space-x-3">
                        <span
                          className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(subdomain.status)}`}
                        >
                          {subdomain.status.toUpperCase()}
                        </span>
                        <div
                          className={`w-12 h-12 rounded-full flex items-center justify-center text-white font-bold ${getColor(subdomain.riskScore)}`}
                        >
                          {subdomain.riskScore}
                        </div>
                      </div>
                    </div>

                    {subdomain.issues.length > 0 && (
                      <div className="mb-4">
                        <h6 className="font-semibold text-red-600 mb-2 block">⚠️ Issues Found:</h6>
                        <ul className="list-disc list-inside space-y-1 text-sm text-gray-700">
                          {subdomain.issues.map((issue, j) => (
                            <li key={j}>{issue}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    <div>
                      <h6 className="font-semibold text-blue-600 mb-2 block">💡 Recommendations:</h6>
                      <ul className="list-disc list-inside space-y-1 text-sm text-gray-700">
                        {subdomain.recommendations.map((rec, j) => (
                          <li key={j}>{rec}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Other existing tabs remain the same... */}
            {activeTab === "vulnerabilities" && (
              <div className="space-y-4">
                <h5 className="font-bold text-xl mb-4">⚠️ Security Vulnerabilities</h5>
                {result.vulnerabilities.length === 0 ? (
                  <div className="text-center py-12 bg-green-50 rounded-lg">
                    <div className="text-6xl mb-4">✅</div>
                    <h6 className="text-xl font-semibold text-green-700 mb-2">No Critical Vulnerabilities Found</h6>
                    <p className="text-green-600">This site appears to be secure from major threats.</p>
                  </div>
                ) : (
                  result.vulnerabilities.map((vuln, i) => (
                    <div key={i} className="border-l-4 border-red-500 bg-red-50 p-6 rounded-r-lg">
                      <div className="flex items-center justify-between mb-3">
                        <h6 className="font-bold text-lg text-red-800">{vuln.type}</h6>
                        <span
                          className={`px-3 py-1 rounded-full text-sm font-medium ${getSeverityColor(vuln.severity)}`}
                        >
                          {vuln.severity.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-gray-700 mb-3">{vuln.description}</p>
                      <div className="grid md:grid-cols-2 gap-4">
                        <div>
                          <h6 className="font-semibold text-red-600 block mb-1">💥 Potential Impact:</h6>
                          <p className="text-sm text-gray-600">{vuln.impact}</p>
                        </div>
                        <div>
                          <h6 className="font-semibold text-blue-600 block mb-1">🛠️ Remediation:</h6>
                          <p className="text-sm text-gray-600">{vuln.remediation}</p>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {activeTab === "security" && (
              <div className="space-y-4">
                <h5 className="font-bold text-xl mb-4">🔒 Security Features Analysis</h5>
                <div className="grid md:grid-cols-2 gap-4">
                  {result.securityFeatures.map((feature, i) => (
                    <div key={i} className="border border-gray-200 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <h6 className="font-semibold">{feature.feature}</h6>
                        <span
                          className={`px-2 py-1 rounded text-sm font-medium ${
                            feature.status === "enabled"
                              ? "bg-green-100 text-green-700"
                              : feature.status === "partial"
                                ? "bg-yellow-100 text-yellow-700"
                                : "bg-red-100 text-red-700"
                          }`}
                        >
                          {feature.status.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600">{feature.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === "intelligence" && (
              <div className="space-y-6">
                <h5 className="font-bold text-xl mb-4">🕵️ Threat Intelligence Report</h5>
                <div className="grid md:grid-cols-2 gap-6">
                  <div className="bg-gray-50 rounded-lg p-6">
                    <h6 className="font-semibold mb-4">📊 Reputation Analysis</h6>
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span>Overall Reputation:</span>
                        <span
                          className={`font-medium ${
                            result.threatIntelligence.reputation === "Excellent"
                              ? "text-green-600"
                              : result.threatIntelligence.reputation === "Good"
                                ? "text-blue-600"
                                : result.threatIntelligence.reputation === "Suspicious"
                                  ? "text-yellow-600"
                                  : "text-red-600"
                          }`}
                        >
                          {result.threatIntelligence.reputation}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span>Last Threat Activity:</span>
                        <span className="font-medium">{result.threatIntelligence.lastSeen}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Geographic Location:</span>
                        <span className="font-medium">{result.threatIntelligence.geolocation}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>ISP/Hosting:</span>
                        <span className="font-medium">{result.threatIntelligence.isp}</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gray-50 rounded-lg p-6">
                    <h6 className="font-semibold mb-4">🎯 Threat Categories</h6>
                    {result.threatIntelligence.threatTypes.length === 0 ? (
                      <p className="text-green-600 font-medium">✅ No known threats detected</p>
                    ) : (
                      <div className="space-y-2">
                        {result.threatIntelligence.threatTypes.map((threat, i) => (
                          <div key={i} className="bg-red-100 text-red-700 px-3 py-2 rounded-lg text-sm font-medium">
                            ⚠️ {threat}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {activeTab === "certificate" && (
              <div className="space-y-6">
                <h5 className="font-bold text-xl mb-4">📜 SSL Certificate Analysis</h5>
                <div className="grid md:grid-cols-2 gap-6">
                  <div className="bg-gray-50 rounded-lg p-6">
                    <h6 className="font-semibold mb-4">🔐 Certificate Details</h6>
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span>Status:</span>
                        <span
                          className={`font-medium ${result.certificateInfo.valid ? "text-green-600" : "text-red-600"}`}
                        >
                          {result.certificateInfo.valid ? "✅ Valid" : "❌ Invalid"}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span>Issuer:</span>
                        <span className="font-medium">{result.certificateInfo.issuer}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Expiry Date:</span>
                        <span className="font-medium">{result.certificateInfo.expiry}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Algorithm:</span>
                        <span className="font-medium">{result.certificateInfo.algorithm}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Key Size:</span>
                        <span className="font-medium">{result.certificateInfo.keySize} bits</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gray-50 rounded-lg p-6">
                    <h6 className="font-semibold mb-4">⚠️ Certificate Warnings</h6>
                    {result.certificateInfo.warnings.length === 0 ? (
                      <p className="text-green-600 font-medium">✅ No certificate issues found</p>
                    ) : (
                      <div className="space-y-2">
                        {result.certificateInfo.warnings.map((warning, i) => (
                          <div key={i} className="bg-yellow-100 text-yellow-700 px-3 py-2 rounded-lg text-sm">
                            ⚠️ {warning}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {activeTab === "dns" && (
              <div className="space-y-6">
                <h5 className="font-bold text-xl mb-4">🌍 DNS Security Analysis</h5>
                <div className="grid md:grid-cols-2 gap-6">
                  <div className="bg-gray-50 rounded-lg p-6">
                    <h6 className="font-semibold mb-4">📋 DNS Records</h6>
                    <div className="space-y-3">
                      {result.dnsAnalysis.records.map((record, i) => (
                        <div
                          key={i}
                          className={`p-3 rounded border-l-4 ${record.suspicious ? "border-red-500 bg-red-50" : "border-green-500 bg-green-50"}`}
                        >
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-mono text-sm font-medium">{record.type}</span>
                            <span className="text-xs text-gray-500">TTL: {record.ttl}s</span>
                          </div>
                          <div className="font-mono text-sm text-gray-700">{record.value}</div>
                          {record.suspicious && <div className="text-xs text-red-600 mt-1">⚠️ Suspicious record</div>}
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="bg-gray-50 rounded-lg p-6">
                    <h6 className="font-semibold mb-4">🔍 DNS Issues</h6>
                    {result.dnsAnalysis.issues.length === 0 ? (
                      <p className="text-green-600 font-medium">✅ No DNS security issues found</p>
                    ) : (
                      <div className="space-y-2">
                        {result.dnsAnalysis.issues.map((issue, i) => (
                          <div key={i} className="bg-yellow-100 text-yellow-700 px-3 py-2 rounded-lg text-sm">
                            ⚠️ {issue}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
