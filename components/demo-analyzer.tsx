"use client"

import type React from "react"

import { useState } from "react"

interface AnalysisResult {
  url: string
  safe: boolean
  reasons: string[]
}

const getColor = (safe: boolean | null): string => {
  if (safe === null) return "text-gray-500"
  return safe ? "text-green-500" : "text-red-500"
}

const getStatusColor = (safe: boolean | null): string => {
  if (safe === null) return "bg-gray-100"
  return safe ? "bg-green-100" : "bg-red-100"
}

const getStatusText = (safe: boolean | null): string => {
  if (safe === null) return "Analyzing..."
  return safe ? "Safe" : "Phishing Detected"
}

const analyzeUrl = async (url: string): Promise<AnalysisResult> => {
  // Simulate analysis (replace with actual API call)
  await new Promise((resolve) => setTimeout(resolve, 1500))

  const isSafe = !url.includes("suspicious") // Simulate phishing detection

  const reasons = isSafe
    ? ["No suspicious patterns found."]
    : ["URL contains suspicious keywords.", "Domain age is relatively new."]

  return { url, safe: isSafe, reasons }
}

export default function EnhancedDemoAnalyzer() {
  const [url, setUrl] = useState("")
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [activeTab, setActiveTab] = useState("overview")

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setResult(null) // Clear previous result
    try {
      const analysisResult = await analyzeUrl(url)
      setResult(analysisResult)
    } catch (error) {
      console.error("Error during analysis:", error)
      setResult({ url: url, safe: false, reasons: ["Analysis failed."] })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="bg-white rounded-xl shadow-lg p-8 max-w-6xl mx-auto">
      {/* BRANDING CHANGE ↓ */}
      <h3 className="text-3xl font-bold text-center mb-8">🛡️ Phishing Detection Analyzer</h3>

      <form onSubmit={handleSubmit} className="mb-6">
        <div className="flex flex-col md:flex-row gap-4">
          <input
            type="url"
            placeholder="Enter URL to analyze"
            className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={loading}
          />
          <button
            type="submit"
            className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline disabled:bg-gray-400"
            disabled={loading}
          >
            {loading ? "Analyzing..." : "Analyze"}
          </button>
        </div>
      </form>

      {result && (
        <div className="mt-8">
          <div className="flex justify-between items-center mb-4">
            <h4 className="text-xl font-semibold">Analysis Result</h4>
            <span className={`text-sm font-medium px-4 py-2 rounded-full ${getStatusColor(result?.safe)}`}>
              Status: <span className={getColor(result?.safe)}>{getStatusText(result?.safe)}</span>
            </span>
          </div>

          <div className="mb-4">
            <div className="border-b border-gray-200">
              <nav className="-mb-px flex space-x-8">
                <button
                  onClick={() => setActiveTab("overview")}
                  className={`${
                    activeTab === "overview"
                      ? "border-blue-500 text-blue-600"
                      : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
                  } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm`}
                >
                  Overview
                </button>
                <button
                  onClick={() => setActiveTab("details")}
                  className={`${
                    activeTab === "details"
                      ? "border-blue-500 text-blue-600"
                      : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
                  } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm`}
                >
                  Details
                </button>
              </nav>
            </div>
          </div>

          {activeTab === "overview" && (
            <div>
              <p>
                The URL <span className="font-bold">{result.url}</span> has been analyzed.
              </p>
              <p className="mt-2">
                Result: <span className={getColor(result.safe)}>{result.safe ? "Safe" : "Potentially Phishing"}</span>
              </p>
            </div>
          )}

          {activeTab === "details" && (
            <div>
              <h5 className="text-lg font-semibold mb-2">Reasons:</h5>
              <ul className="list-disc pl-5">
                {result.reasons.map((reason, index) => (
                  <li key={index}>{reason}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      <p className="text-center mt-6 text-gray-500">Powered by Phishing Detection</p>
    </div>
  )
}
