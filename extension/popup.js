class PhishingShieldPopup {
  constructor() {
    this.apiUrl = "http://localhost:5000/api"
    this.currentTab = null
    this.analysisData = null

    this.initializeElements()
    this.bindEvents()
    this.loadCurrentTab()
    this.loadStats()
  }

  initializeElements() {
    this.elements = {
      statusIndicator: document.getElementById("statusIndicator"),
      statusDot: document.getElementById("statusDot"),
      statusText: document.getElementById("statusText"),
      siteUrl: document.getElementById("siteUrl"),
      riskScore: document.getElementById("riskScore"),
      scoreCircle: document.getElementById("scoreCircle"),
      scoreValue: document.getElementById("scoreValue"),
      riskDetails: document.getElementById("riskDetails"),
      detailsGrid: document.getElementById("detailsGrid"),
      analyzeBtn: document.getElementById("analyzeBtn"),
      reportBtn: document.getElementById("reportBtn"),
      whitelistBtn: document.getElementById("whitelistBtn"),
      loadingOverlay: document.getElementById("loadingOverlay"),
      blockedCount: document.getElementById("blockedCount"),
      scannedCount: document.getElementById("scannedCount"),
    }
  }

  bindEvents() {
    this.elements.analyzeBtn.addEventListener("click", () => this.analyzeCurrentSite())
    this.elements.reportBtn.addEventListener("click", () => this.reportPhishing())
    this.elements.whitelistBtn.addEventListener("click", () => this.whitelistSite())
  }

  async loadCurrentTab() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
      this.currentTab = tab

      if (tab && tab.url) {
        this.elements.siteUrl.textContent = this.formatUrl(tab.url)
        this.updateStatus("ready", "Ready to analyze")

        // Auto-analyze if not a chrome:// or extension page
        if (!tab.url.startsWith("chrome://") && !tab.url.startsWith("chrome-extension://")) {
          this.analyzeCurrentSite()
        }
      } else {
        this.updateStatus("error", "Cannot analyze this page")
      }
    } catch (error) {
      console.error("Error loading current tab:", error)
      this.updateStatus("error", "Error loading page")
    }
  }

  async loadStats() {
    try {
      const result = await chrome.storage.local.get(["blockedCount", "scannedCount"])
      this.elements.blockedCount.textContent = result.blockedCount || 0
      this.elements.scannedCount.textContent = result.scannedCount || 0
    } catch (error) {
      console.error("Error loading stats:", error)
    }
  }

  async analyzeCurrentSite() {
    if (!this.currentTab || !this.currentTab.url) {
      this.showError("No valid URL to analyze")
      return
    }

    this.showLoading(true)
    this.elements.analyzeBtn.disabled = true

    try {
      const response = await fetch(`${this.apiUrl}/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: this.currentTab.url }),
      })

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`)
      }

      const data = await response.json()
      this.analysisData = data

      this.displayAnalysisResults(data)
      this.updateStats("scanned")

      // Check if site should be blocked
      if (data.risk_score >= 70) {
        this.updateStats("blocked")
        this.notifyBackground("block", data)
      }
    } catch (error) {
      console.error("Analysis error:", error)
      this.showError("Failed to analyze URL. Make sure the API server is running.")
    } finally {
      this.showLoading(false)
      this.elements.analyzeBtn.disabled = false
    }
  }

  displayAnalysisResults(data) {
    // Update risk score
    this.elements.scoreValue.textContent = data.risk_score

    // Update score circle color
    this.elements.scoreCircle.className = "score-circle"
    if (data.risk_score >= 70) {
      this.elements.scoreCircle.classList.add("high")
      this.updateStatus("danger", `HIGH RISK - ${data.recommendation}`)
    } else if (data.risk_score >= 40) {
      this.elements.scoreCircle.classList.add("medium")
      this.updateStatus("warning", `MEDIUM RISK - ${data.recommendation}`)
    } else {
      this.updateStatus("safe", `LOW RISK - ${data.recommendation}`)
    }

    // Show action buttons
    this.elements.reportBtn.style.display = data.risk_score >= 40 ? "flex" : "none"
    this.elements.whitelistBtn.style.display = data.risk_score < 70 ? "flex" : "none"

    // Display analysis details
    this.displayAnalysisDetails(data)
    this.elements.riskDetails.style.display = "block"
  }

  displayAnalysisDetails(data) {
    const details = [
      { label: "HTTPS Secure", value: data.features.https, type: data.features.https ? "safe" : "warning" },
      {
        label: "Domain Length",
        value: `${data.features.domain_length} chars`,
        type: data.features.domain_length > 30 ? "warning" : "safe",
      },
      {
        label: "Subdomains",
        value: data.features.subdomain_count,
        type: data.features.subdomain_count > 3 ? "warning" : "safe",
      },
      {
        label: "IP Address",
        value: data.features.has_ip ? "Yes" : "No",
        type: data.features.has_ip ? "danger" : "safe",
      },
      {
        label: "Suspicious TLD",
        value: data.features.suspicious_tld ? "Yes" : "No",
        type: data.features.suspicious_tld ? "warning" : "safe",
      },
      {
        label: "Blacklisted",
        value: data.analysis_details.blacklisted ? "Yes" : "No",
        type: data.analysis_details.blacklisted ? "danger" : "safe",
      },
    ]

    this.elements.detailsGrid.innerHTML = details
      .map(
        (detail) => `
            <div class="detail-item">
                <span class="detail-label">${detail.label}:</span>
                <span class="detail-value ${detail.type}">${detail.value}</span>
            </div>
        `,
      )
      .join("")
  }

  async reportPhishing() {
    if (!this.analysisData) return

    try {
      const response = await fetch(`${this.apiUrl}/report`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: this.currentTab.url,
          report_type: "phishing",
        }),
      })

      if (response.ok) {
        this.showSuccess("Thank you for reporting this site!")
        this.elements.reportBtn.textContent = "✓ Reported"
        this.elements.reportBtn.disabled = true
      }
    } catch (error) {
      console.error("Report error:", error)
      this.showError("Failed to report site")
    }
  }

  async whitelistSite() {
    if (!this.currentTab) return

    try {
      // Add to local whitelist
      const result = await chrome.storage.local.get(["whitelist"])
      const whitelist = result.whitelist || []
      const domain = new URL(this.currentTab.url).hostname

      if (!whitelist.includes(domain)) {
        whitelist.push(domain)
        await chrome.storage.local.set({ whitelist })
      }

      this.showSuccess("Site added to whitelist")
      this.elements.whitelistBtn.textContent = "✓ Whitelisted"
      this.elements.whitelistBtn.disabled = true
    } catch (error) {
      console.error("Whitelist error:", error)
      this.showError("Failed to whitelist site")
    }
  }

  async updateStats(type) {
    try {
      const result = await chrome.storage.local.get([`${type}Count`])
      const count = (result[`${type}Count`] || 0) + 1
      await chrome.storage.local.set({ [`${type}Count`]: count })
      this.elements[`${type}Count`].textContent = count
    } catch (error) {
      console.error("Error updating stats:", error)
    }
  }

  updateStatus(type, message) {
    this.elements.statusDot.className = `status-dot ${type}`
    this.elements.statusText.textContent = message
  }

  showLoading(show) {
    this.elements.loadingOverlay.style.display = show ? "flex" : "none"
  }

  showError(message) {
    this.updateStatus("danger", message)
    setTimeout(() => {
      this.updateStatus("ready", "Ready to analyze")
    }, 3000)
  }

  showSuccess(message) {
    this.updateStatus("safe", message)
    setTimeout(() => {
      this.updateStatus("ready", "Ready to analyze")
    }, 3000)
  }

  formatUrl(url) {
    try {
      const urlObj = new URL(url)
      return urlObj.hostname + urlObj.pathname
    } catch {
      return url
    }
  }

  notifyBackground(action, data) {
    chrome.runtime.sendMessage({
      action: action,
      data: data,
      url: this.currentTab.url,
    })
  }
}

// Initialize popup when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  new PhishingShieldPopup()
})
