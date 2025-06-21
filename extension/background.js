class PhishingShieldBackground {
  constructor() {
    this.apiUrl = "http://localhost:5000/api"
    this.cache = new Map()
    this.whitelist = new Set()

    this.initializeListeners()
    this.loadWhitelist()
  }

  initializeListeners() {
    // Listen for navigation events
    chrome.webNavigation.onBeforeNavigate.addListener((details) => this.handleNavigation(details))

    // Listen for messages from popup and content scripts
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) =>
      this.handleMessage(message, sender, sendResponse),
    )

    // Listen for tab updates
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => this.handleTabUpdate(tabId, changeInfo, tab))
  }

  async loadWhitelist() {
    try {
      const result = await chrome.storage.local.get(["whitelist"])
      this.whitelist = new Set(result.whitelist || [])
    } catch (error) {
      console.error("Error loading whitelist:", error)
    }
  }

  async handleNavigation(details) {
    // Only process main frame navigations
    if (details.frameId !== 0) return

    const url = details.url

    // Skip chrome:// and extension pages
    if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
      return
    }

    // Check if domain is whitelisted
    try {
      const domain = new URL(url).hostname
      if (this.whitelist.has(domain)) {
        return
      }
    } catch (error) {
      console.error("Error parsing URL:", error)
      return
    }

    // Analyze URL for phishing
    this.analyzeUrl(url, details.tabId)
  }

  async analyzeUrl(url, tabId) {
    try {
      // Check cache first
      if (this.cache.has(url)) {
        const cachedResult = this.cache.get(url)
        this.handleAnalysisResult(cachedResult, tabId, url)
        return
      }

      const response = await fetch(`${this.apiUrl}/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      })

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`)
      }

      const result = await response.json()

      // Cache result for 5 minutes
      this.cache.set(url, result)
      setTimeout(() => this.cache.delete(url), 5 * 60 * 1000)

      this.handleAnalysisResult(result, tabId, url)
    } catch (error) {
      console.error("Background analysis error:", error)
      // Fail silently in background to avoid disrupting browsing
    }
  }

  async handleAnalysisResult(result, tabId, url) {
    // Update badge with risk score
    this.updateBadge(tabId, result.risk_score)

    // Block high-risk sites
    if (result.risk_score >= 70) {
      this.blockSite(tabId, url, result)
    } else if (result.risk_score >= 40) {
      // Show warning for medium-risk sites
      this.showWarning(tabId, result)
    }

    // Update stats
    this.updateStats("scanned")
    if (result.risk_score >= 70) {
      this.updateStats("blocked")
    }
  }

  updateBadge(tabId, riskScore) {
    let badgeText = ""
    let badgeColor = "#10b981" // Green

    if (riskScore >= 70) {
      badgeText = "!"
      badgeColor = "#ef4444" // Red
    } else if (riskScore >= 40) {
      badgeText = "?"
      badgeColor = "#f59e0b" // Yellow
    }

    chrome.action.setBadgeText({ text: badgeText, tabId })
    chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId })
  }

  async blockSite(tabId, url, analysisResult) {
    try {
      // Create warning page URL
      const warningUrl =
        chrome.runtime.getURL("warning.html") + `?url=${encodeURIComponent(url)}&score=${analysisResult.risk_score}`

      // Redirect to warning page
      await chrome.tabs.update(tabId, { url: warningUrl })

      // Show notification
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon48.png",
        title: "Phishing Site Blocked",
        message: `Blocked potentially dangerous site with ${analysisResult.risk_score}% risk score`,
      })
    } catch (error) {
      console.error("Error blocking site:", error)
    }
  }

  showWarning(tabId, result) {
    // Inject warning banner into the page
    chrome.scripting
      .executeScript({
        target: { tabId },
        func: this.injectWarningBanner,
        args: [result.risk_score, result.risk_level],
      })
      .catch((error) => {
        console.error("Error injecting warning:", error)
      })
  }

  injectWarningBanner(riskScore, riskLevel) {
    // Remove existing banner
    const existingBanner = document.getElementById("phishing-shield-banner")
    if (existingBanner) {
      existingBanner.remove()
    }

    // Create warning banner
    const banner = document.createElement("div")
    banner.id = "phishing-shield-banner"
    banner.innerHTML = `
            <div style="
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
                color: white;
                padding: 12px 20px;
                text-align: center;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                font-size: 14px;
                font-weight: 500;
                z-index: 999999;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                border-bottom: 2px solid #d97706;
            ">
                ⚠️ <strong>Phishing Shield Warning:</strong> This site has a ${riskScore}% risk score (${riskLevel} risk). Please proceed with caution.
                <button onclick="this.parentElement.parentElement.remove()" style="
                    background: rgba(255,255,255,0.2);
                    border: none;
                    color: white;
                    padding: 4px 8px;
                    margin-left: 10px;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 12px;
                ">Dismiss</button>
            </div>
        `

    document.body.insertBefore(banner, document.body.firstChild)

    // Auto-dismiss after 10 seconds
    setTimeout(() => {
      const banner = document.getElementById("phishing-shield-banner")
      if (banner) banner.remove()
    }, 10000)
  }

  handleMessage(message, sender, sendResponse) {
    switch (message.action) {
      case "block":
        this.handleBlockMessage(message)
        break
      case "getAnalysis":
        sendResponse(this.cache.get(message.url) || null)
        break
      case "updateWhitelist":
        this.loadWhitelist()
        break
    }
  }

  handleTabUpdate(tabId, changeInfo, tab) {
    // Clear badge when navigating to new URL
    if (changeInfo.url) {
      chrome.action.setBadgeText({ text: "", tabId })
    }
  }

  async updateStats(type) {
    try {
      const result = await chrome.storage.local.get([`${type}Count`])
      const count = (result[`${type}Count`] || 0) + 1
      await chrome.storage.local.set({ [`${type}Count`]: count })
    } catch (error) {
      console.error("Error updating stats:", error)
    }
  }
}

// Initialize background script
new PhishingShieldBackground()
