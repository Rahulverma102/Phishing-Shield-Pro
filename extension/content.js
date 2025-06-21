class PhishingShieldContent {
  constructor() {
    this.isAnalyzing = false
    this.initialize()
  }

  initialize() {
    // Listen for messages from background script
    if (typeof chrome !== "undefined" && chrome.runtime) {
      chrome.runtime.onMessage.addListener((message, sender, sendResponse) =>
        this.handleMessage(message, sender, sendResponse),
      )
    }

    // Monitor for suspicious form submissions
    this.monitorForms()

    // Check for suspicious page elements
    this.checkPageElements()
  }

  handleMessage(message, sender, sendResponse) {
    switch (message.action) {
      case "showWarning":
        this.showInlineWarning(message.data)
        break
      case "checkPage":
        this.performPageCheck()
        sendResponse({ status: "checked" })
        break
    }
  }

  monitorForms() {
    // Monitor password and sensitive input fields
    const forms = document.querySelectorAll("form")

    forms.forEach((form) => {
      const sensitiveInputs = form.querySelectorAll(
        'input[type="password"], input[type="email"], input[name*="credit"], input[name*="card"]',
      )

      if (sensitiveInputs.length > 0) {
        form.addEventListener("submit", (e) => {
          this.handleSensitiveFormSubmission(e, form)
        })
      }
    })
  }

  handleSensitiveFormSubmission(event, form) {
    // Check if the form is being submitted to a different domain
    const formAction = form.action || window.location.href
    const currentDomain = window.location.hostname

    try {
      const actionDomain = new URL(formAction).hostname

      if (actionDomain !== currentDomain) {
        // Warn about cross-domain form submission
        const proceed = confirm(
          `⚠️ Phishing Shield Warning:\n\n` +
            `This form is submitting your data to a different domain (${actionDomain}).\n` +
            `This could be a phishing attempt.\n\n` +
            `Do you want to proceed?`,
        )

        if (!proceed) {
          event.preventDefault()
          this.reportSuspiciousActivity("cross_domain_form", {
            currentDomain,
            targetDomain: actionDomain,
            formAction,
          })
        }
      }
    } catch (error) {
      console.error("Error checking form submission:", error)
    }
  }

  checkPageElements() {
    // Check for suspicious page elements
    setTimeout(() => {
      this.checkForSuspiciousLinks()
      this.checkForFakeLoginForms()
      this.checkForUrgentMessages()
    }, 1000)
  }

  checkForSuspiciousLinks() {
    const links = document.querySelectorAll("a[href]")
    let suspiciousCount = 0

    links.forEach((link) => {
      const href = link.href
      const text = link.textContent.toLowerCase()

      // Check for URL shorteners
      if (this.isUrlShortener(href)) {
        link.style.border = "2px solid orange"
        link.title = "Phishing Shield: Shortened URL detected"
        suspiciousCount++
      }

      // Check for misleading link text
      if (this.isMisleadingLink(href, text)) {
        link.style.border = "2px solid red"
        link.title = "Phishing Shield: Misleading link detected"
        suspiciousCount++
      }
    })

    if (suspiciousCount > 3) {
      this.showPageWarning(`Found ${suspiciousCount} suspicious links on this page`)
    }
  }

  checkForFakeLoginForms() {
    const loginForms = document.querySelectorAll("form")

    loginForms.forEach((form) => {
      const hasPasswordField = form.querySelector('input[type="password"]')
      const hasEmailField = form.querySelector('input[type="email"], input[name*="email"], input[name*="username"]')

      if (hasPasswordField && hasEmailField) {
        // Check if form looks like a fake login
        const formText = form.textContent.toLowerCase()
        const suspiciousKeywords = ["verify", "suspended", "locked", "urgent", "immediate"]

        if (suspiciousKeywords.some((keyword) => formText.includes(keyword))) {
          this.highlightSuspiciousForm(form)
        }
      }
    })
  }

  checkForUrgentMessages() {
    const textContent = document.body.textContent.toLowerCase()
    const urgentPhrases = [
      "account suspended",
      "verify immediately",
      "click here now",
      "urgent action required",
      "expires today",
      "limited time offer",
    ]

    const foundPhrases = urgentPhrases.filter((phrase) => textContent.includes(phrase))

    if (foundPhrases.length >= 2) {
      this.showPageWarning(`Detected ${foundPhrases.length} urgent/suspicious phrases`)
    }
  }

  isUrlShortener(url) {
    const shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link", "tiny.cc", "is.gd", "buff.ly"]

    try {
      const domain = new URL(url).hostname.toLowerCase()
      return shorteners.some((shortener) => domain.includes(shortener))
    } catch {
      return false
    }
  }

  isMisleadingLink(href, text) {
    try {
      const linkDomain = new URL(href).hostname.toLowerCase()

      // Check if link text mentions a different domain
      const mentionedDomains = ["google", "facebook", "amazon", "paypal", "microsoft", "apple"]

      return mentionedDomains.some((domain) => text.includes(domain) && !linkDomain.includes(domain))
    } catch {
      return false
    }
  }

  highlightSuspiciousForm(form) {
    form.style.border = "3px solid red"
    form.style.backgroundColor = "rgba(239, 68, 68, 0.1)"

    // Add warning message
    const warning = document.createElement("div")
    warning.innerHTML = `
            <div style="
                background: #fee2e2;
                border: 1px solid #fecaca;
                color: #dc2626;
                padding: 10px;
                margin: 10px 0;
                border-radius: 6px;
                font-size: 14px;
            ">
                ⚠️ <strong>Phishing Shield Warning:</strong> This form contains suspicious elements that are commonly used in phishing attacks.
            </div>
        `

    form.parentNode.insertBefore(warning, form)
  }

  showPageWarning(message) {
    // Create floating warning
    const warning = document.createElement("div")
    warning.innerHTML = `
            <div style="
                position: fixed;
                top: 20px;
                right: 20px;
                background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
                color: white;
                padding: 15px 20px;
                border-radius: 8px;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                font-size: 14px;
                font-weight: 500;
                z-index: 999999;
                box-shadow: 0 4px 20px rgba(0,0,0,0.15);
                max-width: 300px;
                cursor: pointer;
            " onclick="this.remove()">
                🛡️ <strong>Phishing Shield:</strong><br>
                ${message}
                <div style="font-size: 12px; margin-top: 5px; opacity: 0.9;">
                    Click to dismiss
                </div>
            </div>
        `

    document.body.appendChild(warning)

    // Auto-dismiss after 8 seconds
    setTimeout(() => {
      if (warning.parentNode) {
        warning.remove()
      }
    }, 8000)
  }

  showInlineWarning(data) {
    this.showPageWarning(`Risk Score: ${data.risk_score}% - ${data.recommendation}`)
  }

  reportSuspiciousActivity(type, details) {
    if (typeof chrome !== "undefined" && chrome.runtime) {
      chrome.runtime.sendMessage({
        action: "reportActivity",
        type: type,
        details: details,
        url: window.location.href,
      })
    }
  }
}

// Initialize content script
if (typeof chrome !== "undefined" && chrome.runtime) {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      new PhishingShieldContent()
    })
  } else {
    new PhishingShieldContent()
  }
} else {
  console.warn('Phishing Shield extension not properly loaded.  "chrome.runtime" is undefined.')
}
