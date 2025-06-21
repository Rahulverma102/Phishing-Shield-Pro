class PhishingShieldPreview {
  constructor() {
    this.initializeAnimations()
    this.initializeDemo()
    this.initializeScrollEffects()
  }

  initializeAnimations() {
    // Animate statistics on page load
    this.animateStats()

    // Animate feature cards on scroll
    this.observeElements()
  }

  animateStats() {
    const stats = document.querySelectorAll(".stat-number")
    stats.forEach((stat) => {
      const target = Number.parseFloat(stat.getAttribute("data-target"))
      const increment = target / 100
      let current = 0

      const timer = setInterval(() => {
        current += increment
        if (current >= target) {
          current = target
          clearInterval(timer)
        }

        if (target < 1) {
          stat.textContent = current.toFixed(1)
        } else {
          stat.textContent = Math.floor(current).toLocaleString()
        }
      }, 20)
    })
  }

  observeElements() {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.style.opacity = "1"
            entry.target.style.transform = "translateY(0)"
          }
        })
      },
      { threshold: 0.1 },
    )

    // Observe feature cards
    document.querySelectorAll(".feature-card").forEach((card) => {
      card.style.opacity = "0"
      card.style.transform = "translateY(30px)"
      card.style.transition = "opacity 0.6s ease, transform 0.6s ease"
      observer.observe(card)
    })

    // Observe steps
    document.querySelectorAll(".step").forEach((step) => {
      step.style.opacity = "0"
      step.style.transform = "translateY(30px)"
      step.style.transition = "opacity 0.6s ease, transform 0.6s ease"
      observer.observe(step)
    })
  }

  initializeDemo() {
    // Demo URL examples with predefined results
    this.demoData = {
      "https://google.com": {
        risk_score: 5,
        risk_level: "LOW",
        recommendation: "SAFE",
        factors: {
          https: true,
          domain_age: "Old",
          ssl_valid: true,
          blacklisted: false,
          suspicious_patterns: false,
          reputation: "Excellent",
        },
      },
      "http://phishing-site.com": {
        risk_score: 95,
        risk_level: "HIGH",
        recommendation: "BLOCK",
        factors: {
          https: false,
          domain_age: "New",
          ssl_valid: false,
          blacklisted: true,
          suspicious_patterns: true,
          reputation: "Malicious",
        },
      },
      "https://suspicious-bank.tk": {
        risk_score: 75,
        risk_level: "MEDIUM",
        recommendation: "CAUTION",
        factors: {
          https: true,
          domain_age: "New",
          ssl_valid: true,
          blacklisted: false,
          suspicious_patterns: true,
          reputation: "Suspicious",
        },
      },
    }
  }

  initializeScrollEffects() {
    // Smooth scrolling for navigation links
    document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
      anchor.addEventListener("click", (e) => {
        e.preventDefault()
        const target = document.querySelector(anchor.getAttribute("href"))
        if (target) {
          target.scrollIntoView({
            behavior: "smooth",
            block: "start",
          })
        }
      })
    })

    // Navbar background on scroll
    window.addEventListener("scroll", () => {
      const navbar = document.querySelector(".navbar")
      if (window.scrollY > 100) {
        navbar.style.background = "rgba(255, 255, 255, 0.98)"
        navbar.style.boxShadow = "0 2px 20px rgba(0, 0, 0, 0.1)"
      } else {
        navbar.style.background = "rgba(255, 255, 255, 0.95)"
        navbar.style.boxShadow = "none"
      }
    })
  }
}

// Demo functions
function scrollToDemo() {
  document.getElementById("demo").scrollIntoView({
    behavior: "smooth",
    block: "start",
  })
}

function scrollToFeatures() {
  document.getElementById("features").scrollIntoView({
    behavior: "smooth",
    block: "start",
  })
}

function setDemoUrl(url) {
  document.getElementById("demoUrl").value = url
  analyzeDemo()
}

function analyzeDemo() {
  const url = document.getElementById("demoUrl").value.trim()
  if (!url) {
    alert("Please enter a URL to analyze")
    return
  }

  const resultsDiv = document.getElementById("demoResults")
  const analysisUrl = document.getElementById("analysisUrl")
  const scoreCircle = document.getElementById("demoScoreCircle")
  const scoreValue = document.getElementById("demoScoreValue")
  const riskLevel = document.getElementById("demoRiskLevel")
  const recommendation = document.getElementById("demoRecommendation")
  const factorsGrid = document.getElementById("demoFactors")

  // Show loading state
  scoreValue.textContent = "..."
  riskLevel.textContent = "Analyzing..."
  recommendation.textContent = ""
  resultsDiv.style.display = "block"
  analysisUrl.textContent = url

  // Simulate analysis delay
  setTimeout(() => {
    const preview = new PhishingShieldPreview()
    const data = preview.demoData[url] || generateRandomAnalysis(url)

    // Update results
    scoreValue.textContent = data.risk_score
    riskLevel.textContent = `${data.risk_level} RISK`
    recommendation.textContent = data.recommendation

    // Update score circle color
    scoreCircle.className = "score-circle-large"
    if (data.risk_score >= 70) {
      scoreCircle.classList.add("high")
      riskLevel.style.color = "#ef4444"
    } else if (data.risk_score >= 40) {
      scoreCircle.classList.add("medium")
      riskLevel.style.color = "#f59e0b"
    } else {
      riskLevel.style.color = "#10b981"
    }

    // Update factors
    factorsGrid.innerHTML = Object.entries(data.factors)
      .map(([key, value]) => {
        const label = key.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())
        let statusClass = "safe"
        let statusText = value

        if (typeof value === "boolean") {
          statusText = value ? "✓" : "✗"
          statusClass = value ? "safe" : "danger"
        } else if (typeof value === "string") {
          if (value.toLowerCase().includes("malicious") || value.toLowerCase().includes("suspicious")) {
            statusClass = "danger"
          } else if (value.toLowerCase().includes("new")) {
            statusClass = "warning"
          }
        }

        return `
                    <div class="factor-item">
                        <span>${label}</span>
                        <span class="factor-status ${statusClass}">${statusText}</span>
                    </div>
                `
      })
      .join("")
  }, 1500)
}

function generateRandomAnalysis(url) {
  // Generate semi-realistic analysis for unknown URLs
  const domain = url.replace(/^https?:\/\//, "").split("/")[0]
  const isHttps = url.startsWith("https://")
  const hasSuspiciousTld = /\.(tk|ml|ga|cf|pw)$/.test(domain)
  const hasNumbers = /\d/.test(domain)
  const isLongDomain = domain.length > 20

  let riskScore = 10
  if (!isHttps) riskScore += 20
  if (hasSuspiciousTld) riskScore += 30
  if (hasNumbers) riskScore += 15
  if (isLongDomain) riskScore += 20

  riskScore = Math.min(riskScore + Math.random() * 20, 100)

  let riskLevel = "LOW"
  let recommendation = "SAFE"

  if (riskScore >= 70) {
    riskLevel = "HIGH"
    recommendation = "BLOCK"
  } else if (riskScore >= 40) {
    riskLevel = "MEDIUM"
    recommendation = "CAUTION"
  }

  return {
    risk_score: Math.round(riskScore),
    risk_level: riskLevel,
    recommendation: recommendation,
    factors: {
      https: isHttps,
      domain_age: Math.random() > 0.5 ? "Old" : "New",
      ssl_valid: isHttps,
      blacklisted: riskScore > 80,
      suspicious_patterns: hasSuspiciousTld || hasNumbers,
      reputation: riskScore > 70 ? "Poor" : riskScore > 40 ? "Unknown" : "Good",
    },
  }
}

function downloadExtension() {
  alert(
    "Extension download would start here!\n\n" +
      "In a real implementation, this would:\n" +
      "• Download the extension package\n" +
      "• Provide installation instructions\n" +
      "• Link to Chrome Web Store",
  )
}

function viewSource() {
  alert(
    "Source code viewing would open here!\n\n" +
      "This would typically link to:\n" +
      "• GitHub repository\n" +
      "• Documentation\n" +
      "• API documentation",
  )
}

// Initialize the preview when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  new PhishingShieldPreview()
})
