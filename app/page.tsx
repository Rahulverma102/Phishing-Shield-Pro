import EnhancedDemoAnalyzer from "@/components/demo-analyzer"

export default function Page() {
  return (
    <main className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
      {/* Header */}
      <header className="bg-white/80 backdrop-blur-sm border-b border-gray-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <span className="text-2xl">🛡️</span>
            <span className="text-xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
              Phishing Detection
            </span>
          </div>
          <div className="hidden md:flex items-center space-x-6">
            <span className="text-sm text-gray-600">Advanced Security Scanner</span>
            <div className="flex items-center space-x-2 bg-green-100 text-green-700 px-3 py-1 rounded-full text-sm">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
              <span>Live Protection</span>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-16 px-4">
        <div className="max-w-4xl mx-auto text-center mb-12">
          <h1 className="text-5xl font-bold text-gray-900 mb-6">
            🛡️ Advanced Security Scanner
            <span className="block text-3xl bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent mt-2">
              Deep Subdomain & Vulnerability Analysis
            </span>
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto leading-relaxed">
            Comprehensive security analysis with subdomain vulnerability detection, threat intelligence, certificate
            validation, and DNS security assessment. Protect yourself from advanced phishing attacks.
          </p>
        </div>

        {/* Feature Highlights */}
        <div className="max-w-6xl mx-auto mb-12">
          <div className="grid md:grid-cols-4 gap-6 text-center">
            {[
              { icon: "🌐", title: "Subdomain Analysis", desc: "Deep scan of all subdomains" },
              { icon: "⚠️", title: "Vulnerability Detection", desc: "Identify security weaknesses" },
              { icon: "🕵️", title: "Threat Intelligence", desc: "Real-time threat data" },
              { icon: "📜", title: "Certificate Validation", desc: "SSL/TLS security check" },
            ].map((feature, i) => (
              <div
                key={i}
                className="bg-white/60 backdrop-blur-sm rounded-xl p-6 border border-white/20 hover:bg-white/80 transition-all"
              >
                <div className="text-3xl mb-3">{feature.icon}</div>
                <h3 className="font-semibold text-gray-900 mb-2">{feature.title}</h3>
                <p className="text-sm text-gray-600">{feature.desc}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Main Analyzer */}
        <EnhancedDemoAnalyzer />
      </section>

      {/* Footer */}
      <footer className="bg-gray-900 text-white py-12 mt-20">
        <div className="max-w-6xl mx-auto px-4 text-center">
          <div className="flex items-center justify-center space-x-3 mb-4">
            <span className="text-2xl">🛡️</span>
            <span className="text-xl font-bold">Phishing Detection</span>
          </div>
          <p className="text-gray-400 mb-6">Advanced browser protection with enterprise-grade security analysis</p>
          <div className="flex justify-center space-x-8 text-sm text-gray-400">
            <span>✅ Real-time Protection</span>
            <span>✅ Subdomain Analysis</span>
            <span>✅ Threat Intelligence</span>
            <span>✅ Certificate Validation</span>
          </div>
          <div className="mt-8 pt-8 border-t border-gray-800 text-gray-500">
            &copy; 2024 Phishing Detection. Built with advanced security in mind.
          </div>
        </div>
      </footer>
    </main>
  )
}
