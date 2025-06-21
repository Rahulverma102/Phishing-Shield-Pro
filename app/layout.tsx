import type React from "react"
import type { Metadata } from "next"
import Script from "next/script"
import "./globals.css"

export const metadata: Metadata = {
  title: " Phishing ",
  description: "Created with v0",
  generator: "v0.dev",
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en">
      <body>
        {children}
        {/* —————————————————————————————— */}
        {/* Reload once if a chunk fails to load */}
        <Script id="retry-chunk-load" strategy="afterInteractive">{`
        (function () {
          let hasRetried = false;
          window.addEventListener('error', function (e) {
            if (
              !hasRetried &&
              e?.message &&
              e.message.includes('Loading chunk') &&
              /\\.js$/.test(e?.target?.src || '')
            ) {
              hasRetried = true;
              console.warn('Chunk load failed, retrying once…');
              // Bust the cache with a timestamp
              const url = new URL(window.location.href);
              url.searchParams.set('_r', Date.now().toString());
              window.location.replace(url.toString());
            }
          });
        })();
      `}</Script>
        {/* —————————————————————————————— */}
      </body>
    </html>
  )
}
